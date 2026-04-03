
import os
import sys
import json
import uuid
import shutil
import anthropic

#    Let Python find inspector.py in the project root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from flask import Flask, render_template, request, Response, send_file, jsonify, abort
from werkzeug.utils import secure_filename
from inspector import analyze_file, verification_pass, save_json, save_markdown

#   index.html lives in web/ (same folder as this file)
#   app.js and style.css also live in web/

app = Flask(__name__, template_folder='.', static_folder='.', static_url_path='/static')

#    Folders
DOWNLOADS = os.path.join(ROOT, "downloads")
UPLOADS   = os.path.join(ROOT, "uploads")
os.makedirs(DOWNLOADS, exist_ok=True)
os.makedirs(UPLOADS,   exist_ok=True)

#    Files to scan (fixed scope)
SCOPE = [
    "routes/login.ts",
    "routes/search.ts",
    "routes/fileUpload.ts",
    "routes/changePassword.ts",
    "routes/resetPassword.ts",
    "routes/basket.ts",
    "routes/order.ts",
    "lib/insecurity.ts",
    "frontend/src/app/login/login.component.ts",
    "models/user.ts",
]


#    Page
@app.route("/")
def index():
    return render_template("index.html", scope_full=SCOPE)


#    Upload files endpoint
@app.route("/upload", methods=["POST"])
def upload():
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files provided"}), 400

    # Each upload gets its own temp folder so concurrent scans don't clash
    session_id  = uuid.uuid4().hex
    upload_dir  = os.path.join(UPLOADS, session_id)
    os.makedirs(upload_dir, exist_ok=True)

    saved = []
    for f in files:
        filename = secure_filename(f.filename)
        if filename:
            f.save(os.path.join(upload_dir, filename))
            saved.append(filename)

    return jsonify({"path": upload_dir, "files": saved})


#    Scan (Server-Sent Events)
@app.route("/scan")
def scan():
    target  = request.args.get("path", "target/juice-shop")
    mode    = request.args.get("mode", "full")
    api_key = request.args.get("key", "").strip()

    # Build file list depending on mode
    if mode == "upload":
        # Uploaded files — scan every file in the upload folder
        if not os.path.isdir(target):
            def err_stream():
                yield f"data: {json.dumps({'type': 'error', 'msg': 'Upload folder not found.'})}\n\n"
            return Response(err_stream(), mimetype="text/event-stream")
        file_pairs = [
            (os.path.join(target, f), f)
            for f in os.listdir(target)
            if os.path.isfile(os.path.join(target, f))
        ]
    else:
        scope     = SCOPE if mode == "full" else SCOPE[:3]
        file_pairs = [
            (os.path.join(target, rel.replace("/", os.sep)), rel)
            for rel in scope
        ]

    def stream():

        def send(data):
            return f"data: {json.dumps(data)}\n\n"

        if not api_key:
            yield send({"type": "error", "msg": "No API key provided. Enter your Anthropic API key in the sidebar."})
            return

        try:
            api_client = anthropic.Anthropic(api_key=api_key)
        except Exception as error:
            yield send({"type": "error", "msg": f"Invalid API key: {error}"})
            return

        raw_findings = []
        total_files  = len(file_pairs)

        #    Phase 1: analyze each file
        for index, (full_path, rel_name) in enumerate(file_pairs):
            progress = int(index / total_files * 80)

            if not os.path.exists(full_path):
                yield send({"type": "log", "msg": f"⚠️  Skipping (not found): {rel_name}", "pct": progress})
                continue

            yield send({"type": "log", "msg": f"🔍 Analyzing: {rel_name}", "pct": progress})

            try:
                findings = analyze_file(full_path, rel_name, api_client)
                raw_findings.extend(findings)
                yield send({"type": "log", "msg": f"   → {len(findings)} raw finding(s)", "pct": int((index + 1) / total_files * 80)})
            except Exception as error:
                yield send({"type": "log", "msg": f"   ⚠️  Error: {error}", "pct": progress})

        #    Phase 2: verification pass
        yield send({"type": "log", "msg": f"\n📊 Raw findings total: {len(raw_findings)}", "pct": 85})
        yield send({"type": "log", "msg": "🔎 Running verification pass (batched)...", "pct": 87})

        try:
            verified = verification_pass(raw_findings, api_client)
        except Exception as error:
            yield send({"type": "error", "msg": f"Verification failed: {error}"})
            return

        # Clean up upload folder after scan
        if mode == "upload" and os.path.isdir(target):
            shutil.rmtree(target, ignore_errors=True)

        #    Phase 3: save reports
        save_json(verified,     os.path.join(DOWNLOADS, "report.json"))
        save_markdown(verified, os.path.join(DOWNLOADS, "report.md"))

        yield send({"type": "log", "msg": f"✅ Done! {len(verified)} verified findings saved to downloads/", "pct": 100})
        yield send({"type": "done", "raw": len(raw_findings), "verified": len(verified)})

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


#    Results
@app.route("/results")
def results():
    report_path = os.path.join(DOWNLOADS, "report.json")
    if not os.path.exists(report_path):
        return jsonify([])
    with open(report_path, encoding="utf-8") as f:
        return jsonify(json.load(f).get("findings", []))


#    Download
@app.route("/download/<filename>")
def download(filename):
    if filename not in ("report.json", "report.md"):
        abort(404)
    file_path = os.path.join(DOWNLOADS, filename)
    if not os.path.exists(file_path):
        abort(404)
    return send_file(file_path, as_attachment=True)


#    Start server
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("AI Secure Code Inspector")
    print(f"Open: http://localhost:{port}")
    app.run(debug=False, host="0.0.0.0", port=port)