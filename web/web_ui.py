
import os
import sys
import json
import anthropic

#    Let Python find inspector.py in the project root
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from flask import Flask, render_template, request, Response, send_file, jsonify, abort
from inspector import analyze_file, verification_pass, save_json, save_markdown

#   index.html lives in web/ (same folder as this file)
#   app.js and style.css also live in web/

app = Flask(__name__, template_folder='.', static_folder='.', static_url_path='/static')

#    Folders
DOWNLOADS = os.path.join(ROOT, "downloads")
os.makedirs(DOWNLOADS, exist_ok=True)

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


#    Scan (Server-Sent Events)
# SSE lets us push progress updates to the browser in real time.
# The browser opens one long-lived connection; we send JSON events
# as each file is analyzed — no polling needed.

@app.route("/scan")
def scan():
    target  = request.args.get("path", "target/juice-shop")
    mode    = request.args.get("mode", "full")
    api_key = request.args.get("key", "").strip()
    scope   = SCOPE if mode == "full" else SCOPE[:3]

    def stream():

        def send(data):
            return f"data: {json.dumps(data)}\n\n"

        # Validate API key before doing anything
        if not api_key:
            yield send({"type": "error", "msg": "No API key provided. Enter your Anthropic API key in the sidebar."})
            return

        # Create a per-request Anthropic client using the key the user entered
        try:
            api_client = anthropic.Anthropic(api_key=api_key)
        except Exception as error:
            yield send({"type": "error", "msg": f"Invalid API key: {error}"})
            return

        # Make sure the target folder exists before starting
        if not os.path.exists(target):
            yield send({"type": "error", "msg": f"Path not found: {target}"})
            return

        raw_findings = []
        total_files  = len(scope)

        #    Phase 1: analyze each file
        for index, rel_path in enumerate(scope):
            full_path = os.path.join(target, rel_path.replace("/", os.sep))
            progress  = int(index / total_files * 80)   # 0–80% during analysis

            if not os.path.exists(full_path):
                yield send({"type": "log", "msg": f"⚠️  Skipping (not found): {rel_path}", "pct": progress})
                continue

            yield send({"type": "log", "msg": f"🔍 Analyzing: {rel_path}", "pct": progress})

            try:
                findings = analyze_file(full_path, rel_path, api_client)
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

        #    Phase 3: save reports to downloads/
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