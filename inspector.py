

import os        
import json      
import argparse  
import anthropic # the official Anthropic Python SDK (calls Claude API)

from dotenv import load_dotenv

load_dotenv()

# Import our prompt-building functions from prompts.py
from prompts import build_analysis_prompt, build_verification_prompt
                                                                   
CHUNK_SIZE = 80   # Lines per chunk sent to Claude.         
MODEL = "claude-haiku-4-5-20251001"

# Default client for CLI use (reads from environment variable).
# Web UI creates its own client per-request using the key provided in the UI.
client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))



def read_file(path: str) -> str:
    """
    Reads a source file and returns its content as a string.
    errors="ignore" handles any unusual characters in the source.
    """
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


#Chunk the code  
#                                                      
def chunk_code(code: str, chunk_size: int = CHUNK_SIZE):
    """
    Splits source code into chunks of `chunk_size` lines each.
    
    Returns a list of tuples: (start_line_number, chunk_text)
    Example: [(1, "line1\nline2\n..."), (81, "line81\nline82\n...")]
    """
    lines = code.splitlines()  # split into individual lines
    chunks = []
    
    for i in range(0, len(lines), chunk_size):
        block = lines[i : i + chunk_size]   # slice chunk_size lines
        start_line = i + 1                  # line numbers start at 1, not 0
        chunks.append((start_line, "\n".join(block)))
    
    return chunks



#         Call Claude API
def call_claude(prompt: str, api_client=None) -> list:
    """
    Returns a list of finding dictionaries (may be empty).
    api_client: optional Anthropic client (used by web UI per-request).
                Falls back to module-level client if not provided.
    """
    active_client = api_client or client
    message = active_client.messages.create(
        model=MODEL,
        max_tokens=2048,
        messages=[{"role": "user", "content": prompt}]
    )
    
    # Extract the text response from the API result
    raw = message.content[0].text.strip()
    
    # Strip markdown code fences if Claude wrapped the JSON in them
    # e.g. ```json\n[...]\n``` → [...]
    if raw.startswith("```"):
        raw = "\n".join(raw.split("\n")[1:])  # remove first line (```json)
    if raw.endswith("```"):
        raw = "\n".join(raw.split("\n")[:-1]) # remove last line (```)
    
    # Parse the JSON array
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        # If Claude returned something unexpected, warn and continue
        print(f"  ⚠️  Could not parse JSON — skipping this chunk.")
        return []



#     Core: Analyze one file
#   rel_name : relative path
def analyze_file(filepath: str, rel_name: str, api_client=None) -> list:
    """
    Analyzes a single source file for vulnerabilities.

    Steps:
    1. Read the file
    2. Split into chunks
    3. For each chunk, build a prompt and call Claude
    4. Collect all findings from all chunks
    Returns:
        List of all raw findings from this file (not yet verified).
    """
    print(f"\n🔍 Analyzing: {rel_name}")

    code = read_file(filepath)
    chunks = chunk_code(code)

    print(f"   {len(chunks)} chunk(s) of up to {CHUNK_SIZE} lines each")

    all_findings = []

    for start_line, chunk_text in chunks:
        print(f"   → chunk starting at line {start_line}...", end=" ", flush=True)

        # Build the analysis prompt for this specific chunk
        prompt = build_analysis_prompt(rel_name, chunk_text)

        # Send to Claude and get findings back
        findings = call_claude(prompt, api_client)

        print(f"{len(findings)} finding(s)")
        all_findings.extend(findings)  # add to our master list

    return all_findings




#     Core: Verification pass
def verification_pass(all_findings: list, api_client=None) -> list:
    """
    Verifies findings in batches of 10 to avoid token limit issues.
    Each batch is sent to Claude separately then results are combined.
    """
    print(f"\n🔎 Running verification pass on {len(all_findings)} raw finding(s)...")

    if not all_findings:
        print("   No findings to verify.")
        return []

    BATCH_SIZE = 10
    verified_all = []
    batches = [all_findings[i:i+BATCH_SIZE] for i in range(0, len(all_findings), BATCH_SIZE)]
    print(f"   Processing {len(batches)} batch(es) of up to {BATCH_SIZE} findings each...")

    for idx, batch in enumerate(batches, 1):
        print(f"   → batch {idx}/{len(batches)} ({len(batch)} findings)...", end=" ", flush=True)
        prompt = build_verification_prompt(batch)
        verified = call_claude(prompt, api_client)
        print(f"{len(verified)} passed")
        verified_all.extend(verified)

    removed = len(all_findings) - len(verified_all)
    print(f"   ✅ {len(verified_all)} finding(s) passed | {removed} removed as FP/duplicate")
    return verified_all



#     Output: Save JSON report                                                    
def save_json(findings: list, path: str = "report.json"):
    """
    Saves findings to a structured JSON file.
    
    Format:
    {
      "total": <number of findings>,
      "findings": [ ...finding objects... ]
    }
    
    This is machine-readable and can be imported into other tools.
    """
    output = {
        "total": len(findings),
        "findings": findings
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
    print(f"\n📄 Saved: {path}")


#     Output: Save Markdown report                                              
def save_markdown(findings: list, path: str = "report.md"):
    """
    Saves findings to a human-readable Markdown file.
    
    Each finding gets its own section with:
    - OWASP category as the heading
    - File + line range
    - Confidence score
    - Risk summary
    - Specific fix recommendation
    """
    lines = [
        "# AI Secure Code Inspector — Vulnerability Report",
        "",
        "**Target:** OWASP Juice Shop  ",
        "**Scope:** 10 files (routes, lib, models, frontend)  ",
        f"**Total verified findings:** {len(findings)}  ",
        "",
        "---",
        ""
    ]
    
    for i, f in enumerate(findings, 1):
        lines += [
            f"## Finding {i}: {f.get('owasp_category', 'N/A')}",
            "",
            f"**File:** `{f.get('file', 'N/A')}`  ",
            f"**Line range:** {f.get('line_range', 'N/A')}  ",
            f"**Confidence:** {f.get('confidence', 'N/A')}  ",
            "",
            "### Risk Summary",
            f.get('risk_summary', ''),
            "",
            "### Fix Recommendation",
            f.get('fix', ''),
            "",
            "---",
            ""
        ]
    
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"📄 Saved: {path}")


#     Main entry point                                                                
def main():
    """
    Entry point when you run: python inspector.py --target <path>
    --target is required: the path to the Juice Shop root folder.
    --scope  is optional: a text file with custom file paths to analyze.
             If not provided, the default 10 files are used.
    """
    
    # Set up argument parser 
    parser = argparse.ArgumentParser(
        description="AI Secure Code Inspector — finds OWASP Top 10 vulnerabilities using Claude"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Path to the root of the target application (e.g. target\\juice-shop)"
    )
    parser.add_argument(
        "--scope",
        default=None,
        help="Optional: path to a text file listing relative file paths to analyze (one per line)"
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Test mode: scan only 3 files to verify everything works cheaply"
    )
    args = parser.parse_args() 




    #Default scope: our fixed 10 files   
    default_scope = [
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

    # Test scope — only 3 files for quick/cheap testing
    test_scope = [
        "routes/login.ts",
        "lib/insecurity.ts",
        "models/user.ts",
    ]

    # If a custom scope file was provided, use that
    if args.scope and os.path.exists(args.scope):
        with open(args.scope) as f:
            scope = [line.strip() for line in f if line.strip()]
        print(f"📋 Using custom scope from {args.scope}: {len(scope)} file(s)")
    elif args.test:
        scope = test_scope
        print(f"📋 TEST MODE: scanning {len(scope)} files only")
    else:
        scope = default_scope
        print(f"📋 Using default scope: {len(scope)} file(s)")
 


    #     Analyze each file                                              
    all_raw_findings = []
    
    for rel_path in scope:
        # Build the full path by joining target root + relative path
        # os.sep converts forward slashes to backslashes on Windows
        full_path = os.path.join(args.target, rel_path.replace("/", os.sep))
        
        if not os.path.exists(full_path):
            print(f"⚠️  Skipping (file not found): {full_path}")
            continue
        
        findings = analyze_file(full_path, rel_path)
        all_raw_findings.extend(findings)

    print(f"\n📊 Raw findings collected: {len(all_raw_findings)}")

    #     Verification pass                                              
    verified_findings = verification_pass(all_raw_findings)

    #     Save reports to downloads/                               
    os.makedirs("downloads", exist_ok=True)
    save_json(verified_findings,     "downloads/report.json")
    save_markdown(verified_findings, "downloads/report.md")

    print(f"\n✅ Scan complete. {len(verified_findings)} verified findings.")
    print("   → downloads/report.json")
    print("   → downloads/report.md")


# This ensures main() only runs when the script is executed directly,
# not when it's imported as a module by web_ui.py
if __name__ == "__main__":
    main()