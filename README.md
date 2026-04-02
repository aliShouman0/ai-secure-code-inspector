# AI Secure Code Inspector

Prompt-engineering project for CBRS503 (AI Security) at Lebanese University.
Uses Claude AI to detect security vulnerabilities in OWASP Juice Shop, mapped to OWASP Top 10.

---

## What it does

The tool scans a fixed set of 10 files from Juice Shop. For each file, the code is chunked and sent to Claude using three different prompt strategies (role + constraints, few-shot examples, and a verification pass). Results are saved as a structured JSON report and a readable markdown file. There's a CLI for quick runs and a Flask web UI if you prefer a browser.

It was also compared against Semgrep OSS to validate the findings — see `comparison.md`.

---

## Project structure

```
ai-secure-code-inspector/
├── inspector.py          # main CLI entry point
├── prompts.py            # the 3 prompt templates
├── prompt_log.md         # prompt versions and why each change was made
├── comparison.md         # AI tool vs Semgrep results
├── requirements.txt
├── downloads/
│   ├── report.json       # structured output (file, line, OWASP, fix, confidence)
│   └── report.md         # human-readable report
├── baseline/
│   ├── semgrep_results.json
│   └── semgrep_results.txt
├── web/
│   ├── web_ui.py         # Flask server
│   ├── index.html
│   ├── app.js
│   └── style.css
└── target/
    └── juice-shop/       # cloned separately, not tracked in git
```

---

## Requirements

- Python 3.12+
- Anthropic API key — get one at https://console.anthropic.com
- Juice Shop cloned into `target/juice-shop/` (step 2 below)
- Semgrep is only needed if you want to re-run the baseline scan

---

## Setup

**1. Clone this repo**
```bash
git clone <your-repo-url>
cd ai-secure-code-inspector
```

**2. Clone Juice Shop**
```bash
mkdir target
git clone https://github.com/juice-shop/juice-shop target/juice-shop
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Set your API key**
```bash
# Windows PowerShell
$env:ANTHROPIC_API_KEY = "sk-ant-..."

# Linux/Mac
export ANTHROPIC_API_KEY="sk-ant-..."
```

---

## Running

**CLI:**
```bash
python inspector.py --target "target/juice-shop"
```

**Web UI:**
```bash
python web/web_ui.py
```
Then open http://localhost:5000

**Test mode** (3 files only, much cheaper to try):
```bash
python inspector.py --target "target/juice-shop" --test
```

---

## Output

After a scan, two files are written to `downloads/`:

- `report.json` — each finding includes: file, line, OWASP category, risk summary, suggested fix, and confidence score
- `report.md` — same content but formatted for reading

---

## Files analyzed (fixed scope)

| # | File | OWASP categories |
|---|---|---|
| 1 | `routes/login.ts` | A01, A07 |
| 2 | `routes/search.ts` | A03 |
| 3 | `routes/fileUpload.ts` | A04 |
| 4 | `routes/changePassword.ts` | A01, A07 |
| 5 | `routes/resetPassword.ts` | A07 |
| 6 | `routes/basket.ts` | A01 |
| 7 | `routes/order.ts` | A01 |
| 8 | `lib/insecurity.ts` | A02 |
| 9 | `frontend/src/app/login/login.component.ts` | A03, A07 |
| 10 | `models/user.ts` | A02, A04 |

---

## Prompt engineering

Three strategies are in `prompts.py`:

1. **Role + Constraints** — tells Claude to act as a senior AppSec reviewer with hard rules: no style issues, no hallucinated line numbers, every finding must map to OWASP Top 10 (2021).
2. **Few-Shot Examples** — three labeled examples (SQL injection, hardcoded JWT, missing auth check) so Claude learns the expected output format and fix quality before it starts.
3. **Verification Pass** — a second prompt reviews all findings: removes duplicates, drops weak-evidence entries, validates OWASP categories. This cut false positives from ~32% down to ~13%.

Each file is split into 80-line chunks before being sent. The verification pass also runs in batches of 10 to avoid hitting output token limits. Full version history and reasoning behind each prompt change is in `prompt_log.md`.

---

## Semgrep baseline

Semgrep was run on the same 10 files to have a reference point for comparison.

**Install:**
```bash
pip install semgrep
```

**Run:**
```bash
# JSON output
semgrep --config p/javascript --config p/security-audit --config p/owasp-top-ten target/juice-shop/ --json > baseline/semgrep_results.json

# Text output
semgrep --config p/javascript --config p/security-audit --config p/owasp-top-ten target/juice-shop/ > baseline/semgrep_results.txt
```

Results are already in `baseline/` — only re-run if you want fresh output.

---

## Results comparison

| Metric | AI Tool | Semgrep |
|---|---|---|
| Findings | 27 | 3 |
| Precision | ~87% | 100% |
| Recall | ~95% | ~37% |
| OWASP categories | 6+ | 2 |

The two tools aren't really competing — they complement each other. Semgrep has zero false positives but misses most logic-level issues. The AI tool finds a lot more but needs the verification pass to stay clean. Full breakdown in `comparison.md`.

---

## Cost

Full scan (10 files): ~$0.05–0.10 using `claude-haiku-4-5-20251001`
