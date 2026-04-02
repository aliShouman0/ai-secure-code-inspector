
#

# We implement 3 required prompt engineering strategies:
#  Role + Constraints
#  Few-Shot Examples
#  Verification / Deduplication Pass
# Plus two supporting techniques:
#   - OWASP definitions injection (context grounding)
#   - Chunking (handled in inspector.py, prompt built here)
OWASP_REFERENCE = """
OWASP Top 10 (2021) Quick Reference:
A01 - Broken Access Control: Missing authorization checks, IDOR, path traversal.
A02 - Cryptographic Failures: Weak/no encryption, hardcoded secrets, weak hashing.
A03 - Injection: SQL, NoSQL, command, LDAP injection via untrusted input.
A04 - Insecure Design: Missing rate limiting, insecure direct object refs by design.
A05 - Security Misconfiguration: Default creds, verbose errors, unnecessary features.
A06 - Vulnerable Components: Outdated libraries with known CVEs.
A07 - Identification & Auth Failures: Broken auth, weak passwords, missing MFA.
A08 - Software & Data Integrity Failures: Insecure deserialization, unsigned updates.
A09 - Logging & Monitoring Failures: No audit logs, silent failures.
A10 - SSRF: Server-side requests to internal resources via user input.
"""




#  Few-Shot Examples  
# "Few-shot" means we show the AI 2-3 examples of input output
FEW_SHOT_EXAMPLES = """
Example 1 — SQL Injection:
Code:
  const query = "SELECT * FROM Users WHERE email = '" + email + "'";
  db.query(query);

Expected output:
{
  "owasp_category": "A03 - Injection",
  "risk_summary": "User input is concatenated directly into a SQL query without sanitization. An attacker can manipulate the query to bypass authentication or dump the entire database.",
  "fix": "Use parameterized queries: db.query('SELECT * FROM Users WHERE email = ?', [email])",
  "confidence": 0.97
}

Example 2 — Hardcoded Secret:
Code:
  const secret = "jwt_secret_key_123";
  jwt.sign(payload, secret);

Expected output:
{
  "owasp_category": "A02 - Cryptographic Failures",
  "risk_summary": "A hardcoded static JWT secret is used for signing tokens. If the source code is exposed, all tokens can be forged by an attacker.",
  "fix": "Load the secret from an environment variable: process.env.JWT_SECRET. Rotate immediately if exposed.",
  "confidence": 0.95
}

Example 3 — Missing Authorization:
Code:
  app.get('/user/:id/orders', (req, res) => {
    db.query('SELECT * FROM Orders WHERE userId = ' + req.params.id);
  });

Expected output:
{
  "owasp_category": "A01 - Broken Access Control",
  "risk_summary": "No authorization check verifies that the requesting user owns the requested resource. Any authenticated user can access any other user's orders by changing the ID.",
  "fix": "Add ownership check: if (req.user.id !== req.params.id) return res.status(403).send('Forbidden')",
  "confidence": 0.91
}
"""


#  Strategy 1 + 2 + OWASP Injection: Analysis Prompt 
# This is the main prompt sent for each code chunk.
# It combines:
#   - Role assignment ("you are a senior AppSec engineer")
#   - Hard constraints (no hallucination, OWASP only)
#   - OWASP reference text injected directly
#   - Few-shot examples showing expected output format
#   - The actual code chunk to analyze
#   - Strict JSON output schema
def build_analysis_prompt(filename: str, chunk: str) -> str:
    """
    Builds the analysis prompt for a single code chunk.
    
    Parameters:
        filename : the relative path of the file being analyzed
                   (shown to the model so it can reference it in findings)
        chunk    : the actual source code lines to analyze
    
    Returns:
        A complete prompt string ready to send to Claude.
    """
    return f"""You are a senior application security engineer conducting a secure code review.

ROLE & CONSTRAINTS (follow these strictly):
- Your only job is to find real, exploitable security vulnerabilities.
- Do NOT report code style issues, missing comments, or non-security problems.
- Do NOT hallucinate file names, function names, or line numbers you are not certain about.
- Every finding MUST map to one of the OWASP Top 10 (2021) categories below.
- If you are not confident something is a real vulnerability, do not include it.

{OWASP_REFERENCE}

EXAMPLES OF GOOD FINDINGS (few-shot):
{FEW_SHOT_EXAMPLES}

Now analyze the following code from file: `{filename}`
```
{chunk}
```

OUTPUT RULES:
- Return ONLY a valid JSON array of findings.
- Use this exact schema for each finding:
{{
  "file": "<the filename passed to you>",
  "line_range": "<e.g. '12-28' — your best estimate based on the chunk>",
  "owasp_category": "<e.g. 'A03 - Injection'>",
  "risk_summary": "<2-3 sentences: what is vulnerable, how it can be exploited, what the impact is>",
  "fix": "<specific, actionable fix referencing the exact code shown>",
  "confidence": <a float from 0.0 to 1.0 — how certain you are this is a real vulnerability>
}}
- If there are no findings, return an empty array: []
- Do not write anything outside the JSON array. No intro, no explanation.
"""


#  Strategy 3: Verification Prompt 
# After collecting all findings from all chunks of all files,
# we send them through a SECOND prompt — a "verification pass".
# Purpose:
#   - Remove false positives (things that look bad but aren't)
#   - Deduplicate findings that describe the same root cause
#   - Validate that every finding truly maps to OWASP Top 10
#   - Lower confidence scores on weak evidence
# This is a critical quality control step that makes our tool
# significantly more accurate than a single-pass approach.
def build_verification_prompt(findings: list) -> str:
    """
    Builds the verification/deduplication prompt.
    
    Parameters:
        findings : the full list of raw findings from all file chunks
    
    Returns:
        A prompt string asking Claude to clean and validate the findings.
    """
    import json  # imported here to avoid circular imports at module level

    return f"""You are a senior AppSec engineer doing a final quality control pass on AI-generated vulnerability findings.

YOUR TASKS:
1. Remove false positives — findings that are not real, exploitable vulnerabilities.
2. Deduplicate — if two findings describe the same root cause in the same file, keep only the better one.
3. Validate OWASP mapping — ensure every finding uses a valid OWASP Top 10 (2021) category.
4. Adjust confidence — lower the score if the evidence in the finding is weak or speculative.
5. Do NOT add new findings. Only clean what is given.

{OWASP_REFERENCE}

RAW FINDINGS TO VALIDATE:
{json.dumps(findings, indent=2)}

OUTPUT RULES:
- Return ONLY a valid JSON array using the same schema as the input.
- Remove any finding that does not survive scrutiny.
- Do not write anything outside the JSON array.
"""