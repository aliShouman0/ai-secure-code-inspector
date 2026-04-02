# Prompt Log — AI Secure Code Inspector

This file tracks how the prompts evolved during development —
what broke, what was changed, and why each version was better than the last.

---

## Strategy 1 — Role + Constraints

**v1.0 — starting point**

The first prompt was just:
> "Analyze this code for security vulnerabilities."

That was too vague. The model returned a mix of style issues, non-security observations, and a few real findings. Line numbers were sometimes made up. The output format changed between runs — sometimes JSON, sometimes prose. OWASP categories were missing or wrong.

**v1.1 — added expert role and hard constraints**

Rewrote it as:
> "You are a senior application security engineer conducting a secure code review. Your only job is to find real, exploitable security vulnerabilities. Do NOT report code style issues. Do NOT hallucinate file names or line numbers you are not certain about. Every finding MUST map to one of the OWASP Top 10 categories."

This fixed most of the problems. False positives dropped a lot, hallucinated references disappeared, and OWASP mapping became consistent across runs.

Why it works: giving the model a specific role focuses it on the right knowledge domain. The hard constraints ("Do NOT...") act as guardrails against the most common failure modes — hallucination, scope creep, and format drift.

---

## Strategy 2 — Few-Shot Examples

**v1.0 — no examples**

Even with the role prompt, the output format was inconsistent. The `risk_summary` field ranged from one word to a full paragraph depending on the run. The `fix` field was often generic ("sanitize input" instead of showing the actual fix). Confidence scores were not calibrated — everything came back as 0.9 or 0.5.

**v1.1 — added 3 labeled examples**

Added three complete input/output examples before the actual analysis request:
1. SQL Injection — showed a parameterized query as the fix
2. Hardcoded JWT secret — showed the environment variable replacement
3. Missing authorization check — showed the exact middleware to add

After this change, the JSON format was followed in 95%+ of responses. The `risk_summary` consistently came back as 2-3 sentences with actual impact context. Fixes became specific to the code shown, not generic advice. Confidence scores started varying properly (0.91, 0.95, 0.97 instead of all the same).

Why it works: showing examples is more effective than describing the expected format in words. The model sees three complete cases and tries to match that quality and structure. It also sets a bar for how specific the fixes should be.

---

## Strategy 3 — Verification Pass

**v1.0 — single pass**

With just one analysis pass, the same vulnerability would sometimes get flagged multiple times from different chunks of the same file. Some OWASP category assignments were wrong. Low-confidence findings with weak evidence still made it into the output. Raw false positive rate was ~32% — about 13 of 40 findings.

**v1.1 — added a second reviewer prompt**

Added a second call to the model with a different role:
> "You are a senior AppSec engineer doing a final quality control pass. Remove false positives, deduplicate same root cause findings, validate OWASP mapping, lower confidence on weak evidence."

This brought the count from 40 raw findings down to 27 verified ones. Duplicates across chunks were merged. Weak-evidence findings were removed. OWASP categories were checked against the reference text injected in the prompt.

Why it works: a first pass is optimistic — the model flags anything that might be a problem. A second pass with a skeptical role asks a different question: "is this actually exploitable?" That distinction matters. It mirrors how real security teams work: raw findings go through triage before they go into a report.

**v1.2 — added batching**

When all 40 findings were sent to the verification prompt at once, the response hit the output token limit and came back as broken JSON — unparseable.

Fix: split the findings into batches of 10. So 40 findings → 4 batches → results merged at the end. After this change, zero parse failures. Each batch also gets more focused attention from the model, and cost per run is more predictable.

---

## Supporting technique — OWASP definitions injection

The full OWASP Top 10 reference text is included in every prompt, both analysis and verification.

Without it, the model falls back on whatever it learned during training, which might be the 2017 version or a mix of versions. Injecting the exact category names and definitions ensures that when a finding gets tagged as A01 or A07, it's using the right taxonomy. All 27 verified findings used valid category names — none used deprecated or incorrect ones from older versions.

---

## Supporting technique — chunking

Each file is split into 80-line chunks before being sent to Claude.

The 80-line limit came from testing. Sending full files (some were 200+ lines) caused the model to miss vulnerabilities in the middle — probably because the important code got buried in the context. 80 lines fits most functions completely while keeping the prompt focused.

The tradeoff is that chunking can split a function across two chunks, so a finding might miss some context. The verification pass helps catch cases where an incomplete finding slipped through.

Files that needed the most chunks:
- `lib/insecurity.ts` — 3 chunks (largest file in scope)
- `routes/order.ts` — 3 chunks
- Everything else — 1-2 chunks

---

## Model choice

Started with `claude-opus-4-6`. One full scan cost $0.48 — too expensive to iterate on prompts quickly.

Switched to `claude-haiku-4-5-20251001`. Cost dropped to ~$0.05-0.10 per scan. Quality impact was minimal — Haiku produced comparable findings, just with slightly lower confidence scores on average.

The lesson: with chunked, structured code and detailed prompts, a smaller model outperforms a larger one with a vague prompt. The prompt is doing most of the work.

---

## All changes at a glance

| Strategy | Change | Effect |
|---|---|---|
| Role + Constraints | Added expert role + hard constraints | Eliminated hallucinations, focused on real issues |
| Few-Shot Examples | Added 3 labeled examples | Consistent JSON format, specific fixes |
| Verification Pass | Added second reviewer prompt | Removed 32% of false positives |
| Verification Pass | Added batching (10 per batch) | Fixed token limit / JSON parse failures |
| OWASP Injection | Injected full OWASP reference text | Correct taxonomy across all 27 findings |
| Chunking | 80-line chunks per file | Consistent analysis on larger files |
