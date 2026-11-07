# AI disclosure

## AI-generated code

Most of this repository (backend, UI, tests, lab files, documents, sample inputs) was written with the assistance of Claude (Anthropic) through Claude Code, directed and reviewed by the team members. Commits are made under the team member's own identity. The code was run, tested (34 automated unit tests plus a live end-to-end suite - `scripts/e2e_live.py`, ~100 checks against the real Docker lab, last run 99/100 with the one gap being an unrelated timing race, not a safety or correctness issue) and exercised live against the lab before being committed, but it should be reviewed like any other code.

## AI used at runtime

- Default mode uses **no language model**. Action choice is a deterministic rule planner that writes a plain-text reason for every option it considered, not just the one it picked; scope enforcement, correlation, confidence scoring, risk ranking, grounding checks and the report are all code. This alone satisfies the brief's "explain the rationale behind its next steps" requirement with zero external dependency.
- Optional: if `GEMINI_API_KEY` is set (preferred if both are set) or `ANTHROPIC_API_KEY` is set, that model receives a **limited state summary**: target addresses, up to 30 `host:port service product version` strings, up to 40 finding labels (`id issue_key severity status`), open hypothesis texts, and the candidate action ids with rationales to choose among candidates the code generated. It cannot add or invent an action, only pick one of those candidates and write a rationale, and its output is checked against the grounding validator before use. **The Gemini path (`gemini-flash-lite-latest`) has been run live**: a real assessment produced genuinely contextual rationale (e.g. correctly reasoning about a discovered "Apache httpd 2.4.25" service rather than generic text). The Claude path remains unit-tested only (no Anthropic key was available to the team).
- Before any state summary leaves the machine, `planner.redact()` strips anything that looks like a credential or token (Authorization/Cookie/API-key headers, password/secret/token assignments, Bearer tokens, JWTs) from the text.
- The Ask ARGUS copilot answers from stored findings and evidence with rules; it does not call a model.

## Data handling

- All scanning happens against the local Docker lab. Raw tool output stays under `data/` on the local machine (git-ignored).
- No scan output is sent to an external service in the default mode.
- If the optional Gemini/Claude planner is enabled, only the limited, redacted state summary described above is sent; raw tool output, evidence files and credentials are not. Target addresses and service banners are included, so treat them as client data.
- Do not enable the optional planner for confidential client engagements without the client's consent.

## Guard rails against AI errors

- Grounding validator rejects report text that cites unknown evidence ids, CVEs no tool produced, or CVSS values no tool reported.
- Every finding keeps the observed facts (tool evidence) separate from the analysis (rule-based inference).
- Intrusive actions need recorded human approval; the AI path cannot bypass the scope guard.
