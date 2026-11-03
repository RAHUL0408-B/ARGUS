# AI disclosure

## AI-generated code

Most of this repository (backend, UI, tests, lab files, documents, sample inputs) was written with the assistance of Claude (Anthropic) through Claude Code, directed and reviewed by the team members. Commits are made under the team member's own identity. The code was run, tested (23 automated unit tests plus a live end-to-end suite) and exercised live against the lab before being committed, but it should be reviewed like any other code.

## AI used at runtime

- Default mode uses **no language model**. Action choice is a deterministic rule planner; scope enforcement, correlation, confidence scoring, risk ranking, grounding checks and the report are all code.
- Optional: if `ANTHROPIC_API_KEY` is set, Claude receives a **limited state summary**: target addresses, up to 30 `host:port service product version` strings, up to 40 finding labels (`id issue_key severity status`), open hypothesis texts, and the candidate action ids with rationales to choose among candidates the code generated. It cannot add actions, and its output is validated. This path is untested.
- The Ask ARGUS copilot answers from stored findings and evidence with rules; it does not call a model.

## Data handling

- All scanning happens against the local Docker lab. Raw tool output stays under `data/` on the local machine (git-ignored).
- No scan output is sent to an external service in the default mode.
- If the optional Claude planner is enabled, only the limited state summary described above is sent; raw tool output, evidence files and credentials are not. Target addresses and service banners are included, so treat them as client data.
- Do not enable the optional planner for confidential client engagements without the client's consent.

## Guard rails against AI errors

- Grounding validator rejects report text that cites unknown evidence ids, CVEs no tool produced, or CVSS values no tool reported.
- Every finding keeps the observed facts (tool evidence) separate from the analysis (rule-based inference).
- Intrusive actions need recorded human approval; the AI path cannot bypass the scope guard.
