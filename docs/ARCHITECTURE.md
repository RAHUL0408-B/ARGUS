# Architecture

```
 Browser UI (vanilla JS)  <--REST + SSE-->  FastAPI (backend/argus/api.py)
                                                  |
                         +------------------------+--------------------------+
                         |                        |                          |
                   Agent engine              Scope Guard               SQLite store
                  (agent/engine.py)           (scope.py)           (objects, audit, events)
                         |                        ^
              Planner (agent/planner.py)          | every action checked first
              candidates by code; choice by       |
              rules (or optional Claude)          |
                         |                        |
                    Adapters ---- runner.py ------+--> docker exec argus-tools (nmap, nikto, curl)
        nmap | nikto | zap | msf | validators      --> ZAP daemon API (127.0.0.1:18090, Host: zap)
        imports (nessus, burp, openvas)            --> docker run metasploit (approved only)
                         |
              correlation.py -> risk.py -> graph.py -> grounding.py -> report.py (PDF)
```

## Components

| Module | Role |
|---|---|
| `scope.py` | Default-deny guard: CIDR containment, exclusions, tool allow-list, intensity classes (passive / standard / intrusive / exploit), time window. Intrusive and above need approval. |
| `store.py` | SQLite: generic JSON `objects` table, hash-chained `audit` table (SHA-256 over previous hash and fields), `events` table that feeds SSE. |
| `runner.py` | Runs commands with timeout, one retry, cancellation (kill switch). Saves raw output as evidence with a SHA-256. |
| `adapters/` | One parser per tool, producing normalized `Finding` objects. Imports drop out-of-scope hosts. |
| `agent/planner.py` | Generates candidate actions and hypotheses from state. `rule_choose` picks one; `llm_choose` (optional) ranks the same candidates. |
| `agent/engine.py` | The loop: look, think (Decision Card), act, correlate, validate; approvals, retest, import, copilot. |
| `correlation.py` | Canonical issue classes, merge key `host|port|issue_key`, per-URL classes keep all URLs, Confidence Ledger. |
| `risk.py` | `priority = min(10, base x exposure x exploitability x criticality x confidence_weight + path_bonus)`; base is the tool's CVSS or a labelled severity midpoint. |
| `graph.py` | Attack-path graph: verified edges from evidence, hypothesis edges from rules. |
| `grounding.py` | Rejects unknown evidence ids, unseen CVEs and unreported CVSS values. |
| `report.py` | reportlab PDF (sections 7.1-7.6 plus appendices). |

## AI model(s)

- **Default (always on): a deterministic rule-based planner.** `agent/planner.py` generates every candidate action from code (never from a model), then `rule_choose` picks the earliest-phase, cheapest, most-hypothesis-resolving candidate and writes a plain-text reason for every option considered, not just the winner. This is what satisfies "explain the rationale behind its next steps" (brief section 5.2) with zero dependency on an external API, zero cost, and fully reproducible decisions.
- **Optional: an LLM ranking layer** (`llm_choose`). When an API key is set, the model sees the same code-generated candidate list the rule planner sees — it can only pick one of those candidates, never invent an action — and writes a short rationale. That rationale is passed through `grounding.validate()` before being shown anywhere; if it cites anything not in the evidence it is discarded and the rule planner's reasoning is used instead. State is redacted (`planner.redact`) before leaving the machine: credentials, cookies, tokens and bearer/JWT patterns are stripped from the prompt.
- No model is ever allowed to choose, invent, or execute a tool action directly - only to rank options code already generated and explain the choice.

## State & memory

- **Per-assessment state** lives in SQLite (`store.py`): a generic JSON object store (assets, findings, hypotheses, jobs, approvals, evidence), a hash-chained audit table, and an events table that feeds the UI's live activity feed over SSE.
- **Working memory for the next decision** is reconstructed each loop iteration from that same state, not kept in a separate in-process cache: assets discovered so far, findings and their status/confidence, open hypotheses, what has already run (`done`/`failed` action ids) - so the agent never repeats a completed action and can resume correctly after a server restart (state is durable on disk, not in memory).
- **Retest history** is appended per finding (`Finding.retests`), so a finding's status over time (observed -> validated, or reopened on retest) is itself part of its persisted state, not reconstructed from the audit log.
- **No chat/conversation memory** beyond a given assessment: each assessment is independent; the copilot (`ask`) answers are generated fresh from current state each call, not from prior turns.

## Confidence Ledger

+40 tool test or rule, +25 version-only, +50 directly observed open service, +15 version in affected range, +15 request/response evidence, +25 for the second independent tool and +10 for each further tool, -5 import-only, -30 distro backport. Validated findings have a floor of 90; refuted findings are capped at 10. Reasons are stored with the score.

## Safety model

1. Every action passes `scope.enforce` before execution; denials are recorded and never sent.
2. Intrusive actions create an `Approval` object; execution requires `decide(approve=True)` with an analyst name.
3. Metasploit adapter accepts only allow-listed read-only auxiliary modules.
4. Kill switch (`/stop`) cancels running jobs.
5. Audit chain verifies at `/api/health`.

## Deviations from the original plan PDF

| Plan | Built | Why |
|---|---|---|
| React front end | Vanilla JS single page, no build step | Faster to ship and nothing to install |
| WeasyPrint PDF | reportlab | WeasyPrint needs GTK libraries on Windows |
| OpenVAS live (GMP) | Import-only | Greenbone feed sync is heavy; labelled Import-only |
| Claude-driven planning | Rule planner default; optional Gemini (preferred, free tier) or Claude ranks the same code-generated candidates | Gemini/Claude never invent an action, only rank and explain |
| Scope: whole lab subnet | Subnet minus .1/.2/.3 | An early run reached the Docker gateway (the developer's PC); fixed |
