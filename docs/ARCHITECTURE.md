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
| Claude-driven planning | Rule planner default, Claude optional | No API key available; Claude path untested |
| Scope: whole lab subnet | Subnet minus .1/.2/.3 | An early run reached the Docker gateway (the developer's PC); fixed |
