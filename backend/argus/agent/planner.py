"""Candidate generation and action choice.

Candidates are produced by deterministic code from the current state (so the model can never invent an action).
Choice is made by the rule planner by default. If ANTHROPIC_API_KEY is set, Claude ranks the same candidates and
writes the rationale; its answer is validated against the candidate list and falls back to the rules on any problem.
"""
from __future__ import annotations
import json
from urllib.parse import urlparse
from .. import config, scope as scopemod
from ..adapters.nmap import is_http
from ..adapters.validators import VALIDATABLE
from ..models import Asset, Candidate, Finding, Hypothesis, Scope

PHASE_ORDER = {"nmap_scan": 0, "nmap_enum": 1, "nikto": 2, "zap_passive": 2, "validate": 3, "zap_active": 4, "msf_check": 4}
PHASE_NAME = {"nmap_scan": "recon", "nmap_enum": "enumeration", "nikto": "vulnerability-analysis", "zap_passive": "vulnerability-analysis",
              "validate": "triage", "zap_active": "validation", "msf_check": "validation"}


def web_url(a: Asset) -> str:
    scheme = "https" if (a.service or "").startswith(("https", "ssl")) or a.port == 443 else "http"
    default = (scheme == "http" and a.port == 80) or (scheme == "https" and a.port == 443)
    return f"{scheme}://{a.host}" + ("" if default else f":{a.port}")


def generate(scope: Scope, targets: list[str], intents: dict, assets: list[Asset], findings: list[Finding],
             done: set[str], failed: set[str], msf_ready: bool) -> tuple[list[Candidate], list[Hypothesis]]:
    cands: list[Candidate] = []
    hyps: list[Hypothesis] = []
    web = [a for a in assets if a.port and is_http(a.service, a.port)]

    def add(c: Candidate):
        if c.action_id in done or c.action_id in failed:
            return
        cands.append(c)

    # 1. recon: nothing known yet about the targets
    for t in targets:
        add(Candidate(action_id=f"nmap_scan:{t}", tool="nmap", kind="nmap_scan", target=t, intensity="standard", cost="medium", noise="low",
                      why="No hosts or services are known yet. Service discovery is the prerequisite for choosing every other tool."))
    if not assets:
        return cands, hyps

    hosts = sorted({a.host for a in assets})
    # 2. hypotheses from services
    n = 0
    for a in assets:
        if not a.port:
            continue
        banner = f"{a.product} {a.version}".strip()
        if is_http(a.service, a.port):
            n += 1
            hyps.append(Hypothesis(id=f"H-{n:02d}", text=f"The web service on {a.host}:{a.port} ({banner or a.service}) has misconfigurations or known weaknesses",
                                   asset=a.key(), priority=6))
    for f in findings:
        if f.cve and f.status in ("suspected", "observed"):
            n += 1
            hyps.append(Hypothesis(id=f"H-{n:02d}", text=f"{f.asset.key()} is affected by {f.cve[0]} (version-only evidence, not yet confirmed)",
                                   asset=f.asset.key(), source_evidence=f.evidence_ids[:2], priority=9))
        if f.issue_key == "cleartext-protocol" and f.status != "refuted":
            n += 1
            hyps.append(Hypothesis(id=f"H-{n:02d}", text=f"{f.asset.key()} exposes a cleartext protocol that may leak credentials",
                                   asset=f.asset.key(), source_evidence=f.evidence_ids[:1], priority=7))

    # 3. enumeration + web scans
    if not intents.get("no_web"):
        for h in hosts:
            ports = sorted({a.port for a in web if a.host == h})
            if ports:
                add(Candidate(action_id=f"nmap_enum:{h}", tool="nmap", kind="nmap_enum", target=h, intensity="standard", cost="low", noise="low",
                              params={"ports": ports}, resolves=[x.id for x in hyps if x.asset.startswith(h + ":")],
                              why=f"HTTP found on {h} port(s) {ports}: NSE http scripts reveal titles, methods and common paths cheaply before heavier scans."))
        for a in web:
            url = web_url(a)
            res = [x.id for x in hyps if x.asset == a.key()]
            add(Candidate(action_id=f"nikto:{url}", tool="nikto", kind="nikto", target=url, port=a.port, intensity="standard", cost="medium", noise="medium", resolves=res,
                          why=f"{url} serves HTTP: Nikto checks server configuration and known files; complements ZAP, and a second tool lets findings be cross-checked."))
            add(Candidate(action_id=f"zap_passive:{url}", tool="zap", kind="zap_passive", target=url, port=a.port, intensity="standard", cost="medium", noise="low", resolves=res,
                          why=f"{url} is a web application: ZAP spider + passive analysis maps the app and flags headers, cookies and forms without sending attack payloads."))
    elif web:
        for a in web:
            add(Candidate(action_id=f"skip-web:{a.key()}", tool="-", kind="skip", target=a.host, skipped_reason="analyst asked for no web testing"))

    # 4. safe validation of web-config findings (single GET, standard intensity)
    for f in findings:
        if f.issue_key in VALIDATABLE and f.status not in ("validated", "refuted", "fixed") and f.asset.port and is_http(f.asset.service or "http", f.asset.port):
            base = f.affected_urls[0] if f.affected_urls else web_url(f.asset)
            add(Candidate(action_id=f"validate:{f.id}", tool="argus-http", kind="validate", target=base, port=f.asset.port, intensity="standard", cost="low", noise="low",
                          params={"finding_id": f.id, "issue_key": f.issue_key},
                          why=f"{f.id} ({f.title[:50]}) is a configuration claim that one harmless GET can confirm or refute, which removes false positives before ranking."))

    # 5. approval-gated candidates (proposed only once there is something to validate)
    if findings and not intents.get("passive_only"):
        for a in web[:1]:
            url = web_url(a)
            if scope.max_intensity in ("intrusive", "exploit"):
                add(Candidate(action_id=f"zap_active:{url}", tool="zap", kind="zap_active", target=url, port=a.port, intensity="intrusive", cost="high", noise="high",
                              why="Passive results show forms/parameters; an active scan can confirm injection-class issues but sends attack payloads, so a human must approve."))
        if msf_ready:
            for f in findings:
                if f.cve and f.status == "suspected" and f.asset.port and is_http(f.asset.service or "http", f.asset.port):
                    add(Candidate(action_id=f"msf_check:{f.id}", tool="metasploit", kind="msf_check", target=f.asset.host, port=f.asset.port, intensity="exploit",
                                  cost="medium", noise="low", params={"finding_id": f.id, "module": "auxiliary/scanner/http/http_version"},
                                  why=f"{f.id} is a version-only suspicion; a read-only Metasploit auxiliary module can re-read the server version independently. Needs approval."))
    return cands, hyps


APPROVAL_KINDS = {"zap_active", "msf_check"}


def rule_choose(cands: list[Candidate], findings_n: int) -> tuple[list[Candidate], str, list[dict]]:
    """Pick the single best non-approval candidate; annotate every option with why it was or was not chosen."""
    runnable = [c for c in cands if c.kind not in APPROVAL_KINDS and c.kind != "skip"]
    order = sorted(runnable, key=lambda c: (PHASE_ORDER.get(c.kind, 9), -len(c.resolves), {"low": 0, "medium": 1, "high": 2}[c.cost]))
    chosen = order[:1]
    options = []
    for c in cands:
        if c.kind == "skip":
            d = f"skipped: {c.skipped_reason}"
        elif c.kind in APPROVAL_KINDS:
            d = "not auto-run: intrusive/exploit-class action, queued for human approval"
        elif chosen and c.action_id == chosen[0].action_id:
            d = "CHOSEN: earliest workflow phase with the most hypotheses resolved at lowest cost"
        else:
            d = "deferred: a prerequisite or lower-cost action comes first"
        options.append({"action": c.action_id, "tool": c.tool, "cost": c.cost, "noise": c.noise, "resolves": c.resolves, "decision": d, "why": c.why})
    rationale = chosen[0].why if chosen else "No further runnable actions."
    return chosen, rationale, options


def llm_choose(summary: dict, cands: list[Candidate]) -> tuple[str, str] | None:
    """Ask Claude to pick among the candidate action ids. Returns (action_id, rationale) or None to fall back."""
    if not config.ANTHROPIC_API_KEY:
        return None
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        options = [{"action_id": c.action_id, "tool": c.tool, "cost": c.cost, "noise": c.noise, "resolves": c.resolves, "why": c.why}
                   for c in cands if c.kind not in APPROVAL_KINDS and c.kind != "skip"]
        if not options:
            return None
        prompt = ("You are the planning component of an authorized penetration-testing assistant. Choose exactly ONE next action from the list.\n"
                  "Prefer actions that resolve high-priority open hypotheses at low cost and noise; never repeat completed work.\n"
                  "Reply ONLY with JSON: {\"action_id\": \"...\", \"rationale\": \"2-3 sentences citing the state facts\"}.\n\n"
                  f"STATE:\n{json.dumps(summary, indent=1)[:6000]}\n\nOPTIONS:\n{json.dumps(options, indent=1)}")
        msg = client.messages.create(model=config.LLM_MODEL, max_tokens=400, messages=[{"role": "user", "content": prompt}])
        text = "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
        data = json.loads(text[text.index("{"): text.rindex("}") + 1])
        if data.get("action_id") in {o["action_id"] for o in options}:
            return data["action_id"], str(data.get("rationale", ""))[:600]
    except Exception:
        return None
    return None
