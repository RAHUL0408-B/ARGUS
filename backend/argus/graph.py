"""Attack-path graph. Solid edges are backed by tool evidence; dashed edges are rule-based hypotheses."""
from __future__ import annotations
from . import store
from .models import Finding


def build(assessment_id: str) -> dict:
    fs = [f for f in store.list_("finding", Finding, assessment_id) if f.status != "refuted"]
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def node(i, label, kind, **kw):
        nodes.setdefault(i, {"id": i, "label": label, "kind": kind, **kw})

    by_host: dict[str, list[Finding]] = {}
    for f in fs:
        by_host.setdefault(f.asset.host, []).append(f)
    for host, items in by_host.items():
        node(f"h:{host}", host, "host")
        for f in items:
            svc = f"s:{host}:{f.asset.port}" if f.asset.port else None
            if svc:
                node(svc, f"{f.asset.service or 'port'}/{f.asset.port}", "service")
                edges.append({"from": f"h:{host}", "to": svc, "type": "verified", "label": "exposes", "evidence": f.evidence_ids[:1]})
            node(f"f:{f.id}", f"{f.id} {f.title[:48]}", "finding", severity=f.severity, status=f.status)
            edges.append({"from": svc or f"h:{host}", "to": f"f:{f.id}", "type": "verified", "label": "has weakness", "evidence": f.evidence_ids[:2]})
        keys = {f.issue_key: f for f in items}
        chains = []
        # hypothesis: session theft via XSS needs XSS + cookie without HttpOnly
        if "xss" in keys and "cookie-httponly" in keys:
            chains.append(([keys["xss"], keys["cookie-httponly"]], "Session hijack via script injection",
                           "XSS can run script in the victim's browser and the session cookie is readable by script (no HttpOnly)."))
        if "xss" in keys and "missing-csp" in keys:
            chains.append(([keys["xss"], keys["missing-csp"]], "Unrestricted script execution after XSS",
                           "No Content-Security-Policy to limit what injected script can load or send."))
        if "clickjacking" in keys and "csrf" in keys:
            chains.append(([keys["clickjacking"], keys["csrf"]], "UI-redressed state-changing action",
                           "Page can be framed and state-changing requests lack anti-CSRF tokens."))
        for f in items:
            if f.cve and f.status in ("suspected", "corroborated", "validated"):
                chains.append(([f], f"Possible remote compromise via {f.cve[0]}", "A known-vulnerable version may be exploitable; not confirmed."))
            if f.issue_key == "cleartext-protocol":
                chains.append(([f], "Credential interception on the network", "Cleartext protocol can expose credentials to a network observer."))
        for members, label, why in chains:
            nid = f"p:{host}:{label[:24]}"
            node(nid, label, "hypothesis", why=why)
            for m in members:
                edges.append({"from": f"f:{m.id}", "to": nid, "type": "hypothesis", "label": "may enable", "evidence": []})
    path_bonus = {}
    for e in edges:
        if e["type"] == "hypothesis" and e["from"].startswith("f:"):
            fid = e["from"][2:]
            path_bonus[fid] = 0.5
    return {"nodes": list(nodes.values()), "edges": edges, "path_bonus": path_bonus}
