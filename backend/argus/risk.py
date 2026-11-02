"""Transparent risk prioritization. No LLM numbers: every factor is shown.

priority = min(10, base * exposure * exploitability * criticality * confidence_weight [+ attack-path bonus])
"""
from __future__ import annotations
from . import reference, store
from .models import Finding

SEV_MID = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 2.5, "info": 0.5}
CONF_W = {"validated": 1.0, "corroborated": 0.95, "observed": 0.85, "suspected": 0.75}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def score(f: Finding, criticality: float = 1.0, path_bonus: float = 0.0) -> dict:
    if f.status == "refuted":
        return {"priority": 0.0, "excluded": True, "reason": f"refuted: {f.refuted_reason}", "factors": {}}
    if f.cvss_score is not None:
        base, base_src = f.cvss_score, f"CVSS {f.cvss_score} reported by {f.cvss_source}"
    else:
        base, base_src = SEV_MID[f.severity], f"no CVSS available; midpoint of '{f.severity}' severity ({f.severity_source})"
    exposure, exp_src = 1.0, "reachable over the network without authentication (assumed for lab scan)"
    in_kev = [c for c in f.cve if reference.kev(c)]
    if in_kev:
        expl, expl_src = 1.3, f"{', '.join(in_kev)} is in the (partial) CISA KEV snapshot"
    else:
        expl, expl_src = 1.0, "no known-exploited evidence in the offline snapshot"
    cw = CONF_W.get(f.status, 0.75)
    p = min(10.0, round(base * exposure * expl * criticality * cw + path_bonus, 1))
    return {"priority": p, "excluded": False,
            "factors": {"base": base, "base_source": base_src, "exposure": exposure, "exposure_source": exp_src,
                        "exploitability": expl, "exploitability_source": expl_src, "asset_criticality": criticality,
                        "confidence_weight": cw, "confidence_source": f"status '{f.status}', confidence {f.confidence}",
                        "path_bonus": path_bonus}}


def band(p: float) -> str:
    return "critical" if p >= 9 else "high" if p >= 7 else "medium" if p >= 4 else "low" if p >= 1 else "info"


def rank(assessment_id: str, criticality: dict[str, float] | None = None, path_bonus: dict[str, float] | None = None) -> list[Finding]:
    fs = store.list_("finding", Finding, assessment_id)
    for f in fs:
        f.risk = score(f, (criticality or {}).get(f.asset.host, 1.0), (path_bonus or {}).get(f.id, 0.0))
        f.risk["band"] = band(f.risk["priority"]) if not f.risk.get("excluded") else "refuted"
    live = sorted([f for f in fs if not f.risk.get("excluded")], key=lambda x: (-x.risk["priority"], SEV_ORDER.index(x.severity), x.id))
    for i, f in enumerate(live, 1):
        f.risk["rank"] = i
    for f in fs:
        store.put("finding", f)
    return live + [f for f in fs if f.risk.get("excluded")]
