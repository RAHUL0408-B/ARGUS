"""Normalization, de-duplication and the Confidence Ledger.

Merge rule: two findings are the same issue only if they share asset (host:port) AND canonical issue class
(or CVE) -- and, for URL-specific classes, the same URL path + parameter. Different hosts/ports are never merged.
All confidence points come from the fixed rules below, each with a written reason.
"""
from __future__ import annotations
from urllib.parse import urlparse
from . import reference, store
from .models import Finding, Occurrence

PER_URL = {"xss", "sqli", "path-traversal", "csrf", "info-disclosure-file", "default-credentials"}


def normalize(f: Finding) -> Finding:
    key, cwe, ctitle, fix = reference.classify(f.title, f.cwe)
    if f.cve and key.startswith(("other:", "cwe:")):
        key = f"cve:{sorted(f.cve)[0]}"
    f.issue_key = key
    if not f.cwe and cwe:
        f.cwe = [cwe]
    if not f.remediation and fix:
        f.remediation = fix
    for c in f.cwe:
        name, owasp = reference.cwe_info(c)
        if owasp and not f.owasp:
            f.owasp = owasp
    f.attack = sorted(set(f.attack) | set(reference.ATTACK.get(key, []) + (reference.ATTACK["known-cve"] if f.cve else [])))
    f.cve = sorted({c.upper() for c in f.cve})
    return f


def merge_key(f: Finding) -> str:
    a = f.asset
    base = f"{a.host}|{a.port or ''}|{f.issue_key}"
    if f.issue_key in PER_URL:
        p = urlparse(a.url)
        base += f"|{p.path}|{a.parameter}"
    return base


_SEV = ["info", "low", "medium", "high", "critical"]


def _merge_into(base: Finding, new: Finding) -> None:
    seen = {(o.tool, o.rule_id, o.evidence_id) for o in base.occurrences}
    for o in new.occurrences:
        if (o.tool, o.rule_id, o.evidence_id) not in seen:
            base.occurrences.append(o)
    for e in new.evidence_ids:
        if e not in base.evidence_ids:
            base.evidence_ids.append(e)
    base.cve = sorted(set(base.cve) | set(new.cve))
    base.cwe = sorted(set(base.cwe) | set(new.cwe))
    if _SEV.index(new.severity) > _SEV.index(base.severity):
        base.severity, base.severity_source = new.severity, new.severity_source
    if new.cvss_score is not None and (base.cvss_score is None or new.cvss_score > base.cvss_score):
        base.cvss_score, base.cvss_vector, base.cvss_source = new.cvss_score, new.cvss_vector, new.cvss_source
    if len(new.description) > len(base.description):
        base.description = new.description
    if not base.remediation:
        base.remediation = new.remediation
    base.references = sorted(set(base.references) | set(new.references))[:8]
    if new.asset.url and new.asset.url != base.asset.url and new.asset.url not in base.affected_urls:
        base.affected_urls.append(new.asset.url)
    base.confidence_reasons = [r for r in base.confidence_reasons if r.startswith(("zap-confidence", "burp-confidence"))] + \
        [r for r in new.confidence_reasons if r.startswith(("zap-confidence", "burp-confidence")) and r not in base.confidence_reasons]


def score_confidence(f: Finding) -> Finding:
    """Confidence Ledger: deterministic points, every point explained. Validation overrides below."""
    keep = [r for r in f.confidence_reasons if r.startswith(("zap-confidence", "burp-confidence", "validation:"))]
    reasons, pts = [], 0
    tools = sorted({o.tool for o in f.occurrences})
    version_only = all(o.rule_id.startswith("argus-rule:known-version") for o in f.occurrences)
    direct_rule = all(o.rule_id.startswith(("argus-rule:cleartext", "argus-rule:db-exposed")) for o in f.occurrences)
    if version_only:
        pts += 25; reasons.append("+25 reported from a version/banner match only (no active test)")
        if any(reference.known_version_cves(f.asset.product, f.asset.version)):
            pts += 15; reasons.append("+15 detected version is in the affected range of the cited CVE (reference table)")
    elif direct_rule:
        pts += 50; reasons.append("+50 service directly observed as open by a live scan")
    else:
        pts += 40; reasons.append("+40 reported by a tool test or rule (not version-only)")
    if len(tools) >= 2:
        extra = 25 + 10 * (len(tools) - 2)
        pts += extra; reasons.append(f"+{extra} independently reported by {len(tools)} tools ({', '.join(tools)})")
    if any("Evidence:" in f.description for _ in [0]) or any(o.tool == "burp" for o in f.occurrences):
        pts += 15; reasons.append("+15 request/response or matched-string evidence recorded by the tool")
    if any(o.mode == "import" for o in f.occurrences) and all(o.mode == "import" for o in f.occurrences):
        pts -= 5; reasons.append("-5 only from an imported file (not re-executed by ARGUS)")
    if version_only and any(k in (f.asset.version + f.asset.product).lower() for k in ("debian", "ubuntu", "el7", "el8", "rhel")):
        pts -= 30; reasons.append("-30 distribution package: the vendor may have back-ported the fix")
    f.confidence_reasons = reasons + keep
    f.confidence = max(0, min(100, pts))
    if f.status == "validated":
        f.confidence = max(f.confidence, 90)      # an independent confirmation is never lowered by re-scoring
    elif f.status == "refuted":
        f.confidence = min(f.confidence, 10)
    if f.status not in ("validated", "refuted", "fixed"):
        f.status = "corroborated" if len(tools) >= 2 else ("suspected" if version_only else "observed")
    return f


def apply_validation(f: Finding, verdict: str, reason: str, evidence_id: str, by: str) -> Finding:
    from .models import now
    f.validation = {"verdict": verdict, "reason": reason, "evidence_id": evidence_id, "by": by, "at": now()}
    if evidence_id and evidence_id not in f.evidence_ids:
        f.evidence_ids.append(evidence_id)
    f.confidence_reasons = [r for r in f.confidence_reasons if not r.startswith("validation:")]
    if verdict == "confirmed":
        f.status, f.confidence = "validated", max(f.confidence, 90)
        f.confidence_reasons.append(f"validation: confirmed by {by}: {reason}")
    elif verdict == "refuted":
        f.status, f.confidence, f.refuted_reason = "refuted", min(f.confidence, 10), reason
        f.confidence_reasons.append(f"validation: refuted by {by}: {reason}")
    else:
        f.confidence_reasons.append(f"validation: inconclusive ({by}): {reason}")
    return f


def ingest(assessment_id: str, new_findings: list[Finding]) -> tuple[list[Finding], int, int]:
    """Normalize + merge new findings into the assessment. Returns (touched findings, created, merged)."""
    existing = store.list_("finding", Finding, assessment_id)
    index = {merge_key(f): f for f in existing}
    touched, created, merged = {}, 0, 0
    for nf in new_findings:
        nf.assessment_id = assessment_id
        normalize(nf)
        k = merge_key(nf)
        if k in index:
            _merge_into(index[k], nf)
            tgt = index[k]
            merged += 1
        else:
            nf.id = f"F-{len(index) + 1:03d}"
            if nf.asset.url:
                nf.affected_urls = [nf.asset.url]
            index[k] = nf
            tgt = nf
            created += 1
        touched[tgt.id] = tgt
    for f in touched.values():
        score_confidence(f)
        store.put("finding", f)
    return list(touched.values()), created, merged


def link_related(assessment_id: str) -> None:
    """Link findings that share an asset or CVE (kept separate, just cross-referenced)."""
    fs = store.list_("finding", Finding, assessment_id)
    for f in fs:
        f.related = sorted({g.id for g in fs if g.id != f.id and g.asset.host == f.asset.host and
                            (set(g.cve) & set(f.cve) or (g.asset.port == f.asset.port and g.asset.port))})[:8]
        store.put("finding", f)
