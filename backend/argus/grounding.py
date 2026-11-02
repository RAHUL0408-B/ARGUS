"""Grounding validator: AI-written text must cite real evidence and may not introduce unseen CVEs/scores.

Citation syntax inside text: [EV-0003]. A passage is rejected if
  * it cites an evidence id that does not exist,
  * it names a CVE that is not present in this assessment's findings/evidence,
  * it states a CVSS value that no finding carries.
"""
from __future__ import annotations
import re
from . import store
from .models import Evidence, Finding

CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
CITE_RX = re.compile(r"\[(EV-\d{4})\]")
CVSS_RX = re.compile(r"CVSS(?:\s*v?3(?:\.\d)?)?\s*(?:base\s*)?(?:score\s*)?(?:of|:|=)?\s*(\d{1,2}\.\d)", re.I)


def validate(assessment_id: str, text: str, require_citation: bool = True) -> tuple[bool, list[str]]:
    problems: list[str] = []
    evs = {e.id for e in store.list_("evidence", Evidence, assessment_id)}
    fs = store.list_("finding", Finding, assessment_id)
    known_cves = {c.upper() for f in fs for c in f.cve}
    known_scores = {round(f.cvss_score, 1) for f in fs if f.cvss_score is not None}
    cites = CITE_RX.findall(text)
    for c in cites:
        if c not in evs:
            problems.append(f"cites unknown evidence {c}")
    if require_citation and not cites:
        problems.append("makes claims without citing any evidence id")
    for cve in CVE_RX.findall(text):
        if cve.upper() not in known_cves:
            problems.append(f"mentions {cve.upper()} which does not appear in any tool output for this assessment")
    for s in CVSS_RX.findall(text):
        if round(float(s), 1) not in known_scores:
            problems.append(f"states CVSS {s} which no tool reported")
    return (not problems), problems
