"""Adapter interface. Every tool integration exposes the same contract and reports honest status."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional
from ..models import Asset, Finding, Occurrence, Evidence


@dataclass
class Observation:
    """Facts discovered by a tool that are not (yet) vulnerabilities: hosts, open ports, services, urls."""
    asset: Asset
    evidence_id: str
    kind: str = "service"      # service | host | url | tech
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass
class AdapterResult:
    observations: list[Observation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class Adapter:
    name = ""
    mode = "live"            # live | import
    status = "planned"       # live | import-only | planned | unsupported
    description = ""
    limitations = ""

    def info(self) -> dict:
        return {"name": self.name, "status": self.status, "description": self.description, "limitations": self.limitations}

    def available(self) -> tuple[bool, str]:
        return True, "ok"


def mk_finding(assessment_id: str, tool: str, mode: str, ev_id: str, *, title: str, asset: Asset, severity: str = "info",
               description: str = "", cve: Optional[list[str]] = None, cwe: Optional[list[str]] = None,
               cvss: Optional[float] = None, vector: str = "", rule_id: str = "", remediation: str = "",
               references: Optional[list[str]] = None, severity_source: str = "") -> Finding:
    return Finding(assessment_id=assessment_id, title=title, description=description, asset=asset,
                   severity=severity, severity_source=severity_source or tool, cvss_score=cvss, cvss_vector=vector,
                   cvss_source=tool if cvss is not None else "", cve=cve or [], cwe=cwe or [],
                   remediation=remediation, references=references or [], evidence_ids=[ev_id],
                   occurrences=[Occurrence(tool=tool, mode=mode, evidence_id=ev_id, rule_id=rule_id, tool_severity=severity)])
