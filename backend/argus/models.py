"""Common data model. Every tool adapter normalizes into these types."""
from __future__ import annotations
from typing import Any, Literal, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timezone


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# intensity classes, ordered. Anything >= intrusive needs human approval.
INTENSITY = ["passive", "standard", "intrusive", "exploit"]


class Scope(BaseModel):
    id: str = "scope-default"
    name: str = "ARGUS local lab"
    targets: list[str] = Field(default_factory=list)       # CIDR, IP, hostname or URL
    exclusions: list[str] = Field(default_factory=list)
    allowed_ports: list[int] = Field(default_factory=list)  # empty = any
    allowed_tools: list[str] = Field(default_factory=list)  # empty = any registered
    max_intensity: Literal["passive", "standard", "intrusive", "exploit"] = "standard"
    authorized_by: str = ""
    rate_limit_rps: int = 10
    window_start: Optional[str] = None
    window_end: Optional[str] = None
    notes: str = ""


class Evidence(BaseModel):
    id: str
    assessment_id: str
    tool: str
    mode: Literal["live", "import"] = "live"
    job_id: Optional[str] = None
    file_path: str = ""
    sha256: str = ""
    locator: str = ""          # line number / xpath / json path inside the raw file
    excerpt: str = ""
    captured_at: str = Field(default_factory=now)


class Asset(BaseModel):
    host: str
    port: Optional[int] = None
    protocol: str = "tcp"
    service: str = ""
    product: str = ""
    version: str = ""
    url: str = ""
    parameter: str = ""

    def key(self) -> str:
        return f"{self.host}:{self.port or '-'}"


class Occurrence(BaseModel):
    tool: str
    mode: str = "live"
    evidence_id: str
    rule_id: str = ""
    tool_severity: str = ""
    seen_at: str = Field(default_factory=now)


class Inference(BaseModel):
    text: str
    cites: list[str] = Field(default_factory=list)  # evidence ids
    kind: Literal["rule", "ai"] = "rule"


class Finding(BaseModel):
    id: str = ""
    assessment_id: str = ""
    title: str
    description: str = ""
    issue_key: str = ""                 # canonical class used for correlation
    asset: Asset
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    owasp: str = ""
    attack: list[str] = Field(default_factory=list)
    severity: str = "info"               # info|low|medium|high|critical (as reported / derived)
    severity_source: str = ""            # tool name or "derived"
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    cvss_source: str = ""
    status: Literal["observed", "suspected", "corroborated", "validated", "refuted", "fixed"] = "observed"
    confidence: int = 0
    confidence_reasons: list[str] = Field(default_factory=list)
    occurrences: list[Occurrence] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    affected_urls: list[str] = Field(default_factory=list)
    related: list[str] = Field(default_factory=list)
    validation: dict[str, Any] = Field(default_factory=dict)   # {"verdict","reason","evidence_id","by","at"}
    risk: dict[str, Any] = Field(default_factory=dict)
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    inferences: list[Inference] = Field(default_factory=list)
    refuted_reason: str = ""
    created_at: str = Field(default_factory=now)


class Hypothesis(BaseModel):
    id: str
    assessment_id: str = ""
    text: str
    asset: str
    source_evidence: list[str] = Field(default_factory=list)
    status: Literal["open", "supported", "refuted"] = "open"
    priority: int = 5


class Candidate(BaseModel):
    action_id: str
    tool: str
    kind: str                      # nmap_scan, nmap_enum, nikto, zap_passive, zap_active, validate, msf_check ...
    target: str
    port: Optional[int] = None
    intensity: str = "standard"
    cost: str = "low"
    noise: str = "low"
    resolves: list[str] = Field(default_factory=list)   # hypothesis ids
    params: dict[str, Any] = Field(default_factory=dict)
    why: str = ""
    skipped_reason: str = ""


class DecisionCard(BaseModel):
    id: str
    assessment_id: str
    phase: str
    trigger: list[str] = Field(default_factory=list)       # evidence ids
    hypothesis: str = ""
    options: list[dict[str, Any]] = Field(default_factory=list)
    chosen: list[str] = Field(default_factory=list)
    rationale: str = ""
    planner: str = "rules"                                  # rules | claude
    scope_check: str = ""
    outcome: str = ""
    created_at: str = Field(default_factory=now)


class Job(BaseModel):
    id: str
    assessment_id: str
    tool: str
    kind: str
    target: str
    command: str = ""
    status: Literal["queued", "running", "ok", "failed", "timeout", "cancelled", "skipped"] = "queued"
    mode: str = "live"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    exit_code: Optional[int] = None
    error: str = ""
    evidence_id: Optional[str] = None
    attempts: int = 0


class Approval(BaseModel):
    id: str
    assessment_id: str
    action: dict[str, Any]
    reason: str
    finding_id: str = ""
    status: Literal["pending", "approved", "rejected", "executed", "failed"] = "pending"
    requested_at: str = Field(default_factory=now)
    decided_by: str = ""
    decided_at: str = ""
    comment: str = ""
    outcome: str = ""


class Assessment(BaseModel):
    id: str
    title: str = ""
    request: str = ""
    scope: Scope
    targets: list[str] = Field(default_factory=list)
    status: str = "created"   # created|planned|running|awaiting_approval|review|complete|stopped|failed
    phase: str = "scope"
    created_at: str = Field(default_factory=now)
    updated_at: str = Field(default_factory=now)
    planner: str = "rules"
    limitations: list[str] = Field(default_factory=list)
    intents: dict[str, Any] = Field(default_factory=dict)
    criticality: dict[str, float] = Field(default_factory=dict)   # host -> asset criticality multiplier set by the analyst
