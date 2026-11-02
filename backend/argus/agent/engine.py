"""Assessment engine: request parsing, plan, investigation loop, approvals, retest and analyst copilot.

Everything the agent does is: scope-checked -> logged to the audit chain -> emitted as an event -> persisted.
"""
from __future__ import annotations
import re, threading, uuid
from typing import Optional
from pydantic import BaseModel
from .. import config, correlation, graph, risk, runner, scope as scopemod, store
from ..adapters import ADAPTERS
from ..adapters.base import AdapterResult
from ..adapters.nmap import build_scan_cmd, is_http
from ..adapters.validators import evaluate, fetch
from ..models import (Approval, Asset, Assessment, Candidate, DecisionCard, Evidence, Finding, Hypothesis, Job, Scope, now)
from . import planner

TARGET_RX = re.compile(r"(https?://[^\s,;]+|\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b)", re.I)


class AssetRecord(BaseModel):
    id: str
    assessment_id: str
    asset: Asset
    evidence_id: str = ""


_threads: dict[str, threading.Thread] = {}


def log(aid: str, type_: str, msg: str, **body):
    store.event(aid, type_, {"message": msg, **body})


# ------------------------------------------------------------------ request -> assessment
def parse_request(text: str) -> tuple[list[str], dict]:
    t = text.lower()
    intents = {
        "no_web": bool(re.search(r"\bno web\b|network only|infrastructure only|skip web", t)),
        "web_only": bool(re.search(r"web (app|application|site)s?|website|\bweb\b", t)) and not re.search(r"\bno web\b", t),
        "passive_only": bool(re.search(r"passive|non-?intrusive|no active|no exploit|read-?only|\bsafe\b", t)),
        "no_dos": bool(re.search(r"no dos|no denial", t)),
    }
    targets = [m.group(0).rstrip(".,)") for m in TARGET_RX.finditer(text)]
    seen, out = set(), []
    for x in targets:
        if x not in seen and not re.fullmatch(r"\d+\.\d+", x):
            seen.add(x); out.append(x)
    return out, intents


def create_assessment(request: str, scope: Scope, title: str = "") -> Assessment:
    aid = f"A-{uuid.uuid4().hex[:8]}"
    requested, intents = parse_request(request)
    a = Assessment(id=aid, title=title or f"Assessment {aid}", request=request, scope=scope, intents=intents,
                   planner="claude" if config.ANTHROPIC_API_KEY else "rules")
    store.put("assessment", a)
    store.audit(aid, "analyst", "assessment.create", {"request": request, "scope": scope.model_dump()})
    log(aid, "phase", "Assessment created. Validating requested targets against the registered scope.")
    accepted, rejected = [], []
    if not requested:
        requested = list(scope.targets)
        log(aid, "info", f"No explicit target in the request; using the registered scope targets {requested}.")
    for t in requested:
        d = scopemod.check_target(scope, t)
        store.audit(aid, "scope-guard", "scope.check", {"target": t, "allowed": d.allowed, "reason": d.reason})
        (accepted if d.allowed else rejected).append((t, d.reason))
        log(aid, "scope", f"{'ACCEPTED' if d.allowed else 'REJECTED'} {t}: {d.reason}", target=t, allowed=d.allowed)
    a.targets = [t for t, _ in accepted]
    a.limitations += [f"Requested target {t} was rejected: {r}" for t, r in rejected]
    if not a.targets:
        a.status, a.phase = "failed", "scope"
        log(aid, "error", "No requested target is inside the authorized scope; nothing will be tested.")
    store.put("assessment", a)
    return a


# ------------------------------------------------------------------ state helpers
def _assets(aid: str) -> list[Asset]:
    seen, out = set(), []
    for r in store.list_("asset", AssetRecord, aid):
        k = (r.asset.host, r.asset.port, r.asset.protocol)
        if k not in seen:
            seen.add(k); out.append(r.asset)
    return out


def _save_assets(aid: str, res: AdapterResult) -> int:
    have = {(a.host, a.port, a.protocol) for a in _assets(aid)}
    n = 0
    for o in res.observations:
        if o.kind in ("service", "host"):
            k = (o.asset.host, o.asset.port, o.asset.protocol)
            if k not in have:
                have.add(k)
                store.put("asset", AssetRecord(id=f"AS-{len(have):04d}", assessment_id=aid, asset=o.asset, evidence_id=o.evidence_id))
                n += 1
    return n


def _done_failed(aid: str) -> tuple[set[str], set[str]]:
    done, failed = set(), set()
    for c in store.list_("action", ActionRecord, aid):
        (done if c.status == "ok" else failed).add(c.action_id)
    return done, failed


class ActionRecord(BaseModel):
    id: str
    assessment_id: str
    action_id: str
    status: str          # ok | failed | skipped


def _record_action(aid: str, action_id: str, status: str):
    store.put("action", ActionRecord(id=f"ACT-{store.count('action', aid) + 1:04d}", assessment_id=aid, action_id=action_id, status=status))


def _state(aid: str):
    a = store.get("assessment", aid, Assessment)
    return a, _assets(aid), store.list_("finding", Finding, aid)


def _candidates(aid: str):
    a, assets, findings = _state(aid)
    done, failed = _done_failed(aid)
    msf_ready = ADAPTERS["metasploit"].available()[0]
    cands, hyps = planner.generate(a.scope, a.targets, a.intents, assets, findings, done, failed, msf_ready)
    old = {h.id: h for h in store.list_("hypothesis", Hypothesis, aid)}
    texts = {h.text: h for h in old.values()}
    for h in hyps:
        if h.text in texts:
            h.id, h.status = texts[h.text].id, texts[h.text].status
        else:
            h.id = f"H-{len(texts) + 1:02d}"
            texts[h.text] = h
        h.assessment_id = aid
        store.put("hypothesis", h)
    return a, cands, assets, findings


# ------------------------------------------------------------------ planning
def make_plan(aid: str) -> DecisionCard:
    a, cands, assets, findings = _candidates(aid)
    chosen, rationale, options = planner.rule_choose(cands, len(findings))
    card = DecisionCard(id=f"D-{store.count('decision', aid) + 1:03d}", assessment_id=aid, phase="scope",
                        hypothesis="Nothing is known about the targets yet; discovery must come first.",
                        options=options, chosen=[c.action_id for c in chosen], rationale=rationale, planner="rules",
                        scope_check="; ".join(f"{t}: in scope" for t in a.targets))
    store.put("decision", card)
    a.status, a.phase = "planned", "plan"
    a.updated_at = now()
    store.put("assessment", a)
    store.audit(aid, "agent", "plan.proposed", {"chosen": card.chosen})
    store.event(aid, "decision", card.model_dump())
    log(aid, "phase", "Plan ready. Waiting for analyst approval before any scan runs.")
    return card


def approve_plan(aid: str, analyst: str = "analyst") -> None:
    a = store.get("assessment", aid, Assessment)
    if a.status not in ("planned", "stopped"):
        raise ValueError(f"assessment is '{a.status}', not awaiting plan approval")
    store.audit(aid, analyst, "plan.approved", {})
    runner.clear_cancel(aid)
    a.status, a.phase = "running", "recon"
    store.put("assessment", a)
    t = threading.Thread(target=run_loop, args=(aid,), daemon=True, name=f"argus-{aid}")
    _threads[aid] = t
    t.start()


def stop(aid: str, analyst: str = "analyst") -> None:
    runner.cancel(aid)
    store.audit(aid, analyst, "kill-switch", {})
    log(aid, "error", "KILL SWITCH: all running jobs were cancelled by the analyst.")


# ------------------------------------------------------------------ execution of one candidate
def _new_job(aid: str, c: Candidate) -> Job:
    return Job(id=f"J-{store.count('job', aid) + 1:03d}", assessment_id=aid, tool=c.tool, kind=c.kind, target=c.target,
               mode=ADAPTERS[c.tool].mode if c.tool in ADAPTERS else "live")


def _coverage_gap(aid: str, c: Candidate, why: str):
    a = store.get("assessment", aid, Assessment)
    msg = f"{c.tool} ({c.kind}) on {c.target} did not complete: {why}. Coverage for this check is missing."
    if msg not in a.limitations:
        a.limitations.append(msg)
        store.put("assessment", a)
    log(aid, "error", msg, action=c.action_id)
    store.audit(aid, "agent", "action.failed", {"action": c.action_id, "reason": why})


def execute(aid: str, c: Candidate, actor: str = "agent") -> Optional[AdapterResult]:
    a = store.get("assessment", aid, Assessment)
    try:
        d = scopemod.enforce(a.scope, c.tool if c.tool in ADAPTERS else "nmap", c.target, c.intensity, c.port)
    except scopemod.ScopeViolation as ex:
        store.audit(aid, "scope-guard", "action.blocked", {"action": c.action_id, "reason": str(ex)})
        log(aid, "scope", f"BLOCKED {c.action_id}: {ex}")
        _record_action(aid, c.action_id, "failed")
        return None
    store.audit(aid, actor, "action.start", {"action": c.action_id, "scope": d.reason})
    job = _new_job(aid, c)
    log(aid, "info", f"Running {c.kind} on {c.target}", action=c.action_id)
    try:
        res = _dispatch(aid, c, job, a.scope)
    except InterruptedError:
        _record_action(aid, c.action_id, "failed")
        raise
    except runner.ToolUnavailable as ex:
        _coverage_gap(aid, c, f"tool unavailable ({str(ex)[:120]})"); _record_action(aid, c.action_id, "failed"); return None
    except TimeoutError as ex:
        _coverage_gap(aid, c, f"timeout ({ex})"); _record_action(aid, c.action_id, "failed"); return None
    except Exception as ex:
        _coverage_gap(aid, c, f"{ex.__class__.__name__}: {str(ex)[:160]}"); _record_action(aid, c.action_id, "failed"); return None
    n_assets = _save_assets(aid, res)
    touched, created, merged = correlation.ingest(aid, res.findings) if res.findings else ([], 0, 0)
    _record_action(aid, c.action_id, "ok")
    store.audit(aid, actor, "action.done", {"action": c.action_id, "new_assets": n_assets, "new_findings": created, "merged": merged})
    log(aid, "result", f"{c.kind} finished: {n_assets} new asset(s), {created} new finding(s), {merged} merged into existing.",
        action=c.action_id, new_findings=created, merged=merged)
    for n in res.notes:
        log(aid, "info", n)
    return res


def _dispatch(aid: str, c: Candidate, job: Job, scope: Scope) -> AdapterResult:
    if c.kind in ("nmap_scan", "nmap_enum"):
        ad = ADAPTERS["nmap"]
        ok, msg = ad.available()
        if not ok:
            raise runner.ToolUnavailable(msg)
        argv_ports = c.params.get("ports")
        target = c.target
        if c.kind == "nmap_scan":
            ex = [e for e in scope.exclusions]
            return _nmap_scan(aid, job, target, ex)
        return ad.run(aid, job, "nmap_enum", target, argv_ports)
    if c.kind == "nikto":
        ok, msg = ADAPTERS["nikto"].available()
        if not ok:
            raise runner.ToolUnavailable(msg)
        return ADAPTERS["nikto"].run(aid, job, c.target)
    if c.kind in ("zap_passive", "zap_active"):
        return ADAPTERS["zap"].run(aid, job, c.target, active=(c.kind == "zap_active"))
    if c.kind == "validate":
        return _validate(aid, job, c)
    if c.kind == "msf_check":
        return _msf(aid, job, c)
    raise ValueError(f"unknown action kind {c.kind}")


def _nmap_scan(aid: str, job: Job, target: str, exclusions: list[str]) -> AdapterResult:
    from ..adapters import nmap as nm
    cmd = build_scan_cmd("nmap_scan", target)
    if "/" in target:
        cmd.remove("-Pn")
    ex = [e for e in exclusions if re.fullmatch(r"[\d./]+", e)]
    if ex:
        cmd[1:1] = ["--exclude", ",".join(ex)]
    code, out, err = runner.run_command(job, runner.in_tools(*cmd), timeout=config.DEFAULT_TIMEOUT)
    path, sha = runner.save_artifact(aid, f"{job.id}_nmap.xml", out or err)
    if "<nmaprun" not in out:
        raise RuntimeError((err or out)[:200] or "nmap produced no XML")
    ev = runner.new_evidence(aid, "nmap", "live", job.id, path, sha, "nmaprun", job.command)
    res = nm.parse_xml(aid, out, ev.id)
    res.evidence.append(ev)
    runner.finish_ok(job, ev.id)
    return res


def _validate(aid: str, job: Job, c: Candidate) -> AdapterResult:
    f = store.get("finding", c.params["finding_id"], Finding, aid)
    raw, status_line = fetch(aid, job, c.target)
    path, sha = runner.save_artifact(aid, f"{job.id}_validate.txt", raw)
    ev = runner.new_evidence(aid, "argus-http-check", "live", job.id, path, sha, "response headers", f"GET {c.target} -> {status_line}")
    v = evaluate(f.issue_key, c.target, raw)
    correlation.apply_validation(f, v.verdict, v.reason, ev.id, "argus-http-check")
    store.put("finding", f)
    runner.finish_ok(job, ev.id)
    store.event(aid, "finding", {"id": f.id, "status": f.status, "validation": f.validation})
    log(aid, "result", f"Validation of {f.id}: {v.verdict.upper()} - {v.reason}", finding=f.id)
    return AdapterResult(evidence=[ev])


def _msf(aid: str, job: Job, c: Candidate) -> AdapterResult:
    f = store.get("finding", c.params["finding_id"], Finding, aid)
    res = ADAPTERS["metasploit"].run(aid, job, c.params["module"], c.target, c.port or 80)
    ev = res.evidence[0]
    text = (config.DATA_DIR / ev.file_path).read_text(errors="replace")
    ver = f.asset.version or next((x.version for x in _assets(aid) if x.host == f.asset.host and x.port == f.asset.port and x.version), "")
    if ver and ver in text:
        correlation.apply_validation(f, "confirmed", f"read-only module re-read version '{ver}' from the live service", ev.id, "metasploit-aux")
    else:
        correlation.apply_validation(f, "inconclusive", "module output did not reproduce the version string", ev.id, "metasploit-aux")
    store.put("finding", f)
    return res


# ------------------------------------------------------------------ the investigation loop
def run_loop(aid: str) -> None:
    try:
        _loop(aid)
    except InterruptedError:
        a = store.get("assessment", aid, Assessment)
        a.status, a.phase = "stopped", "stopped"
        store.put("assessment", a)
        log(aid, "phase", "Assessment stopped by the analyst.")
    except Exception as ex:  # never leave the assessment in 'running'
        a = store.get("assessment", aid, Assessment)
        a.status = "failed"
        a.limitations.append(f"Agent loop crashed: {ex.__class__.__name__}: {ex}")
        store.put("assessment", a)
        log(aid, "error", f"Agent loop crashed: {ex}")
        store.audit(aid, "agent", "loop.crash", {"error": str(ex)})


def _loop(aid: str) -> None:
    for step in range(1, config.MAX_AGENT_STEPS + 1):
        if runner.is_cancelled(aid):
            raise InterruptedError()
        a, cands, assets, findings = _candidates(aid)
        runnable = [c for c in cands if c.kind not in planner.APPROVAL_KINDS and c.kind != "skip"]
        if not runnable:
            log(aid, "info", "No further runnable actions are justified. Moving to correlation and ranking.")
            break
        chosen, rationale, options = planner.rule_choose(cands, len(findings))
        planner_name = "rules"
        summary = {"targets": a.targets, "services": [f"{x.host}:{x.port} {x.service} {x.product} {x.version}".strip() for x in assets if x.port][:30],
                   "findings": [f"{f.id} {f.issue_key} {f.severity} {f.status}" for f in findings][:40],
                   "open_hypotheses": [h.text for h in store.list_("hypothesis", Hypothesis, aid) if h.status == "open"][:15]}
        pick = planner.llm_choose(summary, cands)
        if pick:
            by_id = {c.action_id: c for c in runnable}
            chosen, rationale, planner_name = [by_id[pick[0]]], pick[1], "claude"
            for o in options:
                o["decision"] = "CHOSEN by Claude" if o["action"] == pick[0] else o["decision"].replace("CHOSEN: ", "deferred: ")
        c = chosen[0]
        a.phase = planner.PHASE_NAME.get(c.kind, a.phase)
        store.put("assessment", a)
        trig = sorted({h.source_evidence[0] for h in store.list_("hypothesis", Hypothesis, aid) if h.source_evidence and h.id in c.resolves})[:3]
        card = DecisionCard(id=f"D-{store.count('decision', aid) + 1:03d}", assessment_id=aid, phase=a.phase, trigger=trig,
                            hypothesis="; ".join(h.text for h in store.list_("hypothesis", Hypothesis, aid) if h.id in c.resolves)[:300] or "Establish a baseline of the attack surface.",
                            options=options, chosen=[c.action_id], rationale=rationale, planner=planner_name,
                            scope_check=scopemod.check_action(a.scope, c.tool if c.tool in ADAPTERS else "nmap", c.target, c.intensity, c.port).reason)
        store.put("decision", card)
        store.event(aid, "decision", card.model_dump())
        store.audit(aid, "agent", "decision", {"id": card.id, "chosen": card.chosen, "planner": planner_name})
        before = len(store.list_("finding", Finding, aid))
        if c.kind == "validate":
            # validations are single harmless GETs on different findings: run them together as one reasoned step
            batch = [x for x in runnable if x.kind == "validate"]
            card.chosen = [x.action_id for x in batch]
            card.rationale = (f"{len(batch)} configuration findings can each be confirmed or refuted with one harmless GET. "
                              "Doing this before ranking removes false positives so they do not distort priorities.")
            verdicts = []
            for x in batch:
                r = execute(aid, x)
                f = store.get("finding", x.params["finding_id"], Finding, aid)
                verdicts.append(f"{f.id}: {f.validation.get('verdict', 'not run') if f else '?'}")
            card.outcome = "validation verdicts: " + "; ".join(verdicts)
            store.put("decision", card)
            continue
        res = execute(aid, c)
        card.outcome = ("action failed or was blocked (see limitations)" if res is None else
                        f"completed: {len(res.findings)} raw finding(s), total findings {before} -> {len(store.list_('finding', Finding, aid))}")
        store.put("decision", card)
        if res is not None:
            _update_hypotheses(aid, c, res)
    finalize(aid)


def _update_hypotheses(aid: str, c: Candidate, res: AdapterResult) -> None:
    hs = store.list_("hypothesis", Hypothesis, aid)
    fs = store.list_("finding", Finding, aid)
    for h in hs:
        if h.status != "open":
            continue
        host_port = h.asset
        mine = [f for f in fs if f.asset.key() == host_port and f.status != "refuted"]
        if c.kind in ("nikto", "zap_passive") and host_port == f"{c.target.split('//')[-1].split(':')[0]}:{c.port}":
            h.status = "supported" if mine else "refuted"
            store.put("hypothesis", h)
        elif "CVE" in h.text and any(f.status in ("corroborated", "validated") for f in mine):
            h.status = "supported"; store.put("hypothesis", h)


def finalize(aid: str) -> None:
    a = store.get("assessment", aid, Assessment)
    correlation.link_related(aid)
    g = graph.build(aid)
    ranked = risk.rank(aid, path_bonus=g["path_bonus"])
    log(aid, "phase", f"Correlation and risk ranking complete: {len([f for f in ranked if not f.risk.get('excluded')])} active findings, "
                      f"{len([f for f in ranked if f.risk.get('excluded')])} refuted.")
    _propose_approvals(aid)
    pending = [x for x in store.list_("approval", Approval, aid) if x.status == "pending"]
    a = store.get("assessment", aid, Assessment)
    a.status, a.phase = ("awaiting_approval" if pending else "review"), ("human-review")
    a.updated_at = now()
    store.put("assessment", a)
    store.audit(aid, "agent", "assessment.ready-for-review", {"pending_approvals": len(pending)})
    log(aid, "phase", f"Ready for human review. {len(pending)} action(s) wait for approval." if pending else "Ready for human review.")


def _propose_approvals(aid: str) -> None:
    a, cands, assets, findings = _candidates(aid)
    existing = {x.action.get("action_id") for x in store.list_("approval", Approval, aid)}
    for c in cands:
        if c.kind in planner.APPROVAL_KINDS and c.action_id not in existing:
            ap = Approval(id=f"AP-{store.count('approval', aid) + 1:03d}", assessment_id=aid, action=c.model_dump(), reason=c.why,
                          finding_id=c.params.get("finding_id", ""))
            store.put("approval", ap)
            store.audit(aid, "agent", "approval.requested", {"id": ap.id, "action": c.action_id})
            store.event(aid, "approval", ap.model_dump())


def decide(aid: str, approval_id: str, approve: bool, analyst: str, comment: str = "") -> Approval:
    ap = store.get("approval", approval_id, Approval, aid)
    if not ap or ap.status != "pending":
        raise ValueError("approval not found or already decided")
    ap.decided_by, ap.decided_at, ap.comment = analyst, now(), comment
    ap.status = "approved" if approve else "rejected"
    store.put("approval", ap)
    store.audit(aid, analyst, "approval." + ap.status, {"id": ap.id, "action": ap.action.get("action_id"), "comment": comment})
    store.event(aid, "approval", ap.model_dump())
    if approve:
        c = Candidate(**ap.action)
        a = store.get("assessment", aid, Assessment)
        a.status = "running"; store.put("assessment", a)
        threading.Thread(target=_run_approved, args=(aid, ap.id, c, analyst), daemon=True).start()
    else:
        ap.outcome = "rejected by analyst; not executed"
        store.put("approval", ap)
        _after_approval(aid)
    return ap


def propose_validation(aid: str, finding_id: str, module: str, analyst: str = "analyst") -> Approval:
    """Analyst-initiated validation request. Still goes through the approval gate; module must be on the allow-list."""
    from ..adapters.msf import ALLOWED_MODULES
    if module not in ALLOWED_MODULES:
        raise ValueError(f"module not allowed. Allowed read-only modules: {', '.join(ALLOWED_MODULES)}")
    f = store.get("finding", finding_id, Finding, aid)
    if not f or not f.asset.port:
        raise ValueError("finding not found or has no network service to validate")
    a = store.get("assessment", aid, Assessment)
    c = Candidate(action_id=f"msf_check:{f.id}:{module.split('/')[-1]}", tool="metasploit", kind="msf_check", target=f.asset.host, port=f.asset.port,
                  intensity="exploit", cost="medium", noise="low", params={"finding_id": f.id, "module": module},
                  why=f"Analyst {analyst} requested read-only module {module} against {f.asset.key()} to corroborate {f.id}.")
    scopemod.enforce(a.scope, "metasploit", c.target, "exploit", c.port)   # scope still applies; raises if not allowed
    ap = Approval(id=f"AP-{store.count('approval', aid) + 1:03d}", assessment_id=aid, action=c.model_dump(), reason=c.why, finding_id=f.id)
    store.put("approval", ap)
    store.audit(aid, analyst, "approval.requested", {"id": ap.id, "action": c.action_id, "initiated_by": "analyst"})
    store.event(aid, "approval", ap.model_dump())
    a.status = "awaiting_approval"; store.put("assessment", a)
    return ap


def request_again(aid: str, approval_id: str, analyst: str = "analyst") -> Approval:
    """A failed approved action may be retried, but only through a NEW approval (each execution needs its own consent)."""
    old = store.get("approval", approval_id, Approval, aid)
    if not old or old.status != "failed":
        raise ValueError("only a failed approval can be re-requested")
    ap = Approval(id=f"AP-{store.count('approval', aid) + 1:03d}", assessment_id=aid, action=old.action,
                  reason=old.reason + f" (retry of {old.id})", finding_id=old.finding_id)
    store.put("approval", ap)
    store.audit(aid, analyst, "approval.re-requested", {"old": old.id, "new": ap.id})
    store.event(aid, "approval", ap.model_dump())
    a = store.get("assessment", aid, Assessment)
    a.status = "awaiting_approval"; store.put("assessment", a)
    return ap


def _run_approved(aid: str, ap_id: str, c: Candidate, analyst: str) -> None:
    ap = store.get("approval", ap_id, Approval, aid)
    try:
        res = execute(aid, c, actor=f"{analyst}(approved)")
        ap.status = "executed" if res is not None else "failed"
        ap.outcome = (f"executed: {len(res.findings)} raw finding(s); {'; '.join(res.notes)[:300]}" if res is not None
                      else "execution failed or tool unavailable; see assessment limitations")
    except InterruptedError:
        ap.status, ap.outcome = "failed", "cancelled by kill switch"
    except Exception as ex:
        ap.status, ap.outcome = "failed", f"{ex.__class__.__name__}: {ex}"
    store.put("approval", ap)
    store.audit(aid, "agent", "approval.outcome", {"id": ap.id, "status": ap.status, "outcome": ap.outcome})
    store.event(aid, "approval", ap.model_dump())
    _after_approval(aid)


def _after_approval(aid: str) -> None:
    finalize(aid)


# ------------------------------------------------------------------ import
def import_file(aid: str, tool: str, filename: str, content: bytes, analyst: str = "analyst") -> dict:
    a = store.get("assessment", aid, Assessment)
    ad = ADAPTERS.get(tool)
    if tool not in ("nessus", "burp", "openvas"):
        raise ValueError(f"'{tool}' does not support file import. Importable: nessus, burp, openvas")
    res = ad.ingest(aid, filename, content)
    kept, dropped = [], []
    for f in res.findings:
        (kept if scopemod.check_target(a.scope, f.asset.host).allowed else dropped).append(f)
    if dropped:
        a.limitations.append(f"{len(dropped)} finding(s) in {filename} were dropped: their hosts are outside the authorized scope "
                             f"({', '.join(sorted({d.asset.host for d in dropped}))}).")
        store.audit(aid, "scope-guard", "import.dropped", {"file": filename, "hosts": sorted({d.asset.host for d in dropped})})
    a.limitations = list(dict.fromkeys(a.limitations + [f"{tool} data in this report is IMPORTED from '{filename}' and was not executed by ARGUS."]))
    store.put("assessment", a)
    _save_assets(aid, AdapterResult(observations=[o for o in res.observations if scopemod.check_target(a.scope, o.asset.host).allowed]))
    touched, created, merged = correlation.ingest(aid, kept)
    store.audit(aid, analyst, "import", {"tool": tool, "file": filename, "findings": created, "merged": merged, "dropped": len(dropped)})
    card = DecisionCard(id=f"D-{store.count('decision', aid) + 1:03d}", assessment_id=aid, phase="import", planner="analyst",
                        hypothesis=f"Analyst supplied {tool} results for cross-checking.", chosen=[f"import:{filename}"],
                        rationale=f"Imported {len(kept)} in-scope finding(s): {created} new, {merged} merged with existing findings; {len(dropped)} out-of-scope dropped.",
                        outcome="IMPORT only: no scan was executed for this tool.")
    store.put("decision", card)
    store.event(aid, "decision", card.model_dump())
    finalize(aid)
    return {"created": created, "merged": merged, "dropped": len(dropped), "mode": "import"}


# ------------------------------------------------------------------ retest
def retest(aid: str, finding_id: str, analyst: str = "analyst") -> dict:
    f = store.get("finding", finding_id, Finding, aid)
    if not f:
        raise ValueError("finding not found")
    from ..adapters.validators import VALIDATABLE
    if f.issue_key not in VALIDATABLE:
        raise ValueError(f"no safe automated retest exists for issue class '{f.issue_key}'")
    a = store.get("assessment", aid, Assessment)
    url = f.affected_urls[0] if f.affected_urls else planner.web_url(f.asset)
    scopemod.enforce(a.scope, "nmap", url, "standard", f.asset.port)
    before = f.status
    job = Job(id=f"J-{store.count('job', aid) + 1:03d}", assessment_id=aid, tool="argus-http", kind="retest", target=url)
    raw, status_line = fetch(aid, job, url)
    path, sha = runner.save_artifact(aid, f"{job.id}_retest.txt", raw)
    ev = runner.new_evidence(aid, "argus-http-check", "live", job.id, path, sha, "response headers", f"RETEST GET {url} -> {status_line}")
    v = evaluate(f.issue_key, url, raw)
    if v.verdict == "refuted" and before in ("validated", "corroborated", "observed", "suspected"):
        f.status, f.refuted_reason = "fixed", v.reason
        f.confidence_reasons.append(f"retest: no longer reproducible: {v.reason}")
    elif v.verdict == "confirmed":
        f.status = "validated" if before != "refuted" else "validated"
        f.confidence = max(f.confidence, 90)
        f.confidence_reasons.append(f"retest: still present: {v.reason}")
    f.evidence_ids.append(ev.id)
    runner.finish_ok(job, ev.id)
    store.put("finding", f)
    store.audit(aid, analyst, "retest", {"finding": f.id, "before": before, "after": f.status, "verdict": v.verdict})
    risk.rank(aid)
    return {"finding": f.id, "before": before, "after": f.status, "verdict": v.verdict, "reason": v.reason, "evidence": ev.id}


# ------------------------------------------------------------------ analyst copilot (grounded in stored data)
def ask(aid: str, question: str) -> dict:
    q = question.lower()
    fs = store.list_("finding", Finding, aid)
    m = re.search(r"f-\d{3}", q)
    if m:
        f = next((x for x in fs if x.id.lower() == m.group(0)), None)
        if not f:
            return {"answer": f"I have no finding {m.group(0).upper()} in this assessment.", "cites": []}
        r = f.risk or {}
        fac = r.get("factors", {})
        lines = [f"{f.id}: {f.title} on {f.asset.key()} ({f.status}, confidence {f.confidence}/100)."]
        if any(k in q for k in ("why", "rank", "priority", "risk")):
            lines.append(f"Priority {r.get('priority')} (rank {r.get('rank')}): base {fac.get('base')} [{fac.get('base_source')}], exploitability x{fac.get('exploitability')} "
                         f"[{fac.get('exploitability_source')}], confidence weight x{fac.get('confidence_weight')} [{fac.get('confidence_source')}].")
        if any(k in q for k in ("evidence", "proof", "source", "trace", "why")):
            lines.append("Evidence: " + ", ".join(f"[{e}]" for e in f.evidence_ids) + ". Reported by: " + ", ".join(sorted({f'{o.tool}({o.mode})' for o in f.occurrences})) + ".")
        if any(k in q for k in ("confiden", "sure", "false", "why")):
            lines.append("Confidence ledger: " + " | ".join(f.confidence_reasons))
        if any(k in q for k in ("fix", "remed", "how")):
            lines.append("Remediation: " + (f.remediation or "none recorded by the tools"))
        if f.status == "refuted":
            lines.append(f"This was REFUTED: {f.refuted_reason}")
        return {"answer": "\n".join(lines), "cites": f.evidence_ids}
    if any(k in q for k in ("summary", "status", "overview", "how many")):
        act = [f for f in fs if f.status != "refuted"]
        by = {}
        for f in act:
            by[f.severity] = by.get(f.severity, 0) + 1
        return {"answer": f"{len(act)} active finding(s) {by}; {len(fs) - len(act)} refuted. Top: " +
                          "; ".join(f"{f.id} {f.title[:50]} (priority {f.risk.get('priority')})" for f in sorted(act, key=lambda x: x.risk.get("rank", 99))[:3]), "cites": []}
    if "approv" in q:
        p = [x for x in store.list_("approval", Approval, aid) if x.status == "pending"]
        return {"answer": f"{len(p)} pending approval(s): " + "; ".join(f"{x.id} {x.action.get('action_id')}" for x in p), "cites": []}
    return {"answer": "Ask about a finding (e.g. 'why is F-003 ranked high?', 'show evidence for F-002'), 'summary', or 'pending approvals'.", "cites": []}
