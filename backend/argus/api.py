"""FastAPI app: REST + SSE + static UI."""
from __future__ import annotations
import asyncio, base64, json
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from . import config, graph, grounding, runner, scope as scopemod, store
from .adapters import ADAPTERS, matrix
from .agent import engine
from .models import (Approval, Assessment, DecisionCard, Evidence, Finding, Hypothesis, Job, Scope)
from .report import build_pdf

app = FastAPI(title="ARGUS", version="1.0")
FRONTEND = config.ROOT / "frontend"
engine.recover_interrupted()


def lab_scope() -> Scope:
    # .1 is the Docker gateway = the developer's own machine and everything it publishes: it is NOT part of the lab.
    # .2 / .3 are the ARGUS tools and ZAP containers. Only .10 (DVWA) and .11 (Juice Shop) are test targets.
    return Scope(id="scope-lab", name="ARGUS local Docker lab", targets=["10.77.0.0/24"], exclusions=["10.77.0.1", "10.77.0.2", "10.77.0.3"],
                 allowed_tools=[], max_intensity="intrusive", authorized_by="Team ARGUS (own isolated lab)", rate_limit_rps=10,
                 notes="Isolated Docker network argus-lab_labnet. Replace with the organizer-provided scope for the live demo.")


class CreateReq(BaseModel):
    request: str
    title: str = ""
    scope: Optional[Scope] = None


class DecideReq(BaseModel):
    approve: bool
    analyst: str = "analyst"
    comment: str = ""


class ImportReq(BaseModel):
    tool: str
    filename: str
    content_b64: str
    analyst: str = "analyst"


class AskReq(BaseModel):
    question: str


def _a(aid: str) -> Assessment:
    a = store.get("assessment", aid, Assessment)
    if not a:
        raise HTTPException(404, "assessment not found")
    return a


@app.get("/api/health")
def health():
    ok, bad = store.verify_audit()
    llm = config.llm_provider_name()
    return {"ok": True, "llm": llm if llm != "rules-only" else "rules-only (no API key set)", "docker": runner.docker_available(), "audit_chain_ok": ok}


@app.get("/api/matrix")
def get_matrix():
    return matrix()


@app.get("/api/scope/default")
def default_scope():
    return lab_scope()


@app.post("/api/scope/check")
def scope_check(body: dict):
    s = Scope(**body["scope"]) if body.get("scope") else lab_scope()
    d = scopemod.check_action(s, body.get("tool", "nmap"), body["target"], body.get("intensity", "standard"), body.get("port"))
    return {"allowed": d.allowed, "reason": d.reason, "needs_approval": d.needs_approval}


@app.post("/api/assessments")
def create(req: CreateReq):
    a = engine.create_assessment(req.request, req.scope or lab_scope(), req.title)
    if a.status != "failed":
        engine.make_plan(a.id)
    return full(a.id)


@app.get("/api/assessments")
def list_assessments():
    return [{"id": a.id, "title": a.title, "status": a.status, "created_at": a.created_at, "targets": a.targets}
            for a in reversed(store.list_("assessment", Assessment))]


def full(aid: str) -> dict:
    a = _a(aid)
    fs = store.list_("finding", Finding, aid)
    fs.sort(key=lambda f: (f.risk.get("excluded", False), f.risk.get("rank", 999)))
    return {"assessment": a.model_dump(),
            "decisions": [d.model_dump() for d in store.list_("decision", DecisionCard, aid)],
            "jobs": [j.model_dump() for j in store.list_("job", Job, aid) if j.kind not in ("read", "cleanup")],
            "findings": [f.model_dump() for f in fs],
            "approvals": [x.model_dump() for x in store.list_("approval", Approval, aid)],
            "hypotheses": [h.model_dump() for h in store.list_("hypothesis", Hypothesis, aid)],
            "evidence": [e.model_dump() for e in store.list_("evidence", Evidence, aid)],
            "assets": [r.model_dump() for r in store.list_("asset", engine.AssetRecord, aid)]}


@app.get("/api/assessments/{aid}")
def get_full(aid: str):
    return full(aid)


@app.post("/api/assessments/{aid}/approve-plan")
def approve_plan(aid: str, body: dict | None = None):
    try:
        engine.approve_plan(aid, (body or {}).get("analyst", "analyst"))
    except ValueError as ex:
        raise HTTPException(409, str(ex))
    return {"ok": True}


@app.post("/api/assessments/{aid}/stop")
def stop(aid: str):
    engine.stop(aid)
    return {"ok": True}


@app.post("/api/assessments/{aid}/import")
def import_(aid: str, req: ImportReq):
    _a(aid)
    try:
        return engine.import_file(aid, req.tool, req.filename, base64.b64decode(req.content_b64), req.analyst)
    except ValueError as ex:
        raise HTTPException(400, str(ex))


@app.post("/api/assessments/{aid}/import-sample/{tool}")
def import_sample(aid: str, tool: str):
    names = {"nessus": "sample_nessus_dvwa.nessus", "burp": "sample_burp_dvwa.xml", "openvas": "sample_openvas_dvwa.xml"}
    if tool not in names:
        raise HTTPException(400, "no sample for that tool")
    p = config.SAMPLES_DIR / names[tool]
    return engine.import_file(aid, tool, "SAMPLE-" + names[tool], p.read_bytes())


@app.post("/api/assessments/{aid}/approvals/{ap}/decide")
def decide(aid: str, ap: str, req: DecideReq):
    try:
        return engine.decide(aid, ap, req.approve, req.analyst, req.comment)
    except ValueError as ex:
        raise HTTPException(409, str(ex))


@app.post("/api/assessments/{aid}/approvals/{ap}/retry")
def retry_approval(aid: str, ap: str):
    try:
        return engine.request_again(aid, ap)
    except ValueError as ex:
        raise HTTPException(409, str(ex))


@app.post("/api/assessments/{aid}/findings/{fid}/propose-validation")
def propose_validation(aid: str, fid: str, body: dict):
    try:
        return engine.propose_validation(aid, fid, body.get("module", "auxiliary/scanner/http/http_version"), body.get("analyst", "analyst"))
    except scopemod.ScopeViolation as ex:
        raise HTTPException(403, str(ex))
    except ValueError as ex:
        raise HTTPException(400, str(ex))


@app.post("/api/assessments/{aid}/findings/{fid}/retest")
def retest(aid: str, fid: str):
    try:
        return engine.retest(aid, fid)
    except scopemod.ScopeViolation as ex:
        raise HTTPException(403, str(ex))
    except TimeoutError as ex:
        raise HTTPException(504, f"retest timed out; the finding was not changed ({ex})")
    except (ValueError, RuntimeError, runner.ToolUnavailable) as ex:
        raise HTTPException(400, str(ex))


class CritReq(BaseModel):
    host: str
    value: float
    analyst: str = "analyst"


@app.post("/api/assessments/{aid}/criticality")
def criticality(aid: str, req: CritReq):
    _a(aid)
    try:
        return engine.set_criticality(aid, req.host, req.value, req.analyst)
    except ValueError as ex:
        raise HTTPException(400, str(ex))


@app.post("/api/assessments/{aid}/ask")
def ask(aid: str, req: AskReq):
    return engine.ask(aid, req.question)


@app.get("/api/assessments/{aid}/graph")
def get_graph(aid: str):
    return graph.build(aid)


@app.get("/api/assessments/{aid}/evidence/{ev}/raw")
def evidence_raw(aid: str, ev: str):
    e = store.get("evidence", ev, Evidence, aid)
    if not e:
        raise HTTPException(404, "evidence not found")
    p = (config.DATA_DIR / e.file_path).resolve()
    if config.DATA_DIR.resolve() not in p.parents or not p.exists():
        raise HTTPException(404, "raw file missing")
    ok = runner.sha256_file(p) == e.sha256
    return PlainTextResponse(p.read_text(errors="replace")[:200000], headers={"X-Evidence-Hash-Verified": str(ok).lower(), "X-Evidence-SHA256": e.sha256})


@app.get("/api/assessments/{aid}/audit")
def audit(aid: str):
    ok, bad = store.verify_audit()
    return {"chain_ok": ok, "first_bad_entry": bad, "entries": store.audit_entries(aid)}


@app.get("/api/assessments/{aid}/report.pdf")
def report(aid: str):
    a = _a(aid)
    pdf = build_pdf(aid)
    if a.status == "review":
        a.status, a.phase = "complete", "complete"
        store.put("assessment", a)
    store.audit(aid, "analyst", "report.download", {})
    return Response(pdf, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=ARGUS_VAPT_{aid}.pdf"})


@app.get("/api/assessments/{aid}/events")
async def events(aid: str, since: int = 0):
    async def gen():
        seq = since
        idle = 0
        while True:
            evs = store.events_since(aid, seq)
            for e in evs:
                seq = e["seq"]
                yield f"id: {seq}\ndata: {json.dumps(e)}\n\n"
            idle = 0 if evs else idle + 1
            if idle % 15 == 14:
                yield ": keepalive\n\n"
            await asyncio.sleep(1)
    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache"})


if FRONTEND.exists():
    app.mount("/", StaticFiles(directory=FRONTEND, html=True), name="ui")
