"""Regression tests for failures found by the live end-to-end run (2026-11-03)."""
import pytest
from fastapi.testclient import TestClient
from argus import config, store
from argus.adapters import ADAPTERS
from argus.agent import engine
from argus.models import Approval, Assessment, Job, Scope

AID = "A-rob"


@pytest.fixture(autouse=True)
def db(tmp_path, monkeypatch):
    store.use_db(tmp_path / "r.db")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "ARTIFACT_DIR", tmp_path / "artifacts")
    yield


def test_interrupted_run_is_marked_stopped_on_restart():
    store.put("assessment", Assessment(id=AID, request="r", scope=Scope(targets=["10.77.0.0/24"]), targets=["10.77.0.10"], status="running"))
    store.put("job", Job(id="J-001", assessment_id=AID, tool="nmap", kind="nmap_scan", target="10.77.0.10", status="running"))
    store.put("approval", Approval(id="AP-001", assessment_id=AID, action={"action_id": "zap_active:x"}, reason="r", status="approved"))
    assert engine.recover_interrupted() == 1
    a = store.get("assessment", AID, Assessment)
    assert a.status == "stopped" and any("restarted" in x for x in a.limitations)
    assert store.get("job", "J-001", Job, AID).status == "cancelled"
    assert store.get("approval", "AP-001", Approval, AID).status == "failed"
    assert engine.recover_interrupted() == 0                     # idempotent


def test_zap_active_scan_over_deadline_keeps_partial_results(monkeypatch):
    zap = ADAPTERS["zap"]
    alerts = [{"pluginId": "40018", "alert": "SQL Injection", "risk": "High", "confidence": "Medium", "url": "http://10.77.0.10/vuln.php?id=1",
               "param": "id", "cweid": "89", "description": "d", "solution": "s"}]
    calls = []

    def fake_get(path, **kw):
        calls.append(path)
        return {"/JSON/spider/action/scan/": {"scan": "1"}, "/JSON/ascan/action/scan/": {"scan": "2"},
                "/JSON/core/view/alerts/": {"alerts": alerts}, "/JSON/core/view/urls/": {"urls": ["http://10.77.0.10/"]}}.get(path, {})

    def fake_wait(job, check, timeout, label):
        if label == "active scan":
            raise TimeoutError("active scan did not finish")

    monkeypatch.setattr(zap, "available", lambda: (True, "ok"))
    monkeypatch.setattr(zap, "_get", fake_get)
    monkeypatch.setattr(zap, "_wait", fake_wait)
    job = Job(id="J-001", assessment_id=AID, tool="zap", kind="zap_active", target="http://10.77.0.10")
    res = zap.run(AID, job, "http://10.77.0.10", active=True)
    assert job.status == "ok" and res.findings and res.findings[0].title == "SQL Injection"
    assert "/JSON/ascan/action/stop/" in calls and any("partial" in n for n in res.notes)


def test_retest_timeout_is_a_clean_504_not_500(monkeypatch):
    from argus import api
    def boom(*a, **k):
        raise TimeoutError("timed out after 40s")
    monkeypatch.setattr(engine, "retest", boom)
    r = TestClient(api.app).post("/api/assessments/A-x/findings/F-001/retest", json={})
    assert r.status_code == 504 and "timed out" in r.json()["detail"]
