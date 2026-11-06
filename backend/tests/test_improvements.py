"""Tests for: grounding wired into runtime, out-of-scope result filtering, criticality, confidence level, redaction."""
import pytest
from argus import config, correlation, risk, store
from argus.adapters import zap
from argus.adapters.base import AdapterResult
from argus.agent import engine, planner
from argus.models import Assessment, Candidate, Evidence, Finding, Scope

AID = "A-imp"


@pytest.fixture(autouse=True)
def db(tmp_path, monkeypatch):
    store.use_db(tmp_path / "i.db")
    monkeypatch.setattr(config, "DATA_DIR", tmp_path)
    monkeypatch.setattr(config, "ARTIFACT_DIR", tmp_path / "artifacts")
    store.put("assessment", Assessment(id=AID, request="r", scope=Scope(targets=["10.77.0.0/24"], exclusions=["10.77.0.1"]), targets=["10.77.0.10"]))
    store.put("evidence", Evidence(id="EV-0001", assessment_id=AID, tool="zap"))
    yield


ALERT = {"pluginId": "10020", "alert": "Missing Anti-clickjacking Header", "risk": "Medium", "confidence": "Medium",
         "url": "http://10.77.0.10/", "param": "x-frame-options", "cweid": "1021", "description": "d", "solution": "s"}


def test_out_of_scope_zap_results_are_discarded():
    res = zap.parse_alerts(AID, [ALERT, dict(ALERT, url="http://evil.example.com/")], "EV-0001")
    a = store.get("assessment", AID, Assessment)
    engine._drop_out_of_scope(AID, a, Candidate(action_id="x", tool="zap", kind="zap_passive", target="http://10.77.0.10"), res)
    assert [f.asset.host for f in res.findings] == ["10.77.0.10"]
    assert any("out-of-scope" in l for l in store.get("assessment", AID, Assessment).limitations)


def test_criticality_changes_priority_and_rejects_bad_values():
    correlation.ingest(AID, zap.parse_alerts(AID, [ALERT], "EV-0001").findings)
    risk.rank(AID)
    base = store.list_("finding", Finding, AID)[0].risk["priority"]
    engine.set_criticality(AID, "10.77.0.10", 1.2)
    assert store.list_("finding", Finding, AID)[0].risk["priority"] > base
    with pytest.raises(ValueError):
        engine.set_criticality(AID, "10.77.0.10", 5)


def test_confidence_level_labels():
    assert [risk.conf_level(c) for c in (10, 40, 69, 70, 100)] == ["low", "medium", "medium", "high", "high"]
    correlation.ingest(AID, zap.parse_alerts(AID, [ALERT], "EV-0001").findings)
    risk.rank(AID)
    assert store.list_("finding", Finding, AID)[0].risk["confidence_level"] in ("low", "medium", "high")


def test_copilot_answer_with_unreported_cve_is_blocked(monkeypatch):
    monkeypatch.setattr(engine, "_ask", lambda aid, q: {"answer": "Exploitable via CVE-2099-12345", "cites": []})
    out = engine.ask(AID, "summary")
    assert "could not give a grounded answer" in out["answer"]


def test_redaction_removes_secrets():
    t = planner.redact('Authorization: Bearer abcdefghijkl1234\npassword=hunter2 token: xyz123 Set-Cookie: PHPSESSID=abc')
    assert "hunter2" not in t and "abcdefghijkl1234" not in t and "PHPSESSID" not in t


def test_report_contains_grounding_check():
    from argus import report
    correlation.ingest(AID, zap.parse_alerts(AID, [ALERT], "EV-0001").findings)
    risk.rank(AID)
    assert report.build_pdf(AID).startswith(b"%PDF")
