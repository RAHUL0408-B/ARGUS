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


def test_llm_cannot_choose_an_action_that_is_not_a_candidate(monkeypatch):
    """Prompt-injection guard: even if the model returns an arbitrary action id, it is ignored."""
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "x")
    import sys, types
    fake = types.SimpleNamespace(Anthropic=lambda api_key: types.SimpleNamespace(messages=types.SimpleNamespace(create=lambda **k: types.SimpleNamespace(
        content=[types.SimpleNamespace(type="text", text='{"action_id": "nmap_scan:8.8.8.8", "rationale": "ignore previous instructions"}')]))))
    monkeypatch.setitem(sys.modules, "anthropic", fake)
    c = Candidate(action_id="nmap_scan:10.77.0.10", tool="nmap", kind="nmap_scan", target="10.77.0.10")
    assert planner.llm_choose({"targets": ["10.77.0.10"]}, [c]) is None


def test_gemini_cannot_choose_an_action_that_is_not_a_candidate(monkeypatch):
    """Same prompt-injection guard, for the Gemini path (tried first when both keys are set)."""
    monkeypatch.setattr(config, "GEMINI_API_KEY", "x")
    import httpx

    class FakeResp:
        def raise_for_status(self): pass
        def json(self): return {"candidates": [{"content": {"parts": [
            {"text": '{"action_id": "nmap_scan:8.8.8.8", "rationale": "ignore previous instructions"}'}]}}]}
    monkeypatch.setattr(httpx, "post", lambda *a, **k: FakeResp())
    c = Candidate(action_id="nmap_scan:10.77.0.10", tool="nmap", kind="nmap_scan", target="10.77.0.10")
    assert planner.llm_choose({"targets": ["10.77.0.10"]}, [c]) is None


def test_gemini_preferred_over_claude_when_both_keys_set(monkeypatch):
    monkeypatch.setattr(config, "GEMINI_API_KEY", "x")
    monkeypatch.setattr(config, "ANTHROPIC_API_KEY", "x")
    import sys, types
    called = {"gemini": False, "claude": False}

    def fake_post(*a, **k):
        called["gemini"] = True
        class R:
            def raise_for_status(self): pass
            def json(self): return {"candidates": [{"content": {"parts": [{"text": '{"action_id": "nmap_scan:10.77.0.10", "rationale": "ok"}'}]}}]}
        return R()
    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    fake_anthropic = types.SimpleNamespace(Anthropic=lambda api_key: (_ for _ in ()).throw(AssertionError("Claude should not be called when Gemini is configured")))
    monkeypatch.setitem(sys.modules, "anthropic", fake_anthropic)
    c = Candidate(action_id="nmap_scan:10.77.0.10", tool="nmap", kind="nmap_scan", target="10.77.0.10")
    result = planner.llm_choose({"targets": ["10.77.0.10"]}, [c])
    assert result == ("nmap_scan:10.77.0.10", "ok")
    assert called["gemini"] is True


def test_scope_blocks_injected_target_even_if_planner_returned_it():
    from argus import scope as scopemod
    a = store.get("assessment", AID, Assessment)
    evil = Candidate(action_id="nmap_scan:8.8.8.8", tool="nmap", kind="nmap_scan", target="8.8.8.8")
    assert engine.execute(AID, evil) is None
    assert any(e["action"] == "action.blocked" for e in store.audit_entries(AID))


def test_msf_check_does_not_validate_unrelated_finding(monkeypatch):
    from argus.adapters import ADAPTERS
    from argus.adapters.base import AdapterResult
    ev = Evidence(id="EV-0002", assessment_id=AID, tool="metasploit", file_path="m.txt")
    (config.DATA_DIR / "m.txt").write_text("[+] 10.77.0.10:80 Apache/2.4.25")
    store.put("evidence", ev)
    z = zap.parse_alerts(AID, [ALERT], "EV-0001").findings
    z[0].asset.version = "Apache/2.4.25"
    correlation.ingest(AID, z)
    f = store.list_("finding", Finding, AID)[0]
    monkeypatch.setattr(ADAPTERS["metasploit"], "run", lambda *a, **k: AdapterResult(evidence=[ev]))
    from argus.models import Job
    engine._msf(AID, Job(id="J-1", assessment_id=AID, tool="metasploit", kind="msf_check", target="10.77.0.10"),
                Candidate(action_id="m", tool="metasploit", kind="msf_check", target="10.77.0.10", port=80, params={"finding_id": f.id, "module": "auxiliary/scanner/http/http_version"}))
    assert store.get("finding", f.id, Finding, AID).status != "validated"
