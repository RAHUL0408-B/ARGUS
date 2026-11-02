import pytest
from argus import store
from argus.models import Scope
from argus.scope import ScopeViolation, check_action, check_target, enforce

LAB = Scope(targets=["10.77.0.0/24"], exclusions=["10.77.0.2", "10.77.0.3"], max_intensity="intrusive",
            allowed_tools=["nmap", "nikto", "zap"])


def test_in_scope_ip_and_url():
    assert check_target(LAB, "10.77.0.10").allowed
    assert check_target(LAB, "http://10.77.0.10:80/login.php").allowed


def test_out_of_scope_rejected():
    d = check_target(LAB, "8.8.8.8")
    assert not d.allowed and "not in the authorized scope" in d.reason
    with pytest.raises(ScopeViolation):
        enforce(LAB, "nmap", "scanme.nmap.org")


def test_exclusion_overrides_target():
    assert not check_target(LAB, "10.77.0.2").allowed


def test_cidr_must_be_fully_inside_scope():
    d = check_target(LAB, "10.77.0.0/28")           # overlaps excluded .2: allowed, exclusions are enforced at scan time
    assert d.allowed and "exclusions enforced" in d.reason
    assert not check_target(LAB, "10.77.0.0/16").allowed
    assert not check_target(LAB, "10.0.0.0/8").allowed


def test_tool_allowlist_and_intensity():
    assert not check_action(LAB, "metasploit", "10.77.0.10", "exploit").allowed
    d = check_action(LAB, "zap", "10.77.0.10", "intrusive")
    assert d.allowed and d.needs_approval
    assert not check_action(LAB, "nmap", "10.77.0.10", "exploit").allowed
    assert not check_action(LAB, "nmap", "10.77.0.10", "standard").needs_approval


def test_allowed_ports():
    s = Scope(targets=["10.77.0.0/24"], allowed_ports=[80])
    assert check_target(s, "10.77.0.10", 80).allowed
    assert not check_target(s, "10.77.0.10", 22).allowed


def test_time_window():
    s = Scope(targets=["10.77.0.0/24"], window_end="2000-01-01T00:00:00+00:00")
    assert not check_action(s, "nmap", "10.77.0.10").allowed


def test_audit_chain_detects_tampering(tmp_path):
    store.use_db(tmp_path / "t.db")
    store.audit("A1", "agent", "plan", {"x": 1})
    store.audit("A1", "analyst", "approve", {"y": 2})
    assert store.verify_audit() == (True, None)
    store.conn().execute("UPDATE audit SET action='forged' WHERE seq=1")
    store.conn().commit()
    ok, bad = store.verify_audit()
    assert not ok and bad == 1
