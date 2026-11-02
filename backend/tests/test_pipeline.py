"""Parser + correlation + risk + grounding tests. Fixtures are small hand-written test inputs, not scanner claims."""
import json
from pathlib import Path
import pytest
from argus import correlation, grounding, risk, store
from argus.adapters import imports, nikto, nmap, zap
from argus.adapters.validators import evaluate
from argus.models import Evidence, Finding

SAMPLES = Path(__file__).resolve().parents[2] / "samples"
AID = "A-test"

NMAP_XML = """<nmaprun><host><status state="up"/><address addr="10.77.0.20" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.49"/>
<script id="http-methods" output="Supported Methods: GET HEAD POST OPTIONS TRACE"/></port>
<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql" product="MySQL" version="5.5"/></port>
<port protocol="tcp" portid="22"><state state="closed"/></port>
</ports></host></nmaprun>"""

NIKTO_JSON = json.dumps([{"host": "10.77.0.10", "ip": "10.77.0.10", "port": "80", "banner": "Apache/2.4.25 (Debian)",
    "vulnerabilities": [
        {"id": "999103", "method": "GET", "url": "/", "msg": "The anti-clickjacking X-Frame-Options header is not present."},
        {"id": "999102", "method": "GET", "url": "/", "msg": "The X-Content-Type-Options header is not set."},
        {"id": "000001", "method": "GET", "url": "/config/", "msg": "Directory indexing found."}]}])

ZAP_ALERTS = [
    {"pluginId": "10020", "alert": "Missing Anti-clickjacking Header", "risk": "Medium", "confidence": "Medium", "url": "http://10.77.0.10/login.php",
     "param": "x-frame-options", "cweid": "1021", "description": "The response does not protect against clickjacking.", "solution": "Add X-Frame-Options."},
    {"pluginId": "10020", "alert": "Missing Anti-clickjacking Header", "risk": "Medium", "confidence": "Medium", "url": "http://10.77.0.10/index.php",
     "param": "x-frame-options", "cweid": "1021", "description": "x", "solution": "x"},
    {"pluginId": "10010", "alert": "Cookie No HttpOnly Flag", "risk": "Low", "confidence": "Medium", "url": "http://10.77.0.10/login.php",
     "param": "PHPSESSID", "cweid": "1004", "description": "cookie", "evidence": "Set-Cookie: PHPSESSID", "solution": "Set HttpOnly"},
]


@pytest.fixture(autouse=True)
def db(tmp_path):
    store.use_db(tmp_path / "p.db")
    yield


def ev(i):
    store.put("evidence", Evidence(id=f"EV-{i:04d}", assessment_id=AID, tool="t"))


def test_nmap_parser_services_and_rule_findings():
    r = nmap.parse_xml(AID, NMAP_XML, "EV-0001")
    svc = [o for o in r.observations if o.kind == "service"]
    assert {o.asset.port for o in svc} == {21, 80, 3306}           # closed port excluded
    titles = " | ".join(f.title for f in r.findings)
    assert "FTP service exposed" in titles and "MySQL database port" in titles and "Risky HTTP methods" in titles
    kv = [f for f in r.findings if f.cve]
    assert {f.cve[0] for f in kv} == {"CVE-2021-41773", "CVE-2011-2523"}


def test_nmap_bad_xml_is_reported_not_raised():
    r = nmap.parse_xml(AID, "<not xml", "EV-0001")
    assert r.notes and not r.findings


def test_import_parsers_on_samples():
    n = imports.parse_nessus(AID, (SAMPLES / "sample_nessus_dvwa.nessus").read_text(), "EV-0002")
    assert {f.title for f in n.findings} >= {"Web Application Potentially Vulnerable to Clickjacking"}
    assert all(f.occurrences[0].mode == "import" for f in n.findings)
    b = imports.parse_burp(AID, (SAMPLES / "sample_burp_dvwa.xml").read_text(), "EV-0003")
    assert any(f.asset.parameter for f in b.findings) and any("CWE-79" in f.cwe for f in b.findings)
    o = imports.parse_openvas(AID, (SAMPLES / "sample_openvas_dvwa.xml").read_text(), "EV-0004")
    assert o.findings[0].cvss_score == 2.6 and o.findings[0].asset.port is None


def test_cross_tool_dedup_keeps_all_evidence_and_urls():
    for i in range(1, 5):
        ev(i)
    nk = nikto.parse_json(AID, NIKTO_JSON, "EV-0001").findings
    zp = zap.parse_alerts(AID, ZAP_ALERTS, "EV-0002").findings
    ne = imports.parse_nessus(AID, (SAMPLES / "sample_nessus_dvwa.nessus").read_text(), "EV-0003").findings
    touched, created, merged = correlation.ingest(AID, nk + zp + ne)
    fs = store.list_("finding", Finding, AID)
    click = [f for f in fs if f.issue_key == "clickjacking"]
    assert len(click) == 1                                              # 4 reports -> 1 finding
    c = click[0]
    assert {o.tool for o in c.occurrences} == {"nikto", "zap", "nessus"}
    assert set(c.evidence_ids) >= {"EV-0001", "EV-0002", "EV-0003"}     # no evidence lost
    assert len(c.affected_urls) >= 2                                    # both ZAP URLs preserved
    assert c.status == "corroborated" and c.confidence == 75      # 40 base + 25 (2nd tool) + 10 (3rd tool)
    assert any("independently reported by 3 tools" in r for r in c.confidence_reasons)
    assert c.owasp.startswith("A05")


def test_same_issue_on_different_hosts_is_not_merged():
    ev(1)
    a = zap.parse_alerts(AID, [ZAP_ALERTS[0]], "EV-0001").findings
    b = zap.parse_alerts(AID, [dict(ZAP_ALERTS[0], url="http://10.77.0.11:3000/")], "EV-0001").findings
    correlation.ingest(AID, a + b)
    assert len(store.list_("finding", Finding, AID)) == 2


def test_version_only_finding_is_suspected_with_reasons():
    ev(1)
    r = nmap.parse_xml(AID, NMAP_XML, "EV-0001")
    correlation.ingest(AID, r.findings)
    f = next(x for x in store.list_("finding", Finding, AID) if x.cve == ["CVE-2021-41773"])
    assert f.status == "suspected" and f.confidence == 40
    assert any("version/banner match only" in x for x in f.confidence_reasons)


def test_validation_refutes_and_risk_excludes():
    for i in range(1, 3):
        ev(i)
    correlation.ingest(AID, zap.parse_alerts(AID, ZAP_ALERTS[:1], "EV-0001").findings)
    f = store.list_("finding", Finding, AID)[0]
    correlation.apply_validation(f, "refuted", "header is present", "EV-0002", "argus-http-check")
    store.put("finding", f)
    ranked = risk.rank(AID)
    assert ranked[0].status == "refuted" and ranked[0].risk["excluded"] and ranked[0].risk["priority"] == 0


def test_risk_uses_tool_cvss_never_invents_and_kev_boost():
    ev(1)
    nf = nmap.parse_xml(AID, NMAP_XML, "EV-0001").findings
    correlation.ingest(AID, nf)
    ranked = risk.rank(AID)
    top = next(f for f in ranked if f.cve == ["CVE-2021-41773"])
    assert top.cvss_score is None                                          # we did not invent a CVSS
    assert top.risk["factors"]["exploitability"] == 1.3
    assert "midpoint" in top.risk["factors"]["base_source"]
    assert top.risk["priority"] <= 10


def test_grounding_rejects_fabricated_cve_and_unknown_evidence():
    ev(1)
    correlation.ingest(AID, nmap.parse_xml(AID, NMAP_XML, "EV-0001").findings)
    ok, p = grounding.validate(AID, "Apache is affected by CVE-2021-41773 [EV-0001].")
    assert ok, p
    ok, p = grounding.validate(AID, "This is exploitable via CVE-2099-99999 [EV-0001].")
    assert not ok and any("CVE-2099-99999" in x for x in p)
    ok, p = grounding.validate(AID, "See [EV-0999].")
    assert not ok
    ok, p = grounding.validate(AID, "Totally unsupported claim.")
    assert not ok and any("without citing" in x for x in p)
    ok, p = grounding.validate(AID, "It has CVSS 9.8 [EV-0001]")
    assert not ok


def test_http_validators():
    raw = "HTTP/1.1 200 OK\nServer: Apache/2.4.25 (Debian)\nSet-Cookie: PHPSESSID=abc; path=/\n\n<html></html>"
    assert evaluate("clickjacking", "http://x/", raw).verdict == "confirmed"
    assert evaluate("clickjacking", "http://x/", raw.replace("Server:", "X-Frame-Options: DENY\nServer:")).verdict == "refuted"
    assert evaluate("missing-hsts", "http://x/", raw).verdict == "refuted"        # HTTP site: HSTS not applicable
    assert evaluate("missing-hsts", "https://x/", raw).verdict == "confirmed"
    assert evaluate("server-disclosure", "http://x/", raw).verdict == "confirmed"
    assert evaluate("cookie-httponly", "http://x/", raw).verdict == "confirmed"
    assert evaluate("xss", "http://x/", raw).verdict == "inconclusive"


def test_validated_confidence_survives_rescoring_and_synonyms_merge():
    for i in range(1, 4):
        ev(i)
    z = zap.parse_alerts(AID, [{"pluginId": "10033", "alert": "Directory Browsing", "risk": "Medium", "confidence": "Medium",
                               "url": "http://10.77.0.10/dvwa/css/", "cweid": "548", "description": "d", "solution": "s"}], "EV-0001").findings
    correlation.ingest(AID, z)
    f = store.list_("finding", Finding, AID)[0]
    correlation.apply_validation(f, "confirmed", "index page seen", "EV-0002", "argus-http-check")
    store.put("finding", f)
    ne = imports.parse_nessus(AID, (SAMPLES / "sample_nessus_dvwa.nessus").read_text(), "EV-0003").findings
    correlation.ingest(AID, [x for x in ne if "Browsable" in x.title])   # synonym from another tool, different URL
    fs = [x for x in store.list_("finding", Finding, AID) if x.issue_key == "directory-listing"]
    assert len(fs) == 1 and {o.tool for o in fs[0].occurrences} == {"zap", "nessus"}
    assert fs[0].status == "validated" and fs[0].confidence >= 90
