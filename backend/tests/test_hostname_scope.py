from argus.adapters import nmap as nm
from argus import scope as scopemod
from argus.models import Scope

XML = """<nmaprun><host><status state="up"/><address addr="203.0.113.7" addrtype="ipv4"/>
<hostnames><hostname name="site.example.org" type="user"/><hostname name="ptr.host.net" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version=""/></port></ports></host></nmaprun>"""


def test_asset_keeps_the_hostname_that_was_scanned():
    res = nm.parse_xml("A-1", XML, "EV-1")
    assert {o.asset.host for o in res.observations} == {"site.example.org"}


def test_follow_up_actions_stay_inside_a_hostname_only_scope():
    res = nm.parse_xml("A-1", XML, "EV-1")
    svc = next(o.asset for o in res.observations if o.asset.port == 443)
    scope = Scope(targets=["site.example.org"], authorized_by="Organizer", max_intensity="intrusive")
    assert scopemod.check_action(scope, "nikto", f"https://{svc.host}", "standard", svc.port).allowed


def test_ip_scans_still_report_the_ip():
    xml = XML.replace('<hostnames><hostname name="site.example.org" type="user"/>', "<hostnames>")
    res = nm.parse_xml("A-1", xml, "EV-1")
    assert {o.asset.host for o in res.observations} == {"203.0.113.7"}


def test_nikto_keeps_the_scanned_name_and_uses_https_on_443():
    import json
    from argus.adapters import nikto
    data = {"host": "site.example.org", "ip": "203.0.113.7", "port": "443", "vulnerabilities": [{"id": "1", "msg": "X-Frame-Options header is not present", "url": "/"}]}
    f = nikto.parse_json("A-1", json.dumps(data), "EV-2").findings[0]
    assert f.asset.host == "site.example.org" and f.asset.url.startswith("https://site.example.org")


def test_nmap_gets_a_host_not_a_url():
    from argus.agent.engine import nmap_host
    assert nmap_host("https://site.example.org/app?x=1") == "site.example.org"
    assert nmap_host("http://203.0.113.7:8080") == "203.0.113.7"
    assert nmap_host("10.77.0.0/24") == "10.77.0.0/24"
    assert nmap_host("site.example.org") == "site.example.org"
