"""Nmap adapter (LIVE, via the argus-tools container). Parses -oX XML."""
from __future__ import annotations
import xml.etree.ElementTree as ET
from .. import runner, reference
from ..models import Asset, Job
from .base import Adapter, AdapterResult, Observation, mk_finding

CLEARTEXT = {"telnet": "Telnet", "ftp": "FTP", "tftp": "TFTP", "pop3": "POP3", "imap": "IMAP", "rsh": "rsh", "rlogin": "rlogin"}
DB_PORTS = {3306: "MySQL", 5432: "PostgreSQL", 1433: "MS SQL Server", 27017: "MongoDB", 6379: "Redis", 1521: "Oracle DB", 9200: "Elasticsearch"}
HTTP_SERVICES = ("http", "http-proxy", "https", "http-alt", "ssl/http", "https-alt")
RISKY_METHODS = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}


def is_http(service: str, port: int) -> bool:
    return service in HTTP_SERVICES or "http" in service or port in (80, 443, 8080, 8000, 8443, 3000)


def parse_xml(assessment_id: str, xml_text: str, ev_id: str) -> AdapterResult:
    res = AdapterResult()
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as ex:
        res.notes.append(f"nmap XML could not be parsed: {ex}")
        return res
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") != "up":
            continue
        addr = next((a.get("addr") for a in h.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")), None)
        if not addr:
            continue
        res.observations.append(Observation(Asset(host=addr), ev_id, "host", {}))
        for p in h.findall("ports/port"):
            state = p.find("state")
            if state is None or state.get("state") != "open":
                continue
            port, proto = int(p.get("portid")), p.get("protocol", "tcp")
            sv = p.find("service")
            name = sv.get("name", "") if sv is not None else ""
            product = sv.get("product", "") if sv is not None else ""
            version = sv.get("version", "") if sv is not None else ""
            asset = Asset(host=addr, port=port, protocol=proto, service=name, product=product, version=version)
            res.observations.append(Observation(asset, ev_id, "service", {"extrainfo": sv.get("extrainfo", "") if sv is not None else ""}))
            banner = " ".join(x for x in (product, version) if x)
            if name in CLEARTEXT:
                f = mk_finding(assessment_id, "nmap", "live", ev_id, title=f"{CLEARTEXT[name]} service exposed (cleartext protocol)", asset=asset,
                               severity="medium", severity_source="derived", rule_id="argus-rule:cleartext",
                               description=f"Nmap found {name} open on {addr}:{port} ({banner or 'unknown version'}). This protocol sends credentials and data unencrypted.")
                res.findings.append(f)
            if port in DB_PORTS:
                f = mk_finding(assessment_id, "nmap", "live", ev_id, title=f"{DB_PORTS[port]} database port reachable on the network", asset=asset,
                               severity="medium", severity_source="derived", rule_id="argus-rule:db-exposed",
                               description=f"Port {port}/{proto} ({name or DB_PORTS[port]}) is open. Databases are normally reachable only from application servers.",
                               remediation="Restrict the database listener to trusted application hosts with a firewall or bind it to localhost.")
                res.findings.append(f)
            for m in reference.known_version_cves(product, version):
                f = mk_finding(assessment_id, "nmap", "live", ev_id, title=f"{product} {version}: {m['note']}", asset=asset,
                               severity="high", severity_source="derived", cve=[m["cve"]], rule_id="argus-rule:known-version",
                               description=f"Nmap's version detection reported {product} {version}. {m['note']} ({m['cve']}). "
                                           "This is a version-only match and has not been confirmed by an active test.")
                res.findings.append(f)
            for sc in p.findall("script"):
                _script(assessment_id, sc, asset, ev_id, res)
    return res


def _script(aid: str, sc, asset: Asset, ev_id: str, res: AdapterResult) -> None:
    sid, out = sc.get("id", ""), (sc.get("output") or "").strip()
    if not out:
        return
    res.observations.append(Observation(asset, ev_id, "tech", {"script": sid, "output": out[:400]}))
    if sid == "http-methods":
        risky = sorted(RISKY_METHODS & set(out.replace("\n", " ").replace(",", " ").split()))
        if risky:
            res.findings.append(mk_finding(aid, "nmap", "live", ev_id, title=f"Risky HTTP methods enabled: {', '.join(risky)}", asset=asset,
                                           severity="low", severity_source="derived", rule_id="nse:http-methods",
                                           description=f"http-methods script output: {out[:300]}",
                                           remediation="Disable HTTP methods that the application does not need (PUT, DELETE, TRACE)."))
    if sid == "http-enum":
        res.findings.append(mk_finding(aid, "nmap", "live", ev_id, title="Interesting or administrative resources found by http-enum", asset=asset,
                                       severity="info", severity_source="derived", rule_id="nse:http-enum", description=out[:600]))


def build_scan_cmd(kind: str, target: str, ports: list[int] | None = None) -> list[str]:
    host = target
    if kind == "nmap_scan":
        return ["nmap", "-sV", "-T4", "--top-ports", "1000", "--open", "-Pn", "-oX", "-", host]
    ports_s = ",".join(str(p) for p in (ports or [80]))
    return ["nmap", "-sV", "-Pn", "-T4", "-p", ports_s, "--script", "http-title,http-methods,http-server-header,http-enum", "-oX", "-", host]


class NmapAdapter(Adapter):
    name, mode, status = "nmap", "live", "live"
    description = "Host/port/service discovery and enumeration (-sV, safe NSE http scripts) via Docker container."
    limitations = "Requires the argus-tools container. No vulners script: CVE hints come only from a small reference table."

    def available(self):
        ok = runner.container_running("argus-tools")
        return ok, "ok" if ok else "argus-tools container not running (start the lab)"

    def run(self, aid: str, job: Job, kind: str, target: str, ports=None, timeout=300) -> AdapterResult:
        argv = runner.in_tools(*build_scan_cmd(kind, target, ports))
        code, out, err = runner.run_command(job, argv, timeout=timeout)
        path, sha = runner.save_artifact(aid, f"{job.id}_nmap.xml", out or err)
        if code != 0 or "<nmaprun" not in out:
            job.status, job.error = "failed", (err or out)[:300]
            raise RuntimeError(job.error)
        ev = runner.new_evidence(aid, "nmap", "live", job.id, path, sha, "nmaprun", f"{job.command}")
        res = parse_xml(aid, out, ev.id)
        res.evidence.append(ev)
        runner.finish_ok(job, ev.id)
        return res
