"""Import-only adapters: Nessus (.nessus v2), Burp Suite (issues XML export), OpenVAS/Greenbone (report XML).

These NEVER run a scan. Evidence is marked mode='import' and the UI/report label it IMPORT.
"""
from __future__ import annotations
import re
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from .. import runner
from ..models import Asset
from .base import Adapter, AdapterResult, Observation, mk_finding

NESSUS_SEV = {"0": "info", "1": "low", "2": "medium", "3": "high", "4": "critical"}
BURP_SEV = {"information": "info", "low": "low", "medium": "medium", "high": "high"}
CVE_RX = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def _t(el, tag, default=""):
    c = el.find(tag)
    return (c.text or "").strip() if c is not None and c.text else default


def _f(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def parse_nessus(aid: str, xml_text: str, ev_id: str) -> AdapterResult:
    res = AdapterResult()
    root = ET.fromstring(xml_text)
    for rh in root.iter("ReportHost"):
        host = rh.get("name", "")
        res.observations.append(Observation(Asset(host=host), ev_id, "host", {}))
        for it in rh.findall("ReportItem"):
            port = int(it.get("port") or 0) or None
            asset = Asset(host=host, port=port, protocol=it.get("protocol", "tcp"), service=it.get("svc_name", ""))
            sev = NESSUS_SEV.get(it.get("severity", "0"), "info")
            if sev == "info" and not _t(it, "cve"):
                if port:
                    res.observations.append(Observation(asset, ev_id, "service", {"plugin": it.get("pluginName", "")}))
                continue   # informational plugins are context, not findings
            cves = [c.upper() for c in (x.text or "" for x in it.findall("cve")) if CVE_RX.fullmatch(c.strip().upper())]
            cwe = [f"CWE-{x.text.strip()}" for x in it.findall("cwe") if x.text and x.text.strip().isdigit()]
            score = _f(_t(it, "cvss3_base_score")) or _f(_t(it, "cvss_base_score"))
            vector = _t(it, "cvss3_vector") or _t(it, "cvss_vector")
            f = mk_finding(aid, "nessus", "import", ev_id, title=it.get("pluginName", ""), asset=asset, severity=sev,
                           description=_t(it, "description") + (f"\nPlugin output: {_t(it, 'plugin_output')[:400]}" if _t(it, "plugin_output") else ""),
                           cve=cves, cwe=cwe, cvss=score, vector=vector, rule_id=f"nessus:{it.get('pluginID', '')}",
                           remediation=_t(it, "solution"), references=[x.text.strip() for x in it.findall("see_also") if x.text][:3])
            res.findings.append(f)
    return res


def parse_burp(aid: str, xml_text: str, ev_id: str) -> AdapterResult:
    res = AdapterResult()
    root = ET.fromstring(xml_text)
    for iss in root.iter("issue"):
        host_el = iss.find("host")
        ip = (host_el.get("ip") if host_el is not None else "") or ""
        url = _t(iss, "host") + _t(iss, "path")
        u = urlparse(_t(iss, "host"))
        host = ip or u.hostname or ""
        port = u.port or (443 if u.scheme == "https" else 80)
        asset = Asset(host=host, port=port, service=u.scheme or "http", url=url, parameter=(_t(iss, "location").split("[")[-1].rstrip("]") if "[" in _t(iss, "location") else ""))
        cwe = [f"CWE-{m}" for m in re.findall(r"CWE-(\d+)", _t(iss, "vulnerabilityClassifications"))]
        cves = [c.upper() for c in CVE_RX.findall(_t(iss, "vulnerabilityClassifications"))]
        f = mk_finding(aid, "burp", "import", ev_id, title=_t(iss, "name"), asset=asset, severity=BURP_SEV.get(_t(iss, "severity").lower(), "info"),
                       description=re.sub(r"<[^>]+>", " ", _t(iss, "issueBackground") + " " + _t(iss, "issueDetail")).strip()[:900],
                       cwe=cwe, cve=cves, rule_id=f"burp:{_t(iss, 'type')}",
                       remediation=re.sub(r"<[^>]+>", " ", _t(iss, "remediationBackground")).strip()[:600])
        f.confidence_reasons.append(f"burp-confidence:{_t(iss, 'confidence') or 'unknown'}")
        res.findings.append(f)
    return res


def parse_openvas(aid: str, xml_text: str, ev_id: str) -> AdapterResult:
    res = AdapterResult()
    root = ET.fromstring(xml_text)
    for r in root.iter("result"):
        host = _t(r, "host").split("\n")[0].strip()
        pm = re.match(r"(\d+)/(\w+)", _t(r, "port"))
        port, proto = (int(pm.group(1)), pm.group(2)) if pm else (None, "tcp")
        nvt = r.find("nvt")
        if nvt is None:
            continue
        threat = _t(r, "threat").lower()
        sev = {"log": "info", "low": "low", "medium": "medium", "high": "high", "critical": "critical"}.get(threat, "info")
        if sev == "info":
            continue
        refs = " ".join((x.get("id", "") for x in nvt.iter("ref") if x.get("type", "").lower() == "cve"))
        cves = sorted({c.upper() for c in CVE_RX.findall(refs + " " + _t(nvt, "cve"))})
        score = _f(_t(nvt, "cvss_base")) or _f(_t(r, "severity"))
        res.findings.append(mk_finding(
            aid, "openvas", "import", ev_id, title=_t(r, "name") or _t(nvt, "name"), asset=Asset(host=host, port=port, protocol=proto),
            severity=sev, description=_t(r, "description")[:900], cve=cves, cvss=score, rule_id=f"openvas:{nvt.get('oid', '')}",
            remediation=_t(nvt, "solution")[:500]))
    return res


class _ImportAdapter(Adapter):
    mode, status = "import", "import-only"
    parser = None

    def ingest(self, aid: str, filename: str, content: bytes, job_id: str | None = None) -> AdapterResult:
        path, sha = runner.save_artifact(aid, f"{self.name}_{filename}", content)
        ev = runner.new_evidence(aid, self.name, "import", job_id, path, sha, "file", f"imported file {filename}")
        text = content.decode("utf-8", "replace")
        try:
            res = self.parser(aid, text, ev.id)
        except ET.ParseError as ex:
            raise ValueError(f"{self.name} import: file is not valid XML ({ex})")
        res.evidence.append(ev)
        return res


class NessusAdapter(_ImportAdapter):
    name = "nessus"
    parser = staticmethod(parse_nessus)
    description = "Imports .nessus (v2) exports. Does NOT call the Nessus API."
    limitations = "Commercial product; live API integration is not implemented or claimed. Informational plugins are treated as context."


class BurpAdapter(_ImportAdapter):
    name = "burp"
    parser = staticmethod(parse_burp)
    description = "Imports Burp Suite 'issues' XML exports."
    limitations = "Burp Community has no scanner export/API; Burp Pro REST API integration is Planned, not implemented."


class OpenVasAdapter(_ImportAdapter):
    name = "openvas"
    parser = staticmethod(parse_openvas)
    description = "Imports OpenVAS / Greenbone report XML (GMP get_reports format)."
    limitations = "Live GMP integration is Planned (Greenbone community feed sync is heavy); import is supported."
