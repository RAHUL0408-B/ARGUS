"""Nikto adapter (LIVE, via the argus-tools container). Parses -Format json output."""
from __future__ import annotations
import json, uuid
from .. import runner
from ..models import Asset, Job
from .base import Adapter, AdapterResult, mk_finding


def parse_json(assessment_id: str, text: str, ev_id: str, base_url: str = "") -> AdapterResult:
    res = AdapterResult()
    try:
        data = json.loads(text)
    except json.JSONDecodeError as ex:
        res.notes.append(f"nikto JSON could not be parsed: {ex}")
        return res
    hosts = data if isinstance(data, list) else [data]
    for h in hosts:
        if not isinstance(h, dict):
            continue
        ip = h.get("ip") or h.get("host") or ""
        port = int(h.get("port") or 80)
        banner = h.get("banner") or h.get("server_banner") or ""
        for v in h.get("vulnerabilities", []) or []:
            msg = v.get("msg", "").strip()
            if not msg:
                continue
            url = v.get("url", "/")
            asset = Asset(host=ip, port=port, service="http", url=f"http://{ip}:{port}{url}")
            ml = msg.lower()
            sev = "low" if (any(k in ml for k in ("missing", "not present", "not set", "leaks", "outdated", "directory indexing", "is old"))
                            and "deprecated" not in ml) else "info"
            res.findings.append(mk_finding(
                assessment_id, "nikto", "live", ev_id, title=msg[:160], asset=asset, severity=sev, severity_source="derived from nikto message",
                description=f"Nikto test {v.get('id', '?')} ({v.get('method', 'GET')} {url}): {msg}" + (f" Server banner: {banner}." if banner else ""),
                rule_id=f"nikto:{v.get('id', '')}", references=[str(v["references"])] if v.get("references") else []))
    return res


class NiktoAdapter(Adapter):
    name, mode, status = "nikto", "live", "live"
    description = "Web server misconfiguration and known-file checks via Docker container."
    limitations = "Nikto reports no CVSS and no severity; ARGUS derives a coarse severity from the message and marks it as derived."

    def available(self):
        ok = runner.container_running("argus-tools")
        return ok, "ok" if ok else "argus-tools container not running (start the lab)"

    def run(self, aid: str, job: Job, url: str, timeout=240) -> AdapterResult:
        out_file = f"/tmp/nikto_{uuid.uuid4().hex[:8]}.json"
        argv = runner.in_tools("nikto", "-h", url, "-Format", "json", "-output", out_file, "-nointeractive", "-maxtime", "150s", "-Tuning", "1234bde")
        code, out, err = runner.run_command(job, argv, timeout=timeout)
        code2, text, err2 = runner.run_command(Job(id=job.id + "-read", assessment_id=aid, tool="nikto", kind="read", target=url),
                                               runner.in_tools("cat", out_file), timeout=30)
        runner.run_command(Job(id=job.id + "-rm", assessment_id=aid, tool="nikto", kind="cleanup", target=url),
                           runner.in_tools("rm", "-f", out_file), timeout=15)
        if not text.strip():
            job.status, job.error = "failed", (err or out or "nikto produced no JSON output")[:300]
            raise RuntimeError(job.error)
        path, sha = runner.save_artifact(aid, f"{job.id}_nikto.json", text)
        ev = runner.new_evidence(aid, "nikto", "live", job.id, path, sha, "$.vulnerabilities", job.command)
        res = parse_json(aid, text, ev.id, url)
        res.evidence.append(ev)
        runner.finish_ok(job, ev.id)
        return res
