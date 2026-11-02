"""OWASP ZAP adapter (LIVE, via ZAP daemon REST API). Spider + passive scan are 'standard'; active scan is 'intrusive'."""
from __future__ import annotations
import json, time
from urllib.parse import urlparse
import httpx
from .. import config, runner
from ..models import Asset, Job
from .base import Adapter, AdapterResult, mk_finding

RISK = {"Informational": "info", "Low": "low", "Medium": "medium", "High": "high"}


def parse_alerts(assessment_id: str, alerts: list[dict], ev_id: str) -> AdapterResult:
    res = AdapterResult()
    for a in alerts:
        u = urlparse(a.get("url", ""))
        port = u.port or (443 if u.scheme == "https" else 80)
        asset = Asset(host=u.hostname or "", port=port, service=u.scheme or "http", url=a.get("url", ""), parameter=a.get("param", ""))
        cwe = [f"CWE-{a['cweid']}"] if str(a.get("cweid", "-1")) not in ("-1", "0", "") else []
        ref = [r for r in (a.get("reference", "") or "").split("\n") if r.strip()]
        f = mk_finding(assessment_id, "zap", "live", ev_id, title=a.get("alert") or a.get("name", "ZAP alert"), asset=asset,
                       severity=RISK.get(a.get("risk", ""), "info"), description=(a.get("description", "") + (f"\nEvidence: {a['evidence']}" if a.get("evidence") else "")).strip(),
                       cwe=cwe, rule_id=f"zap:{a.get('pluginId', a.get('alertRef', ''))}", remediation=a.get("solution", ""), references=ref[:5])
        f.occurrences[0].tool_severity = a.get("risk", "")
        # ZAP's own confidence for the alert is preserved as a reason later in correlation
        f.confidence_reasons.append(f"zap-confidence:{a.get('confidence', 'unknown')}")
        res.findings.append(f)
    return res


class ZapAdapter(Adapter):
    name, mode, status = "zap", "live", "live"
    description = "Spider + passive scan (and approval-gated active scan) through the ZAP REST API."
    limitations = "Needs the argus-zap daemon. ZAP does not provide CVSS scores; none are fabricated."

    def _get(self, path: str, **params):
        # ZAP is also a proxy: the special host name 'zap' makes it treat the request as an API call.
        r = httpx.get(f"{config.ZAP_API}{path}", params=params, timeout=120, headers={"Host": "zap"})
        r.raise_for_status()
        return r.json()

    def available(self):
        try:
            v = self._get("/JSON/core/view/version/")
            return True, f"ZAP {v.get('version', '?')}"
        except Exception as ex:
            return False, f"ZAP API not reachable at {config.ZAP_API}: {ex.__class__.__name__}"

    def _wait(self, job: Job, check, timeout: int, label: str):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if runner.is_cancelled(job.assessment_id):
                raise InterruptedError("cancelled")
            try:
                if check():
                    return
            except httpx.TimeoutException:
                pass   # ZAP's API is slow while an active scan is running; keep polling until our own deadline
            time.sleep(3)
        raise TimeoutError(f"{label} did not finish within {timeout}s")

    def run(self, aid: str, job: Job, url: str, active: bool = False, timeout: int = 240) -> AdapterResult:
        from ..models import now
        job.status, job.started_at, job.command = "running", now(), f"ZAP API spider{'+active' if active else ''} {url}"
        from .. import store
        store.put("job", job); store.event(aid, "job", job.model_dump())
        try:
            ok, msg = self.available()
            if not ok:
                raise runner.ToolUnavailable(msg)
            sid = self._get("/JSON/spider/action/scan/", url=url, recurse="true", maxChildren="60")["scan"]
            self._wait(job, lambda: int(self._get("/JSON/spider/view/status/", scanId=sid)["status"]) >= 100, timeout, "spider")
            if active:
                self._get("/JSON/ascan/action/setOptionMaxScanDurationInMins/", Integer="4")   # cap: lab only, keeps demo bounded
                asid =self._get("/JSON/ascan/action/scan/", url=url, recurse="true")["scan"]
                self._wait(job, lambda: int(self._get("/JSON/ascan/view/status/", scanId=asid)["status"]) >= 100, timeout * 2, "active scan")
            self._wait(job, lambda: int(self._get("/JSON/pscan/view/recordsToScan/")["recordsToScan"]) == 0, 60, "passive scan")
            alerts = self._get("/JSON/core/view/alerts/", baseurl=url, start="0", count="500").get("alerts", [])
            urls = self._get("/JSON/core/view/urls/", baseurl=url).get("urls", [])
        except InterruptedError:
            job.status, job.error, job.finished_at = "cancelled", "cancelled by kill switch", now()
            store.put("job", job); store.event(aid, "job", job.model_dump()); raise
        except runner.ToolUnavailable as ex:
            job.status, job.error, job.finished_at = "failed", f"tool unavailable: {ex}", now()
            store.put("job", job); store.event(aid, "job", job.model_dump()); raise
        except TimeoutError as ex:
            job.status, job.error, job.finished_at = "timeout", str(ex), now()
            store.put("job", job); store.event(aid, "job", job.model_dump()); raise
        except Exception as ex:
            job.status, job.error, job.finished_at = "failed", f"{ex.__class__.__name__}: {ex}", now()
            store.put("job", job); store.event(aid, "job", job.model_dump()); raise RuntimeError(job.error)
        raw = json.dumps({"alerts": alerts, "urls": urls}, indent=1)
        path, sha = runner.save_artifact(aid, f"{job.id}_zap.json", raw)
        ev = runner.new_evidence(aid, "zap", "live", job.id, path, sha, "$.alerts", f"{len(alerts)} alerts, {len(urls)} URLs from {url}")
        res = parse_alerts(aid, alerts, ev.id)
        res.evidence.append(ev)
        res.notes.append(f"ZAP discovered {len(urls)} URLs" + ("; active scan was capped at 4 minutes, so coverage may be partial" if active else ""))
        runner.finish_ok(job, ev.id)
        return res
