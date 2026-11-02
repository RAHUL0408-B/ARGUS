"""Metasploit adapter: HUMAN-APPROVED, lab-only, allow-listed non-exploit modules. Never autonomous.

Only modules in ALLOWED_MODULES can be executed, and only for a recorded, approved Approval.
There are deliberately no exploit/* modules and no payload handling in this adapter.
"""
from __future__ import annotations
import re
from .. import config, runner
from ..models import Asset, Job
from .base import Adapter, AdapterResult, mk_finding

ALLOWED_MODULES = {
    "auxiliary/scanner/http/http_version": "Identify the HTTP server version (read-only)",
    "auxiliary/scanner/http/http_header": "Read HTTP response headers (read-only)",
    "auxiliary/scanner/http/options": "Enumerate allowed HTTP methods (read-only)",
    "auxiliary/scanner/http/robots_txt": "Fetch robots.txt (read-only)",
    "auxiliary/scanner/ftp/ftp_version": "Read FTP banner (read-only)",
    "auxiliary/scanner/ssh/ssh_version": "Read SSH banner (read-only)",
}


class MetasploitAdapter(Adapter):
    name, mode, status = "metasploit", "live", "live"
    description = "Approval-gated validation using allow-listed read-only auxiliary modules via msfconsole in Docker."
    limitations = ("Requires the metasploit-framework Docker image (large) and an approved action. Exploit modules are NOT supported "
                   "by design. Not autonomous.")

    def available(self):
        if not runner.docker_available():
            return False, "Docker is not available"
        import subprocess
        r = subprocess.run(["docker", "image", "inspect", config.MSF_IMAGE], capture_output=True)
        return (r.returncode == 0, "ok" if r.returncode == 0 else f"image {config.MSF_IMAGE} not pulled")

    @staticmethod
    def validate_request(module: str) -> None:
        if module not in ALLOWED_MODULES:
            raise PermissionError(f"module '{module}' is not on the ARGUS allow-list (only read-only auxiliary modules are permitted)")

    def run(self, aid: str, job: Job, module: str, rhost: str, rport: int = 80, timeout: int = 180) -> AdapterResult:
        self.validate_request(module)
        ok, msg = self.available()
        if not ok:
            raise runner.ToolUnavailable(msg)
        argv = ["docker", "run", "--rm", "--network", config.LAB_NETWORK, config.MSF_IMAGE, "msfconsole", "-q", "-x",
                f"use {module}; set RHOSTS {rhost}; set RPORT {rport}; run; exit"]
        code, out, err = runner.run_command(job, argv, timeout=timeout)
        path, sha = runner.save_artifact(aid, f"{job.id}_msf.txt", out + ("\n--stderr--\n" + err if err else ""))
        ev = runner.new_evidence(aid, "metasploit", "live", job.id, path, sha, "stdout", " ".join(argv[-1:]))
        res = AdapterResult(evidence=[ev])
        res.notes.append("\n".join(l for l in out.splitlines() if l.strip().startswith(("[+]", "[*]", "[-]")))[:800])
        runner.finish_ok(job, ev.id)
        return res
