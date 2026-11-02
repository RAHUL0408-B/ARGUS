"""Safe, standard-intensity validation: a single HTTP request from the tools container, no payloads.

Used to confirm or refute web configuration findings (false-positive triage) without human approval,
because it only reads what a browser would read.
"""
from __future__ import annotations
import re
from dataclasses import dataclass
from .. import runner
from ..models import Job


@dataclass
class Validation:
    verdict: str          # confirmed | refuted | inconclusive
    reason: str
    raw: str = ""


def fetch(aid: str, job: Job, url: str) -> tuple[str, str]:
    """GET url, return (raw headers+body-prefix text, status line)."""
    code, out, err = runner.run_command(job, runner.in_tools("curl", "-sS", "-i", "--max-time", "20", "--max-filesize", "200000", url), timeout=40)
    if code != 0 and not out:
        raise RuntimeError(f"curl failed: {(err or '')[:200]}")
    first = out.split("\n", 1)[0].strip()
    return out, first


def headers_of(raw: str) -> tuple[dict[str, list[str]], str]:
    head, _, body = raw.replace("\r\n", "\n").partition("\n\n")
    hs: dict[str, list[str]] = {}
    for line in head.split("\n")[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            hs.setdefault(k.strip().lower(), []).append(v.strip())
    return hs, body


def evaluate(issue_key: str, url: str, raw: str) -> Validation:
    hs, body = headers_of(raw)
    https = url.lower().startswith("https://")
    cookies = hs.get("set-cookie", [])
    if issue_key == "clickjacking":
        xfo = hs.get("x-frame-options")
        csp = " ".join(hs.get("content-security-policy", []))
        if xfo or "frame-ancestors" in csp:
            return Validation("refuted", f"The response carries clickjacking protection ({'X-Frame-Options: ' + xfo[0] if xfo else 'CSP frame-ancestors'}).", raw[:800])
        return Validation("confirmed", "Neither X-Frame-Options nor a CSP frame-ancestors directive is present in the response.", raw[:800])
    if issue_key == "missing-xcto":
        v = ",".join(hs.get("x-content-type-options", []))
        return Validation("refuted" if "nosniff" in v.lower() else "confirmed",
                          "X-Content-Type-Options: nosniff is present." if "nosniff" in v.lower() else "X-Content-Type-Options header is absent.", raw[:800])
    if issue_key == "missing-csp":
        return Validation("refuted" if "content-security-policy" in hs else "confirmed",
                          "Content-Security-Policy header is present." if "content-security-policy" in hs else "No Content-Security-Policy header in the response.", raw[:800])
    if issue_key == "missing-hsts":
        if not https:
            return Validation("refuted", "The service is plain HTTP. Browsers ignore Strict-Transport-Security on HTTP, so this check does not apply until HTTPS is enabled.", raw[:800])
        return Validation("refuted" if "strict-transport-security" in hs else "confirmed",
                          "HSTS header present." if "strict-transport-security" in hs else "HTTPS response lacks Strict-Transport-Security.", raw[:800])
    if issue_key == "server-disclosure":
        s = " ".join(hs.get("server", []) + hs.get("x-powered-by", []))
        if re.search(r"\d+\.\d+", s):
            return Validation("confirmed", f"Response discloses software version: '{s}'.", raw[:800])
        return Validation("refuted", f"Server header does not include a version number ('{s or 'absent'}').", raw[:800])
    if issue_key in ("cookie-httponly", "cookie-secure", "cookie-samesite"):
        if not cookies:
            return Validation("inconclusive", "This URL sets no cookie; the finding may refer to a different page or require a session.", raw[:800])
        flag = {"cookie-httponly": "httponly", "cookie-secure": "secure", "cookie-samesite": "samesite"}[issue_key]
        if issue_key == "cookie-secure" and not https:
            return Validation("inconclusive", "Cookies on plain HTTP cannot carry the Secure flag meaningfully; re-test once HTTPS is enabled.", raw[:800])
        missing = [c.split("=")[0] for c in cookies if flag not in c.lower()]
        if missing:
            return Validation("confirmed", f"Cookie(s) {', '.join(missing)} lack the {flag} attribute.", raw[:800])
        return Validation("refuted", f"All cookies carry the {flag} attribute.", raw[:800])
    if issue_key == "directory-listing":
        if re.search(r"<title>\s*index of /", body, re.I):
            return Validation("confirmed", "The response is an auto-generated directory index ('Index of /').", raw[:800])
        return Validation("refuted", "The response is not a directory index.", raw[:800])
    return Validation("inconclusive", "No safe automated check exists for this issue class; manual validation needed.", "")


VALIDATABLE = {"clickjacking", "missing-xcto", "missing-csp", "missing-hsts", "server-disclosure",
               "cookie-httponly", "cookie-secure", "cookie-samesite", "directory-listing"}
