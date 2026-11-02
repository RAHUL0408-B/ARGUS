"""Scope & policy guard. Deterministic code, no LLM. Default is DENY."""
from __future__ import annotations
import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse
from .models import INTENSITY, Scope


class ScopeViolation(Exception):
    pass


@dataclass
class Decision:
    allowed: bool
    reason: str
    needs_approval: bool = False


def _is_net(t: str) -> bool:
    try:
        ipaddress.ip_network(t, strict=False)
        return True
    except ValueError:
        return False


def host_of(target: str) -> str:
    t = target.strip()
    if "://" in t:
        return urlparse(t).hostname or ""
    if _is_net(t):
        return t.split("/")[0] if "/" not in t else t
    return t.split("/")[0].rsplit(":", 1)[0] if t.count(":") == 1 else t.split("/")[0]


def _matches(host: str, entry: str) -> bool:
    eh = host_of(entry)
    try:
        h_ip = ipaddress.ip_address(host)
    except ValueError:
        return host.lower() == eh.lower()
    try:
        return h_ip in ipaddress.ip_network(eh, strict=False)
    except ValueError:
        return False


def check_target(scope: Scope, target: str, port: Optional[int] = None) -> Decision:
    host = host_of(target)
    if not host:
        return Decision(False, f"cannot parse a host from '{target}'")
    # a CIDR target must be fully contained in an authorized network
    if "/" in host and _is_net(host):
        net = ipaddress.ip_network(host, strict=False)
        for ex in scope.exclusions:
            exn = host_of(ex)
            if _is_net(exn) and ipaddress.ip_network(exn, strict=False).overlaps(net):
                return Decision(False, f"{host} overlaps excluded range {ex}")
        ok = any(_is_net(host_of(t)) and net.subnet_of(ipaddress.ip_network(host_of(t), strict=False))
                 for t in scope.targets if "/" in host_of(t))
        return Decision(ok, f"{host} is within authorized scope" if ok else f"{host} is not fully inside the authorized scope {scope.targets}")
    for ex in scope.exclusions:
        if _matches(host, ex):
            return Decision(False, f"{host} is explicitly excluded ({ex})")
    if not any(_matches(host, t) for t in scope.targets):
        return Decision(False, f"{host} is not in the authorized scope {scope.targets}")
    if port is not None and scope.allowed_ports and port not in scope.allowed_ports:
        return Decision(False, f"port {port} is not in the allowed ports {scope.allowed_ports}")
    return Decision(True, f"{host} is within authorized scope")


def check_action(scope: Scope, tool: str, target: str, intensity: str = "standard", port: Optional[int] = None,
                 now_: Optional[datetime] = None) -> Decision:
    """Full policy check for one action. needs_approval is set for intrusive+ actions."""
    d = check_target(scope, target, port)
    if not d.allowed:
        return d
    if scope.allowed_tools and tool not in scope.allowed_tools:
        return Decision(False, f"tool '{tool}' is not permitted by this scope")
    if intensity not in INTENSITY:
        return Decision(False, f"unknown intensity '{intensity}'")
    if INTENSITY.index(intensity) > INTENSITY.index(scope.max_intensity) and intensity == "exploit":
        return Decision(False, f"'exploit' intensity exceeds the scope maximum '{scope.max_intensity}'")
    n = now_ or datetime.now(timezone.utc)
    for bound, late in ((scope.window_start, False), (scope.window_end, True)):
        if bound:
            b = datetime.fromisoformat(bound)
            b = b if b.tzinfo else b.replace(tzinfo=timezone.utc)
            if (n > b) if late else (n < b):
                return Decision(False, "outside the authorized testing window")
    needs = INTENSITY.index(intensity) >= INTENSITY.index("intrusive")
    return Decision(True, f"{tool}/{intensity} on {host_of(target)} allowed" + (" (human approval required)" if needs else ""), needs)


def enforce(scope: Scope, tool: str, target: str, intensity: str = "standard", port: Optional[int] = None) -> Decision:
    d = check_action(scope, tool, target, intensity, port)
    if not d.allowed:
        raise ScopeViolation(d.reason)
    return d
