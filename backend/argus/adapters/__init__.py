"""Adapter registry and the honest integration status matrix (served to the UI and printed in the report)."""
from .nmap import NmapAdapter
from .nikto import NiktoAdapter
from .zap import ZapAdapter
from .msf import MetasploitAdapter
from .imports import NessusAdapter, BurpAdapter, OpenVasAdapter

ADAPTERS = {a.name: a for a in (NmapAdapter(), NiktoAdapter(), ZapAdapter(), MetasploitAdapter(),
                                NessusAdapter(), BurpAdapter(), OpenVasAdapter())}


def matrix() -> list[dict]:
    """Live availability is probed so the matrix never claims more than the running system can do."""
    out = []
    for name in ("nmap", "nessus", "openvas", "nikto", "zap", "burp", "metasploit"):
        a = ADAPTERS[name]
        row = a.info()
        ok, msg = a.available()
        row["runtime"] = "ready" if ok else f"unavailable: {msg}"
        out.append(row)
    return out
