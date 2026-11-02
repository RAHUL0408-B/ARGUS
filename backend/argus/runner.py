"""Job runner: executes tool commands with timeout, retry, cancellation, and raw-output preservation."""
from __future__ import annotations
import hashlib, subprocess, threading
from pathlib import Path
from typing import Optional
from . import config, store
from .models import Evidence, Job, now

_procs: dict[str, subprocess.Popen] = {}
_cancelled: set[str] = set()      # assessment ids
_plock = threading.Lock()


class ToolUnavailable(Exception):
    """Tool/container not reachable. Not retried: the agent records a coverage gap instead."""


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def save_artifact(assessment_id: str, name: str, data: bytes | str) -> tuple[Path, str]:
    d = config.ARTIFACT_DIR / assessment_id
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8", "replace"))
    return p, sha256_file(p)


def new_evidence(assessment_id: str, tool: str, mode: str, job_id: Optional[str], path: Path, sha: str,
                 locator: str = "", excerpt: str = "") -> Evidence:
    ev = Evidence(id=store.next_id("EV", "evidence", assessment_id, 4), assessment_id=assessment_id, tool=tool, mode=mode,
                  job_id=job_id, file_path=str(path.relative_to(config.DATA_DIR)).replace("\\", "/"), sha256=sha,
                  locator=locator, excerpt=excerpt[:600])
    store.put("evidence", ev)
    return ev


def cancel(assessment_id: str) -> None:
    """Kill switch: stop all running jobs for an assessment."""
    with _plock:
        _cancelled.add(assessment_id)
        for k, p in list(_procs.items()):
            if k.startswith(assessment_id + ":"):
                p.kill()


def clear_cancel(assessment_id: str) -> None:
    with _plock:
        _cancelled.discard(assessment_id)


def is_cancelled(assessment_id: str) -> bool:
    return assessment_id in _cancelled


def docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "info", "--format", "{{.ServerVersion}}"], capture_output=True, timeout=15)
        return r.returncode == 0
    except Exception:
        return False


def container_running(name: str) -> bool:
    try:
        r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", name], capture_output=True, text=True, timeout=15)
        return r.stdout.strip() == "true"
    except Exception:
        return False


def run_command(job: Job, argv: list[str], timeout: int = config.DEFAULT_TIMEOUT, retries: int = 1) -> tuple[int, str, str]:
    """Run argv, persist the Job state, return (exit_code, stdout, stderr). Raises ToolUnavailable/TimeoutError."""
    job.command = " ".join(argv)
    job.status, job.started_at = "running", now()
    store.put("job", job)
    store.event(job.assessment_id, "job", job.model_dump())
    last_err = ""
    for attempt in range(1, retries + 2):
        if is_cancelled(job.assessment_id):
            job.status, job.finished_at, job.error = "cancelled", now(), "cancelled by kill switch"
            store.put("job", job); store.event(job.assessment_id, "job", job.model_dump())
            raise InterruptedError("cancelled")
        job.attempts = attempt
        key = f"{job.assessment_id}:{job.id}"
        try:
            p = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with _plock:
                _procs[key] = p
            try:
                out, err = p.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                p.kill(); p.communicate()
                job.status, job.error, job.finished_at = "timeout", f"timed out after {timeout}s", now()
                store.put("job", job); store.event(job.assessment_id, "job", job.model_dump())
                raise TimeoutError(job.error)
            finally:
                with _plock:
                    _procs.pop(key, None)
            if is_cancelled(job.assessment_id):
                job.status, job.finished_at, job.error = "cancelled", now(), "cancelled by kill switch"
                store.put("job", job); store.event(job.assessment_id, "job", job.model_dump())
                raise InterruptedError("cancelled")
            job.exit_code = p.returncode
            o, e = out.decode("utf-8", "replace"), err.decode("utf-8", "replace")
            if p.returncode != 0 and ("No such container" in e or "is not running" in e or "Cannot connect to the Docker" in e):
                raise ToolUnavailable(e.strip()[:300])
            return p.returncode, o, e
        except FileNotFoundError as ex:
            job.status, job.error, job.finished_at = "failed", f"executable not found: {ex}", now()
            store.put("job", job); store.event(job.assessment_id, "job", job.model_dump())
            raise ToolUnavailable(str(ex))
        except ToolUnavailable as ex:
            job.status, job.error, job.finished_at = "failed", f"tool unavailable: {ex}", now()
            store.put("job", job); store.event(job.assessment_id, "job", job.model_dump())
            raise
        except (TimeoutError, InterruptedError):
            raise
        except Exception as ex:  # transient: retry once
            last_err = str(ex)
    job.status, job.error, job.finished_at = "failed", last_err, now()
    store.put("job", job); store.event(job.assessment_id, "job", job.model_dump())
    raise RuntimeError(last_err)


def in_tools(*argv: str) -> list[str]:
    return ["docker", "exec", config.TOOLS_CONTAINER, *argv]


def finish_ok(job: Job, evidence_id: Optional[str] = None) -> None:
    job.status, job.finished_at, job.evidence_id = "ok", now(), evidence_id
    store.put("job", job)
    store.event(job.assessment_id, "job", job.model_dump())
