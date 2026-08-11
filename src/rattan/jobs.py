"""Background job registry + reaper thread.

Each background job is its own detached bwrap subprocess (``start_new_session=
True``) sharing the session upperdir. The job PID is the bwrap process. The
reaper polls the registry with ``Popen.poll()`` (not bare ``waitpid``) so exit
codes are captured and Popen objects prevent pid reuse.

Reaper discipline (carried from the prior project): register the Popen under
lock, then start the (idempotent) reaper thread.
"""

from __future__ import annotations

import os
import signal
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Optional


class JobStatus(str, Enum):
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELED = "canceled"


@dataclass
class JobRecord:
    job_id: int
    popen: object                 # the bwrap Popen (kept alive to avoid pid reuse)
    pid: int
    log_path: str
    command: str
    cwd: str
    started_at: float
    finished_at: Optional[float] = None
    status: JobStatus = JobStatus.RUNNING
    exit_code: Optional[int] = None
    output_preview: str = ""      # most recent tail, updated on poll


# Module-level registry
_JOBS: dict[int, JobRecord] = {}
_JOBS_LOCK = threading.Lock()
_JOB_COUNTER = 0
_JOB_COUNTER_LOCK = threading.Lock()
_REAPER_TICK = 1.0

# Reaper lifecycle
_reaper_lock = threading.Lock()
_reaper_started = False


def _ensure_reaper():
    """Start the reaper thread exactly once (idempotent)."""
    global _reaper_started
    with _reaper_lock:
        if _reaper_started:
            return
        _reaper_started = True

    def _reap():
        while True:
            try:
                with _JOBS_LOCK:
                    running_ids = [
                        jid for jid, rec in _JOBS.items()
                        if rec.status == JobStatus.RUNNING
                    ]
                for job_id in running_ids:
                    try:
                        _poll_job_now(job_id)
                    except Exception:
                        pass
            except Exception:
                pass
            time.sleep(_REAPER_TICK)

    t = threading.Thread(target=_reap, daemon=True)
    t.start()


def _poll_job_now(job_id: int):
    """Poll one running job, updating its status/exit_code/output."""
    with _JOBS_LOCK:
        rec = _JOBS.get(job_id)
        if rec is None or rec.status != JobStatus.RUNNING:
            return
        popen = rec.popen

    rc = popen.poll()
    if rc is None:
        # Still running — refresh output preview
        rec.output_preview = _tail_log(rec.log_path, 4096)
        return

    rec.exit_code = rc
    rec.finished_at = time.time()
    rec.output_preview = _tail_log(rec.log_path, 8192)
    rec.status = JobStatus.DONE if rc == 0 else JobStatus.FAILED


def _tail_log(log_path: str, nbytes: int) -> str:
    try:
        with open(log_path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            start = max(0, size - nbytes)
            f.seek(start)
            data = f.read()
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def start_job(
    command: str,
    cwd: str,
    popen,
    log_path: str,
    *,
    timeout: int = 300,
) -> int:
    """Register a background job and return its job_id.

    *popen* is the already-launched bwrap Popen. Registers under lock, starts
    the reaper, and returns the monotonically-allocated job_id.
    """
    global _JOB_COUNTER
    with _JOB_COUNTER_LOCK:
        _JOB_COUNTER += 1
        job_id = _JOB_COUNTER

    rec = JobRecord(
        job_id=job_id,
        popen=popen,
        pid=popen.pid,
        log_path=log_path,
        command=command,
        cwd=cwd,
        started_at=time.time(),
    )
    with _JOBS_LOCK:
        _JOBS[job_id] = rec

    _ensure_reaper()
    return job_id


def get_job(job_id: int) -> Optional[JobRecord]:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def job_status(job_id: int) -> dict:
    """Return status WITHOUT polling (read the registry)."""
    rec = get_job(job_id)
    if rec is None:
        return {"error": f"job {job_id} not found"}
    return {
        "job_id": job_id,
        "pid": rec.pid,
        "status": rec.status.value,
        "command": rec.command,
        "started_at": rec.started_at,
        "finished_at": rec.finished_at,
        "exit_code": rec.exit_code,
    }


def job_wait(job_id: int, wait_seconds: float = 30.0) -> dict:
    """Wait for a job to finish, polling inline (bounded ~55s)."""
    import time as _t

    deadline = _t.monotonic() + min(wait_seconds, 55.0)
    while _t.monotonic() < deadline:
        _poll_job_now(job_id)
        rec = get_job(job_id)
        if rec is None:
            return {"error": f"job {job_id} not found"}
        if rec.status != JobStatus.RUNNING:
            return job_status(job_id)
        _t.sleep(0.25)
    # Timed out — return current (running) status
    return job_status(job_id)


def job_output(job_id: int, tail_bytes: int = 8192) -> dict:
    """Return the job's log output (tail)."""
    rec = get_job(job_id)
    if rec is None:
        return {"error": f"job {job_id} not found"}
    _poll_job_now(job_id)
    return {
        "job_id": job_id,
        "status": rec.status.value,
        "output": _tail_log(rec.log_path, tail_bytes),
    }


def job_kill(job_id: int) -> dict:
    """Kill a running job (SIGTERM the bwrap process group)."""
    rec = get_job(job_id)
    if rec is None:
        return {"error": f"job {job_id} not found"}
    if rec.status != JobStatus.RUNNING:
        return {"job_id": job_id, "status": rec.status.value, "already_finished": True}
    try:
        os.killpg(rec.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            os.kill(rec.pid, signal.SIGTERM)
        except OSError:
            pass
    rec.status = JobStatus.CANCELED
    rec.exit_code = -signal.SIGTERM
    rec.finished_at = time.time()
    return {
        "job_id": job_id,
        "status": rec.status.value,
        "killed": True,
    }


def list_jobs() -> list[dict]:
    with _JOBS_LOCK:
        ids = list(_JOBS.keys())
    out = []
    for jid in ids:
        st = job_status(jid)
        if "error" not in st:
            out.append(st)
    out.sort(key=lambda d: d["job_id"])
    return out


def prune_finished() -> None:
    """Remove finished jobs from the registry (best-effort cleanup)."""
    with _JOBS_LOCK:
        finished = [
            jid for jid, rec in _JOBS.items()
            if rec.status != JobStatus.RUNNING
        ]
        for jid in finished:
            _JOBS.pop(jid, None)
