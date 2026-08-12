"""Detached driver for background jobs.

A background job runs the parsed command inside its own detached bwrap
subprocess. Because rattan's bwrap *is* the isolation (the MCP server is never
pledged), the driver is simply the launch of the bwrap agent argv with
``start_new_session=True`` and output redirected to a log file — there is no
separate intermediate Python process (unlike the prior project, which needed a
driver to escape a pledged parent).

Concurrency model: only ONE live overlay may mount a given upperdir+workdir
pair at a time (kernel constraint), so a background job cannot share the
session's live upperdir with a concurrent foreground command. Instead each job
runs on its OWN private upperdir+workdir, layered over the session's committed
layer stack plus a reflink snapshot of the session's current upperdir. This lets
foreground commands and any number of background jobs run concurrently. The job
starts from a point-in-time snapshot of the session; its writes go to its
private upperdir and are NOT merged back into the live session (isolated job
semantics).
"""

from __future__ import annotations

import os
import subprocess
import uuid

from rattan import layers, parser
from rattan.executor import Invocation, _scrub_control_env, build_invocation
from rattan.overlay import provision


def _snapshot_upper(session: layers.Session, dest: str):
    """Reflink-copy the session's live upperdir into *dest* (a job private lower).

    The snapshot is cheap on btrfs/xfs (reflink) and captures the session state
    at job-start time so the background job sees a consistent view.
    """
    from rattan.layers import _copy_upper_to_layer
    os.makedirs(dest, exist_ok=True)
    _copy_upper_to_layer(session.upper, dest)


def _job_dirs(session: layers.Session) -> dict[str, str]:
    """Create and return the private upper/work/snapshot dirs for a bg job."""
    job_dir = os.path.join(session.root, "jobs", uuid.uuid4().hex[:12])
    upper = os.path.join(job_dir, "upper")
    work = os.path.join(job_dir, "work")
    snapshot = os.path.join(job_dir, "snapshot")
    os.makedirs(upper, exist_ok=True)
    os.makedirs(work, exist_ok=True)
    os.makedirs(os.path.join(upper, "workspace"), exist_ok=True)
    return {"root": job_dir, "upper": upper, "work": work, "snapshot": snapshot}


def build_job_invocation(
    command: str,
    session: layers.Session,
    cwd: str,
    timeout: int,
    env_store: dict[str, str] | None = None,
) -> Invocation:
    """Build the :class:`Invocation` for a background job running *command*.

    The job runs on a private upper/work layered over the committed stack plus a
    snapshot of the session's live upper, so it can overlap foreground commands.
    Reuses ``executor.build_invocation`` on the first CommandNode of the parsed
    program so argv expansion, redirect validation, policy resolution, and bwrap
    argv assembly are identical to the foreground path. Raises
    ``parser.ParseError`` on unparseable commands.

    The returned invocation's ``bwrap_argv`` mounts the job's private upper/work.
    """
    provision(session)
    program = parser.parse(command, env_store or {})
    if not program.andors or not program.andors[0].pipelines:
        raise ValueError("empty command")
    cmd_node = program.andors[0].pipelines[0].commands[0]

    dirs = _job_dirs(session)
    _snapshot_upper(session, dirs["snapshot"])

    return build_invocation(
        cmd_node, session, env_store or {}, cwd, timeout,
        extra_lowers=[dirs["snapshot"]],
        upper=dirs["upper"],
        work=dirs["work"],
    )


def launch_background_job(
    command: str,
    session: layers.Session,
    cwd: str,
    timeout: int,
    log_path: str,
    env_store: dict[str, str] | None = None,
):
    """Launch a background bwrap subprocess, returning (Popen, log_fh, job_root).

    ``log_path`` is where stdout+stderr are appended. The subprocess is
    detached (``start_new_session=True``) so it survives the MCP call that
    launched it. Returns the job's private root dir so the caller can clean it
    up when the job finishes.
    """
    inv = build_job_invocation(command, session, cwd, timeout, env_store)
    # The job root is the directory containing upper/work/snapshot; recover it
    # from the invocation's private upper path (<root>/upper).
    job_root = os.path.dirname(inv.bwrap_argv[inv.bwrap_argv.index("--overlay") + 1])
    log_fh = open(log_path, "ab")
    popen = subprocess.Popen(
        inv.bwrap_argv,
        stdin=subprocess.DEVNULL,          # never consume the MCP stdio
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        start_new_session=True,            # detached process group
        env={**_scrub_control_env(os.environ), **inv.env},
    )
    return popen, log_fh, job_root
