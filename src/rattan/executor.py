"""Invocation builder + bwrap spawn + structured return (foreground path).

Parses the command, expands argv, validates redirects, resolves the policy,
assembles the bwrap argv, and runs it via ``subprocess.Popen``.
"""

from __future__ import annotations

import os
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from rattan import bwrap, overlay, parser, policy, redirects
from rattan.config import base_rootfs_path
from rattan.layers import Session
from rattan.parser import (
    AndOrNode,
    CommandNode,
    ParseError,
    PipelineNode,
    ProgramNode,
    Word,
)
from rattan.policy import ResolvedPolicy, resolve, resolve_pipeline, stage3_env
from rattan.redirects import FdDefaults, FdPlan, RedirectPlan


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Invocation:
    """A fully-resolved command invocation ready to spawn."""
    bwrap_argv: list[str]
    env: dict[str, str]
    cwd: str
    fd_plan: FdPlan
    timeout: float
    command: str  # the raw command string (for structured return)


class InvocationError(Exception):
    """Raised when an invocation cannot be built (parse / policy / validation)."""
    pass


class EmptyInvocation(Exception):
    """Raised when the command produces no executable units (e.g. empty)."""
    pass


# ---------------------------------------------------------------------------
# Build invocation
# ---------------------------------------------------------------------------


def _validate_cwd(cwd: str):
    """Ensure *cwd* is inside /workspace (or /tmp)."""
    from rattan.contain import validate_cwd as _vc
    try:
        _vc(cwd)
    except ValueError as e:
        raise InvocationError(str(e))


def _resolve_argv(
    cmd: CommandNode,
    env_store: dict[str, str],
) -> list[str]:
    """Expand the command's argv words against *env_store*."""
    result: list[str] = []
    for w in cmd.argv:
        expanded = w.expand(env_store)
        if expanded:
            result.append(expanded)
    return result


def _copy_env_with_assignments(
    cmd: CommandNode,
    base_env: dict[str, str],
) -> dict[str, str]:
    """Return a new env dict with per-command assignment prefixes applied."""
    if not cmd.assignments:
        return dict(base_env)
    new_env = dict(base_env)
    for var, val in cmd.assignments:
        new_env[var] = val
    return new_env


# Env var prefixes that the agent must NEVER control. stage3 reads RATTAN_* via
# getenv() to decide seccomp/pledge/rlimits — a user `VAR=val cmd` assignment
# could set `RATTAN_ALLOW_PTRACE=1` and disable seccomp entirely (invariant #10
# bypass). LD_*/DYLD_*/PYTHON* are classic loader/execution hijack vectors.
_CONTROL_ENV_PREFIXES = (
    "RATTAN_",
    "LD_",
    "DYLD_",
    "PYTHON",
    "PERL5OPT",
    "PERLLIB",
    "BASH_ENV",
    "ENV",
    "IFS",
)


def _scrub_control_env(env: dict[str, str]) -> dict[str, str]:
    """Return *env* with every control-prefixed key removed."""
    return {k: v for k, v in env.items() if not k.startswith(_CONTROL_ENV_PREFIXES)}


# Minimal environment for bwrap subprocesses. The container process and
# stage3's execvp need PATH/HOME/etc; the host's ``os.environ`` (even scrubbed)
# leaks ~50 unrelated keys and buys nothing for the unprivileged uid-1000
# container. ``inv.env`` carries the stage3 vars + per-command assignments on
# top of this base (see :func:`build_invocation`).
MINIMAL_CONTAINER_ENV: dict[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "HOME": "/workspace",
    "USER": "rattan",
    "TERM": "dumb",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


def _build_subprocess_env(inv_env: dict[str, str]) -> dict[str, str]:
    """Merge the minimal container env with *inv_env* (stage3 + user vars).

    Used for every bwrap subprocess so the host environment is never leaked
    into the container.
    """
    env = dict(MINIMAL_CONTAINER_ENV)
    env.update(inv_env)
    return env


# ---------------------------------------------------------------------------
# Optional timing diagnostic (RATTAN_TIMING=1)
# ---------------------------------------------------------------------------

_TIMING = os.environ.get("RATTAN_TIMING") == "1"


def _timing_log(msg: str) -> None:
    """Emit a timing line to stderr when ``RATTAN_TIMING=1`` (else a no-op).

    Opt-in and zero-cost when unset: the per-stage ``perf_counter`` calls are
    guarded by ``_TIMING``, so the hot path does no extra work by default.
    """
    if _TIMING:
        print(f"[rattan-timing] {msg}", file=sys.stderr, flush=True)


def build_invocation(
    cmd_node: CommandNode,
    session: Session,
    env_store: dict[str, str],
    cwd: str,
    timeout: float,
    *,
    extra_lowers: list[str] | None = None,
    upper: str | None = None,
    work: str | None = None,
) -> Invocation:
    """Build an :class:`Invocation` from a parsed :class:`CommandNode`.

    Args:
        cmd_node: Parsed single command.
        session: The active session.
        env_store: Environment variables available for ``$VAR`` expansion.
        cwd: Container working directory (must be under ``/workspace``).
        timeout: Per-command timeout in seconds.
        extra_lowers: Additional ``--overlay-src`` lower dirs (bg snapshots).
        upper/work: Override overlay upper/work dirs (bg private upper/work).
    """
    _validate_cwd(cwd)

    # Apply per-command assignments
    cmd_env = _copy_env_with_assignments(cmd_node, env_store)

    # Expand argv
    user_argv = _resolve_argv(cmd_node, cmd_env)
    if not user_argv:
        raise EmptyInvocation("command has no executable words")

    # Build fd plan from redirects
    rp = RedirectPlan(specs=cmd_node.redirects)
    fd_plan = rp.apply(FdDefaults(), base=cwd)

    # Resolve container paths to host paths, create /tmp temp files
    _resolve_fd_plan_host(fd_plan, session)

    # Resolve policy
    command_str = " ".join(user_argv)
    resolved = resolve(command_str, mode="agent")

    # Session host binds (from bind_host_dir)
    from rattan.bind import get_session_binds
    sb = get_session_binds(session.sid)
    extra_binds = sb.bwrap_bind_argv() if sb.binds else []
    # Append any /tmp bind fragments from the fd plan
    for bind_triple in fd_plan.extra_binds:
        extra_binds.extend(bind_triple)
    extra_landlock = sb.landlock_extra() if sb.binds else None

    # Build bwrap argv
    bwrap_argv = bwrap.agent_argv(
        session, resolved, user_argv, cwd=cwd,
        extra_binds=extra_binds, extra_landlock=extra_landlock,
        extra_lowers=extra_lowers, upper=upper, work=work,
    )

    # Build env for subprocess (stage3 env vars). Scrub control-prefixed vars
    # so the agent can never set RATTAN_* / LD_* etc (invariant #10, C-1).
    sub_env = _scrub_control_env(cmd_env)
    sub_env.update(stage3_env(resolved))

    return Invocation(
        bwrap_argv=bwrap_argv,
        env=sub_env,
        cwd="/",  # bwrap handles chdir internally
        fd_plan=fd_plan,
        timeout=timeout,
        command=command_str,
    )


def _render_command(cmd: CommandNode, env_store: dict[str, str]) -> str:
    """Render a :class:`CommandNode` back into a shell command string.

    Used to build the ``/bin/sh -c`` payload for a multi-command pipeline, which
    is executed inside a SINGLE sandbox (one overlay mount). Words are expanded
    against *env_store* and shell-quoted; assignment prefixes and redirects are
    reconstructed.
    """
    parts: list[str] = []

    for var, val in cmd.assignments:
        parts.append(f"{var}={shlex.quote(val)}")

    words = _resolve_argv(cmd, env_store)
    parts.extend(shlex.quote(w) for w in words)

    # Redirects: reconstruct fd/op/target.
    for r in cmd.redirects:
        if r.op in ("1>&2", "2>&1"):
            parts.append(r.op)
        else:
            fd = "" if r.fd is None else str(r.fd)
            parts.append(f"{fd}{r.op} {shlex.quote(r.target)}")

    return " ".join(parts)


def build_pipeline_invocation(
    pipeline: PipelineNode,
    session: Session,
    env_store: dict[str, str],
    cwd: str,
    timeout: float,
) -> Invocation:
    """Build a SINGLE :class:`Invocation` that runs a multi-command pipeline.

    A two-command pipeline (``a | b``) cannot run as two separate bwrap mounts
    because only one overlay may mount a given upperdir+workdir pair at a time.
    Instead the whole pipeline is run inside one sandbox via
    ``/bin/sh -c '<a> | <b>'``; the shell performs the pipe. The seccomp/Landlock
    policy is the union of every stage's policy (see :func:`resolve_pipeline`).

    Redirects on the pipeline as a whole are handled by the shell within the
    sandbox, so no host-side fd plan is built here.
    """
    _validate_cwd(cwd)

    command_strings: list[str] = []
    rendered: list[str] = []
    for cmd in pipeline.commands:
        argv = _resolve_argv(cmd, env_store)
        if not argv:
            raise EmptyInvocation("pipeline command has no executable words")
        cs = " ".join(argv)
        command_strings.append(cs)
        rendered.append(_render_command(cmd, env_store))

    shell_payload = " | ".join(rendered)
    user_argv = ["/bin/sh", "-c", shell_payload]

    resolved = resolve_pipeline(command_strings, mode="agent")

    # Session host binds (from bind_host_dir)
    from rattan.bind import get_session_binds
    sb = get_session_binds(session.sid)
    extra_binds = sb.bwrap_bind_argv() if sb.binds else []
    extra_landlock = sb.landlock_extra() if sb.binds else None

    bwrap_argv = bwrap.agent_argv(
        session, resolved, user_argv, cwd=cwd,
        extra_binds=extra_binds, extra_landlock=extra_landlock,
    )

    sub_env = _scrub_control_env(env_store)
    sub_env.update(stage3_env(resolved))

    return Invocation(
        bwrap_argv=bwrap_argv,
        env=sub_env,
        cwd="/",
        fd_plan=FdPlan(),
        timeout=timeout,
        command=" | ".join(command_strings),
    )


# ---------------------------------------------------------------------------
# Host-side redirect resolution
# ---------------------------------------------------------------------------


def _resolve_fd_plan_host(fd_plan, session) -> None:
    """Populate ``host_stdin``/``host_stdout``/``host_stderr`` on *fd_plan*.

    Maps a container redirect target to a host filesystem path:
    * a bind mount point (``bind_host_dir``) → ``<host_path>/<rel>``. For a
      **write** redirect into a ``ro`` bind this is denied (``InvocationError``):
      the fd would be opened by the host-side parent, which can write the host
      dir directly and would otherwise bypass the ``--ro-bind``. Read redirects
      into ``ro`` binds are allowed.
    * ``/workspace/*`` → ``<session.workspace>/*`` (host-backed overlay upper).
    * ``/tmp/*`` → a fresh host temp file (via ``mkstemp``) plus a ``--bind``
      entry in ``fd_plan.extra_binds`` so the temp file is visible inside the
      container at the expected ``/tmp/*`` path.

    The container path has already been validated by :meth:`RedirectPlan.apply`;
    we only need to determine which root it falls under. Bind mounts shadow
    ``/workspace``/``/tmp``, so they are checked first.
    """
    from rattan.bind import get_session_binds
    binds = get_session_binds(session.sid).binds

    def _bind_host(container: str):
        """Return ``(host_path, mode)`` if *container* is under a bind mount."""
        norm = os.path.normpath(container)
        for b in binds:
            mp = os.path.normpath(b.mount_point)
            if norm == mp or norm.startswith(mp + os.sep):
                rel = os.path.relpath(norm, mp)
                return os.path.join(b.host_path, rel), b.mode
        return None

    def _host_for(container: str, write: bool):
        """Resolve *container* to a host path; raise if *write* into a ro bind."""
        norm = os.path.normpath(container)
        bt = _bind_host(norm)
        if bt is not None:
            host, mode = bt
            if write and mode == "ro":
                raise InvocationError(
                    f"cannot write redirect target {container!r}: "
                    f"bound read-only ({host!r})"
                )
            return host
        # /workspace — mapped to the session workspace dir on the host
        if norm == "/workspace" or norm.startswith("/workspace" + os.sep):
            rel = os.path.relpath(norm, "/workspace")
            return os.path.join(session.workspace, rel)
        # /tmp — create a host temp file and bind it in
        if norm == "/tmp" or norm.startswith("/tmp" + os.sep):
            fd, host_path = tempfile.mkstemp(prefix="rattan-redir-")
            os.close(fd)
            fd_plan.cleanup_paths.append(host_path)
            # bind host file -> container /tmp/<rel>
            rel = os.path.relpath(norm, "/tmp")
            fd_plan.extra_binds.append(["--bind", host_path, os.path.join("/tmp", rel)])
            return host_path
        return None  # should not happen (validated already)

    if fd_plan.stdin:
        fd_plan.host_stdin = _host_for(fd_plan.stdin, write=False)
    if fd_plan.stdout and not fd_plan.stdout.startswith("&"):
        fd_plan.host_stdout = _host_for(fd_plan.stdout, write=True)
    if fd_plan.stderr and not fd_plan.stderr.startswith("&"):
        fd_plan.host_stderr = _host_for(fd_plan.stderr, write=True)


def _spawn_kwargs(fd_plan) -> tuple[dict, list]:
    """Return ``(Popen kwargs, list of opened file objects to close)``.

    The returned dict contains ``stdin``, ``stdout``, ``stderr`` keys (only the
    non-default ones; ``stdin`` is omitted when no redirect, ``stdout`` defaults
    to ``subprocess.PIPE``, ``stderr`` defaults to ``subprocess.STDOUT``).

    Merge redirects (``1>&2``, ``2>&1``) are resolved against any file-target
    redirect that is already set for the other fd.
    """
    kwargs: dict = {}
    opened: list = []

    def _makedirs(path):
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)

    # stdin
    if fd_plan.host_stdin:
        kwargs["stdin"] = open(fd_plan.host_stdin, "rb")
        opened.append(kwargs["stdin"])

    # stdout
    if fd_plan.host_stdout:
        _makedirs(fd_plan.host_stdout)
        kwargs["stdout"] = open(
            fd_plan.host_stdout, "ab" if fd_plan.stdout_append else "wb"
        )
        opened.append(kwargs["stdout"])
    else:
        kwargs["stdout"] = subprocess.PIPE

    # stderr
    if fd_plan.stderr == "&1":
        # 2>&1 — stderr goes wherever stdout goes
        kwargs["stderr"] = kwargs["stdout"] if fd_plan.host_stdout else subprocess.STDOUT
    elif fd_plan.stdout == "&2":
        # 1>&2 — stdout goes wherever stderr goes
        if fd_plan.host_stderr:
            _makedirs(fd_plan.host_stderr)
            f = open(fd_plan.host_stderr, "ab" if fd_plan.stderr_append else "wb")
            opened.append(f)
            kwargs["stdout"] = f
            kwargs["stderr"] = f
        else:
            kwargs["stdout"] = subprocess.PIPE
            kwargs["stderr"] = subprocess.STDOUT
    elif fd_plan.host_stderr:
        _makedirs(fd_plan.host_stderr)
        kwargs["stderr"] = open(
            fd_plan.host_stderr, "ab" if fd_plan.stderr_append else "wb"
        )
        opened.append(kwargs["stderr"])
    else:
        kwargs["stderr"] = subprocess.STDOUT

    return kwargs, opened


# ---------------------------------------------------------------------------
# Run command
# ---------------------------------------------------------------------------


# Per-overlay-upper mount locks. Consecutive foreground commands mount the same
# session upper/work; holding this lock across the spawn+communicate cycle
# serializes those mounts so a new command never races a prior command's
# namespace teardown (btrfs ``EBUSY``). Background jobs use private upper/work
# and never pass through :func:`run_command`, so they are unaffected. The dict
# is keyed by upperdir path (one lock per session) and grows by one entry per
# session lifetime — bounded by the number of sessions in a server run.
_overlay_locks: dict[str, threading.Lock] = {}
_overlay_locks_guard = threading.Lock()


def _overlay_mount_lock(upper: str) -> threading.Lock:
    """Return (creating if needed) the mount lock for overlay *upper* dir."""
    with _overlay_locks_guard:
        lock = _overlay_locks.get(upper)
        if lock is None:
            lock = threading.Lock()
            _overlay_locks[upper] = lock
        return lock


def _overlay_upper(inv: Invocation) -> str:
    """Return the overlay upper dir from *inv*'s bwrap argv (the lock key).

    ``bwrap.agent_argv`` always emits ``--overlay <upper> <work> <dest>``, so
    the token following ``--overlay`` is the upper path. Returns ``""`` if the
    argv has no overlay mount (shouldn't happen on the foreground path).
    """
    try:
        return inv.bwrap_argv[inv.bwrap_argv.index("--overlay") + 1]
    except (ValueError, IndexError):
        return ""


def run_command(inv: Invocation) -> dict:
    """Spawn *inv* as a foreground bwrap subprocess and return structured output.

    Returns a dict with keys ``command``, ``output``, ``rc``.
    On timeout the process group is killed with ``SIGKILL``.

    On btrfs the previous command's overlay mount namespace teardown can race
    with the next ``--overlay`` mount reusing the same upperdir+workdir, so
    bwrap occasionally exits with ``EBUSY`` ("Device or resource busy"). We
    serialize consecutive mounts of the same upper via a per-session lock so a
    new command waits for the prior one to finish, and keep a short bounded
    retry as a safety net for the residual teardown lag after process exit.
    """
    _EBUSY = "Device or resource busy"
    max_attempts = 5
    backoff = 0.1

    def _attempt():
        try:
            spawn_kwargs, opened = _spawn_kwargs(inv.fd_plan)
        except (OSError, IOError) as e:
            for p in inv.fd_plan.cleanup_paths:
                try:
                    os.unlink(p)
                except OSError:
                    pass
            return {"command": inv.command, "output": f"redirect error: {e}", "rc": 1}

        try:
            t_popen = time.perf_counter() if _TIMING else 0.0
            proc = subprocess.Popen(
                inv.bwrap_argv,
                env=_build_subprocess_env(inv.env),
                start_new_session=True,
                **spawn_kwargs,
            )
            if _TIMING:
                _timing_log(
                    f"popen_ms={(time.perf_counter() - t_popen) * 1000:.2f} "
                    f"cmd={inv.command!r}"
                )
        except (OSError, IOError) as e:
            for f in opened:
                try:
                    f.close()
                except OSError:
                    pass
            for p in inv.fd_plan.cleanup_paths:
                try:
                    os.unlink(p)
                except OSError:
                    pass
            return {"command": inv.command, "output": f"redirect error: {e}", "rc": 1}

        try:
            t_comm = time.perf_counter() if _TIMING else 0.0
            out_bytes, _ = proc.communicate(timeout=inv.timeout)
            if _TIMING:
                _timing_log(
                    f"communicate_ms={(time.perf_counter() - t_comm) * 1000:.2f} "
                    f"cmd={inv.command!r}"
                )
            rc = proc.returncode
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                out_bytes, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                out_bytes, _ = proc.communicate()
            rc = -1  # signal timeout
        finally:
            for f in opened:
                try:
                    f.close()
                except OSError:
                    pass
            for p in inv.fd_plan.cleanup_paths:
                try:
                    os.unlink(p)
                except OSError:
                    pass

        output = out_bytes.decode("utf-8", errors="replace") if out_bytes else ""
        return {"command": inv.command, "output": output, "rc": rc}

    def _run_with_retry():
        result = _attempt()
        for _ in range(max_attempts - 1):
            if result["rc"] != 1 or _EBUSY not in result["output"]:
                break
            time.sleep(backoff)
            result = _attempt()
        return result

    upper = _overlay_upper(inv)
    if not upper:
        return _run_with_retry()
    with _overlay_mount_lock(upper):
        return _run_with_retry()


# ---------------------------------------------------------------------------
# Execute pipeline / and-or
# ---------------------------------------------------------------------------


def execute_pipeline(
    pipeline: PipelineNode,
    session: Session,
    env_store: dict[str, str],
    cwd: str,
    timeout: float,
    command_str: str = "",
) -> dict:
    """Execute a single :class:`PipelineNode`.

    For single-command pipelines, runs directly.
    For two-command pipelines, the whole pipeline is run inside ONE sandbox via
    ``/bin/sh -c 'a | b'`` (a single overlay mount). Two separate bwrap mounts
    cannot share the same upperdir+workdir pair simultaneously, so running each
    stage as its own sandbox is impossible.
    """
    if len(pipeline.commands) == 0:
        raise EmptyInvocation("empty pipeline")

    if len(pipeline.commands) == 1:
        t_build = time.perf_counter() if _TIMING else 0.0
        inv = build_invocation(
            pipeline.commands[0], session, env_store, cwd, timeout
        )
        if _TIMING:
            _timing_log(f"build_ms={(time.perf_counter() - t_build) * 1000:.2f}")
        return run_command(inv)

    # Multi-command pipeline: single-sandbox execution via /bin/sh -c.
    t_build = time.perf_counter() if _TIMING else 0.0
    inv = build_pipeline_invocation(pipeline, session, env_store, cwd, timeout)
    if _TIMING:
        _timing_log(f"build_ms={(time.perf_counter() - t_build) * 1000:.2f}")
    result = run_command(inv)
    result["command"] = command_str or result["command"]
    return result


def _try_cd(pipeline: PipelineNode, env_store: dict[str, str], cur_cwd: str):
    """Handle a `cd` builtin if *pipeline* is a single `cd` command.

    Returns ``(new_cwd, stage_or_None)``:
    * ``(new_dir, stage)`` — pipeline was a valid ``cd``; *new_dir* is the
      resolved absolute container path (used for subsequent pipelines in the
      same and-or chain) and *stage* is the structured result to record.
    * ``(None, stage)`` — pipeline started with ``cd`` but was invalid; a
      failing stage is returned, the working directory is unchanged.
    * ``(None, None)`` — pipeline is not a ``cd`` command.

    ``cd`` is handled in-process (no bwrap subprocess): it only affects the
    working directory of *following* pipelines in the same command string
    (the ``cd X && command`` form). A bare ``cd`` has no lasting effect beyond
    the chain and does not touch the server's own cwd.
    """
    # Only a single-command pipeline can be a builtin.
    if len(pipeline.commands) != 1:
        return None, None
    cmd = pipeline.commands[0]
    argv = _resolve_argv(cmd, env_store)
    if not argv or argv[0] != "cd":
        return None, None

    from rattan.contain import validate_cwd

    args = argv[1:]
    if len(args) > 1:
        return None, {
            "command": " ".join(argv),
            "output": "cd: too many arguments",
            "rc": 1,
        }
    if not args or args[0] == "":
        # No $HOME concept in the sandbox; cd with no target is a no-op error.
        return None, {
            "command": "cd",
            "output": "cd: no directory",
            "rc": 1,
        }

    target = args[0]
    if not os.path.isabs(target):
        target = os.path.join(cur_cwd, target)
    target = os.path.normpath(target)
    try:
        resolved = validate_cwd(target)
    except ValueError as e:
        return None, {
            "command": "cd " + target,
            "output": f"cd: {e}",
            "rc": 1,
        }
    return resolved, {
        "command": "cd " + args[0],
        "output": "",
        "rc": 0,
    }


def execute_andor(
    andor: AndOrNode,
    session: Session,
    env_store: dict[str, str],
    cwd: str,
    timeout: float,
) -> dict:
    """Execute an :class:`AndOrNode` with short-circuit ``&&`` / ``||``.

    Returns a structured dict with ``stages``, ``skipped``, ``rc``, ``output``.

    A ``cd X`` pipeline updates the working directory for the remaining
    pipelines in the same chain (``cd X && command``), implemented as an
    in-process builtin — no bwrap subprocess and no shell routing.
    """
    stages: list[dict] = []
    last_rc = 0
    skipped = False
    cur_cwd = cwd

    for i, pipeline in enumerate(andor.pipelines):
        if i > 0:
            op = andor.ops[i - 1]
            if op == "&&" and last_rc != 0:
                skipped = True
                continue
            if op == "||" and last_rc == 0:
                skipped = True
                continue

        # `cd` builtin — updates cur_cwd for subsequent pipelines.
        new_cwd, cd_stage = _try_cd(pipeline, env_store, cur_cwd)
        if cd_stage is not None:
            stages.append(cd_stage)
            if new_cwd is not None:
                cur_cwd = new_cwd
            last_rc = cd_stage["rc"]
            continue

        result = execute_pipeline(
            pipeline, session, env_store, cur_cwd, timeout
        )
        stages.append(result)
        last_rc = result["rc"]

    # Build combined output
    combined_output = "\n".join(s["output"] for s in stages if s["output"])

    return {
        "rc": last_rc,
        "skipped": skipped,
        "stages": stages,
        "output": combined_output,
    }


def execute_program(
    program: ProgramNode,
    session: Session,
    env_store: dict[str, str],
    cwd: str,
    timeout: float,
) -> dict:
    """Execute a full :class:`ProgramNode` (semicolon-separated and-or lists)."""
    all_stages: list[dict] = []
    last_rc = 0
    skipped = False

    for andor in program.andors:
        result = execute_andor(andor, session, env_store, cwd, timeout)
        all_stages.extend(result["stages"])
        last_rc = result["rc"]
        if result["skipped"]:
            skipped = True

    combined_output = "\n".join(s["output"] for s in all_stages if s["output"])

    return {
        "rc": last_rc,
        "skipped": skipped,
        "stages": all_stages,
        "output": combined_output,
    }
