"""Invocation builder + bwrap spawn + structured return (foreground path).

Parses the command, expands argv, validates redirects, resolves the policy,
assembles the bwrap argv, and runs it via ``subprocess.Popen``.
"""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
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
from rattan.policy import ResolvedPolicy, resolve, stage3_env
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


def build_invocation(
    cmd_node: CommandNode,
    session: Session,
    env_store: dict[str, str],
    cwd: str,
    timeout: float,
) -> Invocation:
    """Build an :class:`Invocation` from a parsed :class:`CommandNode`.

    Args:
        cmd_node: Parsed single command.
        session: The active session.
        env_store: Environment variables available for ``$VAR`` expansion.
        cwd: Container working directory (must be under ``/workspace``).
        timeout: Per-command timeout in seconds.
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


def run_command(inv: Invocation) -> dict:
    """Spawn *inv* as a foreground bwrap subprocess and return structured output.

    Returns a dict with keys ``command``, ``output``, ``rc``.
    On timeout the process group is killed with ``SIGKILL``.
    """
    try:
        spawn_kwargs, opened = _spawn_kwargs(inv.fd_plan)
    except (OSError, IOError) as e:
        # Clean up any paths registered so far
        for p in inv.fd_plan.cleanup_paths:
            try:
                os.unlink(p)
            except OSError:
                pass
        return {"command": inv.command, "output": f"redirect error: {e}", "rc": 1}

    try:
        proc = subprocess.Popen(
            inv.bwrap_argv,
            env={**_scrub_control_env(os.environ), **inv.env},
            start_new_session=True,
            **spawn_kwargs,
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
        out_bytes, _ = proc.communicate(timeout=inv.timeout)
        rc = proc.returncode
    except subprocess.TimeoutExpired:
        # Kill the whole process group
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
        # Close any opened fd objects
        for f in opened:
            try:
                f.close()
            except OSError:
                pass
        # Remove temp files created for /tmp redirects
        for p in inv.fd_plan.cleanup_paths:
            try:
                os.unlink(p)
            except OSError:
                pass

    output = out_bytes.decode("utf-8", errors="replace") if out_bytes else ""

    return {
        "command": inv.command,
        "output": output,
        "rc": rc,
    }


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
    For two-command pipelines, pipes stdout of the first into stdin of the
    second and returns the combined result.
    """
    if len(pipeline.commands) == 0:
        raise EmptyInvocation("empty pipeline")

    if len(pipeline.commands) == 1:
        inv = build_invocation(
            pipeline.commands[0], session, env_store, cwd, timeout
        )
        return run_command(inv)

    # Two-command pipeline: pipe cmd0 stdout → cmd1 stdin
    cmd0 = pipeline.commands[0]
    cmd1 = pipeline.commands[1]

    inv0 = build_invocation(cmd0, session, env_store, cwd, timeout)
    inv1 = build_invocation(cmd1, session, env_store, cwd, timeout)

    # Build spawn kwargs for both commands
    try:
        kw0, opened0 = _spawn_kwargs(inv0.fd_plan)
        kw1, opened1 = _spawn_kwargs(inv1.fd_plan)
    except (OSError, IOError) as e:
        for plan in (inv0.fd_plan, inv1.fd_plan):
            for p in plan.cleanup_paths:
                try:
                    os.unlink(p)
                except OSError:
                    pass
        return {
            "command": command_str,
            "output": f"redirect error: {e}",
            "rc": 1,
        }

    all_opened = opened0 + opened1
    all_cleanup = inv0.fd_plan.cleanup_paths + inv1.fd_plan.cleanup_paths

    # cmd0: stdout must go to the pipe, keep stdin/stderr redirects
    kw0["stdout"] = subprocess.PIPE
    proc0 = subprocess.Popen(
        inv0.bwrap_argv,
        env={**_scrub_control_env(os.environ), **inv0.env},
        start_new_session=True,
        **kw0,
    )

    # cmd1: stdin comes from cmd0's stdout, keep stdout/stderr redirects
    kw1["stdin"] = proc0.stdout
    proc1 = subprocess.Popen(
        inv1.bwrap_argv,
        env={**_scrub_control_env(os.environ), **inv1.env},
        start_new_session=True,
        **kw1,
    )
    if proc0.stdout:
        proc0.stdout.close()

    try:
        out_bytes, _ = proc1.communicate(timeout=timeout)
        rc = proc1.returncode
        # Wait for proc0 too
        try:
            proc0.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc0.kill()
            proc0.wait()
    except subprocess.TimeoutExpired:
        for p in (proc0, proc1):
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            out_bytes, _ = proc1.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc1.kill()
            out_bytes, _ = proc1.communicate()
        rc = -1
    finally:
        for f in all_opened:
            try:
                f.close()
            except OSError:
                pass
        for p in all_cleanup:
            try:
                os.unlink(p)
            except OSError:
                pass

    output = out_bytes.decode("utf-8", errors="replace") if out_bytes else ""

    full_command = command_str or " | ".join(
        " ".join(w.expand(env_store) for w in cmd.argv)
        for cmd in pipeline.commands
    )

    return {
        "command": full_command,
        "output": output,
        "rc": rc,
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
    """
    stages: list[dict] = []
    last_rc = 0
    skipped = False

    for i, pipeline in enumerate(andor.pipelines):
        if i > 0:
            op = andor.ops[i - 1]
            if op == "&&" and last_rc != 0:
                skipped = True
                continue
            if op == "||" and last_rc == 0:
                skipped = True
                continue

        result = execute_pipeline(
            pipeline, session, env_store, cwd, timeout
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
