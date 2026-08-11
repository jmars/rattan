"""Invocation builder + bwrap spawn + structured return (foreground path).

Parses the command, expands argv, validates redirects, resolves the policy,
assembles the bwrap argv, and runs it via ``subprocess.Popen``.
"""

from __future__ import annotations

import os
import signal
import subprocess
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
    """Ensure *cwd* is inside /workspace."""
    norm = os.path.normpath(cwd)
    if not (norm == "/workspace" or norm.startswith("/workspace/")):
        raise InvocationError(
            f"cwd must be under /workspace, got {cwd!r}"
        )


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
    fd_plan = rp.apply(FdDefaults())

    # Resolve policy
    command_str = " ".join(user_argv)
    resolved = resolve(command_str, mode="agent")

    # Build bwrap argv
    bwrap_argv = bwrap.agent_argv(session, resolved, user_argv, cwd=cwd)

    # Build env for subprocess (stage3 env vars)
    sub_env = dict(cmd_env)
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
# Run command
# ---------------------------------------------------------------------------


def run_command(inv: Invocation) -> dict:
    """Spawn *inv* as a foreground bwrap subprocess and return structured output.

    Returns a dict with keys ``command``, ``output``, ``rc``.
    On timeout the process group is killed with ``SIGKILL``.
    """
    started = time.monotonic()
    proc = subprocess.Popen(
        inv.bwrap_argv,
        env={**os.environ, **inv.env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )

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

    proc0 = subprocess.Popen(
        inv0.bwrap_argv,
        env={**os.environ, **inv0.env},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    proc1 = subprocess.Popen(
        inv1.bwrap_argv,
        env={**os.environ, **inv1.env},
        stdin=proc0.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
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
