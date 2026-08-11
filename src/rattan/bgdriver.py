"""Detached driver for background jobs.

A background job runs the parsed command inside its own detached bwrap
subprocess. Because rattan's bwrap *is* the isolation (the MCP server is never
pledged), the driver is simply the launch of the bwrap agent argv with
``start_new_session=True`` and output redirected to a log file — there is no
separate intermediate Python process (unlike the prior project, which needed a
driver to escape a pledged parent). Each job gets a fresh bwrap namespace,
sharing the session upperdir.
"""

from __future__ import annotations

import os
import subprocess

from rattan import layers, parser
from rattan.executor import Invocation, build_invocation
from rattan.overlay import provision


def build_job_invocation(
    command: str,
    session: layers.Session,
    cwd: str,
    timeout: int,
    env_store: dict[str, str] | None = None,
) -> Invocation:
    """Build the :class:`Invocation` for a background job running *command*.

    Reuses ``executor.build_invocation`` on the first CommandNode of the parsed
    program, so argv expansion, redirect validation, policy resolution, and
    bwrap argv assembly are identical to the foreground path. Raises
    ``parser.ParseError`` on unparseable commands.
    """
    provision(session)
    program = parser.parse(command, env_store or {})
    if not program.andors or not program.andors[0].pipelines:
        raise ValueError("empty command")
    cmd_node = program.andors[0].pipelines[0].commands[0]
    return build_invocation(cmd_node, session, env_store or {}, cwd, timeout)


def launch_background_job(
    command: str,
    session: layers.Session,
    cwd: str,
    timeout: int,
    log_path: str,
    env_store: dict[str, str] | None = None,
):
    """Launch a background bwrap subprocess, returning (Popen, log_fh).

    ``log_path`` is where stdout+stderr are appended. The subprocess is
    detached (``start_new_session=True``) so it survives the MCP call that
    launched it.
    """
    inv = build_job_invocation(command, session, cwd, timeout, env_store)
    log_fh = open(log_path, "ab")
    popen = subprocess.Popen(
        inv.bwrap_argv,
        stdin=subprocess.DEVNULL,          # never consume the MCP stdio
        stdout=log_fh,
        stderr=subprocess.STDOUT,
        start_new_session=True,            # detached process group
        env={**os.environ, **inv.env},
    )
    return popen, log_fh
