"""FastMCP facade for rattan — the full M3 tool surface.

Registers:
- ``shell_run`` (foreground, structured return)
- ``env_status`` / ``env_reset`` / ``env_discard`` / ``env_commit`` /
  ``env_snapshot_list`` / ``env_rollback`` / ``env_gc``
- M3.7 shutdown sweep (atexit + SIGTERM)
- Startup gate (capabilities + validate_base_manifest + sessions GC)
"""

from __future__ import annotations

import atexit
import os
import signal
import sys
import time
from typing import Optional

from mcp.server.fastmcp import FastMCP

from rattan import capabilities, config, layers, sessions
from rattan.executor import InvocationError, EmptyInvocation, execute_program
from rattan.overlay import provision
from rattan.parser import parse, ParseError


# ---------------------------------------------------------------------------
# Startup gate
# ---------------------------------------------------------------------------


def _startup_gate():
    """Run startup checks: capabilities + base manifest + orphan GC sweep."""
    table = capabilities.get_capabilities()
    missing = table.missing_required()
    if missing:
        lines = ["Refusing to start rattan: missing required capabilities:"]
        for c in missing:
            rem = f" {c.remediation}" if c.remediation else ""
            lines.append(f"  - {c.name}: {c.detail}{rem}")
        raise RuntimeError("\n".join(lines))
    config.validate_base_manifest()
    _sweep_orphans()


# ---------------------------------------------------------------------------
# Shutdown sweep (M3.7)
# ---------------------------------------------------------------------------


def _sweep_orphans():
    """Remove sessions whose lockfile PID is dead (best-effort)."""
    sessions_d = config.sessions_dir()
    if not os.path.isdir(sessions_d):
        return
    for name in os.listdir(sessions_d):
        root = os.path.join(sessions_d, name)
        pid_path = os.path.join(root, "pid")
        try:
            with open(pid_path) as f:
                pid_s = f.read().strip()
            pid = int(pid_s)
            # Check if process is alive
            try:
                os.kill(pid, 0)
            except OSError:
                # Process is dead — clean up
                meta = layers.load_meta(root)
                stack = meta.get("stack", []) if meta else []
                try:
                    layers.destroy(
                        layers.Session(
                            sid=name,
                            root=root,
                            upper=os.path.join(root, "upper"),
                            work=os.path.join(root, "work"),
                            stack=stack,
                        )
                    )
                except Exception:
                    pass
        except (OSError, ValueError):
            pass


def _shutdown():
    """Shutdown handler: destroy the current session."""
    try:
        sessions.destroy_all_on_shutdown()
    except Exception:
        pass


def _setup_shutdown():
    """Register atexit + SIGTERM handlers."""
    atexit.register(_shutdown)
    signal.signal(signal.SIGTERM, lambda signum, frame: _shutdown() or sys.exit(0))


# ---------------------------------------------------------------------------
# Tool builders
# ---------------------------------------------------------------------------


def _build_tools(fastmcp: FastMCP):
    session = sessions.get_or_create()
    provision(session)

    @fastmcp.tool(
        description=(
            "Run a shell command inside the sandbox (foreground, agent mode). "
            "Returns {rc, skipped, stages: [{command, output, rc}], output}. "
            "If structured=False, returns just the combined output string."
        )
    )
    def shell_run(
        command: str,
        cwd: str = "/workspace",
        timeout: float = 30,
        structured: bool = True,
    ) -> dict | str:
        """Execute a command in the rattan sandbox."""
        nonlocal session
        if session is None:
            session = sessions.get_or_create()
            provision(session)

        try:
            program = parse(command)
        except ParseError as e:
            return {
                "rc": 1,
                "skipped": False,
                "stages": [{"command": command, "output": str(e), "rc": 1}],
                "output": str(e),
            }

        env_store = {
            "HOME": "/workspace",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "USER": "rattan",
            "TERM": "dumb",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }

        try:
            result = execute_program(
                program, session, env_store, cwd, timeout
            )
        except InvocationError as e:
            return {
                "rc": 1,
                "skipped": False,
                "stages": [{"command": command, "output": str(e), "rc": 1}],
                "output": str(e),
            }
        except EmptyInvocation:
            return {
                "rc": 0,
                "skipped": False,
                "stages": [],
                "output": "",
            }

        if not structured:
            return result["output"]
        return result

    # ---- environment management tools ----

    @fastmcp.tool(description="Report the sandbox environment status.")
    def env_status() -> dict:
        nonlocal session
        if session is None:
            session = sessions.get_or_create()
            provision(session)
        table = capabilities.get_capabilities()
        snapshots = layers.snapshot_list(session)
        return {
            "session": {
                "id": session.sid,
                "root": session.root,
            },
            "base_rootfs": {
                "path": config.base_rootfs_path(),
            },
            "layer_stack": [
                {
                    "commit_id": s.commit_id,
                    "message": s.message,
                    "created_at": s.created_at,
                    "size_bytes": s.size_bytes,
                }
                for s in snapshots
            ],
            "upperdir": {
                "size_bytes": layers.upper_size_bytes(session),
                "dirty_files": layers.dirty_file_count(session),
            },
            "network_policy": {
                "agent": "unshare-net (no network)",
                "provisioning": "share-net (M4)",
            },
            "capabilities": table.to_dict(),
        }

    @fastmcp.tool(
        description=(
            "Reset the sandbox: discard all uncommitted changes and start fresh. "
            "Keeps the committed layer stack."
        )
    )
    def env_reset() -> dict:
        nonlocal session
        if session is None:
            return {"status": "no active session"}
        layers.reset(session)
        return {"status": "reset", "session_id": session.sid}

    @fastmcp.tool(
        description=(
            "Discard all uncommitted changes (alias for env_reset)."
        )
    )
    def env_discard() -> dict:
        return env_reset()

    @fastmcp.tool(
        description=(
            "Commit the current upperdir changes as a new layer snapshot. "
            "Returns the new layer's metadata."
        )
    )
    def env_commit(message: str = "") -> dict:
        nonlocal session
        if session is None:
            return {"error": "no active session"}
        ref = layers.commit(session, message=message)
        return {
            "commit_id": ref.commit_id,
            "message": ref.message,
            "size_bytes": ref.size_bytes,
            "created_at": ref.created_at,
            "layer_count": len(session.stack),
        }

    @fastmcp.tool(
        description="List all committed layer snapshots for this session."
    )
    def env_snapshot_list() -> list[dict]:
        nonlocal session
        if session is None:
            return []
        snapshots = layers.snapshot_list(session)
        return [
            {
                "commit_id": s.commit_id,
                "message": s.message,
                "size_bytes": s.size_bytes,
                "created_at": s.created_at,
            }
            for s in snapshots
        ]

    @fastmcp.tool(
        description=(
            "Rollback the session to a specific commit. "
            "Discards current uncommitted changes and truncates the layer stack."
        )
    )
    def env_rollback(to_commit_id: str) -> dict:
        nonlocal session
        if session is None:
            return {"error": "no active session"}
        try:
            layers.rollback(session, to_commit_id)
        except ValueError as e:
            return {"error": str(e)}
        return {
            "status": "rolled back",
            "session_id": session.sid,
            "active_tip": session.stack[-1] if session.stack else None,
            "stack_depth": len(session.stack),
        }

    @fastmcp.tool(
        description="Run layer garbage collection. Removes unreferenced layers."
    )
    def env_gc() -> dict:
        removed = layers.gc()
        return {
            "removed": removed,
            "count": len(removed),
        }


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if "--probe" in args:
        return capabilities.cli_main(args)

    _startup_gate()
    _setup_shutdown()

    fastmcp = FastMCP("rattan")
    _build_tools(fastmcp)
    fastmcp.run()
    return 0
