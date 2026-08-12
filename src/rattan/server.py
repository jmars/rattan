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

from rattan import capabilities, config, layers, pacman, sessions
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
        upper_size, upper_files = layers.upper_stats(session)
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
                "size_bytes": upper_size,
                "dirty_files": upper_files,
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

    @fastmcp.tool(
        description=(
            "Install one or more packages via pacman inside the container "
            "(provisioning mode: root-in-userns, network access). Packages land "
            "in the session upperdir and are visible to subsequent shell_run "
            "commands. They are lost on env_discard unless committed via "
            "env_commit. Set refresh=False to skip 'pacman -Sy'. Optionally "
            "specify a mirror URL (validated against an allowlist)."
        )
    )
    def pacman_install(
        packages: list[str],
        refresh: bool = True,
        mirror: str | None = None,
        timeout: float = 300,
    ) -> dict:
        try:
            return pacman.pacman_install(
                sessions.current(), packages,
                refresh=refresh, mirror=mirror, timeout=timeout,
            )
        except ValueError as e:
            return {"rc": 1, "command": "pacman -S", "output": str(e), "packages": []}

    @fastmcp.tool(
        description=(
            "Run a read-only pacman query inside the container (e.g. '-Q' list "
            "installed, '-Si pkg' show info, '-F file' search files). "
            "Provisioning mode, NO network."
        )
    )
    def pacman_run(
        args: list[str],
        timeout: float = 60,
    ) -> dict:
        return pacman.pacman_run(sessions.current(), args, timeout=timeout)

    # ---- Background jobs -------------------------------------------------

    @fastmcp.tool(
        description=(
            "Start a command as a detached background job inside the sandbox. "
            "Returns {job_id, pid, status}. Poll with shell_job_status, collect "
            "output with shell_job_output, wait with shell_job_wait."
        )
    )
    def shell_job_start(
        command: str,
        cwd: str = "/workspace",
        timeout: int = 300,
    ) -> dict:
        from rattan import bgdriver, jobs, layers

        s = sessions.current()
        if s is None:
            s = sessions.get_or_create()
        provision(s)
        log_dir = os.path.join(s.root, "logs")
        os.makedirs(log_dir, exist_ok=True)
        log_path = os.path.join(log_dir, f"job-{int(time.time() * 1000)}.log")
        try:
            popen, log_fh = bgdriver.launch_background_job(
                command, s, cwd, timeout, log_path,
            )
        except (ValueError, parser.ParseError, InvocationError) as e:
            return {"error": str(e)}
        # The child subprocess has its own fd via the fork; close the parent's
        # copy so we don't leak one fd per job for the server lifetime (M-3).
        try:
            job_id = jobs.start_job(command, cwd, popen, log_path, timeout=timeout)
        finally:
            log_fh.close()
        return {
            "job_id": job_id,
            "pid": popen.pid,
            "status": "running",
            "log_path": log_path,
        }

    @fastmcp.tool(description="Report the status of a background job (no polling).")
    def shell_job_status(job_id: int) -> dict:
        from rattan import jobs
        return jobs.job_status(job_id)

    @fastmcp.tool(
        description=(
            "Wait for a background job to finish (bounded ~55s). Returns final "
            "status + exit code."
        )
    )
    def shell_job_wait(job_id: int, wait_seconds: float = 30.0) -> dict:
        from rattan import jobs
        return jobs.job_wait(job_id, wait_seconds)

    @fastmcp.tool(
        description="Return the (tail of the) output log for a background job."
    )
    def shell_job_output(job_id: int, tail_bytes: int = 8192) -> dict:
        from rattan import jobs
        return jobs.job_output(job_id, tail_bytes)

    @fastmcp.tool(description="Kill a running background job.")
    def shell_job_kill(job_id: int) -> dict:
        from rattan import jobs
        return jobs.job_kill(job_id)

    @fastmcp.tool(description="List all background jobs.")
    def shell_job_list() -> list[dict]:
        from rattan import jobs
        return jobs.list_jobs()

    # ---- Host dir binding -------------------------------------------------

    @fastmcp.tool(
        description=(
            "Bind a host directory into the container for subsequent commands "
            "at mount_point (a container path). mode='ro' or 'rw'. Rejects "
            "forbidden host paths ($HOME, ~/.config, ~/.local, ~/.cache, /etc, "
            "/proc, /sys) and non-directories."
        )
    )
    def bind_host_dir(
        host_path: str,
        mount_point: str,
        mode: str = "ro",
    ) -> dict:
        from rattan import bind

        s = sessions.current()
        if s is None:
            s = sessions.get_or_create()
        try:
            sb = bind.get_session_binds(s.sid)
            b = sb.add(host_path, mount_point, mode)
        except ValueError as e:
            return {"error": str(e)}
        return {
            "status": "bound",
            "host_path": b.host_path,
            "mount_point": b.mount_point,
            "mode": b.mode,
            "session_id": s.sid,
        }

    # ---- shell_list ------------------------------------------------------

    @fastmcp.tool(
        description=(
            "List the commands available inside the container (reads /usr/bin "
            "inventory + the policy table)."
        )
    )
    def shell_list() -> list[str]:
        from rattan import policy
        names = sorted(policy.POLICY_TABLE.keys())
        try:
            r = pacman.pacman_run(sessions.current(), ["-Qq"], timeout=30)
            if r["rc"] == 0:
                installed = [ln.strip() for ln in r["output"].splitlines() if ln.strip()]
                names.extend(installed[:200])
        except Exception:
            pass
        return sorted(set(names))


# ---------------------------------------------------------------------------
# Main entry
# ---------------------------------------------------------------------------


def _parse_default_binds(argv: list[str]) -> list[tuple[str, str, str]]:
    """Parse ``--bind HOST=MOUNT[:ro|rw]`` into ``(host, mount, mode)``.

    ``--bind`` defaults to read-write; an optional ``:ro``/``:rw`` suffix on the
    mount overrides it. ``--bind-ro HOST=MOUNT`` (no suffix) is an alias for
    ``--bind HOST=MOUNT:ro``. Both repeatable. The mount path is validated later
    to reject ``:``, so splitting the mode off the last ``:ro``/``:rw`` suffix is
    unambiguous. Raises ``ValueError`` on a missing argument or malformed spec.
    """
    binds: list[tuple[str, str, str]] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("--bind", "--bind-ro"):
            default_mode = "rw" if a == "--bind" else "ro"
            if i + 1 >= len(argv):
                raise ValueError(f"{a} requires an argument (HOST=MOUNT[:ro|rw])")
            spec = argv[i + 1]
            if "=" not in spec:
                raise ValueError(
                    f"{a} expects HOST=MOUNT[:ro|rw], got {spec!r}"
                )
            host, mount_mode = spec.split("=", 1)
            mode = default_mode
            if mount_mode.endswith(":ro"):
                mode, mount = "ro", mount_mode[:-3]
            elif mount_mode.endswith(":rw"):
                mode, mount = "rw", mount_mode[:-3]
            else:
                mount = mount_mode
            binds.append((host, mount, mode))
            i += 2
        else:
            i += 1
    return binds


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if "--probe" in args:
        return capabilities.cli_main(args)

    _startup_gate()
    _setup_shutdown()

    # Configure default host binds (auto-applied to every session). Fail fast on
    # a bad spec so a misconfigured bind is caught at startup, not per-command.
    from rattan import bind
    try:
        defaults = [
            bind.validate_host_bind(host, mount, mode)
            for host, mount, mode in _parse_default_binds(args)
        ]
    except ValueError as e:
        print(f"rattan: invalid --bind: {e}", file=sys.stderr)
        return 1
    bind.set_default_binds(defaults)

    fastmcp = FastMCP("rattan")
    _build_tools(fastmcp)
    fastmcp.run()
    return 0
