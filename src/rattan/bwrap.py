"""bwrap argv builder for agent vs provisioning modes.

Builds the exact ``bwrap`` command-line that launches the sandbox, mounts the
overlay, and execs stage3 as ``/init``.
"""

from __future__ import annotations

from rattan import config, overlay
from rattan.layers import Session
from rattan.policy import ResolvedPolicy


def agent_argv(
    session: Session,
    resolved_policy: ResolvedPolicy,
    user_argv: list[str],
    cwd: str = "/workspace",
) -> list[str]:
    """Build the full ``bwrap`` argv for an agent-mode command.

    The resulting argv is passed directly to ``subprocess.Popen``.
    """
    stage3 = config.stage3_path()

    argv = [
        "bwrap",
        "--unshare-all",
        "--uid", "1000",
        "--gid", "1000",
        # Overlay lower dirs
        *overlay.lower_argv(session),
        # Overlay mount at /
        *overlay.overlay_argv(session, "/"),
        # Runtime mounts
        "--proc", "/proc",
        "--dev", "/dev",
        "--tmpfs", "/tmp",
        # Stage3 as /init (read-only)
        "--ro-bind", stage3, "/init",
        # Working directory
        "--dir", cwd,
        "--chdir", cwd,
        # --
        "--",
        "/init",
        resolved_policy.promises,
        resolved_policy.full_landlock_spec,
        "--",
        *user_argv,
    ]
    return argv


def provisioning_argv() -> list[str]:
    """Build the bwrap argv for provisioning mode.

    Not implemented in M3 — raises ``NotImplementedError``.
    """
    raise NotImplementedError("provisioning mode arrives in M4")
