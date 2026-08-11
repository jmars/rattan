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


def provisioning_argv(
    session: Session,
    pacman_args: list[str],
    *,
    share_net: bool = True,
    mirror_tmpfile: str | None = None,
) -> list[str]:
    """Build the ``bwrap`` argv for provisioning mode (pacman).

    Pacman runs **directly** under bwrap (root-in-userns, no stage3). Isolation
    is userns + bwrap + overlay: there are no host bind mounts beyond the
    session upperdir and resolv.conf, so pacman cannot reach the host
    filesystem. Landlock/seccomp are skipped because Landlock's deny-by-default
    model cannot express "restrict /workspace but leave / open" for pacman's
    writes to /usr, /var/lib/pacman, /etc.

    - *share_net*: True → ``--share-net`` (networked install). False → omit it
      (read-only ``pacman_run`` stays offline via ``--unshare-all``).
    - *mirror_tmpfile*: when set, bind it over the container's
      ``/etc/pacman.d/mirrorlist`` for this call only.
    """
    argv = [
        "bwrap",
        "--unshare-all",
    ]
    if share_net:
        argv.append("--share-net")
    argv += [
        "--uid", "0",
        "--gid", "0",
        # Overlay lower dirs (base + committed layers)
        *overlay.lower_argv(session),
        # Overlay mount at /
        *overlay.overlay_argv(session, "/"),
        # Runtime mounts
        "--proc", "/proc",
        "--dev", "/dev",  # provides /dev/urandom (needed by pacman-key / gpg)
        "--tmpfs", "/tmp",
        # DNS: bind the host's resolv.conf (the base stub doesn't resolve)
        "--ro-bind", "/etc/resolv.conf", "/etc/resolv.conf",
    ]
    if mirror_tmpfile:
        argv += ["--bind", mirror_tmpfile, "/etc/pacman.d/mirrorlist"]
    argv += ["--", "/usr/bin/pacman", *pacman_args]
    return argv
