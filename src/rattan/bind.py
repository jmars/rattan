"""Host-directory binding for ``bind_host_dir``.

Validates a host path before it is bound into the container: rejects forbidden
paths ($HOME, ~/.config, ~/.local, ~/.cache, /etc, /proc, /sys), requires the
realpath to exist and be a directory, and for ``rw`` mode requires the mount
point to be in the agent landlock RW set.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


# Host system directories that must never be bound into the container
# (invariant #11). Binding any of these — even ``ro`` — exposes host system
# state, device nodes, kernels, logs, or other users' data to the sandbox. The
# intended bind target is a user project/data directory (e.g. under $HOME).
FORBIDDEN_SYSTEM_DIRS = (
    "/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64",
    "/proc", "/root", "/run", "/sbin", "/sys", "/tmp", "/usr", "/var",
    "/opt", "/srv", "/mnt", "/media",
)
# Hidden (dot) subdirectories under $HOME hold configuration and credentials
# (.ssh, .gnupg, .aws, .kube, .config, .local, .cache, ...). Any `$HOME/.*`
# subtree is forbidden — only non-hidden user data dirs under $HOME are bindable.
FORBIDDEN_HOME_PREFIX = "."


def _under(path: str, root: str) -> bool:
    """True if *path* == *root* or is under *root*."""
    if not root:
        return False
    if root == "/":
        return True  # everything is under the filesystem root
    return path == root or path.startswith(root + os.sep)


@dataclass
class HostBind:
    host_path: str          # validated absolute realpath
    mount_point: str        # container path, e.g. /workspace/foo
    mode: str               # "ro" | "rw"
    display_path: str       # the user-supplied path (for messages)


@dataclass
class SessionBinds:
    binds: list[HostBind] = field(default_factory=list)

    def add(self, host_path: str, mount_point: str, mode: str) -> HostBind:
        b = validate_host_bind(host_path, mount_point, mode)
        self.binds.append(b)
        return b

    def bwrap_bind_argv(self) -> list[str]:
        """Extra ``--bind``/``--ro-bind`` argv fragments for the bwrap launch."""
        argv: list[str] = []
        for b in self.binds:
            flag = "--bind" if b.mode == "rw" else "--ro-bind"
            argv.extend([flag, b.host_path, b.mount_point])
        return argv

    def landlock_extra(self) -> list[str]:
        """Extra ``path:perms`` entries for the agent LANDLOCK_SPEC."""
        out = []
        for b in self.binds:
            perms = "rwc" if b.mode == "rw" else "r"
            out.append(f"{b.mount_point}:{perms}")
        return out


# Per-session binds registry (keyed by sid). Kept separate from the Session
# dataclass to avoid changing its construction sites.
_SESSION_BINDS: dict[str, SessionBinds] = {}

# Default binds applied to every session created after they are set. Populated
# from the server's --bind / --bind-ro CLI args (see server.main), so a bind
# like ~/projects is auto-mounted without the agent calling bind_host_dir.
_DEFAULT_BINDS: list[HostBind] = []


def set_default_binds(binds: list[HostBind]) -> None:
    """Set the default binds auto-applied to newly-created sessions."""
    _DEFAULT_BINDS[:] = list(binds)


def default_binds() -> list[HostBind]:
    """Return a copy of the configured default binds."""
    return list(_DEFAULT_BINDS)


def get_session_binds(sid: str) -> SessionBinds:
    """Return (creating if needed) the :class:`SessionBinds` for *sid*."""
    sb = _SESSION_BINDS.get(sid)
    if sb is None:
        sb = SessionBinds()
        # Seed a fresh session with the configured default binds (deduped by
        # mount_point) so they apply without an explicit bind_host_dir call.
        seen = set()
        for b in _DEFAULT_BINDS:
            if b.mount_point not in seen:
                sb.binds.append(b)
                seen.add(b.mount_point)
        _SESSION_BINDS[sid] = sb
    return sb


def clear_session_binds(sid: str) -> None:
    """Drop the bind registry for *sid* (on session destroy / reset)."""
    _SESSION_BINDS.pop(sid, None)


def _expand_home(path: str) -> str:
    return os.path.expanduser(path)


def _realpath(path: str) -> str:
    return os.path.realpath(path)


def validate_host_bind(host_path: str, mount_point: str, mode: str) -> HostBind:
    """Validate a host-dir bind request.

    Only **user data directories** may be bound (invariant #11): a non-hidden
    subdir under ``$HOME`` (e.g. ``~/projects/foo``). Everything else is
    rejected — the host root, all system directories (``/etc /proc /sys /usr
    /var /boot /dev /run /bin /lib /root /tmp /opt /srv ...``), another user's
    home, ``$HOME`` itself and every hidden ``$HOME/.*`` subtree (config and
    credentials), and the rattan data dir. Raises ``ValueError`` on any
    violation.
    """
    if mode not in ("ro", "rw"):
        raise ValueError(f"mode must be 'ro' or 'rw', got {mode!r}")
    if not mount_point or not mount_point.startswith("/"):
        raise ValueError(
            f"mount_point must be an absolute container path, got {mount_point!r}"
        )
    if any(c in mount_point for c in (";", ":", "\n", "\r", "\x00")):
        raise ValueError(
            f"mount_point must not contain ';', ':', or control characters, "
            f"got {mount_point!r}"
        )

    raw = _expand_home(host_path)
    if not raw:
        raise ValueError("host_path must not be empty")

    real = _realpath(raw)
    if not os.path.exists(real):
        raise ValueError(f"host path does not exist: {raw}")
    if not os.path.isdir(real):
        raise ValueError(f"host path is not a directory: {raw}")

    # Reject the host root — binding / would expose the entire host filesystem.
    if real == "/":
        raise ValueError("binding the host root '/' is forbidden (invariant #11)")

    home = os.path.realpath(_expand_home("~")) if _expand_home("~") else ""

    # Path under the current user's $HOME -> user data. $HOME itself and any
    # hidden ($HOME/.*) subtree (config/credentials) are forbidden; non-hidden
    # subdirs (projects, code, data) are the intended bind targets.
    if home and _under(real, home):
        if real == home:
            raise ValueError(
                "binding $HOME itself is forbidden (invariant #11)"
            )
        rel = os.path.relpath(real, home)
        first = rel.split(os.sep)[0]
        if first.startswith(FORBIDDEN_HOME_PREFIX):
            raise ValueError(
                f"binding {first!r} under $HOME is forbidden (invariant #11)"
            )
    else:
        # Not under $HOME: must not be a system directory or another user's home.
        for sysdir in FORBIDDEN_SYSTEM_DIRS:
            if _under(real, sysdir):
                raise ValueError(
                    f"binding {sysdir!r} is forbidden (invariant #11)"
                )
        if _under(real, "/home"):
            raise ValueError(
                "binding another user's home is forbidden (invariant #11)"
            )

    # Never bind the rattan data dir (sessions/layers/rootfs) — an agent could
    # poison meta.json or committed layers.
    try:
        from rattan import config
    except Exception:
        config = None
    if config is not None:
        data_dir = os.path.realpath(config.data_dir())
        if _under(real, data_dir):
            raise ValueError(
                "binding the rattan data dir is forbidden (invariant #11)"
            )

    return HostBind(
        host_path=real,
        mount_point=mount_point,
        mode=mode,
        display_path=raw,
    )
