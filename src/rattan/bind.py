"""Host-directory binding for ``bind_host_dir``.

Validates a host path before it is bound into the container: rejects forbidden
paths ($HOME, ~/.config, ~/.local, ~/.cache, /etc, /proc, /sys), requires the
realpath to exist and be a directory, and for ``rw`` mode requires the mount
point to be in the agent landlock RW set.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


# Host paths that must never be bound into the container (invariant #11).
FORBIDDEN_HOST_DIRS = ("/etc", "/proc", "/sys")
# Forbidden relative-to-$HOME dirs.
FORBIDDEN_HOME_SUBDIRS = (".config", ".local", ".cache")


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


def get_session_binds(sid: str) -> SessionBinds:
    """Return (creating if needed) the :class:`SessionBinds` for *sid*."""
    if sid not in _SESSION_BINDS:
        _SESSION_BINDS[sid] = SessionBinds()
    return _SESSION_BINDS[sid]


def clear_session_binds(sid: str) -> None:
    """Drop the bind registry for *sid* (on session destroy / reset)."""
    _SESSION_BINDS.pop(sid, None)


def _expand_home(path: str) -> str:
    return os.path.expanduser(path)


def _realpath(path: str) -> str:
    return os.path.realpath(path)


def validate_host_bind(host_path: str, mount_point: str, mode: str) -> HostBind:
    """Validate a host-dir bind request.

    Raises ``ValueError`` with a clear message on any violation.
    """
    if mode not in ("ro", "rw"):
        raise ValueError(f"mode must be 'ro' or 'rw', got {mode!r}")
    if not mount_point or not mount_point.startswith("/"):
        raise ValueError(
            f"mount_point must be an absolute container path, got {mount_point!r}"
        )

    raw = _expand_home(host_path)
    if not raw:
        raise ValueError("host_path must not be empty")

    real = _realpath(raw)
    if not os.path.exists(real):
        raise ValueError(f"host path does not exist: {raw}")
    if not os.path.isdir(real):
        raise ValueError(f"host path is not a directory: {raw}")

    # Forbidden absolute dirs
    for forbidden in FORBIDDEN_HOST_DIRS:
        if real == forbidden or real.startswith(forbidden + os.sep):
            raise ValueError(
                f"binding {forbidden!r} is forbidden (invariant #11)"
            )

    # Forbidden $HOME subdirs
    home = _expand_home("~")
    if home and real != home:
        for sub in FORBIDDEN_HOME_SUBDIRS:
            cand = os.path.join(home, sub)
            if real == cand or real.startswith(cand + os.sep):
                raise ValueError(
                    f"binding {sub!r} under $HOME is forbidden (invariant #11)"
                )

    return HostBind(
        host_path=real,
        mount_point=mount_point,
        mode=mode,
        display_path=raw,
    )
