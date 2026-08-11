"""Per-connection session registry.

The MCP server holds ONE session per connection.  ``get_or_create()`` returns
the singleton; ``destroy_all_on_shutdown()`` sweeps all sessions (the M3.7
shutdown gate).
"""

from __future__ import annotations

import os
from typing import Optional

from rattan import config, layers

_current: Optional[layers.Session] = None


def get_or_create(sid: Optional[str] = None) -> layers.Session:
    """Return the current connection-scoped session, creating one if needed.

    When *sid* is given and matches a previously persisted session on disk that
    session is loaded; otherwise a fresh session is created.
    """
    global _current
    if _current is not None:
        return _current

    # Try to load from disk if sid provided
    if sid is not None:
        loaded = layers.load_session(sid)
        if loaded is not None:
            _current = loaded
            return _current

    _current = layers.create_session(sid)
    return _current


def current() -> Optional[layers.Session]:
    """Return the current session, or ``None`` if none has been created yet."""
    return _current


def destroy_all_on_shutdown():
    """Remove every session directory under ``<sessions-dir>/``.

    Called by the atexit + SIGTERM handler (M3.7).  Sessions that still have a
    live lockfile PID are left alone (best-effort) — full orphan GC runs at next
    startup.
    """
    global _current
    sessions_d = config.sessions_dir()
    if not os.path.isdir(sessions_d):
        return
    current_pid = os.getpid()
    for name in os.listdir(sessions_d):
        root = os.path.join(sessions_d, name)
        pid_path = os.path.join(root, "pid")
        try:
            with open(pid_path) as f:
                pid_s = f.read().strip()
            pid = int(pid_s)
            if pid != current_pid:
                # Another process owns this session — leave it alone
                continue
        except (OSError, ValueError):
            pass
        try:
            meta = layers.load_meta(root)
            stack = meta.get("stack", []) if meta else []
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
    _current = None
