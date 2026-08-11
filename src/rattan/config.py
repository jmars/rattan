"""Configuration: paths, capability gates, and cache settings."""

from __future__ import annotations

import os
import tempfile


def data_dir():
    """Root data directory for sessions, layers and the rootfs.

    Overridable via ``RATTAN_DATA_DIR``. Falls back to ``~/.local/share/rattan``,
    or the system temp dir when ``$HOME`` is unset (e.g. in a bare sandbox).
    """
    override = os.environ.get("RATTAN_DATA_DIR")
    if override:
        return override
    home = os.environ.get("HOME")
    if home:
        return os.path.join(home, ".local", "share", "rattan")
    return os.path.join(tempfile.gettempdir(), "rattan")


def cache_path():
    """Path to the JSON capability cache consumed by ``env_status``."""
    return os.path.join(data_dir(), "capabilities.json")


# Startup gate: the server refuses to start if any of these is absent.
REQUIRED_CAPABILITIES = [
    "kernel_version",
    "userns_enabled",
    "landlock_present",
    "bwrap_version",
]

# Reported but never blocking.
OPTIONAL_CAPABILITIES = [
    "landlock_abi",
    "overlay_in_userns",
    "reflink_support",
]

# A cached probe is reused within this window (seconds) before re-probing.
CACHE_TTL = 60.0
