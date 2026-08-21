"""Configuration: paths, capability gates, and cache settings."""

from __future__ import annotations

import os
import subprocess
import tempfile


def repo_root():
    """Absolute path to the repository root (3 levels up from this file).

    When the package is installed site-wide ``bin/stage3`` won't exist there,
    but for the dev/CI workflow this is the canonical location.
    """
    return os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )


def stage3_path():
    """Absolute path to the ``bin/stage3`` inner binary."""
    return os.path.join(repo_root(), "vendor", "palisade", "bin", "stage3")


def layers_dir():
    """Path to the committed-layer store."""
    return os.path.join(data_dir(), "layers")


def sessions_dir():
    """Path to the active-session store."""
    return os.path.join(data_dir(), "sessions")


def index_lock_path():
    """Path to the ``flock`` lock file guarding ``layers/index.json``."""
    return os.path.join(layers_dir(), "index.lock")


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


def base_rootfs_path():
    """Path to the bootstrapped (immutable) base rootfs."""
    return os.path.join(data_dir(), "rootfs", "base")


def _full_manifest_check(base, manifest):
    """Full ``sha256sum -c`` over the manifest; raise RuntimeError on drift."""
    try:
        result = subprocess.run(
            ["sha256sum", "-c", manifest, "--quiet"],
            cwd=base,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"Could not run base manifest check: {e}") from e
    if result.returncode != 0:
        lines = result.stdout.strip().splitlines()
        failed = lines[:20]
        msg = "Base rootfs integrity check FAILED — files have drifted:\n"
        msg += "\n".join(f"  {line}" for line in failed)
        if len(lines) > 20:
            msg += "\n  ... (truncated)"
        msg += "\n\nRe-run: make bootstrap-rootfs"
        raise RuntimeError(msg)


def _fast_manifest_check(base, manifest):
    """Cheap mtime fast path: ``find . -type f -newer MANIFEST.sha256``.

    Bootstrap writes MANIFEST.sha256 last (before ``chmod -R a-w``), so its
    mtime is >= every regular file's mtime. Any regular file with a *newer*
    mtime therefore implies a post-bootstrap change.

    Returns True when no regular file is newer than the manifest (base
    unchanged); False when some file is newer (possible drift); None when the
    fast path could not run (find missing / non-zero exit / timeout) and the
    caller must fall through to the full hash check.
    """
    try:
        result = subprocess.run(
            ["find", ".", "-type", "f", "-newer", "MANIFEST.sha256",
             "-print", "-quit"],
            cwd=base,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    return not bool(result.stdout.strip())


def validate_base_manifest():
    """Verify the base rootfs ``MANIFEST.sha256``; raise RuntimeError on drift.

    Called at server startup. If the manifest is missing, reports that
    bootstrap is needed.

    Default fast path: ``find -type f -newer MANIFEST.sha256`` — cheap, catches
    file additions and mtime-bumping edits, but NOT pure deletions or
    mtime-preserving tampering. Set ``RATTAN_VERIFY_BASE=1`` to force the full
    ``sha256sum -c``. Any fast-path miss or failure falls through to the full
    hash check, so errors are never silently skipped.
    """
    base = base_rootfs_path()
    manifest = os.path.join(base, "MANIFEST.sha256")
    if not os.path.exists(manifest):
        raise RuntimeError(
            "Base rootfs not bootstrapped.\n"
            "Run: make bootstrap-rootfs"
        )
    if os.environ.get("RATTAN_VERIFY_BASE") == "1":
        _full_manifest_check(base, manifest)
        return
    if _fast_manifest_check(base, manifest) is True:
        return
    _full_manifest_check(base, manifest)


# Marker file inside a session root recording that the provisioning seed has
# run for that session's *current* upperdir. layers._wipe_upper removes it, so a
# fresh upper (after commit/discard/reset) is re-seeded on the next pacman call.
SEED_MARKER = ".rattan-seeded"


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
