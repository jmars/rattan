"""Pacman provisioning — mirror validation, invocation building, and MCP tools.

Provisioning mode runs pacman directly under bwrap (root-in-userns, optional
``--share-net``), writing into the session overlay upperdir. Packages installed
here are visible to subsequent agent-mode ``shell_run`` commands and are
subject to the usual commit/discard semantics.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile

from rattan import bwrap
from rattan.layers import Session

# ---------------------------------------------------------------------------
# Mirror validation
# ---------------------------------------------------------------------------

# Allowlist: HTTPS only, known Arch mirror domains, no credentials, no path
# traversal. Never accept arbitrary URLs (DNS exfil + supply-chain).
MIRROR_ALLOWLIST = re.compile(
    r"^https://"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]*[a-zA-Z0-9])?\.)*"
    r"(?:"
    r"archlinux\.org|"                     # official
    r"kernel\.org|"                        # tier 1
    r"pkgbuild\.com|"                      # tier 1
    r"rackspace\.com|"                     # tier 1
    r"c3sl\.ufpr\.br|"                     # tier 2 (representative)
    r"surfnet\.nl|"                        # tier 2
    r"heanet\.ie|"                         # tier 2
    r"leaseweb\.(?:com|net)|"              # tier 2
    r"[a-z0-9.-]*\.archlinux\.(?:org|de|fr|uk|jp|tw|sg|in|za|se|no|dk|fi|is|"
    r"cz|pl|es|pt|it|gr|ch|at|be|nl|lv|lt|ee|ro|bg|hr|sk|hu|rs|ua|by|ru|tr|cn|"
    r"kr|au|nz|br|cl|ar|mx|ca)"            # country mirrors on archlinux.*
    r")"
    r"(?::\d+)?"
    r"(?:/[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]*)?"
    r"/?$"
)

# Additional literal domains that pass the regex above but must not be
# accepted because they're not Arch mirrors. (Currently empty — kept as a
# guard rail for future tightening.)
_MIRROR_DENYLIST: frozenset[str] = frozenset()


def validate_mirror(url: str) -> str:
    """Validate a mirror URL against the allowlist; return it on success.

    Raises ``ValueError`` for empty, non-HTTPS, credentialed, path-traversing,
    or non-allowlisted URLs.
    """
    if not url:
        raise ValueError("mirror URL must not be empty")
    if not url.startswith("https://"):
        raise ValueError("mirror must use HTTPS")
    if "@" in url:
        raise ValueError("mirror URL must not contain credentials")
    if ".." in url:
        raise ValueError("mirror URL must not contain path traversal")
    host = url.split("/", 3)[2] if "://" in url else ""
    if host in _MIRROR_DENYLIST:
        raise ValueError(f"mirror URL '{url}' is denylisted")
    if not MIRROR_ALLOWLIST.match(url):
        raise ValueError(f"mirror URL '{url}' is not in the allowed mirror list")
    return url


_MIRRORLIST_TEMPLATE = (
    "# Rattan temporary mirrorlist for this provisioning call\n"
    "Server = {mirror}\n"
)


def _write_temp_mirrorlist(mirror: str) -> str:
    """Write a temporary mirrorlist file with the validated mirror URL."""
    content = _MIRRORLIST_TEMPLATE.format(mirror=mirror)
    fd, path = tempfile.mkstemp(prefix="rattan-mirrorlist-", suffix=".mirrorlist")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return path


# ---------------------------------------------------------------------------
# Provisioning directory seed
# ---------------------------------------------------------------------------


def provisioning_seed(session: Session) -> None:
    """Mirror the base rootfs directory skeleton into the session upperdir.

    The base rootfs is ``chmod -R a-w`` (read-only, M2). Overlayfs cannot
    copy-up a file into a read-only lower directory, so pacman cannot create
    ``/usr/bin/tree`` etc. directly. By mirroring every base directory as an
    (empty, writable) directory in the session upper, overlay merges the base's
    file contents with writable directories — pacman can write anywhere in the
    container, and writes land in the upper (subject to commit/discard).

    Idempotent. Call once per provisioning bwrap spawn (or at session creation).
    """
    from rattan import config
    base = config.base_rootfs_path()
    if not os.path.isdir(base):
        return
    upper = session.upper
    for dp, _dns, _fns in os.walk(base):
        rel = os.path.relpath(dp, base)
        if rel == ".":
            continue
        os.makedirs(os.path.join(upper, rel), exist_ok=True)


# ---------------------------------------------------------------------------
# Pacman invocations
# ---------------------------------------------------------------------------


def _check_packages(packages: list[str]) -> None:
    """Reject empty lists and flag-prefixed (option-looking) package names."""
    if not packages:
        raise ValueError("no packages specified")
    for p in packages:
        if p.startswith("-"):
            raise ValueError(
                f"invalid package name {p!r}: package names must not start with '-'"
            )


def pacman_install(
    session: Session,
    packages: list[str],
    refresh: bool = True,
    mirror: str | None = None,
    timeout: float = 300,
) -> dict:
    """Install package(s) via pacman in provisioning mode.

    Returns ``{rc, command, output, packages}``. Raises ``ValueError`` on
    invalid package names or an invalid mirror URL.
    """
    _check_packages(packages)

    args = ["--noconfirm"]
    if refresh:
        args.append("--refresh")   # pacman -S --refresh pkg (refresh + install in one op)
    args.append("-S")
    args.extend(packages)

    mirror_tmpfile = None
    try:
        if mirror is not None:
            validated = validate_mirror(mirror)
            mirror_tmpfile = _write_temp_mirrorlist(validated)

        provisioning_seed(session)
        bwrap_argv = bwrap.provisioning_argv(
            session, args, share_net=True, mirror_tmpfile=mirror_tmpfile,
        )
        proc = subprocess.Popen(
            bwrap_argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        out_bytes, _ = proc.communicate(timeout=timeout)
        output = out_bytes.decode("utf-8", errors="replace") if out_bytes else ""
        return {
            "rc": proc.returncode,
            "command": f"pacman {' '.join(args)}",
            "output": output,
            "packages": list(packages),
        }
    finally:
        if mirror_tmpfile is not None:
            try:
                os.unlink(mirror_tmpfile)
            except OSError:
                pass


def pacman_run(
    session: Session,
    args: list[str],
    timeout: float = 60,
) -> dict:
    """Run a read-only pacman command (e.g. ``-Q``, ``-Si``, ``-F``).

    No network (``--unshare-net`` via ``--unshare-all``). Returns
    ``{rc, command, output}``.
    """
    provisioning_seed(session)
    bwrap_argv = bwrap.provisioning_argv(
        session, args, share_net=False,
    )
    proc = subprocess.Popen(
        bwrap_argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    out_bytes, _ = proc.communicate(timeout=timeout)
    output = out_bytes.decode("utf-8", errors="replace") if out_bytes else ""
    return {
        "rc": proc.returncode,
        "command": f"pacman {' '.join(args)}",
        "output": output,
    }
