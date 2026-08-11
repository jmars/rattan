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
from rattan.executor import _scrub_control_env
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

    Idempotent. The expensive walk runs once per session *upper* (C1): the
    completion marker ``<session.root>/config.SEED_MARKER`` short-circuits
    subsequent calls, and ``layers._wipe_upper`` removes that marker whenever
    the upper is wiped (commit/discard/reset), so a fresh upper is re-seeded.
    """
    from rattan import config
    base = config.base_rootfs_path()
    if not os.path.isdir(base):
        return
    marker = os.path.join(session.root, config.SEED_MARKER)
    if os.path.exists(marker):
        return
    upper = session.upper
    for dp, _dns, _fns in os.walk(base):
        rel = os.path.relpath(dp, base)
        if rel == ".":
            continue
        os.makedirs(os.path.join(upper, rel), exist_ok=True)
    # Record completion only after the walk; an interrupted run leaves no marker
    # and is re-seeded next time (makedirs(exist_ok=True) makes that idempotent).
    try:
        with open(marker, "w") as f:
            f.write("1")
    except OSError:
        pass


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


# Read-only pacman operations accepted by pacman_run. Anything else mutates
# state and is rejected, so an agent cannot use pacman_run as a second,
# less-restricted provisioning path (H-1). Every -Q* form is a read-only local
# database query (accepted). Only the read-only query forms of the sync (-S)
# and files (-F) operations are allowed; install/upgrade/remove/db and
# cache-clean (-S, -Sy, -Su, -Sw, -Sc, -Scc, -U, -R, -D) are rejected.
_QUERY_SAFE_SYNCOPS = {"-Si", "-Sii", "-Sl", "-Ss", "-Sss", "-Sg"}
_QUERY_SAFE_FILEOPS = {"-F", "-Fl", "-Fs", "-Fh"}
_QUERY_SAFE_LONG = {
    "--noconfirm", "--quiet", "--color", "--debug", "--verbose",
    "--print", "--print-format", "--version", "--help",
}
_QUERY_FORBIDDEN_FLAGS = {
    "--config", "--root", "--dbpath", "--cachedir", "--hookdir",
    "--gpgdir", "--logfile", "--arch", "--sysroot", "--ignore",
    "--ignoregroup", "--assume-installed", "--needed",
}


def _check_query_args(args: list[str]) -> None:
    """Reject any pacman_run arg that isn't a safe read-only query flag.

    Operation-letter clusters are parsed: ``-Q*`` is always read-only; ``-S*``
    and ``-F*`` are only allowed in their specific read-only query forms;
    ``-U``/``-R``/``-D`` and bare/upgrading/cleaning ``-S`` forms are rejected
    (H-1). Long ``--config``/``--root``/``--hookdir``/``--dbpath``/``--cachedir``
    etc. are rejected outright. Raises ``ValueError`` on anything disallowed.
    """
    for a in args:
        if not a.startswith("-"):
            continue  # package names / query terms (e.g. "--color auto" value)
        if a.startswith("--"):
            base = a.split("=", 1)[0]
            if base in _QUERY_FORBIDDEN_FLAGS:
                raise ValueError(f"pacman_run rejects unsafe flag {a!r}")
            if base not in _QUERY_SAFE_LONG:
                raise ValueError(f"pacman_run rejects unknown flag {a!r}")
            continue
        # Single-dash operation cluster: first char after '-' is the operation.
        op = a[1] if len(a) > 1 else ""
        if op == "Q":
            continue  # all -Q queries are read-only
        if op == "S":
            if a not in _QUERY_SAFE_SYNCOPS:
                raise ValueError(
                    f"pacman_run rejects mutating sync operation {a!r} "
                    "(use pacman_install instead)"
                )
            continue
        if op == "F":
            if a not in _QUERY_SAFE_FILEOPS:
                raise ValueError(
                    f"pacman_run rejects unsupported -F operation {a!r}"
                )
            continue
        if op in ("T", "V"):
            continue
        raise ValueError(f"pacman_run rejects unknown flag {a!r}")


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
            env=_scrub_control_env(os.environ),
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

    Only read-only query flags are accepted (H-1). No network
    (``--unshare-net`` via ``--unshare-all``). Returns ``{rc, command, output}``.
    """
    _check_query_args(args)
    provisioning_seed(session)
    bwrap_argv = bwrap.provisioning_argv(
        session, args, share_net=False,
    )
    proc = subprocess.Popen(
        bwrap_argv,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=_scrub_control_env(os.environ),
    )
    out_bytes, _ = proc.communicate(timeout=timeout)
    output = out_bytes.decode("utf-8", errors="replace") if out_bytes else ""
    return {
        "rc": proc.returncode,
        "command": f"pacman {' '.join(args)}",
        "output": output,
    }
