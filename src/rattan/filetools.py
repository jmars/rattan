"""Sandboxed file tools: ``read_file`` / ``write_file`` / ``edit`` / ``grep``.

These mirror Vibe's host-side file tools but operate **inside** the rattan
sandbox. Every path is a **container path** under ``/workspace`` or ``/tmp``;
host paths are rejected loudly. The existing sandbox (uid 1000, Landlock
baseline ``/workspace:rwc`` + ``/tmp:rwc``) is the enforcement layer — these
tools build shell commands and run them through :func:`execute_program`, which
applies the same per-command policy to whatever argv0 runs.

Security model
--------------

Path validation is two-phase to close the symlink-escape gap:

1. **Lexical** (host-side): :func:`rattan.contain.contained_in_any` uses
   ``os.path.realpath`` on the HOST, so ``..``-escapes and absolute host paths
   are rejected before anything runs.
2. **Container-side re-resolution**: ``realpath -- <path>`` is run *inside* the
   sandbox and the result is re-checked against the container roots. A
   ``/workspace/evil -> /etc/passwd`` symlink passes the lexical check (the
   host cannot see the container's symlink) but fails here because the sandbox
   ``realpath`` resolves it to ``/etc/passwd``.

Writing is done with ``printf '%s' <content> | tee <path>`` rather than a
``>`` redirect: the executor resolves a ``> /tmp/...`` redirect to an ephemeral
host temp file (bound for one invocation only), so a redirect would not persist
a write to ``/tmp``. ``tee`` writes inside the container, landing the file in
the overlay upper for both ``/workspace`` and ``/tmp``.
"""

from __future__ import annotations

import os
import secrets
import shlex

from rattan.contain import CONTAINER_ROOTS, contained_in_any
from rattan.executor import EmptyInvocation, InvocationError, execute_program
from rattan.parser import ParseError, parse

# Environment for every sandbox invocation the file tools make. Matches the
# env_store used by shell_run / test_e2e so `$VAR` expansion behaves identically.
_SANDBOX_ENV = {
    "HOME": "/workspace",
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "USER": "rattan",
    "TERM": "dumb",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}


def _sandbox(session, command, cwd="/workspace", timeout=30) -> dict:
    """Run *command* inside the sandbox; return a structured dict.

    Wraps ``parse`` + ``execute_program`` and normalizes the error paths to the
    same ``{rc, skipped, stages, output}`` shape as ``shell_run``.
    """
    try:
        program = parse(command)
    except ParseError as e:
        return {"rc": 1, "output": str(e), "stages": [], "skipped": False}

    try:
        return execute_program(
            program, session, dict(_SANDBOX_ENV), cwd, timeout
        )
    except InvocationError as e:
        return {"rc": 1, "output": str(e), "stages": [], "skipped": False}
    except EmptyInvocation:
        return {"rc": 0, "output": "", "stages": [], "skipped": False}


def _validate_container_path(
    session, raw, *, must_exist=False, is_file=False
) -> str:
    """Validate *raw* as a container path; return the resolved container path.

    Raises ``ValueError`` (surfaced as ``{"error": ...}`` by the tools) when the
    path is empty, relative, outside ``/workspace``/``/tmp``, escapes via a
    container-side symlink, or — when ``must_exist`` — is missing/wrong-typed.
    """
    if not raw:
        raise ValueError("path must not be empty")
    if not os.path.isabs(raw):
        raise ValueError(f"path must be an absolute container path, got {raw!r}")

    # Phase 1: lexical containment (host-side realpath rejects `..` escapes).
    if contained_in_any(raw, CONTAINER_ROOTS) is None:
        raise ValueError(
            f"path must be under /workspace or /tmp (got {raw}); "
            "pass '/workspace/<rel>' instead"
        )

    # Phase 2: re-resolve inside the sandbox so container-side symlinks that
    # point outside the roots are caught (the lexical check cannot see them).
    r = _sandbox(session, f"realpath -- {shlex.quote(raw)}")
    lines = [ln for ln in (r.get("output") or "").splitlines() if ln.strip()]
    if r.get("rc") != 0 or not lines:
        if must_exist:
            raise ValueError(f"path does not exist in sandbox: {raw}")
        return raw

    resolved = lines[0].strip()
    if contained_in_any(resolved, CONTAINER_ROOTS) is None:
        raise ValueError(f"resolved path escapes container roots: {resolved}")

    if must_exist:
        test_cmd = "test -f" if is_file else "test -e"
        t = _sandbox(session, f"{test_cmd} {shlex.quote(resolved)}")
        if t.get("rc") != 0:
            raise ValueError(f"path does not exist or wrong type: {raw}")

    return resolved


# ---------------------------------------------------------------------------
# read_file
# ---------------------------------------------------------------------------


def read_file(session, file_path: str, offset: int | None = None, limit: int = 2000) -> dict:
    """Read a file from the sandbox; return a ``ReadFileResult``-shaped dict.

    ``file_path`` must be a container path under ``/workspace`` or ``/tmp``.
    ``offset`` is 1-indexed (defaults to 1); ``limit`` is the max lines returned.
    """
    try:
        resolved = _validate_container_path(
            session, file_path, must_exist=True, is_file=True
        )
    except ValueError as e:
        return {"error": str(e)}

    total = _sandbox(session, f"wc -l {shlex.quote(resolved)}")
    try:
        n_lines = int((total.get("output") or "0").strip().split()[0])
    except (ValueError, IndexError):
        n_lines = 0

    start = offset or 1
    end = start + limit - 1

    slice_res = _sandbox(
        session, f"sed -n '{start},{end}p' {shlex.quote(resolved)}"
    )
    lines = (slice_res.get("output") or "").split("\n")
    if lines and lines[-1] == "":
        lines = lines[:-1]

    content = "\n".join(
        f"{str(n).rjust(9)}\u2192{ln}" for n, ln in enumerate(lines, start=start)
    )

    return {
        "file_path": file_path,
        "content": content,
        "num_lines": len(lines),
        "start_line": start,
        "requested_offset": offset,
        "requested_limit": limit,
        "total_lines": n_lines,
        "was_truncated": (start + len(lines) - 1) < n_lines,
    }


# ---------------------------------------------------------------------------
# write_file
# ---------------------------------------------------------------------------


def write_file(session, file_path: str, content: str) -> dict:
    """Write *content* to a NEW file in the sandbox (fails if it exists).

    ``file_path`` must be a container path under ``/workspace`` or ``/tmp``.
    Parent directories are created as needed. Use ``edit`` to modify an
    existing file.
    """
    if "\x00" in content:
        return {"error": "content contains NUL bytes"}
    encoded = content.encode("utf-8")
    if len(encoded) > 64000:
        return {"error": "content exceeds 64000-byte limit"}

    try:
        resolved = _validate_container_path(
            session, file_path, must_exist=False, is_file=False
        )
    except ValueError as e:
        return {"error": str(e)}

    exists = _sandbox(session, f"test -e {shlex.quote(resolved)}")
    if exists.get("rc") == 0:
        return {
            "error": f"file already exists: {file_path} (use rattan_edit to modify)"
        }

    dirname = os.path.dirname(resolved)
    r = _sandbox(
        session,
        f"mkdir -p {shlex.quote(dirname)} && "
        f"printf '%s' {shlex.quote(content)} | tee {shlex.quote(resolved)}",
    )
    if r.get("rc") != 0:
        return {"error": f"write failed: {(r.get('output') or '').strip()}"}

    return {
        "file_path": file_path,
        "bytes_written": len(encoded),
        "content": content,
    }


# ---------------------------------------------------------------------------
# edit
# ---------------------------------------------------------------------------


def edit(
    session,
    file_path: str,
    old_string: str,
    new_string: str,
    replace_all: bool = False,
) -> dict:
    """Replace ``old_string`` with ``new_string`` in a sandbox file (atomic).

    ``file_path`` must be a container path under ``/workspace`` or ``/tmp``.
    The replacement is written to a temp file in the same directory and renamed
    over the target, so the update is atomic on the container filesystem.
    """
    if not old_string:
        return {"error": "old_string must not be empty"}
    if old_string == new_string:
        return {"error": "old_string and new_string must differ"}
    if "\x00" in new_string:
        return {"error": "new_string contains NUL bytes"}

    try:
        resolved = _validate_container_path(
            session, file_path, must_exist=True, is_file=True
        )
    except ValueError as e:
        return {"error": str(e)}

    orig = _sandbox(session, f"cat {shlex.quote(resolved)}")
    original = orig.get("output") or ""

    if old_string not in original:
        return {"error": f"old_string not found in {file_path}"}

    occurrences = original.count(old_string)
    if occurrences > 1 and not replace_all:
        return {
            "error": f"found {occurrences} matches; set replace_all=true or add more context"
        }

    modified = (
        original.replace(old_string, new_string)
        if replace_all
        else original.replace(old_string, new_string, 1)
    )

    dirname = os.path.dirname(resolved)
    tmp = f"{dirname}/.rattan-edit-{secrets.token_hex(6)}"
    # Write modified content to a temp file in the SAME directory (same fs),
    # then atomically rename over the target.
    r = _sandbox(
        session,
        f"printf '%s' {shlex.quote(modified)} | tee {shlex.quote(tmp)} && "
        f"mv -- {shlex.quote(tmp)} {shlex.quote(resolved)}",
    )
    if r.get("rc") != 0:
        _sandbox(session, f"rm -f {shlex.quote(tmp)}")  # best-effort cleanup
        return {"error": f"edit failed: {(r.get('output') or '').strip()}"}

    message = (
        "The file has been updated. All occurrences were successfully replaced"
        if replace_all
        else "The file has been updated successfully."
    )
    return {
        "file": file_path,
        "message": message,
        "old_string": old_string,
        "new_string": new_string,
    }


# ---------------------------------------------------------------------------
# grep
# ---------------------------------------------------------------------------

# Default exclusion globs/dirs applied on every search. `.gitignore` awareness
# (the `use_default_ignore` flag in Vibe) cannot be implemented with plain grep,
# so a hardcoded set of common noise directories/files is used instead.
_DEFAULT_EXCLUDE_DIRS = (
    ".venv",
    "venv",
    ".git",
    "__pycache__",
    "node_modules",
    "dist",
    "build",
)
_DEFAULT_EXCLUDE_FILES = ("*.egg-info", "*.pyc")


def grep(
    session,
    pattern: str,
    path: str = "/workspace",
    max_matches: int | None = None,
    use_default_ignore: bool = True,
) -> dict:
    """Search for *pattern* (extended regex) under container *path*.

    ``path`` must be a container path under ``/workspace`` or ``/tmp``.

    Known limitation: ``use_default_ignore`` (gitignore-awareness) is accepted
    for API compatibility but not implementable with plain ``grep``; only the
    hardcoded default excludes (``.venv``, ``.git``, ``__pycache__``,
    ``node_modules``, ``dist``, ``build``, ``*.egg-info``, ``*.pyc``) are
    applied regardless of this flag.
    """
    if not pattern:
        return {"error": "pattern must not be empty"}

    try:
        resolved = _validate_container_path(session, path, must_exist=True)
    except ValueError as e:
        return {"error": str(e)}

    n = max_matches or 100
    parts = ["grep", "-rnH", "-I", "-E", f"--max-count={n + 1}"]
    if pattern.islower():
        parts.append("-i")
    for d in _DEFAULT_EXCLUDE_DIRS:
        parts.append(f"--exclude-dir={d}")
    for f in _DEFAULT_EXCLUDE_FILES:
        parts.append(f"--exclude={f}")
    parts.append("-e")
    parts.append(pattern)
    parts.append(resolved)

    command = " ".join(shlex.quote(p) for p in parts)
    r = _sandbox(session, command, timeout=60)
    if r.get("rc") not in (0, 1):
        return {"error": f"grep failed: {(r.get('output') or '').strip()}"}

    out_lines = (r.get("output") or "").splitlines()
    matches = "\n".join(out_lines[:n])[:64000]
    return {
        "matches": matches,
        "match_count": len(out_lines[:n]),
        "was_truncated": len(out_lines) > n,
    }
