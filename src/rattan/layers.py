"""Session layer stack; commit / discard / rollback / GC.

Content-addressed commits (manifest hash), deduplication, reflink-aware copy,
and an ``index.json`` under ``flock`` for refcount-based GC.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass
from typing import Optional

from rattan import config


# ---------------------------------------------------------------------------
# Reflink capability probe (cached — probed once per process, not per commit)
# ---------------------------------------------------------------------------


_reflink_ok: Optional[bool] = None


def _reflink_available() -> bool:
    """Cache whether the data filesystem supports reflink (btrfs/xfs)."""
    global _reflink_ok
    if _reflink_ok is None:
        try:
            from rattan import capabilities
            table = capabilities.get_capabilities()
            cap = table.get("reflink_support")
            _reflink_ok = cap is not None and cap.available
        except Exception:
            _reflink_ok = False
    return _reflink_ok


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class LayerRef:
    """A committed layer snapshot."""

    commit_id: str
    path: str
    message: str = ""
    created_at: str = ""
    size_bytes: int = 0


@dataclass
class Session:
    """An active overlay session."""

    sid: str
    root: str         # <sessions-dir>/<sid>/
    upper: str        # .../upper/
    work: str         # .../work/
    stack: list[str]  # commit_ids in chronological order (tip = last)

    @property
    def workspace(self) -> str:
        return os.path.join(self.upper, "workspace")

    @property
    def tmp(self) -> str:
        return os.path.join(self.upper, "tmp")

    @property
    def lock_path(self) -> str:
        return os.path.join(self.root, "lock")

    @property
    def pid_path(self) -> str:
        return os.path.join(self.root, "pid")

    @property
    def meta_path(self) -> str:
        return os.path.join(self.root, "meta.json")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256_file(path: str) -> str:
    """Return the hex-encoded SHA-256 of *path* contents."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _force_rmtree(func, path, exc_info):
    """shutil.rmtree onerror handler: chmod the path writable.

    ``func`` may be ``os.open`` (which needs a flags argument we don't have),
    so we only chmod and skip the retry of the failing call; the outer retry
    loop in ``destroy`` re-runs rmtree and picks up the now-writable entry.
    """
    try:
        os.chmod(path, stat.S_IWUSR | stat.S_IRUSR | stat.S_IXUSR)
    except OSError:
        pass
    if func is os.open:
        return
    try:
        func(path)
    except OSError:
        pass


def _copy_upper_to_layer(upper: str, dest: str):
    """Copy the upper directory tree into *dest*, preferring reflink when possible.

    On btrfs/xfs (detected via the ``reflink_support`` capability probe) we use
    ``cp -a --reflink=auto``.  Otherwise we try ``rsync -aHAX --delete``,
    falling back to ``rsync -aHX --delete`` if ACLs are not supported, then
    ``cp -a``, and finally a pure-Python ``shutil.copytree``.
    """
    if _reflink_available():
        subprocess.run(
            ["cp", "-a", "--reflink=auto",
             os.path.join(upper, "") + "/.", dest + "/"],
            check=True, timeout=300,
        )
        return

    src = os.path.join(upper, "") + "/."
    dst = dest + "/"
    for args in (
        ["rsync", "-aHAX", "--delete", src, dst],
        ["rsync", "-aHX", "--delete", src, dst],
        ["cp", "-a", src, dst],
    ):
        try:
            subprocess.run(args, check=True, timeout=300)
            return
        except subprocess.CalledProcessError:
            continue
    # Last resort: pure-Python copy (works even under restrictive seccomp)
    shutil.copytree(upper, dest, symlinks=True, dirs_exist_ok=True)


def _load_index() -> dict:
    """Load and return the layers index (mutable dict)."""
    idx_path = os.path.join(config.layers_dir(), "index.json")
    if os.path.exists(idx_path):
        with open(idx_path) as f:
            return json.load(f)
    return {}


@contextlib.contextmanager
def _index_lock():
    """Hold the exclusive flock on the layers index across a read-modify-write."""
    lock_path = config.index_lock_path()
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(lock_path, "w") as lf:
        fcntl.flock(lf, fcntl.LOCK_EX)
        try:
            yield lf
        finally:
            fcntl.flock(lf, fcntl.LOCK_UN)


def _save_index(index: dict, lock=None):
    """Atomically write the index.

    If *lock* (an already-locked open file) is given, write WITHOUT re-acquiring
    (the caller holds the lock across a read-modify-write; re-acquiring would
    deadlock).  Otherwise acquire the exclusive lock for just the write.
    """
    layers = config.layers_dir()
    os.makedirs(layers, exist_ok=True)
    idx_path = os.path.join(layers, "index.json")
    tmp = idx_path + ".tmp"
    if lock is not None:
        with open(tmp, "w") as f:
            json.dump(index, f, indent=2, sort_keys=True)
        os.replace(tmp, idx_path)
        return
    with _index_lock():
        with open(tmp, "w") as f:
            json.dump(index, f, indent=2, sort_keys=True)
        os.replace(tmp, idx_path)


def _compute_manifest(upper_path: str) -> str:
    """Build a deterministic manifest string for content-addressing.

    Format: ``"<relpath>\\0<mode>\\0<type>\\0[<symlink_target>|<sha256>]\\n"``
    per entry.  ``type`` is one of ``d`` (directory), ``l`` (symlink), or ``f``
    (regular file).  Entries are ordered by relpath (``os.walk`` top-down with
    sorted dirnames / filenames).  The ``workspace/`` seed directory IS included:
    its content is part of the commit identity — without it, two sessions with
    identical non-workspace state but different ``/workspace`` content would
    collide and dedupe incorrectly, leaking one session's workspace into another.
    """
    lines: list[str] = []

    for dirpath, dirnames, filenames in os.walk(upper_path, topdown=True):
        rel = os.path.relpath(dirpath, upper_path)
        if rel == ".":
            rel = ""

        dirnames.sort()
        filenames.sort()

        # Include directories (except the root itself)
        for d in dirnames:
            drel = os.path.join(rel, d) if rel else d
            st = os.lstat(os.path.join(dirpath, d))
            m = oct(st.st_mode)
            lines.append(f"{drel}\0{m}\0d\0\n")

        for f in filenames:
            frel = os.path.join(rel, f) if rel else f
            fpath = os.path.join(dirpath, f)
            st = os.lstat(fpath)
            m = oct(st.st_mode)
            if stat.S_ISLNK(st.st_mode):
                target = os.readlink(fpath)
                lines.append(f"{frel}\0{m}\0l\0{target}\n")
            elif stat.S_ISREG(st.st_mode):
                sha = _sha256_file(fpath)
                lines.append(f"{frel}\0{m}\0f\0{sha}\n")
            # Other types (fifos, devices, sockets) are skipped.

    return "".join(lines)


def _compute_commit_id(upper_path: str) -> str:
    """Content-address *upper_path*; return the hex SHA-256 of its manifest."""
    manifest = _compute_manifest(upper_path)
    return hashlib.sha256(manifest.encode()).hexdigest()


def _upper_size_bytes(upper_path: str) -> int:
    """Return the total on-disk size of everything in *upper_path*."""
    total = 0
    for dirpath, _, filenames in os.walk(upper_path):
        for f in filenames:
            try:
                total += os.lstat(os.path.join(dirpath, f)).st_size
            except OSError:
                pass
    return total


def _dirty_file_count(upper_path: str) -> int:
    """Return a count of regular files in *upper_path*.

    Includes files under ``workspace/`` — a write there is an uncommitted
    change and must make ``env_status`` report the session as dirty.
    """
    count = 0
    for dirpath, _, filenames in os.walk(upper_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                if stat.S_ISREG(os.lstat(fp).st_mode):
                    count += 1
            except OSError:
                pass
    return count


def _upper_stats(upper_path: str) -> tuple[int, int]:
    """Return (size_bytes, regular_file_count) with a single os.walk."""
    total = 0
    count = 0
    for dirpath, _, filenames in os.walk(upper_path):
        for f in filenames:
            fp = os.path.join(dirpath, f)
            try:
                st = os.lstat(fp)
            except OSError:
                continue
            total += st.st_size
            if stat.S_ISREG(st.st_mode):
                count += 1
    return total, count


# ---------------------------------------------------------------------------
# Session lifecycle
# ---------------------------------------------------------------------------


def create_session(sid: Optional[str] = None) -> Session:
    """Create a new session with empty upper / work directories.

    Returns a :class:`Session`.  If *sid* is ``None`` a fresh UUID4 is
    generated.  The session directory and its sub-structure are created on disk.
    """
    if sid is None:
        sid = uuid.uuid4().hex[:12]
    root = os.path.join(config.sessions_dir(), sid)
    upper = os.path.join(root, "upper")
    work = os.path.join(root, "work")
    workspace = os.path.join(upper, "workspace")
    tmpdir = os.path.join(upper, "tmp")

    os.makedirs(workspace, exist_ok=True)
    os.makedirs(tmpdir, exist_ok=True)
    os.makedirs(work, exist_ok=True)

    session = Session(sid=sid, root=root, upper=upper, work=work, stack=[])

    with open(session.pid_path, "w") as f:
        f.write(str(os.getpid()))
    with open(session.lock_path, "w") as f:
        f.write("")

    _persist_meta(session)
    return session


def _persist_meta(session: Session):
    meta = {
        "sid": session.sid,
        "stack": session.stack,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    with open(session.meta_path, "w") as f:
        json.dump(meta, f, indent=2)


def load_meta(root: str) -> Optional[dict]:
    """Load session metadata from *root*/meta.json, or None."""
    mp = os.path.join(root, "meta.json")
    if not os.path.exists(mp):
        return None
    with open(mp) as f:
        return json.load(f)


def load_session(sid: str) -> Optional[Session]:
    """Load a previously persisted session by id, or None."""
    root = os.path.join(config.sessions_dir(), sid)
    mp = os.path.join(root, "meta.json")
    if not os.path.exists(mp):
        return None
    meta = load_meta(root)
    if meta is None:
        return None
    return Session(
        sid=meta["sid"],
        root=root,
        upper=os.path.join(root, "upper"),
        work=os.path.join(root, "work"),
        stack=meta.get("stack", []),
    )


# ---------------------------------------------------------------------------
# Stack operations
# ---------------------------------------------------------------------------


def lower_stack(session: Session) -> list[str]:
    """Return the ordered lower-directory paths for *session*.

    Always starts with the immutable base rootfs, followed by each committed
    layer in stack order.
    """
    base = config.base_rootfs_path()
    layers_d = config.layers_dir()
    return [base] + [os.path.join(layers_d, cid) for cid in session.stack]


def commit(session: Session, message: str = "") -> LayerRef:
    """Snapshot the session upperdir into a new content-addressed layer.

    1. Compute ``commit_id = sha256(manifest(upper))``.
    2. If ``<layers-dir>/<commit_id>/`` already exists → dedupe (no copy).
    3. Otherwise ``cp/rsync`` upper → new layer dir.
    4. Append ``commit_id`` to ``session.stack``, persist meta.
    5. Wipe upper (recreate empty + workspace/).
    6. Update ``index.json`` refcounts.

    Returns a :class:`LayerRef`.
    """
    commit_id = _compute_commit_id(session.upper)
    layers_d = config.layers_dir()
    os.makedirs(layers_d, exist_ok=True)

    layer_path = os.path.join(layers_d, commit_id)
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    # Hold the index flock across the existence-check + copy + read-modify-write
    # so a concurrent gc() (which rmtree's only under the lock) cannot delete a
    # layer this commit is about to reference (M-2). Holding it across the copy
    # serializes concurrent commits — correctness over throughput.
    with _index_lock() as lf:
        if not os.path.exists(layer_path):
            os.makedirs(layer_path)
            _copy_upper_to_layer(session.upper, layer_path)
        size = _upper_size_bytes(layer_path)

        # Update index
        index = _load_index()
        entry = index.get(commit_id, {})
        if not entry:
            parent = session.stack[-1] if session.stack else None
            entry = {
                "refcount_sessions": 1,
                "refcount_layers": 0,
                "parent": parent,
                "message": message,
                "created_at": now,
                "size_bytes": size,
            }
            index[commit_id] = entry
            if parent and parent in index:
                index[parent]["refcount_layers"] = (
                    index[parent].get("refcount_layers", 0) + 1
                )
        else:
            entry["refcount_sessions"] = entry.get("refcount_sessions", 0) + 1
            if not entry.get("parent") and session.stack:
                entry["parent"] = session.stack[-1]
                if session.stack[-1] in index:
                    index[session.stack[-1]]["refcount_layers"] = (
                        index[session.stack[-1]].get("refcount_layers", 0) + 1
                    )
        _save_index(index, lock=lf)

    session.stack.append(commit_id)
    _persist_meta(session)

    # Wipe upper, recreate workspace
    _wipe_upper(session)
    _ensure_seeds(session)

    return LayerRef(
        commit_id=commit_id,
        path=layer_path,
        message=message,
        created_at=now,
        size_bytes=size,
    )


def _wipe_upper(session: Session):
    """Remove everything in upper, then recreate the directory."""
    if os.path.exists(session.upper):
        _rmtree_force(session.upper)
    os.makedirs(session.upper, exist_ok=True)
    # The provisioning seed mirrors base dirs into the upper; a fresh upper must
    # be re-seeded, so drop the seed-completion marker (config.SEED_MARKER).
    try:
        marker = os.path.join(session.root, config.SEED_MARKER)
        if os.path.exists(marker):
            os.unlink(marker)
    except OSError:
        pass


def _rmtree_force(path: str):
    """Remove a tree even if it contains read-only overlay workdir entries."""
    for _ in range(3):
        try:
            shutil.rmtree(path, onerror=_force_rmtree)
            return
        except OSError:
            continue


def _ensure_seeds(session: Session):
    """Recreate the writable session seed dirs (workspace/ + tmp/).

    The base rootfs is ``chmod -R a-w``, so its ``/workspace`` and ``/tmp`` are
    read-only. A fresh upper must seed writable copies of both so the overlay
    exposes them as writable container dirs (writes land in the upper).
    """
    os.makedirs(session.workspace, exist_ok=True)
    os.makedirs(session.tmp, exist_ok=True)


def rollback(session: Session, to_commit_id: str):
    """Truncate the session stack so it ends at *to_commit_id*.

    Raises ``ValueError`` if *to_commit_id* is not in the stack.
    """
    try:
        idx = session.stack.index(to_commit_id)
    except ValueError:
        raise ValueError(
            f"commit_id {to_commit_id!r} not in session stack"
        ) from None
    removed = session.stack[idx + 1:]
    session.stack = session.stack[: idx + 1]

    with _index_lock() as lf:
        index = _load_index()
        for cid in removed:
            if cid in index:
                index[cid]["refcount_sessions"] = max(
                    0, index[cid].get("refcount_sessions", 0) - 1
                )
        _save_index(index, lock=lf)

    _wipe_upper(session)
    _ensure_seeds(session)
    _persist_meta(session)


def reset(session: Session):
    """Wipe upper + work, KEEP the stack (this is env_reset / env_discard)."""
    _wipe_upper(session)
    if os.path.exists(session.work):
        _rmtree_force(session.work)
    os.makedirs(session.work, exist_ok=True)
    _ensure_seeds(session)


def destroy(session: Session):
    """Remove the entire session directory and decrement index refcounts."""
    with _index_lock() as lf:
        index = _load_index()
        for cid in session.stack:
            if cid in index:
                index[cid]["refcount_sessions"] = max(
                    0, index[cid].get("refcount_sessions", 0) - 1
                )
        _save_index(index, lock=lf)

    if os.path.exists(session.root):
        # The overlay workdir may contain read-only or nested entries after a
        # bwrap run; make it removable.
        _rmtree_force(session.root)


def dirty_file_count(session: Session) -> int:
    """Return the number of dirty (user-written) files in the upperdir."""
    return _dirty_file_count(session.upper)


def upper_size_bytes(session: Session) -> int:
    return _upper_size_bytes(session.upper)


def upper_stats(session: Session) -> tuple[int, int]:
    """Return ``(size_bytes, regular_file_count)`` for *session* with one walk."""
    return _upper_stats(session.upper)


# ---------------------------------------------------------------------------
# GC
# ---------------------------------------------------------------------------


def gc() -> list[str]:
    """Remove unreferenced layers and return the list of removed commit_ids.

    A layer is unreferenced when both ``refcount_sessions`` and
    ``refcount_layers`` are 0, and it is not referenced by any live session
    stack.  When a layer is removed, its parent's ``refcount_layers`` is
    decremented, potentially making the parent eligible on a subsequent pass.

    The index flock is held for the ENTIRE scan + rmtree + save so a concurrent
    commit cannot reference a layer this GC pass is deleting (M-2).
    """
    with _index_lock() as lf:
        index = _load_index()
        layers_d = config.layers_dir()

        # Collect all commit_ids referenced by live sessions
        sessions_d = config.sessions_dir()
        live_stack_ids: set[str] = set()
        if os.path.isdir(sessions_d):
            for name in os.listdir(sessions_d):
                meta = load_meta(os.path.join(sessions_d, name))
                if meta:
                    for cid in meta.get("stack", []):
                        live_stack_ids.add(cid)

        removed: list[str] = []
        changed = True
        while changed:
            changed = False
            to_remove = []
            for cid, entry in list(index.items()):
                if cid in live_stack_ids:
                    continue
                rc_s = entry.get("refcount_sessions", 0)
                rc_l = entry.get("refcount_layers", 0)
                if rc_s <= 0 and rc_l <= 0:
                    to_remove.append(cid)

            for cid in to_remove:
                entry = index.pop(cid, None)
                if entry is None:
                    continue
                parent = entry.get("parent")
                if parent and parent in index:
                    index[parent]["refcount_layers"] = max(
                        0, index[parent].get("refcount_layers", 0) - 1
                    )
                layer_path = os.path.join(layers_d, cid)
                if os.path.exists(layer_path):
                    shutil.rmtree(layer_path)
                removed.append(cid)
                changed = True

        _save_index(index, lock=lf)
    return removed


def snapshot_list(session: Session) -> list[LayerRef]:
    """Return committed layers for *session* as a list of :class:`LayerRef`."""
    index = _load_index()
    layers_d = config.layers_dir()
    result = []
    for cid in session.stack:
        entry = index.get(cid, {})
        result.append(
            LayerRef(
                commit_id=cid,
                path=os.path.join(layers_d, cid),
                message=entry.get("message", ""),
                created_at=entry.get("created_at", ""),
                size_bytes=entry.get("size_bytes", 0),
            )
        )
    return result
