"""Unit tests for the session layer stack (layers.py)."""

import os
import shutil
import tempfile
import unittest
from unittest import mock

from rattan import config, layers


def _simple_copytree(src, dst):
    """Copy src to dst preserving only file content and directory structure.

    Does NOT attempt to preserve permissions, ACLs, or xattrs (works under
    restrictive seccomp filters).
    """
    if not os.path.isdir(src):
        return
    os.makedirs(dst, exist_ok=True)
    for entry in os.listdir(src):
        s = os.path.join(src, entry)
        d = os.path.join(dst, entry)
        if os.path.isdir(s):
            _simple_copytree(s, d)
        elif os.path.islink(s):
            linkto = os.readlink(s)
            if os.path.exists(d):
                os.remove(d)
            os.symlink(linkto, d)
        else:
            with open(s, "rb") as fsrc:
                with open(d, "wb") as fdst:
                    fdst.write(fsrc.read())


class TestLayerStack(unittest.TestCase):
    """Commit / rollback / reset / dedupe / GC tests using temp dirs."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="rattan-test-layers-")
        self.data_dir = self._tmp.name
        # Patch config functions to point into the temp dir
        self._patches = [
            mock.patch.object(config, "data_dir", return_value=self.data_dir),
            mock.patch.object(config, "layers_dir",
                              lambda: os.path.join(self.data_dir, "layers")),
            mock.patch.object(config, "sessions_dir",
                              lambda: os.path.join(self.data_dir, "sessions")),
            mock.patch.object(config, "index_lock_path",
                              lambda: os.path.join(self.data_dir, "layers", "index.lock")),
            mock.patch.object(config, "base_rootfs_path",
                              lambda: os.path.join(self.data_dir, "rootfs", "base")),
            # Mock _copy_upper_to_layer to avoid rsync/cp/chmod failures
            mock.patch.object(layers, "_copy_upper_to_layer",
                              side_effect=_simple_copytree),
        ]
        for p in self._patches:
            p.start()

        os.makedirs(os.path.join(self.data_dir, "rootfs", "base"), exist_ok=True)

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        self._tmp.cleanup()

    def _make_file(self, session, path, content="hello"):
        """Create a file inside the session's upperdir."""
        fpath = os.path.join(session.upper, path)
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, "w") as f:
            f.write(content)

    def _read_file(self, session, path):
        with open(os.path.join(session.upper, path)) as f:
            return f.read()

    def test_create_session(self):
        s = layers.create_session()
        self.assertTrue(os.path.isdir(s.upper))
        self.assertTrue(os.path.isdir(s.work))
        self.assertTrue(os.path.isdir(s.workspace))
        self.assertEqual(s.stack, [])

    def test_lower_stack_base_only(self):
        s = layers.create_session()
        lowers = layers.lower_stack(s)
        self.assertEqual(len(lowers), 1)
        self.assertTrue(lowers[0].endswith("rootfs/base"))

    def test_commit_creates_layer(self):
        s = layers.create_session()
        self._make_file(s, "test.txt", "hello commit")
        ref = layers.commit(s, message="first commit")

        # Check the layer exists on disk
        self.assertTrue(os.path.isdir(ref.path))
        self.assertTrue(os.path.isfile(os.path.join(ref.path, "test.txt")))
        self.assertEqual(ref.message, "first commit")

        # Stack was advanced
        self.assertEqual(s.stack, [ref.commit_id])
        self.assertEqual(len(layers.lower_stack(s)), 2)  # base + layer

    def test_commit_wipe_upper(self):
        s = layers.create_session()
        self._make_file(s, "test.txt")
        layers.commit(s)
        # Upper should be clean (only workspace/)
        self.assertFalse(os.path.exists(os.path.join(s.upper, "test.txt")))
        self.assertTrue(os.path.isdir(s.workspace))

    def test_commit_dedupe(self):
        s = layers.create_session()
        self._make_file(s, "file.txt", "content A")
        ref1 = layers.commit(s, message="first")

        # Make the same content again
        self._make_file(s, "file.txt", "content A")
        ref2 = layers.commit(s, message="second")

        # Same commit_id
        self.assertEqual(ref1.commit_id, ref2.commit_id)
        # Stack has the same commit twice (deduplicated on disk)
        self.assertEqual(s.stack, [ref1.commit_id, ref1.commit_id])

    def test_commit_different_content(self):
        s = layers.create_session()
        self._make_file(s, "f.txt", "A")
        ref1 = layers.commit(s)

        self._make_file(s, "f.txt", "B")
        ref2 = layers.commit(s)

        self.assertNotEqual(ref1.commit_id, ref2.commit_id)
        self.assertEqual(len(s.stack), 2)

    def test_rollback_truncate(self):
        s = layers.create_session()
        self._make_file(s, "f1.txt")
        ref1 = layers.commit(s)

        self._make_file(s, "f2.txt")
        ref2 = layers.commit(s)

        self._make_file(s, "f3.txt")
        ref3 = layers.commit(s)

        self.assertEqual(len(s.stack), 3)

        layers.rollback(s, ref1.commit_id)
        self.assertEqual(len(s.stack), 1)
        self.assertEqual(s.stack[0], ref1.commit_id)

    def test_rollback_nonexistent(self):
        s = layers.create_session()
        with self.assertRaises(ValueError):
            layers.rollback(s, "nonexistent")

    def test_reset_keeps_stack(self):
        s = layers.create_session()
        self._make_file(s, "f.txt")
        ref = layers.commit(s)

        self._make_file(s, "dirty.txt")
        layers.reset(s)

        # Stack preserved
        self.assertEqual(s.stack, [ref.commit_id])
        # Dirty file gone
        self.assertFalse(os.path.exists(os.path.join(s.upper, "dirty.txt")))
        # workspace still exists
        self.assertTrue(os.path.isdir(s.workspace))

    def test_destroy(self):
        s = layers.create_session()
        root = s.root
        self.assertTrue(os.path.isdir(root))
        layers.destroy(s)
        self.assertFalse(os.path.exists(root))

    def test_dirty_file_count(self):
        s = layers.create_session()
        self.assertEqual(layers.dirty_file_count(s), 0)
        self._make_file(s, "a.txt")
        self._make_file(s, "b.txt")
        self.assertEqual(layers.dirty_file_count(s), 2)
        # Workspace files DO count as dirty — a write there is an uncommitted
        # change and must make env_status report the session as dirty.
        self._make_file(s, "workspace/c.txt")
        self.assertEqual(layers.dirty_file_count(s), 3)

    def test_upper_size_bytes(self):
        s = layers.create_session()
        self._make_file(s, "big.txt", "x" * 100)
        self.assertGreater(layers.upper_size_bytes(s), 90)

    def test_gc_removes_unreferenced(self):
        s = layers.create_session()
        self._make_file(s, "f.txt", "A")
        ref1 = layers.commit(s)

        self._make_file(s, "f.txt", "B")
        ref2 = layers.commit(s)

        # Destroy the session → decrements refcounts
        layers.destroy(s)

        removed = layers.gc()
        # Both layers should be removed (no session references them)
        self.assertIn(ref1.commit_id, removed)
        self.assertIn(ref2.commit_id, removed)

    def test_gc_keeps_referenced(self):
        s = layers.create_session()
        self._make_file(s, "f.txt", "A")
        ref = layers.commit(s)

        removed = layers.gc()
        # Layer is referenced by s, so not removed
        self.assertNotIn(ref.commit_id, removed)

        layers.destroy(s)
        removed2 = layers.gc()
        self.assertIn(ref.commit_id, removed2)

    def test_manifest_deterministic(self):
        s = layers.create_session()
        self._make_file(s, "a.txt", "hello")
        self._make_file(s, "b.txt", "world")
        manifest1 = layers._compute_manifest(s.upper)

        # Rebuild same state in a new session
        s2 = layers.create_session()
        self._make_file(s2, "b.txt", "world")
        self._make_file(s2, "a.txt", "hello")
        manifest2 = layers._compute_manifest(s2.upper)

        self.assertEqual(manifest1, manifest2)
        self.assertEqual(
            layers._compute_commit_id(s.upper),
            layers._compute_commit_id(s2.upper),
        )

    def test_snapshot_list(self):
        s = layers.create_session()
        self._make_file(s, "f.txt")
        ref = layers.commit(s, message="test")

        snapshots = layers.snapshot_list(s)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0].commit_id, ref.commit_id)
        self.assertEqual(snapshots[0].message, "test")

    def test_load_save_session(self):
        s = layers.create_session()
        self._make_file(s, "f.txt")
        ref = layers.commit(s)
        sid = s.sid

        loaded = layers.load_session(sid)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.sid, sid)
        self.assertEqual(loaded.stack, [ref.commit_id])


if __name__ == "__main__":
    unittest.main()
