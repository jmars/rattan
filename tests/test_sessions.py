"""Unit tests for the session registry (sessions.py)."""

import os
import tempfile
import unittest
from unittest import mock

from rattan import config, layers, sessions


def _simple_copytree(src, dst):
    """Copy src to dst preserving only file content and directory structure."""
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


class TestSessions(unittest.TestCase):
    """Session registry tests using a temp data dir."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="rattan-test-sessions-")
        self.data_dir = self._tmp.name
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
            mock.patch.object(layers, "_copy_upper_to_layer",
                              side_effect=_simple_copytree),
        ]
        for p in self._patches:
            p.start()
        os.makedirs(os.path.join(self.data_dir, "rootfs", "base"), exist_ok=True)
        sessions._current = None

    def tearDown(self):
        sessions._current = None
        for p in reversed(self._patches):
            p.stop()
        self._tmp.cleanup()

    def test_get_or_create(self):
        s = sessions.get_or_create()
        self.assertIsNotNone(s)
        self.assertTrue(os.path.isdir(s.root))
        self.assertTrue(os.path.isfile(s.meta_path))

    def test_get_or_create_returns_same(self):
        s1 = sessions.get_or_create()
        s2 = sessions.get_or_create()
        self.assertIs(s1, s2)
        self.assertEqual(s1.sid, s2.sid)

    def test_current(self):
        self.assertIsNone(sessions.current())
        s = sessions.get_or_create()
        self.assertIs(sessions.current(), s)

    def test_load_existing(self):
        s1 = sessions.get_or_create(sid="test-sid")
        sessions._current = None  # force reload
        s2 = sessions.get_or_create(sid="test-sid")
        self.assertEqual(s1.sid, s2.sid)
        self.assertEqual(s1.root, s2.root)

    def test_destroy_all_on_shutdown(self):
        s = sessions.get_or_create()
        self.assertTrue(os.path.isdir(s.root))
        sessions.destroy_all_on_shutdown()
        self.assertFalse(os.path.exists(s.root))
        self.assertIsNone(sessions.current())

    def test_meta_persistence(self):
        s = sessions.get_or_create()
        # Commit something to add to stack
        fpath = os.path.join(s.upper, "test.txt")
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, "w") as f:
            f.write("hello")
        ref = layers.commit(s, message="test")
        self.assertIn(ref.commit_id, s.stack)

        # Reload and check meta
        meta = layers.load_meta(s.root)
        self.assertIsNotNone(meta)
        self.assertEqual(meta["sid"], s.sid)
        self.assertIn(ref.commit_id, meta["stack"])


if __name__ == "__main__":
    unittest.main()
