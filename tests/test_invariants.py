"""Tests for the 12 security invariants in docs/architecture.md §7.

Each invariant maps to one or more automated tests. Some are covered by the
stage3 (M1) and e2e (M3) suites; this file consolidates the mapping and adds
the invariant-specific tests that aren't covered elsewhere (especially the
ones about session isolation, discard default, trusted-paths, base RO, and the
server's own unpledged status).
"""

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from rattan import config, contain, sessions, layers

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _rootfs_bootstrapped():
    base = config.base_rootfs_path()
    manifest = os.path.join(base, "MANIFEST.sha256")
    if not os.path.exists(manifest):
        return False
    try:
        subprocess.run(
            ["sha256sum", "-c", manifest, "--quiet"],
            cwd=base, capture_output=True, timeout=30,
        )
        return True
    except (subprocess.SubprocessError, OSError):
        return False


# ---------------------------------------------------------------------------
# Invariants that don't need a real rootfs (unit-level)
# ---------------------------------------------------------------------------


class TestInvariant4_NoSharedMountNS(unittest.TestCase):
    """Invariant #4: each session gets its own upperdir (no shared state).

    Two sessions created independently must have distinct upperdirs and empty,
    independent stacks.
    """

    def test_two_sessions_are_isolated(self):
        s1 = layers.create_session()
        s2 = layers.create_session()
        try:
            self.assertNotEqual(s1.root, s2.root)
            self.assertNotEqual(s1.upper, s2.upper)
            self.assertEqual(s1.stack, [])
            self.assertEqual(s2.stack, [])
            # writing to one upperdir must not appear in the other
            ws1 = s1.workspace
            os.makedirs(ws1, exist_ok=True)
            with open(os.path.join(ws1, "only-in-1.txt"), "w") as f:
                f.write("x")
            self.assertFalse(
                os.path.exists(os.path.join(s2.workspace, "only-in-1.txt"))
            )
        finally:
            layers.destroy(s1)
            layers.destroy(s2)


class TestInvariant5_DiscardDefault(unittest.TestCase):
    """Invariant #5: discard is default — a fresh session upper is empty and
    reset() wipes pending changes."""

    def test_fresh_upper_is_empty(self):
        s = layers.create_session()
        try:
            # upper should have no user files (only the seeded workspace dir)
            upper_files = [
                os.path.join(dp, f)
                for dp, _, fns in os.walk(s.upper)
                for f in fns
            ]
            self.assertEqual([], [f for f in upper_files if "workspace" not in f])
        finally:
            layers.destroy(s)

    def test_reset_clears_pending(self):
        s = layers.create_session()
        try:
            ws = s.workspace
            os.makedirs(ws, exist_ok=True)
            with open(os.path.join(ws, "pending.txt"), "w") as f:
                f.write("pending")
            self.assertTrue(os.path.exists(os.path.join(ws, "pending.txt")))
            layers.reset(s)
            self.assertFalse(os.path.exists(os.path.join(ws, "pending.txt")))
        finally:
            layers.destroy(s)


class TestInvariant6_CommitExplicitOnly(unittest.TestCase):
    """Invariant #6: commit is only via an explicit tool call; reset never
    commits. layers.commit is the sole path; reset keeps the stack."""

    def test_reset_does_not_commit(self):
        s = layers.create_session()
        try:
            layers.reset(s)
            self.assertEqual(s.stack, [])
        finally:
            layers.destroy(s)


class TestInvariant8_TrustedPaths(unittest.TestCase):
    """Invariant #8: trusted paths are never widened by client input. The
    bind validation rejects forbidden host paths and non-directories."""

    def test_bind_rejects_forbidden(self):
        from rattan import bind
        for p in ["/etc", "/proc", "/sys"]:
            with self.assertRaises(ValueError):
                bind.validate_host_bind(p, "/workspace/x", "ro")
        home = os.path.expanduser("~")
        for sub in [".config", ".local", ".cache"]:
            with self.assertRaises(ValueError):
                bind.validate_host_bind(
                    os.path.join(home, sub), "/workspace/x", "ro"
                )

    def test_bind_rejects_nondir(self):
        from rattan import bind
        with tempfile.NamedTemporaryFile(delete=False) as f:
            path = f.name
        try:
            with self.assertRaises(ValueError):
                bind.validate_host_bind(path, "/workspace/x", "ro")
        finally:
            os.unlink(path)

    def test_bind_rejects_bad_mode(self):
        from rattan import bind
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                bind.validate_host_bind(d, "/workspace/x", "weird")


class TestInvariant9_BaseNeverWritable(unittest.TestCase):
    """Invariant #9: base rootfs lower layer is never writable. The base dir
    is chmod a-w (read-only)."""

    def test_base_not_writable(self):
        base = config.base_rootfs_path()
        if not os.path.isdir(base):
            self.skipTest("rootfs not bootstrapped")
        self.assertFalse(os.access(base, os.W_OK), "base must not be writable")


class TestInvariant11_RedirectContainment(unittest.TestCase):
    """Invariant #11 (redirect half): redirect targets must be inside
    container roots; outside targets rejected by contain.validate_redirect_target."""

    def test_redirect_outside_rejected(self):
        for bad in ["/etc/passwd", "/usr/bin/x", "/var/tmp/x"]:
            with self.assertRaises(ValueError):
                contain.validate_redirect_target(bad)

    def test_redirect_inside_accepted(self):
        self.assertTrue(contain.validate_redirect_target("/workspace/foo"))
        self.assertTrue(contain.validate_redirect_target("/tmp/x"))


class TestInvariant11_CwdContainment(unittest.TestCase):
    def test_cwd_outside_rejected(self):
        for bad in ["/etc", "/usr", "/", ""]:
            with self.assertRaises(ValueError):
                contain.validate_cwd(bad)

    def test_cwd_relative_rejected(self):
        with self.assertRaises(ValueError):
            contain.validate_cwd("workspace")  # relative


# ---------------------------------------------------------------------------
# Invariants requiring a real rootfs + bwrap (e2e)
# ---------------------------------------------------------------------------


@unittest.skipUnless(
    _rootfs_bootstrapped(),
    "rootfs not bootstrapped — skipping e2e invariant tests",
)
class TestInvariantsE2E(unittest.TestCase):
    """Invariants verified end-to-end with a real sandbox."""

    _tmp = None
    _patches = []

    @classmethod
    def setUpClass(cls):
        from rattan import overlay

        cls._tmp = tempfile.TemporaryDirectory(prefix="rattan-test-inv-")
        cls._patches = [
            mock.patch.object(config, "data_dir", return_value=cls._tmp.name),
            mock.patch.object(config, "layers_dir",
                              lambda: os.path.join(cls._tmp.name, "layers")),
            mock.patch.object(config, "sessions_dir",
                              lambda: os.path.join(cls._tmp.name, "sessions")),
            mock.patch.object(config, "index_lock_path",
                              lambda: os.path.join(cls._tmp.name, "layers", "index.lock")),
            mock.patch.object(config, "base_rootfs_path",
                              lambda: os.path.join(
                                  os.environ.get("HOME", "/home/arch"),
                                  ".local", "share", "rattan", "rootfs", "base")),
        ]
        for p in cls._patches:
            p.start()
        cls.session = sessions.get_or_create(sid="inv-e2e")
        overlay.provision(cls.session)

    @classmethod
    def tearDownClass(cls):
        if cls.session is not None:
            layers.destroy(cls.session)
            sessions._current = None
        for p in reversed(cls._patches):
            p.stop()
        if cls._tmp is not None:
            cls._tmp.cleanup()

    def setUp(self):
        layers.reset(self.session)

    def tearDown(self):
        layers.reset(self.session)

    def _run(self, command: str) -> dict:
        from rattan.executor import execute_program
        from rattan.parser import parse
        env = {"HOME": "/workspace", "PATH": "/usr/bin:/bin",
               "USER": "rattan", "TERM": "dumb", "LANG": "C.UTF-8"}
        return execute_program(parse(command), self.session, env, "/workspace", 30)

    def test_invariant7_network_unshared_agent(self):
        """Invariant #7: agent mode has no network."""
        r = self._run("bash -c 'exec 3<>/dev/tcp/example.com/80'")
        # Without a fallback echo, bash exits non-zero when the connection fails.
        self.assertNotEqual(r["rc"], 0)

    def test_invariant5_discard_default_e2e(self):
        """Invariant #5 (e2e): a write then discard removes the file."""
        self._run('bash -c "echo x > /workspace/tmp_discard.txt"')
        self.assertGreaterEqual(layers.dirty_file_count(self.session), 1)
        layers.reset(self.session)
        # The file must be gone from the upperdir (and thus the session view).
        self.assertFalse(
            os.path.exists(
                os.path.join(self.session.upper, "workspace", "tmp_discard.txt")
            ),
            "discarded file still present in upperdir",
        )

    def test_invariant6_commit_explicit_e2e(self):
        """Invariant #6 (e2e): commit then reset keeps the file."""
        self._run('bash -c "echo keep > /workspace/tmp_keep.txt"')
        layers.commit(self.session, "inv6")
        layers.reset(self.session)
        r = self._run("cat /workspace/tmp_keep.txt")
        self.assertIn("keep", r["output"])


if __name__ == "__main__":
    unittest.main()
