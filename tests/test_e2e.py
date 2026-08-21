"""End-to-end tests for the agent-mode sandbox.

These tests require a bootstrapped rootfs, a built stage3 binary, and the
bwrap binary on the host.  All tests are skipped when any prerequisite is
missing, mirroring the ``test_bootstrap.py`` skip pattern.
"""

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from rattan import config

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _has_binary(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)


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


def _prerequisites_met():
    """All conditions must hold for the e2e tests to run."""
    if not _has_binary(config.stage3_path()):
        return False
    if not _rootfs_bootstrapped():
        return False
    try:
        result = subprocess.run(
            ["bwrap", "--version"], capture_output=True, timeout=5
        )
        if result.returncode != 0:
            return False
        # Also check bwrap can actually create a namespace (not blocked by seccomp)
        result2 = subprocess.run(
            ["bwrap", "--unshare-all", "--uid", "1000", "--gid", "1000",
             "--ro-bind", "/", "/", "--", "/bin/true"],
            capture_output=True, timeout=10,
        )
        return result2.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


@unittest.skipUnless(
    _prerequisites_met(),
    "prerequisites not met: need built stage3, bootstrapped rootfs, and bwrap "
    "(run 'make stage3' and/or 'make bootstrap-rootfs')",
)
class TestE2EAgentMode(unittest.TestCase):
    """Full round-trip through the executor in agent mode."""

    _tmp = None
    _patches = []

    @classmethod
    def setUpClass(cls):
        from rattan import layers, overlay, sessions

        cls._tmp = tempfile.TemporaryDirectory(prefix="rattan-test-e2e-real-")
        cls._patches = [
            mock.patch.object(config, "data_dir", return_value=cls._tmp.name),
            mock.patch.object(config, "layers_dir",
                              lambda: os.path.join(cls._tmp.name, "layers")),
            mock.patch.object(config, "sessions_dir",
                              lambda: os.path.join(cls._tmp.name, "sessions")),
            mock.patch.object(config, "index_lock_path",
                              lambda: os.path.join(cls._tmp.name, "layers", "index.lock")),
            # The REAL bootstrapped base rootfs must be the overlay lower — do NOT
            # point base_rootfs_path at the temp dir (that would make the container
            # root empty and every command fail with "unveil(/usr,...): no such file").
            mock.patch.object(config, "base_rootfs_path",
                              lambda: os.path.join(
                                  os.environ.get("HOME", "/home/arch"),
                                  ".local", "share", "rattan", "rootfs", "base")),
        ]
        for p in cls._patches:
            p.start()

        cls.session = sessions.get_or_create(sid="e2e-test")
        overlay.provision(cls.session)

    @classmethod
    def tearDownClass(cls):
        from rattan import layers, sessions

        if hasattr(cls, "session") and cls.session is not None:
            layers.destroy(cls.session)
            sessions._current = None
        for p in reversed(cls._patches):
            p.stop()
        if cls._tmp is not None:
            cls._tmp.cleanup()

    def _run(self, command: str, cwd="/workspace", timeout=30) -> dict:
        from rattan.executor import execute_program
        from rattan.parser import parse

        env_store = {
            "HOME": "/workspace",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "USER": "rattan",
            "TERM": "dumb",
            "LANG": "C.UTF-8",
        }
        program = parse(command)
        return execute_program(program, self.session, env_store, cwd, timeout)

    def setUp(self):
        # Fresh, empty session per test so tests don't interfere via shared
        # upper/stack state (the class-level session is reused across tests).
        from rattan import layers
        layers.reset(self.session)

    def tearDown(self):
        from rattan import layers
        layers.reset(self.session)

    def test_echo(self):
        result = self._run("echo hello")
        self.assertEqual(result["rc"], 0)
        self.assertIn("hello", result["output"])

    def test_cd_then_command(self):
        """`cd X && command` runs the command from X (in-process builtin)."""
        # Write a marker in /workspace, then cd into /workspace and pwd.
        self._run("cd /tmp && pwd")
        result = self._run("cd /tmp && pwd")
        self.assertEqual(result["rc"], 0)
        self.assertIn("/tmp", result["output"])

    def test_cd_relative_chain(self):
        """`cd X && command` resolves relative targets against the prior cwd."""
        result = self._run("cd /workspace && cd tmp && pwd")
        # /workspace/tmp may not exist; cd is a pure path builtin and does not
        # check existence (matching a stateless per-call cd). Just verify it
        # resolved to /workspace/tmp without error.
        self.assertEqual(result["rc"], 0)
        self.assertIn("/workspace/tmp", result["output"])

    def test_cd_rejects_outside_roots(self):
        """`cd /etc && command` short-circuits with rc 1; command not run."""
        result = self._run("cd /etc && echo SHOULD_NOT_RUN")
        self.assertNotEqual(result["rc"], 0)
        self.assertNotIn("SHOULD_NOT_RUN", result["output"])

    def test_discard_default(self):
        """Write a file, discard, verify it's gone."""
        from rattan import layers

        self._run('bash -c "echo dirty > /workspace/dirty.txt"')
        # Check dirty count
        dirty = layers.dirty_file_count(self.session)
        self.assertGreater(dirty, 0, "File write should make session dirty")

        # Discard
        layers.reset(self.session)
        # Verify
        result = self._run("test -f /workspace/dirty.txt && echo EXISTS || echo GONE")
        self.assertIn("GONE", result["output"])

    def test_commit_survives_reset(self):
        """Commit a file, reset, verify the file survives."""
        from rattan import layers

        self._run('bash -c "echo committed > /workspace/committed.txt"')
        ref = layers.commit(self.session, message="test commit")

        # Reset
        layers.reset(self.session)

        # File should survive because it's in a committed layer
        result = self._run("cat /workspace/committed.txt")
        self.assertIn("committed", result["output"])

        # Clean up: rollback
        layers.rollback(self.session, ref.commit_id)

    def test_rollback(self):
        """Commit layer A, commit layer B, rollback to A, verify B is gone."""
        from rattan import layers

        self._run('bash -c "echo A > /workspace/rollback_test.txt"')
        ref_a = layers.commit(self.session, message="layer A")

        self._run('bash -c "echo B > /workspace/rollback_test.txt"')
        ref_b = layers.commit(self.session, message="layer B")

        # Rollback to A
        layers.rollback(self.session, ref_a.commit_id)
        result = self._run("cat /workspace/rollback_test.txt")
        self.assertIn("A", result["output"])
        self.assertNotIn("B", result["output"])

    def test_write_outside_workspace_rejected(self):
        """Writing outside /workspace or /tmp should fail (landlock/seccomp)."""
        from rattan import layers
        # Try writing to /etc — landlock denies it (spec has /etc:r)
        self._run('bash -c "echo x > /etc/should_fail 2>&1 || true"')
        # The write must NOT have landed (neither in the container nor the upper).
        self.assertEqual(
            layers.dirty_file_count(self.session), 0,
            "write to /etc must be denied by landlock (no dirty files)",
        )


class TestE2EUnit(unittest.TestCase):
    """Unit-level e2e tests that don't need a real rootfs."""

    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory(prefix="rattan-test-e2e-")
        self._patches = [
            mock.patch.object(config, "data_dir", return_value=self._tmp.name),
            mock.patch.object(config, "layers_dir",
                              lambda: os.path.join(self._tmp.name, "layers")),
            mock.patch.object(config, "sessions_dir",
                              lambda: os.path.join(self._tmp.name, "sessions")),
            mock.patch.object(config, "index_lock_path",
                              lambda: os.path.join(self._tmp.name, "layers", "index.lock")),
            mock.patch.object(config, "base_rootfs_path",
                              lambda: os.path.join(self._tmp.name, "rootfs", "base")),
        ]
        for p in self._patches:
            p.start()
        os.makedirs(os.path.join(self._tmp.name, "rootfs", "base"), exist_ok=True)

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        self._tmp.cleanup()

    def test_empty_invocation(self):
        from rattan.parser import CommandNode
        from rattan.executor import EmptyInvocation, build_invocation
        from rattan import layers

        s = layers.create_session()
        cmd = CommandNode(argv=(), redirects=(), assignments=())
        with self.assertRaises(EmptyInvocation):
            build_invocation(cmd, s, {}, "/workspace", 30)
        layers.destroy(s)


if __name__ == "__main__":
    unittest.main()
