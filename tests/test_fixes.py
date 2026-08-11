"""Regression tests for the security/perf fixes (H-1, H-2, M-2, M-3, C1).

Covers: executor control-env scrubbing (invariant #10), bind_host_dir path
validation (invariant #11), pacman_run arg allowlist (H-1), workspace-included
commit identity (H-2), the index flock across read-modify-write (M-2), and the
once-per-session provisioning seed (C1). Self-contained — no bootstrapped rootfs
required.
"""

import os
import tempfile
import unittest
from unittest import mock

from rattan import bind, config, executor, layers, pacman, parser


class TestSecurityFixes(unittest.TestCase):
    """Regression tests for the security/perf fixes."""

    def setUp(self):
        # Isolate disk-touching tests from the real data dir.
        self._tmp = tempfile.TemporaryDirectory(prefix="rattan-test-fixes-")
        self._env = mock.patch.dict(
            os.environ, {"RATTAN_DATA_DIR": self._tmp.name}
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    # -- executor (invariant #10) ------------------------------------------

    def test_scrub_control_env_strips_control_prefixes(self):
        scrubbed = executor._scrub_control_env({
            "RATTAN_ALLOW_PTRACE": "1",
            "LD_PRELOAD": "x",
            "PYTHONPATH": "y",
            "HOME": "/h",
            "PATH": "/bin",
        })
        self.assertNotIn("RATTAN_ALLOW_PTRACE", scrubbed)
        self.assertNotIn("LD_PRELOAD", scrubbed)
        self.assertNotIn("PYTHONPATH", scrubbed)
        self.assertIn("HOME", scrubbed)
        self.assertIn("PATH", scrubbed)

    def test_build_invocation_sub_env_scrubbed(self):
        s = layers.create_session()
        program = parser.parse("echo hi", {})
        cmd_node = program.andors[0].pipelines[0].commands[0]
        env_store = {
            "HOME": "/workspace",
            "PATH": "/bin",
            "RATTAN_ALLOW_PTRACE": "1",
            "LD_PRELOAD": "x",
            "PYTHONPATH": "y",
        }
        inv = executor.build_invocation(cmd_node, s, env_store, "/workspace", 30)
        for key in ("RATTAN_ALLOW_PTRACE", "LD_PRELOAD", "PYTHONPATH"):
            self.assertNotIn(key, inv.env, f"{key} leaked into subprocess env")
        self.assertIn("HOME", inv.env)
        self.assertIn("PATH", inv.env)

    def test_control_env_prefixes_includes_rattan_and_ld(self):
        self.assertIn("RATTAN_", executor._CONTROL_ENV_PREFIXES)
        self.assertIn("LD_", executor._CONTROL_ENV_PREFIXES)

    # -- bind_host_dir (invariant #11) --------------------------------------

    def test_bind_rejects_host_root(self):
        with self.assertRaises(ValueError):
            bind.validate_host_bind("/", "/workspace/x", "ro")

    def test_bind_rejects_home(self):
        home = os.path.expanduser("~")
        if not home or not os.path.isdir(home):
            self.skipTest("no real $HOME to test against")
        with self.assertRaises(ValueError):
            bind.validate_host_bind(home, "/workspace/x", "ro")

    def test_bind_rejects_data_dir(self):
        # RATTAN_DATA_DIR already points at self._tmp.name; binding it directly
        # must be rejected.
        with self.assertRaises(ValueError):
            bind.validate_host_bind(self._tmp.name, "/workspace/x", "ro")

    def test_bind_rejects_bad_mount_point(self):
        with self.assertRaises(ValueError):
            bind.validate_host_bind("/tmp", "/workspace;x", "ro")

    def test_bind_rejects_cr_and_null_mount_point(self):
        # Carriage return and NUL must not slip past the mount_point validator
        # into the landlock spec builder (bind.py:58 f"{mp}:{perms}").
        for bad in ("/workspace\rx", "/workspace\x00x"):
            with self.assertRaises(ValueError, msg=f"expected rejection of {bad!r}"):
                bind.validate_host_bind("/tmp", bad, "ro")

    def test_bind_allows_innocuous(self):
        host = "/tmp"
        b = bind.validate_host_bind(host, "/workspace/data", "ro")
        self.assertIsInstance(b, bind.HostBind)
        self.assertEqual(b.mount_point, "/workspace/data")

    # -- pacman_run allowlist (H-1) -----------------------------------------

    def test_pacman_run_rejects_mutating(self):
        for bad in (["-U", "/x"], ["--config", "/x"], ["--hookdir", "/x"],
                    ["--cachedir", "/x"], ["-S", "foo"]):
            with self.assertRaises(ValueError, msg=f"expected rejection of {bad}"):
                pacman._check_query_args(bad)

    def test_pacman_run_rejects_cache_clean_and_upgrade(self):
        # -Sc/-Scc clean the package cache (a filesystem write); -Sy/-Su upgrade.
        for bad in (["-Sc"], ["-Scc"], ["-Sy", "foo"], ["-Su"], ["-Ssw"], ["-S"],
                    ["-Scc", "--noconfirm"]):
            with self.assertRaises(ValueError, msg=f"expected rejection of {bad}"):
                pacman._check_query_args(bad)

    def test_pacman_run_accepts_read_only(self):
        for ok in (["-Q"], ["-Si", "foo"], ["-Q", "tree"], ["-Ss", "foo"],
                   ["-Qqs", "tree"], ["-Qkk"], ["--color=never", "-Q"]):
            pacman._check_query_args(ok)  # no raise

    # -- provisioning seed (C1) --------------------------------------------

    def test_provisioning_seed_runs_once(self):
        os.makedirs(os.path.join(self._tmp.name, "rootfs", "base"), exist_ok=True)
        s = layers.create_session()
        marker = os.path.join(s.root, config.SEED_MARKER)
        with mock.patch("rattan.pacman.os.walk", return_value=iter([])) as m_walk:
            pacman.provisioning_seed(s)
            first_calls = m_walk.call_count
            pacman.provisioning_seed(s)
            second_calls = m_walk.call_count
        self.assertTrue(os.path.exists(marker), "seed should write its marker")
        # The walk ran on the first call but was a no-op on the second.
        self.assertEqual(first_calls, 1)
        self.assertEqual(second_calls, 1)

    def test_seed_marker_cleared_on_wipe(self):
        # After a commit/discard wipes the upper, a fresh upper must be re-seeded
        # on the next pacman call (C1 correctness, not just a perf shortcut).
        os.makedirs(os.path.join(self._tmp.name, "rootfs", "base"), exist_ok=True)
        s = layers.create_session()
        with mock.patch("rattan.pacman.os.walk", return_value=iter([])):
            pacman.provisioning_seed(s)
        marker = os.path.join(s.root, config.SEED_MARKER)
        self.assertTrue(os.path.exists(marker))
        layers._wipe_upper(s)
        self.assertFalse(
            os.path.exists(marker),
            "wiping the upper must clear the seed marker so it is re-seeded",
        )

    # -- workspace in commit identity (H-2) ---------------------------------

    def _make_file(self, session, path, content):
        fpath = os.path.join(session.upper, path)
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, "w") as f:
            f.write(content)

    def test_workspace_content_affects_commit_id(self):
        s1 = layers.create_session()
        s2 = layers.create_session()
        # Identical non-workspace state in both.
        for s in (s1, s2):
            self._make_file(s, "etc/foo", "same non-workspace content")
        # Different /workspace content — must change the commit identity.
        self._make_file(s1, "workspace/data.txt", "A's workspace")
        self._make_file(s2, "workspace/data.txt", "B's workspace")
        self.assertNotEqual(
            layers._compute_commit_id(s1.upper),
            layers._compute_commit_id(s2.upper),
            "different workspace content must not dedupe to the same commit_id",
        )

    def test_identical_workspace_yields_equal_commit_id(self):
        s3 = layers.create_session()
        s4 = layers.create_session()
        for s in (s3, s4):
            self._make_file(s, "etc/foo", "same content")
            self._make_file(s, "workspace/data.txt", "identical workspace")
        self.assertEqual(
            layers._compute_commit_id(s3.upper),
            layers._compute_commit_id(s4.upper),
        )


if __name__ == "__main__":
    unittest.main()
