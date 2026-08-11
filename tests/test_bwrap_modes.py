"""Tests for the bwrap argv builder (agent vs provisioning modes)."""

import os
import unittest

from rattan import bwrap, layers, overlay, policy


class TestBwrapAgentArgv(unittest.TestCase):
    """Verify the agent-mode bwrap argv shape."""

    def setUp(self):
        # Create a minimal in-memory session representation
        self.session = layers.Session(
            sid="test",
            root="/tmp/rattan-test/sessions/test",
            upper="/tmp/rattan-test/sessions/test/upper",
            work="/tmp/rattan-test/sessions/test/work",
            stack=[],
        )
        # We need to mock config.stage3_path
        import rattan.config as cfg
        self._stage3_patch = unittest.mock.patch.object(
            cfg, "stage3_path", return_value="/repo/bin/stage3"
        )
        self._stage3_patch.start()

        # Mock base_rootfs_path
        self._base_patch = unittest.mock.patch.object(
            cfg, "base_rootfs_path",
            return_value="/data/rootfs/base"
        )
        self._base_patch.start()

    def tearDown(self):
        self._stage3_patch.stop()
        self._base_patch.stop()

    def test_agent_argv_shape(self):
        resolved = policy.ResolvedPolicy(
            promises=policy.AGENT_BASELINE_PROMISES,
            landlock_spec="",
            rlimits="",
            allow_ptrace=False,
        )
        argv = bwrap.agent_argv(
            self.session,
            resolved,
            ["echo", "hello"],
            cwd="/workspace",
        )

        # Verify key elements
        self.assertEqual(argv[0], "bwrap")
        self.assertIn("--unshare-all", argv)
        self.assertIn("--uid", argv)
        self.assertIn("1000", argv)
        self.assertIn("--gid", argv)
        # Check overlay mounting
        self.assertIn("--overlay-src", argv)
        self.assertIn("--overlay", argv)
        self.assertIn("/", argv)  # mount at /
        # Runtime mounts
        self.assertIn("--proc", argv)
        self.assertIn("/proc", argv)
        self.assertIn("--dev", argv)
        self.assertIn("/dev", argv)
        self.assertIn("--tmpfs", argv)
        self.assertIn("/tmp", argv)
        # Stage3
        self.assertIn("--ro-bind", argv)
        self.assertIn("/repo/bin/stage3", argv)
        self.assertIn("/init", argv)
        # Working dir
        self.assertIn("--dir", argv)
        self.assertIn("/workspace", argv)
        # Separator
        self.assertIn("--", argv)
        # Init args: find /init after the first bare "--"
        dash_idx = argv.index("--")
        init_idx = argv.index("/init", dash_idx)
        self.assertGreater(init_idx, dash_idx)
        promises_idx = init_idx + 1
        self.assertIn("stdio", argv[promises_idx])
        # Landlock spec is after promises, before the last --
        dash_indices = [i for i, a in enumerate(argv) if a == "--"]
        user_cmd_idx = dash_indices[-1] + 1
        self.assertEqual(argv[user_cmd_idx], "echo")
        self.assertEqual(argv[user_cmd_idx + 1], "hello")

    def test_no_share_net(self):
        resolved = policy.ResolvedPolicy(
            promises=policy.AGENT_BASELINE_PROMISES,
            landlock_spec="",
            rlimits="",
            allow_ptrace=False,
        )
        argv = bwrap.agent_argv(self.session, resolved, ["true"])
        self.assertNotIn("--share-net", argv)
        self.assertIn("--unshare-all", argv)

    def test_provisioning_raises(self):
        with self.assertRaises(NotImplementedError):
            bwrap.provisioning_argv()

    def test_baseline_promises_match_stage3(self):
        """AGENT_BASELINE_PROMISES must exactly match stage3.c BASELINE_PROMISES."""
        import re

        repo_root = os.path.join(os.path.dirname(__file__), "..")
        stage3_src = os.path.join(repo_root, "src", "rattan", "stage3.c")
        with open(stage3_src) as f:
            source = f.read()

        m = re.search(
            r'#define\s+BASELINE_PROMISES\s+"([^"]+)"',
            source,
        )
        self.assertIsNotNone(m, "BASELINE_PROMISES not found in stage3.c")
        c_promises = m.group(1)
        self.assertEqual(
            policy.AGENT_BASELINE_PROMISES,
            c_promises,
            "AGENT_BASELINE_PROMISES in policy.py must match BASELINE_PROMISES "
            "in stage3.c",
        )

    def test_baseline_landlock_spec(self):
        """AGENT_BASELINE_LANDLOCK must contain required paths."""
        spec = policy.AGENT_BASELINE_LANDLOCK
        required = ["/workspace", "/tmp", "/usr", "/bin", "/lib", "/proc", "/etc", "/dev"]
        for r in required:
            self.assertIn(r, spec, f"{r!r} should be in AGENT_BASELINE_LANDLOCK")


if __name__ == "__main__":
    unittest.main()
