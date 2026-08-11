"""Tests for pacman provisioning mode — mirror validation + e2e install."""

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from rattan import config, pacman

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ---------------------------------------------------------------------------
# Mirror validation (unit — no rootfs needed)
# ---------------------------------------------------------------------------


class TestMirrorValidation(unittest.TestCase):
    def _accept(self, url):
        self.assertEqual(pacman.validate_mirror(url), url)

    def _reject(self, url):
        with self.assertRaises(ValueError):
            pacman.validate_mirror(url)

    def test_valid_official(self):
        self._accept("https://geo.mirror.pkgbuild.com/$repo/os/$arch")

    def test_valid_tier1(self):
        self._accept("https://mirror.rackspace.com/archlinux/$repo/os/$arch")

    def test_valid_kernel_org(self):
        self._accept("https://mirrors.kernel.org/archlinux/$repo/os/$arch")

    def test_valid_archlinux_org(self):
        self._accept("https://archlinux.org/$repo/os/$arch")

    def test_valid_country_mirror(self):
        self._accept("https://mirror.archlinux.de/$repo/os/$arch")

    def test_valid_with_port(self):
        self._accept("https://geo.mirror.pkgbuild.com:443/$repo/os/$arch")

    def test_http_rejected(self):
        self._reject("http://geo.mirror.pkgbuild.com/$repo/os/$arch")

    def test_ip_rejected(self):
        self._reject("https://1.2.3.4/archlinux/$repo/os/$arch")

    def test_random_domain_rejected(self):
        self._reject("https://evil.com/archlinux/$repo/os/$arch")

    def test_subdomain_random_rejected(self):
        self._reject("https://pkgbuild.com.evil.com/$repo/os/$arch")

    def test_credentials_rejected(self):
        self._reject("https://user:pass@geo.mirror.pkgbuild.com/$repo/os/$arch")

    def test_path_traversal_rejected(self):
        self._reject("https://geo.mirror.pkgbuild.com/../../etc/passwd")

    def test_empty_rejected(self):
        self._reject("")


# ---------------------------------------------------------------------------
# Check packages
# ---------------------------------------------------------------------------


class TestCheckPackages(unittest.TestCase):
    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            pacman._check_packages([])

    def test_flag_rejected(self):
        with self.assertRaises(ValueError):
            pacman._check_packages(["-Sy"])

    def test_mixed_flag_rejected(self):
        with self.assertRaises(ValueError):
            pacman._check_packages(["hello", "--noconfirm"])

    def test_valid_ok(self):
        pacman._check_packages(["tree", "jq"])  # no raise


# ---------------------------------------------------------------------------
# E2E (requires bootstrapped rootfs + network)
# ---------------------------------------------------------------------------


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


@unittest.skipUnless(
    _rootfs_bootstrapped(),
    "rootfs not bootstrapped — run 'make bootstrap-rootfs' — skipping",
)
class TestPacmanE2E(unittest.TestCase):
    """End-to-end provisioning tests. Requires network access."""

    _tmp = None
    _patches = []

    @classmethod
    def setUpClass(cls):
        from rattan import overlay, sessions

        cls._tmp = tempfile.TemporaryDirectory(prefix="rattan-test-pacman-")
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
        cls.session = sessions.get_or_create(sid="pacman-e2e")
        overlay.provision(cls.session)
        pacman.provisioning_seed(cls.session)

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

    def setUp(self):
        # Fresh session per test (destroy the class-level one) so committed
        # layers from a prior test can't leak into this one. layers.reset keeps
        # the stack, which would let a committed tree package from an earlier
        # test appear in a later "discard" assertion.
        from rattan import layers, overlay, sessions
        if self.session is not None:
            layers.destroy(self.session)
            sessions._current = None  # drop the cached session object
        self.session = sessions.get_or_create(sid="pacman-e2e")
        overlay.provision(self.session)
        pacman.provisioning_seed(self.session)

    def tearDown(self):
        from rattan import layers, sessions
        if self.session is not None:
            layers.destroy(self.session)
            sessions._current = None
            self.session = None

    def _install(self, pkg, **kw):
        return pacman.pacman_install(self.session, [pkg], timeout=180, **kw)

    def _agent(self, command: str) -> dict:
        from rattan.executor import execute_program
        from rattan.parser import parse
        env = {"HOME": "/workspace", "PATH": "/usr/bin:/bin",
               "USER": "rattan", "TERM": "dumb", "LANG": "C.UTF-8"}
        return execute_program(parse(command), self.session, env, "/workspace", 30)

    def test_pacman_run_query(self):
        r = pacman.pacman_run(self.session, ["-Q"], timeout=30)
        self.assertEqual(r["rc"], 0)
        self.assertIn("bash", r["output"])

    def test_install_visible_to_agent(self):
        r = self._install("tree")
        self.assertEqual(r["rc"], 0, f"install failed: {r['output']}")
        agent = self._agent("tree --version")
        self.assertEqual(agent["rc"], 0)
        self.assertIn("tree", agent["output"])

    def test_install_lands_in_upperdir(self):
        r = self._install("tree")
        self.assertEqual(r["rc"], 0)
        self.assertTrue(
            os.path.exists(os.path.join(self.session.upper, "usr", "bin", "tree")),
            "installed binary not in session upperdir",
        )

    def test_discard_removes_package(self):
        r = self._install("tree")
        self.assertEqual(r["rc"], 0)
        from rattan import layers
        layers.reset(self.session)
        # After discard the package db and files are gone from the session view.
        q = pacman.pacman_run(self.session, ["-Q", "tree"], timeout=30)
        self.assertNotIn("tree 2", q["output"])

    def test_commit_preserves_package(self):
        r = self._install("tree")
        self.assertEqual(r["rc"], 0)
        from rattan import layers
        layers.commit(self.session, "install tree")
        layers.reset(self.session)
        q = pacman.pacman_run(self.session, ["-Q", "tree"], timeout=30)
        self.assertIn("tree 2", q["output"])

    def test_invalid_mirror_rejected(self):
        with self.assertRaises(ValueError):
            self._install("tree", mirror="http://evil.com/archlinux")

    def test_bad_packages_rejected(self):
        with self.assertRaises(ValueError):
            self._install("-Sy")


if __name__ == "__main__":
    unittest.main()
