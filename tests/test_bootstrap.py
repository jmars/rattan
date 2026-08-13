"""Tests for the base rootfs manifest validation."""

import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from rattan import config


def _make_fake_base():
    """Create a fake bootstrapped base rootfs in a temp dir.

    Returns a (cleanup_callable, fake_base) pair: call cleanup() to remove the
    temp dir after the test. The fake base contains a dummy MANIFEST.sha256
    so callers can exercise the fast/full manifest checks.
    """
    td = tempfile.mkdtemp()
    fake_base = os.path.join(td, "base")
    os.makedirs(fake_base)
    manifest = os.path.join(fake_base, "MANIFEST.sha256")
    with open(manifest, "w") as f:
        f.write("# dummy manifest\n")
    return (lambda: shutil.rmtree(td), fake_base)


class FastManifestCheckTest(unittest.TestCase):
    """Unit tests for ``config._fast_manifest_check`` — mocked subprocess."""

    def test_clean_returns_true(self):
        """Empty find output (no newer file) -> True."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.object(
            config.subprocess, "run",
            return_value=mock.Mock(returncode=0, stdout="", stderr=""),
        ):
            self.assertTrue(config._fast_manifest_check(fake_base, manifest))

    def test_newer_file_returns_false(self):
        """A newer file in find output -> False."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.object(
            config.subprocess, "run",
            return_value=mock.Mock(
                returncode=0,
                stdout="./usr/bin/tampered\n",
                stderr="",
            ),
        ):
            self.assertFalse(config._fast_manifest_check(fake_base, manifest))

    def test_nonzero_exit_returns_none(self):
        """find exits non-zero -> None (caller falls through to full check)."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.object(
            config.subprocess, "run",
            return_value=mock.Mock(returncode=1, stdout="", stderr=""),
        ):
            self.assertIsNone(config._fast_manifest_check(fake_base, manifest))

    def test_find_missing_returns_none(self):
        """find missing (OSError) -> None (caller falls through)."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.object(
            config.subprocess, "run",
            side_effect=OSError("no such tool"),
        ):
            self.assertIsNone(config._fast_manifest_check(fake_base, manifest))


class FullManifestCheckTest(unittest.TestCase):
    """Unit tests for ``config._full_manifest_check`` — mocked subprocess."""

    def test_passes(self):
        """sha256sum -c returns 0 -> no raise."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.object(
            config.subprocess, "run",
            return_value=mock.Mock(returncode=0, stdout="", stderr=""),
        ):
            config._full_manifest_check(fake_base, manifest)  # no raise

    def test_drifted_raises(self):
        """sha256sum -c fails -> RuntimeError listing failed files."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.object(
            config.subprocess, "run",
            return_value=mock.Mock(
                returncode=1,
                stdout="./usr/bin/bash: FAILED\n",
                stderr="",
            ),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                config._full_manifest_check(fake_base, manifest)
            self.assertIn("FAILED", str(ctx.exception))
            self.assertIn("make bootstrap-rootfs", str(ctx.exception))

    def test_subprocess_error_raises(self):
        """sha256sum can't run -> RuntimeError."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.object(
            config.subprocess, "run",
            side_effect=OSError("no such tool"),
        ):
            with self.assertRaises(RuntimeError) as ctx:
                config._full_manifest_check(fake_base, manifest)
            self.assertIn("Could not run", str(ctx.exception))


class ManifestValidationTest(unittest.TestCase):
    """Unit tests for ``config.validate_base_manifest`` routing — mocked."""

    def test_missing_manifest_raises(self):
        """Raises 'not bootstrapped' if MANIFEST.sha256 doesn't exist."""
        with tempfile.TemporaryDirectory() as td:
            fake_base = os.path.join(td, "base")
            os.makedirs(fake_base)
            with mock.patch.object(config, "base_rootfs_path",
                                   return_value=fake_base):
                with self.assertRaises(RuntimeError) as ctx:
                    config.validate_base_manifest()
                self.assertIn("not bootstrapped", str(ctx.exception))

    def test_verify_env_forces_full_and_skips_fast(self):
        """RATTAN_VERIFY_BASE=1 runs the full hash, not the fast path."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.dict(os.environ, {"RATTAN_VERIFY_BASE": "1"}), \
             mock.patch.object(config, "base_rootfs_path",
                               return_value=fake_base), \
             mock.patch.object(
                 config.subprocess, "run",
                 return_value=mock.Mock(returncode=0, stdout="", stderr=""),
             ) as m_run:
            config.validate_base_manifest()  # no raise
        # Exactly one call, and it must be the sha256sum full check.
        m_run.assert_called_once()
        cmd = m_run.call_args.args[0]
        self.assertEqual(cmd[0], "sha256sum")

    def test_fast_true_skips_full(self):
        """Fast path True (clean) -> full hash is never run."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.object(config, "base_rootfs_path",
                               return_value=fake_base), \
             mock.patch.object(
                 config.subprocess, "run",
                 return_value=mock.Mock(returncode=0, stdout="", stderr=""),
             ) as m_run:
            config.validate_base_manifest()  # no raise
        # Exactly one subprocess call: the find fast path.
        m_run.assert_called_once()
        cmd = m_run.call_args.args[0]
        self.assertEqual(cmd[0], "find")

    def test_fast_false_falls_to_full(self):
        """Fast path False (drift hint) -> full hash runs and passes."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.object(config, "base_rootfs_path",
                               return_value=fake_base), \
             mock.patch.object(
                 config.subprocess, "run",
                 side_effect=[
                     mock.Mock(returncode=0, stdout="./x\n", stderr=""),  # find: newer
                     mock.Mock(returncode=0, stdout="", stderr=""),       # sha256sum: pass
                 ],
             ) as m_run:
            config.validate_base_manifest()  # no raise
        self.assertEqual(m_run.call_count, 2)
        self.assertEqual(m_run.call_args_list[0].args[0][0], "find")
        self.assertEqual(m_run.call_args_list[1].args[0][0], "sha256sum")

    def test_fast_none_falls_to_full(self):
        """Fast path None (find missing) -> full hash runs and passes."""
        cleanup, fake_base = _make_fake_base()
        self.addCleanup(cleanup)
        manifest = os.path.join(fake_base, "MANIFEST.sha256")
        with mock.patch.object(config, "base_rootfs_path",
                               return_value=fake_base), \
             mock.patch.object(
                 config.subprocess, "run",
                 side_effect=[
                     OSError("no such tool"),            # find: missing
                     mock.Mock(returncode=0, stdout="", stderr=""),  # sha256sum: pass
                 ],
             ) as m_run:
            config.validate_base_manifest()  # no raise
        self.assertEqual(m_run.call_count, 2)
        self.assertEqual(m_run.call_args_list[0].args[0][0], "find")
        self.assertEqual(m_run.call_args_list[1].args[0][0], "sha256sum")


def _rootfs_bootstrapped():
    """True only if the base rootfs exists with a valid manifest."""
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
class BootstrapIntegrationTest(unittest.TestCase):
    """Integration — run only when a valid bootstrapped rootfs exists."""

    def test_manifest_validates(self):
        config.validate_base_manifest()  # no raise

    def test_bwrap_smoke(self):
        """Verify the base rootfs is usable inside bwrap."""
        base = config.base_rootfs_path()
        result = subprocess.run(
            [
                "bwrap",
                "--unshare-all",
                "--uid", "0", "--gid", "0",
                "--ro-bind", base, "/",
                "--proc", "/proc",
                "--dev", "/dev",
                "--", "/usr/bin/ls", "/",
            ],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0,
                         f"bwrap ls failed: {result.stderr}")
        self.assertIn("usr", result.stdout)
        self.assertIn("etc", result.stdout)


if __name__ == "__main__":
    unittest.main()
