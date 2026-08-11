"""Tests for the base rootfs manifest validation."""

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from rattan import config


class ManifestValidationTest(unittest.TestCase):
    """Unit tests — mocked, run on any host."""

    def test_missing_manifest_raises(self):
        """validate_base_manifest raises if MANIFEST.sha256 doesn't exist."""
        with tempfile.TemporaryDirectory() as td:
            fake_base = os.path.join(td, "base")
            os.makedirs(fake_base)
            with mock.patch.object(config, "base_rootfs_path",
                                   return_value=fake_base):
                with self.assertRaises(RuntimeError) as ctx:
                    config.validate_base_manifest()
                self.assertIn("not bootstrapped", str(ctx.exception))

    def test_valid_manifest_passes(self):
        """validate_base_manifest succeeds when sha256sum -c passes."""
        with tempfile.TemporaryDirectory() as td:
            fake_base = os.path.join(td, "base")
            os.makedirs(fake_base)
            manifest = os.path.join(fake_base, "MANIFEST.sha256")
            with open(manifest, "w") as f:
                f.write("# dummy manifest\n")
            with mock.patch.object(
                config.subprocess, "run",
                return_value=mock.Mock(returncode=0, stdout="", stderr=""),
            ), mock.patch.object(config, "base_rootfs_path",
                                 return_value=fake_base):
                config.validate_base_manifest()  # no raise

    def test_drifted_manifest_raises(self):
        """validate_base_manifest raises when sha256sum -c fails."""
        with tempfile.TemporaryDirectory() as td:
            fake_base = os.path.join(td, "base")
            os.makedirs(fake_base)
            manifest = os.path.join(fake_base, "MANIFEST.sha256")
            with open(manifest, "w") as f:
                f.write("# stale manifest\n")
            with mock.patch.object(
                config.subprocess, "run",
                return_value=mock.Mock(
                    returncode=1,
                    stdout="./usr/bin/bash: FAILED\n",
                    stderr="",
                ),
            ), mock.patch.object(config, "base_rootfs_path",
                                 return_value=fake_base):
                with self.assertRaises(RuntimeError) as ctx:
                    config.validate_base_manifest()
                self.assertIn("FAILED", str(ctx.exception))

    def test_subprocess_error_raises(self):
        """validate_base_manifest raises if sha256sum can't run."""
        with tempfile.TemporaryDirectory() as td:
            fake_base = os.path.join(td, "base")
            os.makedirs(fake_base)
            manifest = os.path.join(fake_base, "MANIFEST.sha256")
            with open(manifest, "w") as f:
                f.write("# x\n")
            with mock.patch.object(
                config.subprocess, "run",
                side_effect=OSError("no such tool"),
            ), mock.patch.object(config, "base_rootfs_path",
                                 return_value=fake_base):
                with self.assertRaises(RuntimeError) as ctx:
                    config.validate_base_manifest()
                self.assertIn("Could not run", str(ctx.exception))


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
