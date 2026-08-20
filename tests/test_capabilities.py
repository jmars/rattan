"""Unit + integration tests for the rattan host capability probe.

Unit tests mock /proc, /sys, subprocess and the ctypes syscall so they run on any
host. The integration test probes the real host and is skipped when the probe is
unavailable (e.g. no Landlock LSM in CI).
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from rattan import capabilities


class KernelVersionTest(unittest.TestCase):
    def test_above_minimum(self):
        self.assertTrue(capabilities.kernel_version("7.1.5-arch1-2").available)

    def test_at_minimum(self):
        self.assertTrue(capabilities.kernel_version("6.2.0").available)

    def test_below_minimum(self):
        c = capabilities.kernel_version("6.1.99")
        self.assertFalse(c.available)
        self.assertTrue(c.required)

    def test_old_kernel(self):
        self.assertFalse(capabilities.kernel_version("5.15.0").available)

    def test_unparseable(self):
        self.assertFalse(capabilities.kernel_version("not-a-version").available)


class UsernsTest(unittest.TestCase):
    def _write(self, content):
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_enabled(self):
        p = self._write("1\n")
        try:
            self.assertTrue(capabilities.userns_enabled(p).available)
        finally:
            os.unlink(p)

    def test_disabled(self):
        p = self._write("0\n")
        try:
            self.assertFalse(capabilities.userns_enabled(p).available)
        finally:
            os.unlink(p)

    def test_missing_file_falls_back_to_runtime_probe(self):
        # Missing sysctl is NOT "disabled" — the gate falls back to a live
        # unshare probe (kernels like openSUSE expose no userns sysctl).
        c = capabilities.userns_enabled("/nonexistent/userns-ctl")
        self.assertTrue(c.required)
        # Whether it's available now depends on the host kernel allowing
        # unprivileged userns; on a working kernel the fallback returns True.
        if c.available:
            self.assertIn("unshare probe", c.detail)
        else:
            self.assertIn("probe failed", c.detail)

    def test_missing_file_probe_failure_disables(self):
        class _FakeResult:
            returncode = 1
            stderr = "operation not permitted"

        with mock.patch(
            "rattan.capabilities.subprocess.run", return_value=_FakeResult()
        ):
            c = capabilities.userns_enabled("/nonexistent/userns-ctl")
        self.assertFalse(c.available)
        self.assertTrue(c.required)


class LandlockPresentTest(unittest.TestCase):
    def _write(self, content):
        f = tempfile.NamedTemporaryFile("w", delete=False)
        f.write(content)
        f.close()
        return f.name

    def test_present(self):
        p = self._write("capability,landlock,lockdown,yama,bpf\n")
        try:
            self.assertTrue(capabilities.landlock_present(p).available)
        finally:
            os.unlink(p)

    def test_absent(self):
        p = self._write("capability,lockdown,yama\n")
        try:
            self.assertFalse(capabilities.landlock_present(p).available)
        finally:
            os.unlink(p)


class BwrapVersionTest(unittest.TestCase):
    def test_parse(self):
        out = mock.Mock(returncode=0, stdout="bubblewrap 0.11.2\n", stderr="")
        with mock.patch.object(
            capabilities.subprocess, "run", return_value=out
        ):
            c = capabilities.bwrap_version()
            self.assertTrue(c.available)
            self.assertIn("0.11.2", c.detail)
            self.assertTrue(c.required)

    def test_missing_binary(self):
        with mock.patch.object(
            capabilities.subprocess, "run", side_effect=FileNotFoundError
        ):
            c = capabilities.bwrap_version()
            self.assertFalse(c.available)
            self.assertTrue(c.required)

    def test_bad_output(self):
        out = mock.Mock(returncode=1, stdout="", stderr="nope")
        with mock.patch.object(
            capabilities.subprocess, "run", return_value=out
        ):
            self.assertFalse(capabilities.bwrap_version().available)


class LandlockAbiTest(unittest.TestCase):
    def test_abi_mapping(self):
        self.assertEqual(capabilities._abi_for(-1, False), 0)
        self.assertEqual(capabilities._abi_for(0, False), 1)
        self.assertEqual(capabilities._abi_for(13, False), 2)
        self.assertEqual(capabilities._abi_for(14, False), 3)
        self.assertEqual(capabilities._abi_for(15, False), 5)
        self.assertEqual(capabilities._abi_for(17, False), 5)
        # NET support forces ABI >= 4
        self.assertEqual(capabilities._abi_for(0, True), 4)
        self.assertEqual(capabilities._abi_for(-1, True), 4)

    def test_abi_probe_full(self):
        def fake_fd(handled_fs=0, handled_net=0):
            if handled_fs:
                return 3 if (handled_fs & (1 << 15)) else -1
            if handled_net:
                return 4
            return -1

        with mock.patch.object(
            capabilities, "_create_ruleset_fd", side_effect=fake_fd
        ):
            c = capabilities.landlock_abi()
            self.assertTrue(c.available)
            self.assertIn("FS", c.detail)
            self.assertIn("NET", c.detail)

    def test_abi_probe_enosys(self):
        with mock.patch.object(
            capabilities, "_create_ruleset_fd", return_value=-1
        ):
            c = capabilities.landlock_abi()
            self.assertFalse(c.available)

    def test_abi_probe_exception(self):
        with mock.patch.object(
            capabilities,
            "_create_ruleset_fd",
            side_effect=OSError("boom"),
        ):
            c = capabilities.landlock_abi()
            self.assertFalse(c.available)
            self.assertIn("probe failed", c.detail)


class ReflinkTest(unittest.TestCase):
    def test_classify(self):
        self.assertTrue(capabilities.classify_reflink("btrfs"))
        self.assertTrue(capabilities.classify_reflink("xfs"))
        self.assertFalse(capabilities.classify_reflink("ext4"))
        self.assertFalse(capabilities.classify_reflink("tmpfs"))
        self.assertFalse(capabilities.classify_reflink("unknown"))

    def test_reflink_from_fs(self):
        with mock.patch.object(capabilities, "_fs_type", return_value="btrfs"):
            c = capabilities.reflink_support("/tmp")
            self.assertTrue(c.available)
            self.assertFalse(c.required)
        with mock.patch.object(capabilities, "_fs_type", return_value="ext4"):
            c = capabilities.reflink_support("/tmp")
            self.assertFalse(c.available)


class OverlayTest(unittest.TestCase):
    def test_filesystems_present(self):
        with mock.patch.object(capabilities.shutil, "which", return_value=None):
            with mock.patch(
                "builtins.open", mock.mock_open(read_data="nodev\toverlay\n")
            ):
                c = capabilities.overlay_in_userns()
                self.assertTrue(c.available)

    def test_filesystems_absent(self):
        with mock.patch.object(capabilities.shutil, "which", return_value=None):
            with mock.patch(
                "builtins.open", mock.mock_open(read_data="nodev\text4\n")
            ):
                c = capabilities.overlay_in_userns()
                self.assertFalse(c.available)

    def test_bwrap_probe_fails_gracefully(self):
        out = mock.Mock(returncode=1, stdout="", stderr="mount failed\n")
        with mock.patch.object(
            capabilities.shutil, "which", return_value="/usr/bin/bwrap"
        ):
            with mock.patch.object(
                capabilities.subprocess, "run", return_value=out
            ):
                c = capabilities.overlay_in_userns()
                self.assertFalse(c.available)
                self.assertIn("failed", c.detail)

    def test_bwrap_probe_success(self):
        out = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(
            capabilities.shutil, "which", return_value="/usr/bin/bwrap"
        ):
            with mock.patch.object(
                capabilities.subprocess, "run", return_value=out
            ):
                c = capabilities.overlay_in_userns()
                self.assertTrue(c.available)


class CapabilityTableTest(unittest.TestCase):
    def test_missing_required(self):
        caps = capabilities.CapabilityTable(
            {
                "a": capabilities.Capability("a", False, "", required=True),
                "b": capabilities.Capability("b", True, "", required=True),
                "c": capabilities.Capability("c", True, "", required=False),
            }
        )
        self.assertEqual([c.name for c in caps.missing_required()], ["a"])


class CacheTest(unittest.TestCase):
    def test_roundtrip(self):
        table = capabilities.probe_all()
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "capabilities.json")
            self.assertTrue(capabilities.save_cache(table, p))
            loaded = capabilities.load_cache(p)
            self.assertEqual(loaded.to_dict(), table.to_dict())

    def test_load_cache_json_invalid(self):
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "capabilities.json")
            with open(p, "w") as f:
                f.write("{not valid json")
            self.assertIsNone(capabilities.load_cache(p))

    def test_get_capabilities_uses_cache_when_fresh(self):
        table = capabilities.probe_all()
        with tempfile.TemporaryDirectory() as td:
            p = os.path.join(td, "capabilities.json")
            capabilities.save_cache(table, p)
            # A bogus table would only appear if the cache were NOT reused.
            with open(p, "w") as f:
                json.dump(
                    {
                        "kernel_version": {
                            "name": "kernel_version",
                            "available": False,
                            "detail": "cached",
                            "required": True,
                            "remediation": "",
                        }
                    },
                    f,
                )
            got = capabilities.get_capabilities(cache_path=p)
            self.assertFalse(got.get("kernel_version").available)


def _host_probe_available():
    """True only if the real host probe can read the LSM stack.

    Guards the integration probe so it is skipped in constrained environments
    (e.g. CI, or a sandbox that denies /sys reads) while still running on a
    provisioned host.
    """
    try:
        with open("/sys/kernel/security/lsm"):
            return True
    except OSError:
        return False


@unittest.skipUnless(
    _host_probe_available(),
    "host probe unavailable (cannot read LSM stack) - skipping integration probe",
)
class ProbeIntegrationTest(unittest.TestCase):
    def test_probe_all(self):
        table = capabilities.probe_all()
        self.assertIn("kernel_version", table)
        # A provisioned host must satisfy every required capability.
        self.assertEqual(table.missing_required(), [])

    def test_gate_passes(self):
        table = capabilities.probe_all()
        capabilities.assert_required_present(table)  # no raise


if __name__ == "__main__":
    unittest.main()
