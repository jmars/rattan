"""Unit tests for the MCP-latency optimizations.

Covers the four contained steps from the ``mcp-latency`` handoff:

1. ``shell_list`` installed-package cache (hit / miss / TTL / invalidation).
2. Minimal-env construction for bwrap subprocesses (no host-env leak).
3. EBUSY teardown serialization lock + bounded retry.
4. ``RATTAN_TIMING`` diagnostic (no-op when unset).

None of these require a bootstrapped rootfs or bwrap — they exercise the
pure-Python build/spawn scaffolding with mocks.
"""

import contextlib
import io
import os
import subprocess
import unittest
from unittest import mock

from rattan import executor, server
from rattan.executor import Invocation
from rattan.redirects import FdPlan


# ---------------------------------------------------------------------------
# Step 1: shell_list installed-package cache
# ---------------------------------------------------------------------------


class TestShellListCache(unittest.TestCase):
    def tearDown(self):
        server._invalidate_shell_list_cache()

    def test_cache_miss_then_hit(self):
        self.assertIsNone(server._cached_installed("s1"))
        server._cache_installed("s1", ["a", "b"])
        self.assertEqual(server._cached_installed("s1"), ["a", "b"])

    def test_ttl_expiry(self):
        server._cache_installed("s1", ["a", "b"])
        # A monotonic clock far in the future makes the entry stale.
        with mock.patch.object(server.time, "monotonic", return_value=1e9):
            self.assertIsNone(server._cached_installed("s1"))
        # The stale entry is dropped, not just ignored.
        self.assertNotIn("s1", server._shell_list_cache)

    def test_invalidate_specific_sid(self):
        server._cache_installed("s1", ["a"])
        server._cache_installed("s2", ["b"])
        server._invalidate_shell_list_cache("s1")
        self.assertIsNone(server._cached_installed("s1"))
        self.assertEqual(server._cached_installed("s2"), ["b"])

    def test_invalidate_all(self):
        server._cache_installed("s1", ["a"])
        server._cache_installed("s2", ["b"])
        server._invalidate_shell_list_cache()
        self.assertEqual(server._shell_list_cache, {})

    def test_shell_list_cache_hit_skips_pacman(self):
        session = mock.Mock()
        session.sid = "sess1"
        with mock.patch.object(server.pacman, "pacman_run") as pr:
            pr.return_value = {"rc": 0, "output": "bash\ncoreutils\n"}
            first = server._shell_list(session)
            second = server._shell_list(session)
        # One pacman -Qq subprocess total, despite two _shell_list calls.
        self.assertEqual(pr.call_count, 1)
        self.assertEqual(first, second)
        self.assertIn("bash", first)
        self.assertIn("coreutils", first)

    def test_shell_list_invalidation_forces_repopulate(self):
        session = mock.Mock()
        session.sid = "sess1"
        with mock.patch.object(server.pacman, "pacman_run") as pr:
            pr.return_value = {"rc": 0, "output": "bash\n"}
            server._shell_list(session)
            server._invalidate_shell_list_cache("sess1")
            server._shell_list(session)
            self.assertEqual(pr.call_count, 2)

    def test_shell_list_pacman_error_returns_policy_and_not_cached(self):
        session = mock.Mock()
        session.sid = "sess1"
        with mock.patch.object(server.pacman, "pacman_run") as pr:
            pr.return_value = {"rc": 1, "output": "some error"}
            result = server._shell_list(session)
        # Policy table keys are always present.
        self.assertIn("echo", result)
        self.assertIn("git", result)
        # A failed pacman run is not cached (so the next call retries).
        self.assertIsNone(server._cached_installed("sess1"))

    def test_shell_list_pacman_exception_returns_policy(self):
        session = mock.Mock()
        session.sid = "sess1"
        with mock.patch.object(server.pacman, "pacman_run", side_effect=OSError("boom")):
            result = server._shell_list(session)
        self.assertIn("echo", result)
        self.assertIsNone(server._cached_installed("sess1"))

    def test_shell_list_none_session(self):
        self.assertTrue(server._shell_list(None))  # policy table only, no crash


# ---------------------------------------------------------------------------
# Step 2: minimal-env construction
# ---------------------------------------------------------------------------


class TestMinimalEnv(unittest.TestCase):
    def test_contains_required_vars(self):
        env = executor._build_subprocess_env({})
        for k in ("PATH", "HOME", "USER", "TERM", "LANG", "LC_ALL"):
            self.assertIn(k, env)
        self.assertEqual(env["HOME"], "/workspace")
        self.assertEqual(env["USER"], "rattan")

    def test_inv_env_overrides_base(self):
        env = executor._build_subprocess_env({"PATH": "/custom/bin", "FOO": "bar"})
        self.assertEqual(env["PATH"], "/custom/bin")
        self.assertEqual(env["FOO"], "bar")
        self.assertEqual(env["HOME"], "/workspace")  # untouched base var preserved

    def test_no_host_env_leak(self):
        with mock.patch.dict(
            os.environ,
            {"RATTAN_LEAK_TEST": "1", "HOST_ONLY_VAR": "x"},
            clear=False,
        ):
            env = executor._build_subprocess_env({"RATTAN_EXTRA_PROMISES": "sendfd"})
        self.assertNotIn("HOST_ONLY_VAR", env)
        self.assertNotIn("RATTAN_LEAK_TEST", env)
        # Explicit stage3 var carried through inv.env is preserved.
        self.assertEqual(env["RATTAN_EXTRA_PROMISES"], "sendfd")


# ---------------------------------------------------------------------------
# Step 3: EBUSY serialization lock + bounded retry
# ---------------------------------------------------------------------------


class _FakeProc:
    def __init__(self, out, rc):
        self._out = out
        self.returncode = rc
        self.pid = 1234

    def communicate(self, timeout=None):
        return self._out, None

    def kill(self):
        pass


class TestEbusyRetry(unittest.TestCase):
    def _make_inv(self, upper="/tmp/sess/upper"):
        return Invocation(
            bwrap_argv=[
                "bwrap", "--overlay", upper, "/tmp/sess/work", "/",
                "--", "/init", "stdio", "--", "echo", "hi",
            ],
            env={"PATH": "/usr/bin:/bin", "HOME": "/workspace"},
            cwd="/",
            fd_plan=FdPlan(),
            timeout=30,
            command="echo hi",
        )

    def test_overlay_upper_extraction(self):
        self.assertEqual(executor._overlay_upper(self._make_inv()), "/tmp/sess/upper")

    def test_overlay_upper_missing(self):
        inv = Invocation(
            bwrap_argv=["bwrap", "--", "/init"],
            env={}, cwd="/", fd_plan=FdPlan(), timeout=30, command="x",
        )
        self.assertEqual(executor._overlay_upper(inv), "")

    def test_mount_lock_same_key_shared(self):
        self.assertIs(executor._overlay_mount_lock("k"), executor._overlay_mount_lock("k"))

    def test_mount_lock_distinct_keys(self):
        self.assertIsNot(
            executor._overlay_mount_lock("k1"), executor._overlay_mount_lock("k2")
        )

    def test_retry_on_ebusy_then_success(self):
        inv = self._make_inv()
        results = iter([
            _FakeProc(b"mount: Device or resource busy\n", 1),
            _FakeProc(b"ok", 0),
        ])
        with mock.patch.object(
            subprocess, "Popen", side_effect=lambda *a, **k: next(results)
        ) as popen, mock.patch.object(executor.time, "sleep") as sleep:
            out = executor.run_command(inv)

        self.assertEqual(out["rc"], 0)
        self.assertEqual(out["output"], "ok")
        self.assertEqual(popen.call_count, 2)
        sleep.assert_called_once_with(0.1)

    def test_no_retry_on_other_error(self):
        inv = self._make_inv()
        with mock.patch.object(
            subprocess, "Popen", return_value=_FakeProc(b"permission denied\n", 1)
        ) as popen, mock.patch.object(executor.time, "sleep") as sleep:
            out = executor.run_command(inv)

        self.assertEqual(out["rc"], 1)
        self.assertEqual(popen.call_count, 1)
        sleep.assert_not_called()

    def test_ebusy_exhausts_attempts_bounded(self):
        inv = self._make_inv()
        with mock.patch.object(
            subprocess,
            "Popen",
            return_value=_FakeProc(b"mount: Device or resource busy\n", 1),
        ) as popen, mock.patch.object(executor.time, "sleep") as sleep:
            out = executor.run_command(inv)

        # 5 attempts total, 4 sleeps, then gives up with the EBUSY error surfaced.
        self.assertEqual(popen.call_count, 5)
        self.assertEqual(sleep.call_count, 4)
        self.assertEqual(out["rc"], 1)
        self.assertIn("Device or resource busy", out["output"])


# ---------------------------------------------------------------------------
# Step 4: RATTAN_TIMING diagnostic
# ---------------------------------------------------------------------------


class TestTimingDiagnostic(unittest.TestCase):
    def test_timing_log_noop_when_unset(self):
        with mock.patch.object(executor, "_TIMING", False):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                executor._timing_log("should not appear")
            self.assertEqual(buf.getvalue(), "")

    def test_timing_log_writes_when_set(self):
        with mock.patch.object(executor, "_TIMING", True):
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                executor._timing_log("hello")
            self.assertIn("hello", buf.getvalue())
            self.assertIn("[rattan-timing]", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
