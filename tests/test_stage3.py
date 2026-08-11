"""Tests for the stage3 inner security binary.

These tests invoke ``bin/stage3`` (and the probe binaries under
``tests/probes/``) via ``subprocess``.  The entire module is skipped when
``bin/stage3`` has not been built (``make stage3``).
"""

import os
import re
import subprocess
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STAGE3 = os.path.join(REPO_ROOT, "bin", "stage3")
PROBE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "probes"))

KEYTEST     = os.path.join(PROBE_DIR, "keytest")
PTRACETEST  = os.path.join(PROBE_DIR, "ptracetest")
MOUNTTEST   = os.path.join(PROBE_DIR, "mounttest")
UNSHARETEST = os.path.join(PROBE_DIR, "unsharetest")
REVERSE_PROBE = os.path.join(PROBE_DIR, "reverse_order_probe")

# A realistic agent-mode LANDLOCK_SPEC: the container-internal paths a command
# needs to exec a dynamically-linked binary (via /usr, /bin, /lib), read status
# (/proc), write to /tmp, and reach the probe binaries (tests/probes).
SPEC = ("/tmp:rwc;/usr:rx;/bin:rx;/lib:rx;/lib64:rx;/proc:r;"
        + PROBE_DIR + ":rx")

# A write-capable promise set that permits exec'ing a dynamically-linked binary
# (prot_exec is required for mmap(PROT_EXEC) of shared libraries).
PROMISES = "stdio rpath wpath cpath flock exec prot_exec proc recvfd"


def _has_binary(path):
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _stage3(*args, env=None, timeout=10):
    """Run stage3 with the given args and return a CompletedProcess."""
    cmd = [STAGE3] + list(args)
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          env={**os.environ, **(env or {})})


def _run_probe_under_stage3(probe, promise_set=PROMISES, spec=SPEC, env=None):
    """Run a probe binary under stage3 with the realistic spec."""
    return _stage3(promise_set, spec, "--", probe, env=env)


# ---------------------------------------------------------------------------
# Module-level skip when stage3 hasn't been built
# ---------------------------------------------------------------------------

STAGE3_MISSING = not _has_binary(STAGE3)


def setUpModule():
    if STAGE3_MISSING:
        raise unittest.SkipTest(
            f"bin/stage3 not found at {STAGE3!r} — run 'make stage3' first"
        )


# ============================================================================
# Tests
# ============================================================================

class TestVerifyBaseline(unittest.TestCase):
    """test_verify_baseline — stage3 --verify exits 0, shows all status fields."""

    def test_verify_baseline(self):
        # --verify uses a fixed internal config (full baseline promises + a
        # minimal spec), so caller promises/spec are ignored.
        r = _stage3("stdio", "rpath", "exec", "--verify")
        self.assertIn("NoNewPrivs:", r.stdout)
        self.assertIn("Seccomp:", r.stdout)
        self.assertIn("Seccomp_filters:", r.stdout)
        self.assertIn("Landlock:", r.stdout)
        self.assertIn("VERIFY OK", r.stdout)
        self.assertEqual(r.returncode, 0,
                         f"expected exit 0, got {r.returncode}\n"
                         f"stdout={r.stdout}\nstderr={r.stderr}")


class TestExecvpSucceeds(unittest.TestCase):
    """test_execvp_succeeds — stage3 can exec /bin/echo and print hello."""

    def test_execvp_succeeds(self):
        r = _stage3(PROMISES, SPEC, "--", "/bin/echo", "hello")
        self.assertEqual(r.returncode, 0,
                         f"execvp failed: stderr={r.stderr}")
        self.assertIn("hello", r.stdout)


class TestPledgeDeniesWrite(unittest.TestCase):
    """test_pledge_denies_write — write denied when wpath not in promises."""

    def test_pledge_denies_write(self):
        # No wpath/cpath token: seccomp blocks write syscalls.
        r = _stage3("stdio rpath exec prot_exec", SPEC, "--",
                    "/bin/sh", "-c", "echo x > /tmp/should_fail")
        self.assertNotEqual(r.returncode, 0,
                            f"expected non-zero exit, got {r.returncode}\n"
                            f"stdout={r.stdout}\nstderr={r.stderr}")


class TestPledgeDeniesKeyctl(unittest.TestCase):
    """keyctl (250) must be blocked by seccomp under stage3."""

    @unittest.skipUnless(_has_binary(KEYTEST), "keytest probe not built")
    def test_denied_under_stage3(self):
        r = _run_probe_under_stage3(KEYTEST)
        out = r.stdout + r.stderr
        self.assertIn("Operation not permitted", out,
                      f"expected EPERM under stage3, got: {out}")
        self.assertNotEqual(r.returncode, 0,
                            f"expected non-zero exit, got {r.returncode}\n{out}")


class TestPledgeDeniesPtrace(unittest.TestCase):
    """ptrace (101) must be blocked under stage3."""

    @unittest.skipUnless(_has_binary(PTRACETEST), "ptracetest probe not built")
    def test_denied_under_stage3(self):
        r = _run_probe_under_stage3(PTRACETEST)
        out = r.stdout + r.stderr
        self.assertIn("Operation not permitted", out,
                      f"expected EPERM under stage3, got: {out}")
        self.assertNotEqual(r.returncode, 0,
                            f"expected non-zero exit, got {r.returncode}\n{out}")


class TestPledgeDeniesMount(unittest.TestCase):
    """mount (165) must be blocked under stage3."""

    @unittest.skipUnless(_has_binary(MOUNTTEST), "mounttest probe not built")
    def test_denied_under_stage3(self):
        r = _run_probe_under_stage3(MOUNTTEST)
        out = r.stdout + r.stderr
        self.assertIn("Operation not permitted", out,
                      f"expected EPERM under stage3, got: {out}")
        self.assertNotEqual(r.returncode, 0,
                            f"expected non-zero exit, got {r.returncode}\n{out}")


class TestPledgeDeniesUnshare(unittest.TestCase):
    """unshare (166, CLONE_NEWUSER) must be blocked under stage3."""

    @unittest.skipUnless(_has_binary(UNSHARETEST), "unsharetest probe not built")
    def test_denied_under_stage3(self):
        r = _run_probe_under_stage3(UNSHARETEST)
        out = r.stdout + r.stderr
        self.assertIn("Operation not permitted", out,
                      f"expected EPERM under stage3, got: {out}")
        self.assertNotEqual(r.returncode, 0,
                            f"expected non-zero exit, got {r.returncode}\n{out}")


class TestUnveilDeniesWrite(unittest.TestCase):
    """test_unveil_denies_write — Landlock denies a write outside the unveiled
    set even with write-capable promises."""

    def test_unveil_denies_write(self):
        # Write-capable promises, but LANDLOCK_SPEC only unveils /tmp/rattan-verify
        # (rwc) and /proc (r). A write to /tmp/rattan-verify-sibling (outside the
        # unveiled set) must be denied by Landlock.
        spec = "/proc:r;/tmp/rattan-verify:rwc"
        r = _stage3(PROMISES, spec, "--",
                    "/bin/sh", "-c",
                    "mkdir -p /tmp/rattan-verify && "
                    "echo x > /tmp/rattan-verify-sibling")
        self.assertNotEqual(r.returncode, 0,
                            f"expected non-zero exit, got {r.returncode}\n"
                            f"stdout={r.stdout}\nstderr={r.stderr}")


class TestReverseOrderFails(unittest.TestCase):
    """test_reverse_order_fails — pledge-then-unveil must fail with EPERM."""

    @unittest.skipUnless(_has_binary(REVERSE_PROBE),
                         "reverse_order_probe not built")
    def test_reverse_order_fails(self):
        r = subprocess.run([REVERSE_PROBE], capture_output=True, text=True,
                           timeout=10)
        output = r.stdout + r.stderr
        self.assertIn("unveil-after-pledge: errno=1", output,
                      f"expected EPERM errno=1, got: {output}")
        self.assertEqual(r.returncode, 1,
                         f"expected exit 1, got {r.returncode}\n{output}")


class TestNoEarlyReturnStructurally(unittest.TestCase):
    """test_no_early_return_structurally — setup_layers calls the four functions
    in order (nonewprivs, unveil, rlimits, pledge) with no return/goto between."""

    def test_no_early_return_structurally(self):
        stage3_src = os.path.join(REPO_ROOT, "src", "rattan", "stage3.c")
        with open(stage3_src) as f:
            source = f.read()

        m = re.search(
            r'static void setup_layers\(.*?\)\s*\{([^}]+)\}',
            source, re.DOTALL
        )
        self.assertIsNotNone(m, "setup_layers function not found in stage3.c")
        body = m.group(1)

        self.assertNotIn("return", body,
                         "setup_layers must not contain 'return'")
        self.assertNotIn("goto", body,
                         "setup_layers must not contain 'goto'")

        calls = re.findall(r'(\w+)\s*\(', body)
        expected = ["setup_nonewprivs", "apply_unveil", "apply_rlimits",
                    "apply_pledge"]
        filtered = [c for c in calls if c in expected]
        self.assertEqual(
            filtered, expected,
            f"setup_layers call order: got {filtered}, expected {expected}"
        )


class TestExtraPromisesEnv(unittest.TestCase):
    """test_extra_promises_env — RATTAN_EXTRA_PROMISES=flock works."""

    def test_extra_promises_env(self):
        env = {"RATTAN_EXTRA_PROMISES": "flock"}
        r = _stage3(PROMISES, SPEC, "--verify", env=env)
        self.assertEqual(r.returncode, 0,
                         f"expected exit 0, got {r.returncode}\n"
                         f"stdout={r.stdout}\nstderr={r.stderr}")


class TestUnknownExtraPromiseRejected(unittest.TestCase):
    """test_unknown_extra_promise_rejected — bogus token should fail."""

    def test_unknown_extra_promise_rejected(self):
        env = {"RATTAN_EXTRA_PROMISES": "bogus"}
        r = _stage3(PROMISES, SPEC, "--verify", env=env)
        self.assertNotEqual(r.returncode, 0,
                            f"expected non-zero for bogus token, got {r.returncode}")
        self.assertIn("unknown pledge token", r.stderr)


class TestAllowPtrace(unittest.TestCase):
    """test_allow_ptrace — RATTAN_ALLOW_PTRACE=1 skips seccomp (ptrace works)."""

    @unittest.skipUnless(_has_binary(PTRACETEST), "ptracetest probe not built")
    def test_allow_ptrace_skips_seccomp(self):
        env = {"RATTAN_ALLOW_PTRACE": "1"}
        # With seccomp skipped, ptrace should reach the kernel (PTRACE_TRACEME
        # on self returns 0) rather than EPERM.
        r = _run_probe_under_stage3(PTRACETEST, env=env)
        out = r.stdout + r.stderr
        self.assertNotIn("Operation not permitted", out,
                         f"ptrace should not be EPERM'd with allow_ptrace: {out}")


if __name__ == "__main__":
    unittest.main()
