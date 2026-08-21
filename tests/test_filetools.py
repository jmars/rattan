"""Tests for the sandboxed file tools (read_file / write_file / edit / grep).

Two test classes:

* ``TestFiletoolsUnit`` — mock-based, no real sandbox. Verifies the path
  validation, symlink-escape rejection, error messages, and the read_file
  pagination logic against a fake ``_sandbox``. Runs everywhere.
* ``TestFiletoolsSandbox`` — a real end-to-end sandbox (mirrors
  ``test_e2e.py``'s setup) exercising the tools against a live bwrap container.
  Skipped when the prerequisites (built stage3, bootstrapped rootfs, bwrap) are
  missing.
"""

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from rattan import config, filetools

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
    """All conditions must hold for the e2e file tools tests to run."""
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
        result2 = subprocess.run(
            ["bwrap", "--unshare-all", "--uid", "1000", "--gid", "1000",
             "--ro-bind", "/", "/", "--", "/bin/true"],
            capture_output=True, timeout=10,
        )
        return result2.returncode == 0
    except (subprocess.SubprocessError, OSError):
        return False


# ---------------------------------------------------------------------------
# Unit tests (mock-based — no sandbox required)
# ---------------------------------------------------------------------------


class _FakeSandbox:
    """A ``filetools._sandbox`` stand-in that routes commands to canned results."""

    def __init__(self, routes):
        self.routes = routes  # {command-prefix: result-dict}
        self.calls = []

    def __call__(self, session, command, cwd="/workspace", timeout=30):
        self.calls.append(command)
        for prefix, result in self.routes.items():
            if command.startswith(prefix):
                return result
        raise AssertionError(f"unexpected sandbox command: {command!r}")


class TestFiletoolsUnit(unittest.TestCase):
    """Validation and pagination logic, without a real sandbox."""

    def _patch_sandbox(self, routes):
        fake = _FakeSandbox(routes)
        patcher = mock.patch.object(filetools, "_sandbox", fake)
        patcher.start()
        self.addCleanup(patcher.stop)
        return fake

    # --- path validation --------------------------------------------------

    def test_read_rejects_host_path(self):
        res = filetools.read_file(None, "/home/arch/foo")
        self.assertIn("error", res)
        self.assertIn("/workspace", res["error"])

    def test_read_rejects_etc_passwd(self):
        res = filetools.read_file(None, "/etc/passwd")
        self.assertIn("error", res)
        self.assertIn("/workspace", res["error"])

    def test_read_rejects_dotdot_escape(self):
        res = filetools.read_file(None, "/workspace/../etc/passwd")
        self.assertIn("error", res)
        self.assertIn("/workspace", res["error"])

    def test_read_rejects_relative(self):
        res = filetools.read_file(None, "relative/path")
        self.assertIn("error", res)
        self.assertIn("absolute container path", res["error"])

    def test_read_symlink_escape_rejected(self):
        """A container symlink resolving to /etc/passwd must be rejected."""
        self._patch_sandbox({
            "realpath": {"rc": 0, "output": "/etc/passwd\n"},
        })
        res = filetools.read_file(None, "/workspace/evil")
        self.assertIn("error", res)
        self.assertIn("escapes container roots", res["error"])

    # --- read_file pagination ---------------------------------------------

    def test_read_pagination(self):
        self._patch_sandbox({
            "realpath": {"rc": 0, "output": "/workspace/foo\n"},
            "test -f": {"rc": 0, "output": ""},
            "wc -l": {"rc": 0, "output": "100 /workspace/foo\n"},
            "sed -n": {"rc": 0, "output": "a\nb\nc\nd\ne\n"},
        })
        res = filetools.read_file(None, "/workspace/foo", offset=10, limit=5)
        self.assertEqual(res["total_lines"], 100)
        self.assertEqual(res["num_lines"], 5)
        self.assertEqual(res["start_line"], 10)
        self.assertTrue(res["was_truncated"])
        self.assertIn("10\u2192a", res["content"])
        self.assertIn("14\u2192e", res["content"])

    # --- argument validation (no sandbox calls needed) --------------------

    def test_write_rejects_nul(self):
        res = filetools.write_file(None, "/workspace/x", "a\x00b")
        self.assertIn("error", res)
        self.assertIn("NUL", res["error"])

    def test_write_rejects_oversized(self):
        res = filetools.write_file(None, "/workspace/x", "a" * 64001)
        self.assertIn("error", res)
        self.assertIn("64000", res["error"])

    def test_edit_rejects_empty_old(self):
        res = filetools.edit(None, "/workspace/x", "", "new")
        self.assertIn("error", res)

    def test_edit_rejects_old_equals_new(self):
        res = filetools.edit(None, "/workspace/x", "same", "same")
        self.assertIn("error", res)

    def test_edit_rejects_nul_in_new(self):
        res = filetools.edit(None, "/workspace/x", "old", "a\x00b")
        self.assertIn("error", res)
        self.assertIn("NUL", res["error"])

    def test_grep_rejects_empty_pattern(self):
        res = filetools.grep(None, "")
        self.assertIn("error", res)


# ---------------------------------------------------------------------------
# End-to-end tests (real sandbox — mirrors test_e2e.py)
# ---------------------------------------------------------------------------


@unittest.skipUnless(
    _prerequisites_met(),
    "prerequisites not met: need built stage3, bootstrapped rootfs, and bwrap "
    "(run 'make stage3' and/or 'make bootstrap-rootfs')",
)
class TestFiletoolsSandbox(unittest.TestCase):
    """File tools exercised against a live bwrap sandbox."""

    _tmp = None
    _patches = []

    @classmethod
    def setUpClass(cls):
        from rattan import layers, overlay, sessions

        cls._tmp = tempfile.TemporaryDirectory(prefix="rattan-test-filetools-")
        cls._patches = [
            mock.patch.object(config, "data_dir", return_value=cls._tmp.name),
            mock.patch.object(config, "layers_dir",
                              lambda: os.path.join(cls._tmp.name, "layers")),
            mock.patch.object(config, "sessions_dir",
                              lambda: os.path.join(cls._tmp.name, "sessions")),
            mock.patch.object(config, "index_lock_path",
                              lambda: os.path.join(cls._tmp.name, "layers", "index.lock")),
            # The REAL bootstrapped base rootfs must be the overlay lower.
            mock.patch.object(config, "base_rootfs_path",
                              lambda: os.path.join(
                                  os.environ.get("HOME", "/home/arch"),
                                  ".local", "share", "rattan", "rootfs", "base")),
        ]
        for p in cls._patches:
            p.start()

        sessions._current = None  # drop any stale singleton from other modules
        cls.session = sessions.get_or_create(sid="filetools-test")
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
        from rattan import layers
        layers.reset(self.session)

    def tearDown(self):
        from rattan import layers
        layers.reset(self.session)

    # --- read_file --------------------------------------------------------

    def test_read_roundtrip(self):
        self._run("seq 1 100 > /workspace/lines100.txt")
        res = filetools.read_file(self.session, "/workspace/lines100.txt", offset=10, limit=5)
        self.assertNotIn("error", res)
        self.assertEqual(res["total_lines"], 100)
        self.assertEqual(res["num_lines"], 5)
        self.assertEqual(res["start_line"], 10)
        self.assertTrue(res["was_truncated"])
        self.assertIn("10\u219210", res["content"])
        self.assertIn("14\u219214", res["content"])

    def test_read_full_file(self):
        # echo adds a trailing newline, so wc -l reports exactly 1 line.
        self._run("echo 'hello world' > /workspace/hello.txt")
        res = filetools.read_file(self.session, "/workspace/hello.txt")
        self.assertNotIn("error", res)
        self.assertEqual(res["total_lines"], 1)
        self.assertEqual(res["num_lines"], 1)
        self.assertIn("hello world", res["content"])
        self.assertFalse(res["was_truncated"])

    def test_read_offset_past_eof(self):
        self._run("seq 1 100 > /workspace/lines100.txt")
        res = filetools.read_file(self.session, "/workspace/lines100.txt", offset=500)
        self.assertNotIn("error", res)
        self.assertEqual(res["num_lines"], 0)
        self.assertEqual(res["content"], "")
        self.assertFalse(res["was_truncated"])

    def test_read_missing_file(self):
        res = filetools.read_file(self.session, "/workspace/nonexistent.txt")
        self.assertIn("error", res)

    def test_read_directory(self):
        res = filetools.read_file(self.session, "/workspace")
        self.assertIn("error", res)

    # --- write_file -------------------------------------------------------

    def test_write_create_and_verify(self):
        res = filetools.write_file(self.session, "/workspace/new.txt", "hello world")
        self.assertNotIn("error", res)
        self.assertEqual(res["bytes_written"], len("hello world"))
        check = self._run("cat /workspace/new.txt")
        self.assertIn("hello world", check["output"])

    def test_write_parent_dir_creation(self):
        res = filetools.write_file(self.session, "/workspace/a/b/c/new.txt", "x")
        self.assertNotIn("error", res)
        check = self._run("cat /workspace/a/b/c/new.txt")
        self.assertIn("x", check["output"])

    def test_write_existing_file(self):
        self._run("printf 'existing' > /workspace/dup.txt")
        res = filetools.write_file(self.session, "/workspace/dup.txt", "new")
        self.assertIn("error", res)
        self.assertIn("already exists", res["error"])

    def test_write_nul_rejected(self):
        res = filetools.write_file(self.session, "/workspace/nul.txt", "a\x00b")
        self.assertIn("error", res)
        self.assertIn("NUL", res["error"])

    def test_write_oversized_rejected(self):
        res = filetools.write_file(self.session, "/workspace/big.txt", "a" * 64001)
        self.assertIn("error", res)
        self.assertIn("64000", res["error"])

    # --- edit -------------------------------------------------------------

    def test_edit_single_replace(self):
        self._run("printf 'hello world' > /workspace/e.txt")
        res = filetools.edit(self.session, "/workspace/e.txt", "hello", "goodbye")
        self.assertNotIn("error", res)
        self.assertIn("updated", res["message"])
        check = self._run("cat /workspace/e.txt")
        self.assertIn("goodbye world", check["output"])

    def test_edit_multiple_requires_replace_all(self):
        self._run("printf 'aa bb aa' > /workspace/e.txt")
        res = filetools.edit(self.session, "/workspace/e.txt", "aa", "zz")
        self.assertIn("error", res)
        self.assertIn("2 matches", res["error"])

    def test_edit_replace_all(self):
        self._run("printf 'aa bb aa' > /workspace/e.txt")
        res = filetools.edit(self.session, "/workspace/e.txt", "aa", "zz", replace_all=True)
        self.assertNotIn("error", res)
        check = self._run("cat /workspace/e.txt")
        self.assertIn("zz bb zz", check["output"])

    def test_edit_old_absent(self):
        self._run("printf 'hello' > /workspace/e.txt")
        res = filetools.edit(self.session, "/workspace/e.txt", "missing", "x")
        self.assertIn("error", res)
        self.assertIn("not found", res["error"])

    def test_edit_idempotency(self):
        self._run("printf 'hello' > /workspace/e.txt")
        filetools.edit(self.session, "/workspace/e.txt", "hello", "goodbye")
        res = filetools.edit(self.session, "/workspace/e.txt", "hello", "again")
        self.assertIn("error", res)
        self.assertIn("not found", res["error"])

    def test_edit_no_temp_left(self):
        self._run("printf 'hello world' > /workspace/e.txt")
        filetools.edit(self.session, "/workspace/e.txt", "hello", "goodbye")
        names = os.listdir(self.session.workspace)
        self.assertFalse(
            any(n.startswith(".rattan-edit-") for n in names),
            f"leftover temp file in workspace: {names}",
        )

    # --- grep -------------------------------------------------------------

    def test_grep_basic_across_two_files(self):
        filetools.write_file(self.session, "/workspace/g1.txt", "alpha needle one\n")
        filetools.write_file(self.session, "/workspace/g2.txt", "beta needle two\n")
        res = filetools.grep(self.session, "needle", path="/workspace")
        self.assertNotIn("error", res)
        self.assertIn("g1.txt", res["matches"])
        self.assertIn("g2.txt", res["matches"])
        self.assertEqual(res["match_count"], 2)
        self.assertFalse(res["was_truncated"])

    def test_grep_max_matches_truncation(self):
        self._run("seq 1 200 > /workspace/num200.txt")
        res = filetools.grep(self.session, "[0-9]+", path="/workspace/num200.txt", max_matches=5)
        self.assertNotIn("error", res)
        self.assertEqual(res["match_count"], 5)
        self.assertTrue(res["was_truncated"])

    def test_grep_excludes_venv(self):
        self._run("mkdir -p /workspace/proj/.venv")
        filetools.write_file(self.session, "/workspace/proj/.venv/hidden.py", "NEEDLE\n")
        filetools.write_file(self.session, "/workspace/proj/main.py", "NEEDLE\n")
        res = filetools.grep(self.session, "NEEDLE", path="/workspace/proj")
        self.assertNotIn("error", res)
        self.assertIn("main.py", res["matches"])
        self.assertNotIn(".venv", res["matches"])
        self.assertNotIn("hidden.py", res["matches"])

    def test_grep_host_path_rejected(self):
        res = filetools.grep(self.session, "x", path="/home/arch/foo")
        self.assertIn("error", res)


if __name__ == "__main__":
    unittest.main()
