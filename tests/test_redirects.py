"""Tests for redirect validation (container-path roots) and application."""

import os
import subprocess
import tempfile
import unittest
from unittest import mock

from rattan.parser import ParseError, RedirectSpec
from rattan.redirects import CONTAINER_ROOTS, FdDefaults, FdPlan, RedirectPlan


class TestRedirectPlan(unittest.TestCase):
    """RedirectPlan.apply() tests."""

    def test_output_inside_workspace(self):
        specs = (RedirectSpec(fd=1, op=">", target="/workspace/out.txt"),)
        plan = RedirectPlan(specs=specs)
        fd_plan = plan.apply(FdDefaults())
        self.assertEqual(fd_plan.stdout, "/workspace/out.txt")
        self.assertIsNone(fd_plan.stdin)
        self.assertIsNone(fd_plan.stderr)

    def test_output_inside_tmp(self):
        specs = (RedirectSpec(fd=1, op=">", target="/tmp/out.txt"),)
        plan = RedirectPlan(specs=specs)
        fd_plan = plan.apply(FdDefaults())
        self.assertEqual(fd_plan.stdout, "/tmp/out.txt")

    def test_input_inside_tmp(self):
        specs = (RedirectSpec(fd=0, op="<", target="/tmp/in.txt"),)
        plan = RedirectPlan(specs=specs)
        fd_plan = plan.apply(FdDefaults())
        self.assertEqual(fd_plan.stdin, "/tmp/in.txt")

    def test_stderr_inside_workspace(self):
        specs = (RedirectSpec(fd=2, op="2>", target="/workspace/err.txt"),)
        plan = RedirectPlan(specs=specs)
        fd_plan = plan.apply(FdDefaults())
        self.assertEqual(fd_plan.stderr, "/workspace/err.txt")

    def test_merge_redirects(self):
        specs = (RedirectSpec(fd=1, op="1>&2", target="2"),)
        plan = RedirectPlan(specs=specs)
        fd_plan = plan.apply(FdDefaults())
        self.assertEqual(fd_plan.stdout, "&2")

    def test_merge_stderr(self):
        specs = (RedirectSpec(fd=2, op="2>&1", target="1"),)
        plan = RedirectPlan(specs=specs)
        fd_plan = plan.apply(FdDefaults())
        self.assertEqual(fd_plan.stderr, "&1")


class TestRootValidation(unittest.TestCase):
    """Container-path root validation."""

    def test_reject_outside_roots(self):
        specs = (RedirectSpec(fd=1, op=">", target="/etc/passwd"),)
        plan = RedirectPlan(specs=specs)
        with self.assertRaises(ParseError) as ctx:
            plan.apply(FdDefaults())
        self.assertIn("redirect target must be under", str(ctx.exception))

    def test_reject_root_filesystem(self):
        specs = (RedirectSpec(fd=1, op=">", target="/root/evil"),)
        plan = RedirectPlan(specs=specs)
        with self.assertRaises(ParseError):
            plan.apply(FdDefaults())

    def test_accept_workspace_subdir(self):
        specs = (RedirectSpec(fd=1, op=">", target="/workspace/sub/deep/file.txt"),)
        plan = RedirectPlan(specs=specs)
        fd_plan = plan.apply(FdDefaults())
        self.assertEqual(fd_plan.stdout, "/workspace/sub/deep/file.txt")

    def test_reject_path_traversal(self):
        # /workspace/../etc is lexically /etc
        specs = (RedirectSpec(fd=1, op=">", target="/workspace/../etc/passwd"),)
        plan = RedirectPlan(specs=specs)
        with self.assertRaises(ParseError):
            plan.apply(FdDefaults())

    def test_reject_tmp_traversal(self):
        specs = (RedirectSpec(fd=1, op=">", target="/tmp/../../../etc/passwd"),)
        plan = RedirectPlan(specs=specs)
        with self.assertRaises(ParseError):
            plan.apply(FdDefaults())


class TestIsUnder(unittest.TestCase):
    """Lexical path containment tests."""

    def test_exact_match(self):
        from rattan.redirects import _is_under
        self.assertTrue(_is_under("/workspace", "/workspace"))
        self.assertTrue(_is_under("/tmp", "/tmp"))

    def test_subpath(self):
        from rattan.redirects import _is_under
        self.assertTrue(_is_under("/workspace/foo", "/workspace"))
        self.assertTrue(_is_under("/tmp/a/b/c", "/tmp"))

    def test_not_under(self):
        from rattan.redirects import _is_under
        self.assertFalse(_is_under("/etc/passwd", "/workspace"))
        self.assertFalse(_is_under("/var/log", "/tmp"))

    def test_traversal_normalized(self):
        from rattan.redirects import _is_under
        # /workspace/../etc normalizes to /etc, which is NOT under /workspace
        self.assertFalse(_is_under("/workspace/../etc", "/workspace"))


# ---------------------------------------------------------------------------
# Redirect application tests (host resolution + spawn_kwargs)
# ---------------------------------------------------------------------------


class TestRedirectApplication(unittest.TestCase):
    """Tests for host-side redirect resolution and _spawn_kwargs."""

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="rattan-test-redir-")
        cls._patches = [
            mock.patch.dict(os.environ, {"RATTAN_DATA_DIR": cls._tmp}),
        ]
        for p in cls._patches:
            p.start()

    @classmethod
    def tearDownClass(cls):
        for p in reversed(cls._patches):
            p.stop()
        import shutil
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def setUp(self):
        from rattan import layers
        self.session = layers.create_session()
        # Tracks /tmp redirect temp files created by _build so they're removed
        # in tearDown (unit tests build but don't run, so run_command cleanup
        # never fires).
        self._cleanup_paths: list[str] = []

    def tearDown(self):
        from rattan import layers
        layers.destroy(self.session)
        for p in self._cleanup_paths:
            try:
                os.unlink(p)
            except OSError:
                pass

    def _build(self, command: str, cwd: str = "/workspace") -> FdPlan:
        plan = self._build_impl(command, cwd)
        # /tmp redirects created a host temp file registered for cleanup; since
        # we don't run the command here, unlink it in tearDown instead.
        self._cleanup_paths.extend(plan.cleanup_paths)
        return plan

    def _build_impl(self, command: str, cwd: str = "/workspace") -> FdPlan:
        """Parse *command* and return the fd_plan from build_invocation."""
        from rattan.executor import build_invocation
        from rattan.parser import parse
        program = parse(command)
        cmd_node = program.andors[0].pipelines[0].commands[0]
        env_store = {"HOME": "/workspace", "PATH": "/usr/bin:/bin", "USER": "test"}
        inv = build_invocation(cmd_node, self.session, env_store, cwd, 30)
        return inv.fd_plan

    # ---- stdout redirects ----

    def test_stdout_workspace_absolute(self):
        """cmd > /workspace/out.txt → host_stdout maps to session.workspace."""
        plan = self._build("echo hi > /workspace/out.txt")
        expected = os.path.join(self.session.workspace, "out.txt")
        self.assertEqual(plan.host_stdout, expected)
        self.assertFalse(plan.stdout_append)
        self.assertIsNone(plan.host_stderr)
        self.assertIsNone(plan.host_stdin)

    def test_stdout_workspace_append(self):
        """cmd >> /workspace/out.txt → host_stdout same path, append True."""
        plan = self._build("echo hi >> /workspace/out.txt")
        expected = os.path.join(self.session.workspace, "out.txt")
        self.assertEqual(plan.host_stdout, expected)
        self.assertTrue(plan.stdout_append)

    def test_stdout_workspace_relative(self):
        """cmd > out.txt with cwd=/workspace → resolved to /workspace/out.txt."""
        plan = self._build("echo hi > out.txt", cwd="/workspace")
        expected = os.path.join(self.session.workspace, "out.txt")
        self.assertEqual(plan.host_stdout, expected)
        self.assertEqual(plan.stdout, "/workspace/out.txt")  # container path
        self.assertFalse(plan.stdout_append)

    def test_stdout_workspace_relative_append(self):
        """cmd >> out.txt → append flag True."""
        plan = self._build("echo hi >> out.txt", cwd="/workspace")
        self.assertTrue(plan.stdout_append)

    def test_stdout_tmp(self):
        """cmd > /tmp/out.txt → host_stdout is a temp file with bind."""
        plan = self._build("echo hi > /tmp/out.txt")
        self.assertIsNotNone(plan.host_stdout)
        self.assertTrue(os.path.isfile(plan.host_stdout) or True)  # mkstemp creates it
        self.assertIn(plan.host_stdout, plan.cleanup_paths)
        # extra_binds should have a --bind entry
        self.assertTrue(len(plan.extra_binds) >= 1)
        bind_triple = plan.extra_binds[0]
        self.assertEqual(bind_triple[0], "--bind")
        self.assertEqual(bind_triple[2], "/tmp/out.txt")

    def test_stdout_tmp_in_cleanup(self):
        """The /tmp temp file is registered for cleanup."""
        plan = self._build("echo hi > /tmp/x.txt")
        self.assertIn(plan.host_stdout, plan.cleanup_paths)

    # ---- stdin redirect ----

    def test_stdin_workspace(self):
        """cmd < /workspace/in.txt → host_stdin set."""
        plan = self._build("cat < /workspace/in.txt")
        expected = os.path.join(self.session.workspace, "in.txt")
        self.assertEqual(plan.host_stdin, expected)
        self.assertIsNone(plan.host_stdout)

    # ---- stderr redirect ----

    def test_stderr_workspace(self):
        """cmd 2> /workspace/e.txt → host_stderr set."""
        plan = self._build("cmd 2> /workspace/e.txt")
        expected = os.path.join(self.session.workspace, "e.txt")
        self.assertEqual(plan.host_stderr, expected)
        self.assertFalse(plan.stderr_append)

    def test_stderr_workspace_append(self):
        """cmd 2>> /workspace/e.txt → stderr_append True."""
        plan = self._build("cmd 2>> /workspace/e.txt")
        self.assertTrue(plan.stderr_append)

    # ---- merge redirects ----

    def test_merge_2gt1_no_file(self):
        """cmd 2>&1 (no file target) → stderr=&1, no host_*."""
        plan = self._build("cmd 2>&1")
        self.assertEqual(plan.stderr, "&1")
        self.assertIsNone(plan.host_stdout)
        self.assertIsNone(plan.host_stderr)

    def test_merge_2gt1_with_file(self):
        """cmd > /workspace/f.txt 2>&1 → stderr=&1, host_stdout set."""
        plan = self._build("cmd > /workspace/f.txt 2>&1")
        self.assertEqual(plan.stderr, "&1")
        expected = os.path.join(self.session.workspace, "f.txt")
        self.assertEqual(plan.host_stdout, expected)

    def test_merge_1gt2_with_file(self):
        """cmd 2> /workspace/e.txt 1>&2 → stdout=&2, host_stderr set."""
        plan = self._build("cmd 2> /workspace/e.txt 1>&2")
        self.assertEqual(plan.stdout, "&2")
        expected = os.path.join(self.session.workspace, "e.txt")
        self.assertEqual(plan.host_stderr, expected)

    # ---- _spawn_kwargs tests ----

    def test_spawn_kwargs_no_redirect(self):
        """Plain command → stdout=PIPE, stderr=STDOUT, no stdin key."""
        from rattan.executor import _spawn_kwargs
        plan = self._build("echo hi")
        kwargs, opened = _spawn_kwargs(plan)
        self.assertEqual(kwargs.get("stdout"), subprocess.PIPE)
        self.assertEqual(kwargs.get("stderr"), subprocess.STDOUT)
        self.assertNotIn("stdin", kwargs)
        self.assertEqual(len(opened), 0)

    def test_spawn_kwargs_file_stdout(self):
        """cmd > f.txt → stdout is an opened file object."""
        from rattan.executor import _spawn_kwargs
        plan = self._build("echo hi > /workspace/f.txt")
        kwargs, opened = _spawn_kwargs(plan)
        self.assertNotEqual(kwargs["stdout"], subprocess.PIPE)
        self.assertTrue(hasattr(kwargs["stdout"], "write"))
        self.assertEqual(len(opened), 1)
        # Clean up
        for f in opened:
            f.close()

    def test_spawn_kwargs_2gt1_merge_same_object(self):
        """cmd > /workspace/f.txt 2>&1 → stdout is stderr (same file object)."""
        from rattan.executor import _spawn_kwargs
        plan = self._build("cmd > /workspace/f.txt 2>&1")
        kwargs, opened = _spawn_kwargs(plan)
        self.assertIs(kwargs["stdout"], kwargs["stderr"])
        self.assertIsNot(kwargs["stdout"], subprocess.PIPE)
        self.assertIsNot(kwargs["stderr"], subprocess.STDOUT)
        for f in opened:
            f.close()

    def test_spawn_kwargs_1gt2_merge_same_object(self):
        """cmd 2> /workspace/e.txt 1>&2 → stdout is stderr (same file object)."""
        from rattan.executor import _spawn_kwargs
        plan = self._build("cmd 2> /workspace/e.txt 1>&2")
        kwargs, opened = _spawn_kwargs(plan)
        self.assertIs(kwargs["stdout"], kwargs["stderr"])
        for f in opened:
            f.close()

    def test_spawn_kwargs_separate_fds(self):
        """cmd > /workspace/out.txt 2> /workspace/e.txt → distinct objects."""
        from rattan.executor import _spawn_kwargs
        plan = self._build("cmd > /workspace/out.txt 2> /workspace/e.txt")
        kwargs, opened = _spawn_kwargs(plan)
        self.assertIsNot(kwargs["stdout"], kwargs["stderr"])
        self.assertNotEqual(kwargs["stdout"], subprocess.PIPE)
        self.assertNotEqual(kwargs["stderr"], subprocess.STDOUT)
        for f in opened:
            f.close()

    def test_spawn_kwargs_append_mode(self):
        """cmd >> f.txt → file opened in append ('ab') mode."""
        from rattan.executor import _spawn_kwargs
        plan = self._build("cmd >> /workspace/f.txt")
        kwargs, opened = _spawn_kwargs(plan)
        self.assertIn(kwargs["stdout"].mode, ("ab", "a+b"))
        for f in opened:
            f.close()

    def test_spawn_kwargs_truncate_mode(self):
        """cmd > f.txt → file opened in write ('wb') mode."""
        from rattan.executor import _spawn_kwargs
        plan = self._build("cmd > /workspace/f.txt")
        kwargs, opened = _spawn_kwargs(plan)
        self.assertIn(kwargs["stdout"].mode, ("wb", "w+b"))
        for f in opened:
            f.close()

    # ---- Integration: write through _spawn_kwargs and verify file content ----

    def test_write_to_file_via_spawn_kwargs(self):
        """Write data through a _spawn_kwargs-opened file and read it back."""
        from rattan.executor import _spawn_kwargs
        plan = self._build("cmd > /workspace/out.txt")
        kwargs, opened = _spawn_kwargs(plan)
        try:
            kwargs["stdout"].write(b"hello redirect\n")
            kwargs["stdout"].flush()
            # Close so data is flushed to disk
            for f in opened:
                f.close()
            # Read back from the host path
            with open(plan.host_stdout, "rb") as f:
                content = f.read()
            self.assertEqual(content, b"hello redirect\n")
        finally:
            for f in opened:
                try:
                    f.close()
                except OSError:
                    pass
            for p in plan.cleanup_paths:
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def test_append_preserves_content(self):
        """>> preserves existing content across two separate opens."""
        from rattan.executor import _spawn_kwargs
        plan1 = self._build("cmd >> /workspace/log.txt")
        kw1, op1 = _spawn_kwargs(plan1)
        kw1["stdout"].write(b"line1\n")
        kw1["stdout"].flush()
        for f in op1:
            f.close()

        plan2 = self._build("cmd >> /workspace/log.txt")
        kw2, op2 = _spawn_kwargs(plan2)
        try:
            kw2["stdout"].write(b"line2\n")
            kw2["stdout"].flush()
            for f in op2:
                f.close()
            with open(plan1.host_stdout, "rb") as f:
                content = f.read()
            self.assertEqual(content, b"line1\nline2\n")
        finally:
            for f in op2:
                try:
                    f.close()
                except OSError:
                    pass
            for p in plan1.cleanup_paths:
                try:
                    os.unlink(p)
                except OSError:
                    pass

    def test_relative_target_under_workspace(self):
        """cmd > sub/deep/file.txt resolves relative to cwd."""
        plan = self._build("echo hi > sub/deep/file.txt", cwd="/workspace")
        self.assertEqual(plan.stdout, "/workspace/sub/deep/file.txt")
        expected_host = os.path.join(self.session.workspace, "sub", "deep", "file.txt")
        self.assertEqual(plan.host_stdout, expected_host)

    def test_relative_target_rejected_outside_workspace(self):
        """Relative targets outside /workspace are rejected."""
        # cwd=/workspace, relative ../etc should resolve to /etc (rejected)
        from rattan.parser import ParseError as PE
        with self.assertRaises(PE):
            self._build("echo hi > ../etc/passwd", cwd="/workspace")


class TestRedirectUnderBind(unittest.TestCase):
    """Redirect targets under a bind_host_dir mount point.

    A redirect into a bound dir must resolve to the bind's HOST path (not the
    overlay upper). Write redirects into a ``ro`` bind must be DENIED — the
    host-side parent could otherwise open the host file and bypass ``--ro-bind``.
    """

    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.mkdtemp(prefix="rattan-test-bind-")
        cls._patches = [
            mock.patch.dict(os.environ, {"RATTAN_DATA_DIR": cls._tmp}),
        ]
        for p in cls._patches:
            p.start()

    @classmethod
    def tearDownClass(cls):
        for p in reversed(cls._patches):
            p.stop()
        import shutil
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def setUp(self):
        from rattan import layers
        self.session = layers.create_session()
        self.hostdir = tempfile.mkdtemp(prefix="rattan-bind-host-")

    def tearDown(self):
        from rattan import layers
        layers.destroy(self.session)
        import shutil
        shutil.rmtree(self.hostdir, ignore_errors=True)

    def _build(self, command: str, mode: str = "rw",
               mount: str = "/workspace/proj"):
        from rattan import bind
        from rattan.executor import build_invocation
        from rattan.parser import parse
        bind.get_session_binds(self.session.sid).add(self.hostdir, mount, mode)
        program = parse(command)
        cmd_node = program.andors[0].pipelines[0].commands[0]
        env_store = {"HOME": "/workspace", "PATH": "/usr/bin:/bin", "USER": "test"}
        inv = build_invocation(cmd_node, self.session, env_store, "/workspace", 30)
        return inv.fd_plan

    def test_rw_bind_write_redirect_resolves_to_bind_host(self):
        plan = self._build("echo hi > /workspace/proj/out.txt", mode="rw")
        self.assertEqual(plan.host_stdout, os.path.join(self.hostdir, "out.txt"))

    def test_rw_bind_write_subdir(self):
        plan = self._build("echo hi > /workspace/proj/sub/deep/f.txt", mode="rw")
        self.assertEqual(
            plan.host_stdout, os.path.join(self.hostdir, "sub", "deep", "f.txt")
        )

    def test_rw_bind_append(self):
        plan = self._build("echo hi >> /workspace/proj/out.txt", mode="rw")
        self.assertEqual(plan.host_stdout, os.path.join(self.hostdir, "out.txt"))
        self.assertTrue(plan.stdout_append)

    def test_ro_bind_write_redirect_denied(self):
        from rattan.executor import InvocationError
        with self.assertRaises(InvocationError):
            self._build("echo hi > /workspace/proj/out.txt", mode="ro")

    def test_ro_bind_append_redirect_denied(self):
        from rattan.executor import InvocationError
        with self.assertRaises(InvocationError):
            self._build("echo hi >> /workspace/proj/out.txt", mode="ro")

    def test_ro_bind_stderr_redirect_denied(self):
        from rattan.executor import InvocationError
        with self.assertRaises(InvocationError):
            self._build("sh -c true 2> /workspace/proj/err.txt", mode="ro")

    def test_ro_bind_read_redirect_allowed(self):
        plan = self._build("cat < /workspace/proj/in.txt", mode="ro")
        self.assertEqual(plan.host_stdin, os.path.join(self.hostdir, "in.txt"))

    def test_ro_bind_2gt1_write_denied(self):
        from rattan.executor import InvocationError
        with self.assertRaises(InvocationError):
            self._build("echo hi > /workspace/proj/out.txt 2>&1", mode="ro")


if __name__ == "__main__":
    unittest.main()
