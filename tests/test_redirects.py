"""Tests for redirect validation (container-path roots)."""

import unittest

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


if __name__ == "__main__":
    unittest.main()
