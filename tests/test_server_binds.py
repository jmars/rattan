"""Server --bind / --bind-ro arg parsing (regression).

Split out of test_fixes.py during the core extraction: these two
tests exercise the server's _parse_default_binds and the
launch-dir-to-/workspace bind-cwd behavior.
"""

import os
import tempfile
import unittest

from palisade import bind
from rattan.server import _parse_default_binds

class TestDefaultBinds(unittest.TestCase):
    """Server --bind / --bind-ro args and per-session default-bind seeding."""

    def test_parse_default_binds(self):
        from rattan.server import _parse_default_binds
        # no suffix -> rw (--bind default)
        self.assertEqual(
            _parse_default_binds(["--bind", "~/projects=/workspace/projects"]),
            [("~/projects", "/workspace/projects", "rw")],
        )
        # :ro / :rw suffix overrides the default
        self.assertEqual(
            _parse_default_binds(["--bind", "/data=/mnt/data:ro"]),
            [("/data", "/mnt/data", "ro")],
        )
        self.assertEqual(
            _parse_default_binds(["--bind", "/data=/mnt/data:rw"]),
            [("/data", "/mnt/data", "rw")],
        )
        # --bind-ro without suffix -> ro
        self.assertEqual(
            _parse_default_binds(["--bind-ro", "/x=/mnt/x"]),
            [("/x", "/mnt/x", "ro")],
        )
        # mixed, repeatable
        self.assertEqual(
            _parse_default_binds(
                ["--bind", "/a=/mnt/a", "--bind", "/b=/mnt/b:ro",
                 "--bind-ro", "/c=/mnt/c"]
            ),
            [("/a", "/mnt/a", "rw"), ("/b", "/mnt/b", "ro"),
             ("/c", "/mnt/c", "ro")],
        )
        self.assertEqual(_parse_default_binds(["--probe"]), [])
        with self.assertRaises(ValueError):
            _parse_default_binds(["--bind"])
        with self.assertRaises(ValueError):
            _parse_default_binds(["--bind", "no-equals"])

    def test_bind_cwd_binds_launch_dir_to_workspace(self):
        """--bind-cwd binds the server launch dir onto /workspace (rw)."""
        from palisade import bind
        from rattan.server import _parse_default_binds
        # Simulate main()'s --bind-cwd handling: build the default list exactly
        # as main() does (parsed binds + a validate of os.getcwd() -> /workspace).
        host = tempfile.mkdtemp(prefix="rattan-bindcwd-",
                                dir=os.path.expanduser("~"))
        old_cwd = os.getcwd()
        try:
            os.chdir(host)
            defaults = [
                bind.validate_host_bind(h, m, mode)
                for h, m, mode in _parse_default_binds([])
            ]
            launch_dir = os.path.abspath(os.getcwd())
            defaults.append(
                bind.validate_host_bind(launch_dir, "/workspace", "rw")
            )
            self.assertEqual(len(defaults), 1)
            self.assertEqual(defaults[0].mount_point, "/workspace")
            self.assertEqual(defaults[0].mode, "rw")
            self.assertEqual(defaults[0].host_path, os.path.realpath(host))

            bind.set_default_binds(defaults)
            sb = bind.get_session_binds("bindcwd-sid")
            ws = [x for x in sb.binds if x.mount_point == "/workspace"]
            self.assertEqual(len(ws), 1)
            self.assertEqual(ws[0].mode, "rw")
            self.assertEqual(ws[0].host_path, os.path.realpath(host))
        finally:
            os.chdir(old_cwd)
            from palisade import bind as _b
            _b.set_default_binds([])
            _b.clear_session_binds("bindcwd-sid")
            import shutil
            shutil.rmtree(host, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
