"""Regression tests for the security/perf fixes (H-1, H-2, M-2, M-3, C1).

Covers: executor control-env scrubbing (invariant #10), bind_host_dir path
validation (invariant #11), pacman_run arg allowlist (H-1), workspace-included
commit identity (H-2), the index flock across read-modify-write (M-2), and the
once-per-session provisioning seed (C1). Self-contained — no bootstrapped rootfs
required.
"""

import os
import tempfile
import unittest
from unittest import mock

from rattan import bind, config, executor, layers, pacman, parser, policy


class TestSecurityFixes(unittest.TestCase):
    """Regression tests for the security/perf fixes."""

    def setUp(self):
        # Isolate disk-touching tests from the real data dir.
        self._tmp = tempfile.TemporaryDirectory(prefix="rattan-test-fixes-")
        self._env = mock.patch.dict(
            os.environ, {"RATTAN_DATA_DIR": self._tmp.name}
        )
        self._env.start()

    def tearDown(self):
        self._env.stop()
        self._tmp.cleanup()

    # -- executor (invariant #10) ------------------------------------------

    def test_scrub_control_env_strips_control_prefixes(self):
        scrubbed = executor._scrub_control_env({
            "RATTAN_ALLOW_PTRACE": "1",
            "LD_PRELOAD": "x",
            "PYTHONPATH": "y",
            "HOME": "/h",
            "PATH": "/bin",
        })
        self.assertNotIn("RATTAN_ALLOW_PTRACE", scrubbed)
        self.assertNotIn("LD_PRELOAD", scrubbed)
        self.assertNotIn("PYTHONPATH", scrubbed)
        self.assertIn("HOME", scrubbed)
        self.assertIn("PATH", scrubbed)

    def test_build_invocation_sub_env_scrubbed(self):
        s = layers.create_session()
        program = parser.parse("echo hi", {})
        cmd_node = program.andors[0].pipelines[0].commands[0]
        env_store = {
            "HOME": "/workspace",
            "PATH": "/bin",
            "RATTAN_ALLOW_PTRACE": "1",
            "LD_PRELOAD": "x",
            "PYTHONPATH": "y",
        }
        inv = executor.build_invocation(cmd_node, s, env_store, "/workspace", 30)
        for key in ("RATTAN_ALLOW_PTRACE", "LD_PRELOAD", "PYTHONPATH"):
            self.assertNotIn(key, inv.env, f"{key} leaked into subprocess env")
        self.assertIn("HOME", inv.env)
        self.assertIn("PATH", inv.env)

    def test_control_env_prefixes_includes_rattan_and_ld(self):
        self.assertIn("RATTAN_", executor._CONTROL_ENV_PREFIXES)
        self.assertIn("LD_", executor._CONTROL_ENV_PREFIXES)

    # -- bind_host_dir (invariant #11) --------------------------------------

    def test_bind_rejects_host_root(self):
        with self.assertRaises(ValueError):
            bind.validate_host_bind("/", "/workspace/x", "ro")

    def test_bind_rejects_home(self):
        home = os.path.expanduser("~")
        if not home or not os.path.isdir(home):
            self.skipTest("no real $HOME to test against")
        with self.assertRaises(ValueError):
            bind.validate_host_bind(home, "/workspace/x", "ro")

    def test_bind_rejects_data_dir(self):
        # RATTAN_DATA_DIR already points at self._tmp.name; binding it directly
        # must be rejected.
        with self.assertRaises(ValueError):
            bind.validate_host_bind(self._tmp.name, "/workspace/x", "ro")

    def test_bind_rejects_bad_mount_point(self):
        with self.assertRaises(ValueError):
            bind.validate_host_bind("/tmp", "/workspace;x", "ro")

    def test_bind_rejects_cr_and_null_mount_point(self):
        # Carriage return and NUL must not slip past the mount_point validator
        # into the landlock spec builder (bind.py:58 f"{mp}:{perms}").
        for bad in ("/workspace\rx", "/workspace\x00x"):
            with self.assertRaises(ValueError, msg=f"expected rejection of {bad!r}"):
                bind.validate_host_bind("/tmp", bad, "ro")

    def test_bind_allows_innocuous(self):
        # A non-hidden user data dir under $HOME is the intended bind target.
        home = os.path.expanduser("~")
        d = tempfile.mkdtemp(prefix="rattan-allow-", dir=home)
        try:
            b = bind.validate_host_bind(d, "/workspace/data", "ro")
            self.assertIsInstance(b, bind.HostBind)
            self.assertEqual(b.mount_point, "/workspace/data")
        finally:
            os.rmdir(d)

    def test_bind_rejects_system_dirs(self):
        for p in ("/var", "/boot", "/dev", "/run", "/usr", "/bin",
                  "/lib", "/opt", "/srv", "/root", "/tmp"):
            with self.assertRaises(ValueError, msg=f"expected rejection of {p}"):
                bind.validate_host_bind(p, "/workspace/x", "ro")

    def test_bind_rejects_hidden_home_subdirs(self):
        # Hidden $HOME subtrees hold credentials/config (.ssh, .gnupg, ...).
        home = os.path.expanduser("~")
        for sub in (".ssh", ".gnupg", ".config", ".local", ".cache", ".aws"):
            cand = os.path.join(home, sub)
            if not os.path.exists(cand):
                continue  # can't test a nonexistent dir
            with self.assertRaises(ValueError, msg=f"expected rejection of {sub}"):
                bind.validate_host_bind(cand, "/workspace/x", "ro")

    def test_bind_rejects_other_users_home(self):
        # /home/<someone-else> (that isn't our $HOME) must be rejected.
        if os.path.expanduser("~") == "/root":
            self.skipTest("running as root; no /home to test against")
        if not os.path.isdir("/home"):
            self.skipTest("no /home on this system")
        for name in ("other", "nobody"):
            cand = os.path.join("/home", name)
            if os.path.exists(cand) and os.path.realpath(cand) != os.path.realpath(
                os.path.expanduser("~")
            ):
                with self.assertRaises(ValueError):
                    bind.validate_host_bind(cand, "/workspace/x", "ro")

    # -- pacman_run allowlist (H-1) -----------------------------------------

    def test_pacman_run_rejects_mutating(self):
        for bad in (["-U", "/x"], ["--config", "/x"], ["--hookdir", "/x"],
                    ["--cachedir", "/x"], ["-S", "foo"]):
            with self.assertRaises(ValueError, msg=f"expected rejection of {bad}"):
                pacman._check_query_args(bad)

    def test_pacman_run_rejects_cache_clean_and_upgrade(self):
        # -Sc/-Scc clean the package cache (a filesystem write); -Sy/-Su upgrade.
        for bad in (["-Sc"], ["-Scc"], ["-Sy", "foo"], ["-Su"], ["-Ssw"], ["-S"],
                    ["-Scc", "--noconfirm"]):
            with self.assertRaises(ValueError, msg=f"expected rejection of {bad}"):
                pacman._check_query_args(bad)

    def test_pacman_run_accepts_read_only(self):
        for ok in (["-Q"], ["-Si", "foo"], ["-Q", "tree"], ["-Ss", "foo"],
                   ["-Qqs", "tree"], ["-Qkk"], ["--color=never", "-Q"]):
            pacman._check_query_args(ok)  # no raise

    # -- provisioning seed (C1) --------------------------------------------

    def test_provisioning_seed_runs_once(self):
        os.makedirs(os.path.join(self._tmp.name, "rootfs", "base"), exist_ok=True)
        s = layers.create_session()
        marker = os.path.join(s.root, config.SEED_MARKER)
        with mock.patch("rattan.pacman.os.walk", return_value=iter([])) as m_walk:
            pacman.provisioning_seed(s)
            first_calls = m_walk.call_count
            pacman.provisioning_seed(s)
            second_calls = m_walk.call_count
        self.assertTrue(os.path.exists(marker), "seed should write its marker")
        # The walk ran on the first call but was a no-op on the second.
        self.assertEqual(first_calls, 1)
        self.assertEqual(second_calls, 1)

    def test_seed_marker_cleared_on_wipe(self):
        # After a commit/discard wipes the upper, a fresh upper must be re-seeded
        # on the next pacman call (C1 correctness, not just a perf shortcut).
        os.makedirs(os.path.join(self._tmp.name, "rootfs", "base"), exist_ok=True)
        s = layers.create_session()
        with mock.patch("rattan.pacman.os.walk", return_value=iter([])):
            pacman.provisioning_seed(s)
        marker = os.path.join(s.root, config.SEED_MARKER)
        self.assertTrue(os.path.exists(marker))
        layers._wipe_upper(s)
        self.assertFalse(
            os.path.exists(marker),
            "wiping the upper must clear the seed marker so it is re-seeded",
        )

    # -- workspace in commit identity (H-2) ---------------------------------

    def _make_file(self, session, path, content):
        fpath = os.path.join(session.upper, path)
        os.makedirs(os.path.dirname(fpath), exist_ok=True)
        with open(fpath, "w") as f:
            f.write(content)

    def test_workspace_content_affects_commit_id(self):
        s1 = layers.create_session()
        s2 = layers.create_session()
        # Identical non-workspace state in both.
        for s in (s1, s2):
            self._make_file(s, "etc/foo", "same non-workspace content")
        # Different /workspace content — must change the commit identity.
        self._make_file(s1, "workspace/data.txt", "A's workspace")
        self._make_file(s2, "workspace/data.txt", "B's workspace")
        self.assertNotEqual(
            layers._compute_commit_id(s1.upper),
            layers._compute_commit_id(s2.upper),
            "different workspace content must not dedupe to the same commit_id",
        )

    def test_identical_workspace_yields_equal_commit_id(self):
        s3 = layers.create_session()
        s4 = layers.create_session()
        for s in (s3, s4):
            self._make_file(s, "etc/foo", "same content")
            self._make_file(s, "workspace/data.txt", "identical workspace")
        self.assertEqual(
            layers._compute_commit_id(s3.upper),
            layers._compute_commit_id(s4.upper),
        )


class TestExtraPromisesPlumbing(unittest.TestCase):
    """extra_promises must flow: POLICY_TABLE -> resolve -> stage3_env -> env.

    Regression for the pre-existing dead-code bug where stage3_env never set
    RATTAN_EXTRA_PROMISES, so git (sendfd) / gcc (prot_exec) silently ran with
    the baseline promise set only.
    """

    def test_resolve_carries_extra_promises(self):
        self.assertEqual(policy.resolve("git status").extra_promises, "sendfd")
        self.assertEqual(policy.resolve("gcc -c x.c").extra_promises, "prot_exec")
        self.assertEqual(policy.resolve("cc -c x.c").extra_promises, "prot_exec")
        self.assertEqual(policy.resolve("echo hi").extra_promises, "")

    def test_stage3_env_sets_extra_promises(self):
        env = policy.stage3_env(policy.resolve("git status"))
        self.assertEqual(env.get("RATTAN_EXTRA_PROMISES"), "sendfd")
        env = policy.stage3_env(policy.resolve("gcc -c x.c"))
        self.assertEqual(env.get("RATTAN_EXTRA_PROMISES"), "prot_exec")
        # A plain command must NOT set it (baseline stays tight).
        env = policy.stage3_env(policy.resolve("echo hi"))
        self.assertNotIn("RATTAN_EXTRA_PROMISES", env)

    def test_extra_promises_reaches_invocation_env(self):
        s = layers.create_session()
        program = parser.parse("git status", {})
        cmd_node = program.andors[0].pipelines[0].commands[0]
        env_store = {"HOME": "/workspace", "PATH": "/usr/bin:/bin"}
        inv = executor.build_invocation(cmd_node, s, env_store, "/workspace", 30)
        self.assertEqual(inv.env.get("RATTAN_EXTRA_PROMISES"), "sendfd")
        # The agent cannot override it: an attacker-supplied RATTAN_EXTRA_PROMISES
        # in the env store is scrubbed, so only the policy value survives.
        env_store2 = {"HOME": "/workspace", "PATH": "/usr/bin:/bin",
                      "RATTAN_EXTRA_PROMISES": "bogus"}
        inv2 = executor.build_invocation(cmd_node, s, env_store2, "/workspace", 30)
        self.assertEqual(inv2.env.get("RATTAN_EXTRA_PROMISES"), "sendfd",
                         "policy value must win over an agent-supplied override")


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

    def test_default_binds_seed_new_sessions(self):
        from rattan import bind
        host = tempfile.mkdtemp(prefix="rattan-defbind-",
                                dir=os.path.expanduser("~"))
        try:
            b = bind.validate_host_bind(host, "/workspace/proj", "rw")
            bind.set_default_binds([b])
            # A fresh session gets the default without an explicit bind call.
            sb = bind.get_session_binds("defbind-sid-1")
            self.assertIn("/workspace/proj",
                          [x.mount_point for x in sb.binds])
            self.assertEqual(sb.binds[0].mode, "rw")
            # A second fresh sid is also seeded.
            sb2 = bind.get_session_binds("defbind-sid-2")
            self.assertIn("/workspace/proj",
                          [x.mount_point for x in sb2.binds])
        finally:
            from rattan import bind as _b
            _b.set_default_binds([])
            _b.clear_session_binds("defbind-sid-1")
            _b.clear_session_binds("defbind-sid-2")
            import shutil
            shutil.rmtree(host, ignore_errors=True)

    def test_bind_cwd_binds_launch_dir_to_workspace(self):
        """--bind-cwd binds the server launch dir onto /workspace (rw)."""
        from rattan import bind
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
            from rattan import bind as _b
            _b.set_default_binds([])
            _b.clear_session_binds("bindcwd-sid")
            import shutil
            shutil.rmtree(host, ignore_errors=True)


class TestCdBuiltin(unittest.TestCase):
    """Unit tests for the in-process `cd` builtin (_try_cd).

    `cd` must only work in the `cd X && command` form (as agents use it),
    handled by the executor's own parser — never routed through /bin/sh.
    These tests exercise the pure resolution logic with no subprocess/rootfs.
    """

    def _try(self, cmdstr, cur_cwd="/workspace"):
        program = parser.parse(cmdstr)
        pipeline = program.andors[0].pipelines[0]
        return executor._try_cd(pipeline, {}, cur_cwd)

    def test_valid_absolute(self):
        new_cwd, stage = self._try("cd /tmp")
        self.assertEqual(new_cwd, "/tmp")
        self.assertEqual(stage["rc"], 0)
        self.assertEqual(stage["output"], "")

    def test_valid_relative_resolves_against_cwd(self):
        new_cwd, stage = self._try("cd sub")
        self.assertEqual(new_cwd, "/workspace/sub")
        self.assertEqual(stage["rc"], 0)

    def test_relative_from_changed_cwd(self):
        new_cwd, stage = self._try("cd ../tmp", cur_cwd="/workspace")
        self.assertEqual(new_cwd, "/tmp")
        self.assertEqual(stage["rc"], 0)

    def test_rejects_outside_roots(self):
        new_cwd, stage = self._try("cd /etc")
        self.assertIsNone(new_cwd)
        self.assertEqual(stage["rc"], 1)
        self.assertIn("must be under one of", stage["output"])

    def test_bare_cd_errors(self):
        new_cwd, stage = self._try("cd")
        self.assertIsNone(new_cwd)
        self.assertEqual(stage["rc"], 1)
        self.assertIn("no directory", stage["output"])

    def test_too_many_arguments(self):
        new_cwd, stage = self._try("cd a b")
        self.assertIsNone(new_cwd)
        self.assertEqual(stage["rc"], 1)
        self.assertIn("too many arguments", stage["output"])

    def test_non_cd_command_passes_through(self):
        new_cwd, stage = self._try("echo hi")
        self.assertIsNone(new_cwd)
        self.assertIsNone(stage)

    def test_multicommand_pipeline_is_not_builtin(self):
        # `cd /tmp && ls` parsed as separate pipelines; but a pipeline with
        # >1 command (e.g. a pipe) must not be treated as a builtin.
        program = parser.parse("cd /tmp | wc -l")
        pipeline = program.andors[0].pipelines[0]
        new_cwd, stage = executor._try_cd(pipeline, {}, "/workspace")
        self.assertIsNone(new_cwd)
        self.assertIsNone(stage)


if __name__ == "__main__":
    unittest.main()
