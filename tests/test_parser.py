"""Tests for the clean-room AST command parser."""

import unittest

from rattan.parser import (
    AndOrNode,
    CommandNode,
    PartKind,
    ParseError,
    PipelineNode,
    ProgramNode,
    RedirectSpec,
    Word,
    WordPart,
    parse,
)


class TestSimpleCommands(unittest.TestCase):
    """Basic single-command parsing."""

    def test_single_word(self):
        prog = parse("echo")
        self.assertEqual(len(prog.andors), 1)
        self.assertEqual(len(prog.andors[0].pipelines), 1)
        self.assertEqual(len(prog.andors[0].pipelines[0].commands), 1)
        cmd = prog.andors[0].pipelines[0].commands[0]
        self.assertEqual(len(cmd.argv), 1)
        self.assertEqual(cmd.argv[0].expand({}), "echo")

    def test_multiple_words(self):
        prog = parse("echo hello world")
        cmd = prog.andors[0].pipelines[0].commands[0]
        self.assertEqual(len(cmd.argv), 3)
        self.assertEqual(cmd.argv[0].expand({}), "echo")
        self.assertEqual(cmd.argv[1].expand({}), "hello")
        self.assertEqual(cmd.argv[2].expand({}), "world")

    def test_single_quoted(self):
        prog = parse("echo 'hello world'")
        cmd = prog.andors[0].pipelines[0].commands[0]
        self.assertEqual(len(cmd.argv), 2)
        w = cmd.argv[1]
        self.assertEqual(len(w.parts), 1)
        self.assertEqual(w.parts[0].kind, PartKind.SINGLE_QUOTED)
        self.assertEqual(w.parts[0].text, "hello world")
        self.assertEqual(w.expand({}), "hello world")

    def test_double_quoted_var(self):
        prog = parse('echo "hello $USER"')
        cmd = prog.andors[0].pipelines[0].commands[0]
        w = cmd.argv[1]
        self.assertEqual(len(w.parts), 2)
        self.assertEqual(w.parts[0].kind, PartKind.DOUBLE_QUOTED)
        self.assertEqual(w.parts[0].text, "hello ")
        self.assertEqual(w.parts[1].kind, PartKind.VAR)
        self.assertEqual(w.parts[1].text, "USER")
        self.assertEqual(w.expand({"USER": "test"}), "hello test")

    def test_backslash_escape(self):
        prog = parse(r"echo hello\ world")
        cmd = prog.andors[0].pipelines[0].commands[0]
        self.assertEqual(len(cmd.argv), 2)
        self.assertEqual(cmd.argv[1].expand({}), "hello world")

    def test_var_expansion(self):
        prog = parse("echo $HOME")
        cmd = prog.andors[0].pipelines[0].commands[0]
        w = cmd.argv[1]
        self.assertEqual(w.parts[0].kind, PartKind.VAR)
        self.assertEqual(w.parts[0].text, "HOME")

    def test_braced_var(self):
        prog = parse("echo ${HOME}")
        cmd = prog.andors[0].pipelines[0].commands[0]
        w = cmd.argv[1]
        self.assertEqual(w.parts[0].kind, PartKind.VAR)
        self.assertEqual(w.parts[0].text, "{HOME}")

    def test_assignment_prefix(self):
        prog = parse("VAR=val echo hi")
        cmd = prog.andors[0].pipelines[0].commands[0]
        self.assertEqual(cmd.assignments, (("VAR", "val"),))
        self.assertEqual(len(cmd.argv), 2)

    def test_comment(self):
        prog = parse("echo hi # this is a comment")
        cmd = prog.andors[0].pipelines[0].commands[0]
        self.assertEqual(len(cmd.argv), 2)


class TestPipelines(unittest.TestCase):
    """Pipeline parsing (1-2 commands)."""

    def test_single_pipe(self):
        prog = parse("cmd1 | cmd2")
        self.assertEqual(len(prog.andors), 1)
        pipe = prog.andors[0].pipelines[0]
        self.assertEqual(len(pipe.commands), 2)
        self.assertEqual(pipe.commands[0].argv[0].expand({}), "cmd1")
        self.assertEqual(pipe.commands[1].argv[0].expand({}), "cmd2")

    def test_multi_pipe_rejected(self):
        with self.assertRaises(ParseError):
            parse("cmd1 | cmd2 | cmd3")


class TestAndOr(unittest.TestCase):
    """And-or list parsing (&& / ||)."""

    def test_and(self):
        prog = parse("cmd1 && cmd2")
        andor = prog.andors[0]
        self.assertEqual(len(andor.pipelines), 2)
        self.assertEqual(andor.ops, ("&&",))

    def test_or(self):
        prog = parse("cmd1 || cmd2")
        andor = prog.andors[0]
        self.assertEqual(andor.ops, ("||",))

    def test_chained(self):
        prog = parse("a && b || c")
        andor = prog.andors[0]
        self.assertEqual(len(andor.pipelines), 3)
        self.assertEqual(andor.ops, ("&&", "||"))


class TestSemicolon(unittest.TestCase):
    """Semicolon-separated command lists."""

    def test_two_commands(self):
        prog = parse("echo a; echo b")
        self.assertEqual(len(prog.andors), 2)

    def test_trailing_semicolon(self):
        prog = parse("echo a;")
        self.assertEqual(len(prog.andors), 1)


class TestRedirects(unittest.TestCase):
    """Redirect parsing."""

    def test_output_redirect(self):
        prog = parse("echo hi > /workspace/out.txt")
        cmd = prog.andors[0].pipelines[0].commands[0]
        self.assertEqual(len(cmd.redirects), 1)
        r = cmd.redirects[0]
        self.assertEqual(r.fd, 1)
        self.assertEqual(r.op, ">")
        self.assertEqual(r.target, "/workspace/out.txt")

    def test_input_redirect(self):
        prog = parse("cat < /tmp/in.txt")
        cmd = prog.andors[0].pipelines[0].commands[0]
        r = cmd.redirects[0]
        self.assertEqual(r.fd, 0)
        self.assertEqual(r.op, "<")
        self.assertEqual(r.target, "/tmp/in.txt")

    def test_append_redirect(self):
        prog = parse("echo hi >> /workspace/out.txt")
        cmd = prog.andors[0].pipelines[0].commands[0]
        r = cmd.redirects[0]
        self.assertEqual(r.op, ">>")

    def test_stderr_redirect(self):
        prog = parse("cmd 2> /workspace/err.txt")
        cmd = prog.andors[0].pipelines[0].commands[0]
        r = cmd.redirects[0]
        self.assertEqual(r.fd, 2)
        self.assertEqual(r.op, "2>")
        self.assertEqual(r.target, "/workspace/err.txt")

    def test_stderr_append(self):
        prog = parse("cmd 2>> /workspace/err.txt")
        cmd = prog.andors[0].pipelines[0].commands[0]
        r = cmd.redirects[0]
        self.assertEqual(r.fd, 2)
        self.assertEqual(r.op, "2>>")

    def test_merge_out_to_err(self):
        prog = parse("cmd 1>&2")
        cmd = prog.andors[0].pipelines[0].commands[0]
        r = cmd.redirects[0]
        self.assertEqual(r.fd, 1)
        self.assertEqual(r.op, "1>&2")
        self.assertEqual(r.target, "2")

    def test_merge_err_to_out(self):
        prog = parse("cmd 2>&1")
        cmd = prog.andors[0].pipelines[0].commands[0]
        r = cmd.redirects[0]
        self.assertEqual(r.fd, 2)
        self.assertEqual(r.op, "2>&1")
        self.assertEqual(r.target, "1")


class TestRejections(unittest.TestCase):
    """Out-of-scope constructs must raise ParseError."""

    def test_background(self):
        with self.assertRaises(ParseError):
            parse("cmd &")

    def test_command_substitution(self):
        with self.assertRaises(ParseError):
            parse("echo $(whoami)")

    def test_backtick(self):
        with self.assertRaises(ParseError):
            parse("echo `whoami`")

    def test_glob(self):
        with self.assertRaises(ParseError):
            parse("echo *.txt")

    def test_empty(self):
        with self.assertRaises(ParseError):
            parse("")

    def test_unterminated_single_quote(self):
        with self.assertRaises(ParseError):
            parse("echo 'hello")

    def test_unterminated_double_quote(self):
        with self.assertRaises(ParseError):
            parse('echo "hello')


class TestGoldenDifferential(unittest.TestCase):
    """Golden tests: known input → expected AST structure."""

    GOLDEN = {
        "echo hello": {
            "andor_count": 1,
            "pipeline_count": 1,
            "command_count": 1,
            "argv_count": 2,
            "argv": ["echo", "hello"],
            "redirects": 0,
        },
        "ls -la /workspace": {
            "andor_count": 1,
            "argv_count": 3,
            "argv": ["ls", "-la", "/workspace"],
        },
        "VAR=x cmd": {
            "assignments": (("VAR", "x"),),
            "argv": ["cmd"],
        },
        "a | b": {
            "command_count": 2,
            "pipeline_commands": [["a"], ["b"]],
        },
        "a && b": {
            "pipeline_count": 2,
            "ops": ("&&",),
        },
        "a || b": {
            "ops": ("||",),
        },
        "a; b": {
            "andor_count": 2,
        },
        "echo > /workspace/x": {
            "redirects": 1,
            "redirect_fd": 1,
            "redirect_op": ">",
            "redirect_target": "/workspace/x",
        },
    }

    def test_golden(self):
        for command, expected in self.GOLDEN.items():
            with self.subTest(command=command):
                prog = parse(command)
                if "andor_count" in expected:
                    self.assertEqual(len(prog.andors), expected["andor_count"])
                andor = prog.andors[0]
                if "pipeline_count" in expected:
                    self.assertEqual(len(andor.pipelines), expected["pipeline_count"])
                pipe = andor.pipelines[0]
                if "command_count" in expected:
                    self.assertEqual(len(pipe.commands), expected["command_count"])
                cmd = pipe.commands[0]
                if "argv_count" in expected:
                    self.assertEqual(len(cmd.argv), expected["argv_count"])
                if "argv" in expected:
                    got = [w.expand({}) for w in cmd.argv]
                    self.assertEqual(got, expected["argv"])
                if "redirects" in expected:
                    self.assertEqual(len(cmd.redirects), expected["redirects"])
                if "redirect_fd" in expected:
                    self.assertEqual(cmd.redirects[0].fd, expected["redirect_fd"])
                if "redirect_op" in expected:
                    self.assertEqual(cmd.redirects[0].op, expected["redirect_op"])
                if "redirect_target" in expected:
                    self.assertEqual(cmd.redirects[0].target, expected["redirect_target"])
                if "assignments" in expected:
                    self.assertEqual(cmd.assignments, expected["assignments"])
                if "ops" in expected:
                    self.assertEqual(andor.ops, expected["ops"])
                if "pipeline_commands" in expected:
                    for i, expected_argv in enumerate(expected["pipeline_commands"]):
                        got = [w.expand({}) for w in pipe.commands[i].argv]
                        self.assertEqual(got, expected_argv)


if __name__ == "__main__":
    unittest.main()
