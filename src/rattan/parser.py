"""Clean-room AST command parser (AST-native only — single code path).

Scope IN: words (bare, single-quoted, double-quoted with ``$VAR``, backslash
escapes), operators (``|``, ``||``, ``&&``, ``;``), redirects (``>``, ``>>``,
``<``, ``2>``, ``2>>``, ``1>&2``, ``2>&1``), ``$VAR`` / ``${VAR}`` expansion
(no field-splitting), comments (``#``), single-pipe pipelines (len 1 or 2),
assignment ``VAR=val`` prefixes.

Scope OUT (rejected with :class:`ParseError`): control flow, ``$( )`` /
backticks, arithmetic, globbing, heredocs, background ``&``, multi-pipe (>2
stages), process substitution.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Mapping, Optional


# ---------------------------------------------------------------------------
# AST nodes (frozen dataclasses)
# ---------------------------------------------------------------------------

class PartKind(enum.Enum):
    BARE = "bare"
    SINGLE_QUOTED = "single_quoted"
    DOUBLE_QUOTED = "double_quoted"
    VAR = "var"


@dataclass(frozen=True)
class WordPart:
    """A fragment of a shell word."""
    text: str
    kind: PartKind


@dataclass(frozen=True)
class Word:
    """A fully-assembled shell word (argv element after expansion)."""
    parts: tuple[WordPart, ...] = ()

    def expand(self, env: Mapping[str, str]) -> str:
        """Expand this word against *env*; return the resolved string."""
        result: list[str] = []
        for p in self.parts:
            if p.kind in (PartKind.BARE, PartKind.SINGLE_QUOTED, PartKind.DOUBLE_QUOTED):
                result.append(p.text)
            elif p.kind == PartKind.VAR:
                varname = p.text.strip("{}")
                result.append(env.get(varname, ""))
        return "".join(result)

    def __bool__(self):
        return bool(self.parts)


@dataclass(frozen=True)
class RedirectSpec:
    """A single redirect descriptor."""
    fd: Optional[int]  # 0/1/2, or None for < (implied 0) / >/>> (implied 1)
    op: str            # '<', '>', '>>', '1>&2', '2>&1'
    target: str        # path for file redirs, fd number for merge


@dataclass(frozen=True)
class CommandNode:
    """A single command: argv, redirects, and optional assignment prefixes."""
    argv: tuple[Word, ...]
    redirects: tuple[RedirectSpec, ...]
    assignments: tuple[tuple[str, str], ...]  # (var, value) pairs


@dataclass(frozen=True)
class PipelineNode:
    """A pipeline of 1-2 commands."""
    commands: tuple[CommandNode, ...]


@dataclass(frozen=True)
class AndOrNode:
    """A sequence of pipelines joined by ``&&`` or ``||``."""
    pipelines: tuple[PipelineNode, ...]
    ops: tuple[str, ...]  # '&&' or '||' between pipelines


@dataclass(frozen=True)
class ProgramNode:
    """Top-level AST: a sequence of and-or lists joined by ``;``."""
    andors: tuple[AndOrNode, ...]


# ---------------------------------------------------------------------------
# ParseError
# ---------------------------------------------------------------------------


class ParseError(ValueError):
    """Raised when a command string cannot be parsed."""
    pass


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

# Tokens the lexer produces.
_TOKEN_WORD = "WORD"

# Operator tokens (longest-match first).
_OPERATORS = [
    # Composite redirects must come before their prefixes.
    ("2>>", "DGREATERR"),
    ("2>&1", "GREATAND_ERR"),
    ("2>", "GREATERR"),
    ("1>&2", "GREATAND_OUT"),
    (">>", "DGREAT"),
    (">", "GREAT"),
    ("<", "LESS"),
    ("||", "OR_IF"),
    ("&&", "AND_IF"),
    ("|", "PIPE"),
    (";", "SEMI"),
]

_VAR_RE = re.compile(r"\$([a-zA-Z_][a-zA-Z0-9_]*|\{[a-zA-Z_][a-zA-Z0-9_]*\})")
_ASSIGN_RE = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_]*)=(.*)")

# Chars that always terminate a bare word.
_WORD_TERMINATORS = set(" \t\n|&;<>#'\"$\\")


def _tokenize(command: str) -> list[tuple[str, str]]:
    """Tokenize *command* into a list of ``(kind, value)`` pairs.

    Raises :class:`ParseError` for out-of-scope constructs.
    """
    tokens: list[tuple[str, str]] = []
    i = 0
    n = len(command)

    while i < n:
        ch = command[i]

        # Whitespace
        if ch in " \t\n":
            i += 1
            continue

        # Comment — rest of line is ignored
        if ch == "#":
            break

        # Out-of-scope rejections
        if ch == "&":
            if i + 1 < n and command[i + 1] == "&":
                tokens.append(("AND_IF", "&&"))
                i += 2
                continue
            raise ParseError(
                "background operator '&' is not supported in rattan commands"
            )
        if ch == "`":
            raise ParseError("backtick command substitution is not supported")
        if ch in "*?[":
            raise ParseError(f"glob character {ch!r} is not supported")
        if ch == "$":
            if i + 1 < n and command[i + 1] == "(":
                raise ParseError("$( ) command substitution is not supported")
            if i + 1 < n and command[i + 1] == "{":
                # Check if it's a valid ${VAR} or something else
                rest = command[i:]
                m = _VAR_RE.match(rest)
                if m:
                    # ${VAR} is valid — fall through to word parsing
                    pass
                else:
                    raise ParseError(
                        "${ } parameter expansion is not supported (use simple $VAR)"
                    )

        # Operator match (longest-first)
        matched = False
        for op_str, op_kind in _OPERATORS:
            if command.startswith(op_str, i):
                tokens.append((op_kind, op_str))
                i += len(op_str)
                matched = True
                break
        if matched:
            continue

        # Word
        word_text, i = _lex_word_text(command, i)
        if word_text:
            tokens.append((_TOKEN_WORD, word_text))
        elif i < n:
            raise ParseError(f"unexpected character {command[i]!r} at position {i}")

    return tokens


def _lex_word_text(command: str, start: int) -> tuple[str, int]:
    """Lex a single word (raw text) starting at *start*.

    Returns ``(raw_text, new_pos)``.  The raw text includes quotes literally;
    the parser will decompose it into :class:`WordPart` later.
    """
    i = start
    n = len(command)
    buf: list[str] = []

    while i < n:
        ch = command[i]

        # Terminators
        if ch in " \t\n#":
            break

        # Check for operator at current position
        op_found = False
        for op_str, _ in _OPERATORS:
            if command.startswith(op_str, i):
                op_found = True
                break
        if op_found:
            break

        # Out-of-scope inside word
        if ch == "&":
            if i + 1 < n and command[i + 1] == "&":
                break
            raise ParseError("background operator '&' is not supported")
        if ch == "`":
            raise ParseError("backtick command substitution is not supported")
        if ch in "*?[":
            raise ParseError(f"glob character {ch!r} is not supported")
        if ch == "$" and i + 1 < n and command[i + 1] == "(":
            raise ParseError("$( ) command substitution is not supported")

        # Single-quoted string
        if ch == "'":
            buf.append(ch)
            i += 1
            while i < n and command[i] != "'":
                buf.append(command[i])
                i += 1
            if i >= n:
                raise ParseError("unterminated single-quoted string")
            buf.append(command[i])  # closing '
            i += 1
            continue

        # Double-quoted string
        if ch == '"':
            buf.append(ch)
            i += 1
            while i < n and command[i] != '"':
                if command[i] == "\\" and i + 1 < n:
                    buf.append(command[i])
                    buf.append(command[i + 1])
                    i += 2
                else:
                    buf.append(command[i])
                    i += 1
            if i >= n:
                raise ParseError("unterminated double-quoted string")
            buf.append(command[i])  # closing "
            i += 1
            continue

        # Backslash escape in bare word
        if ch == "\\" and i + 1 < n:
            buf.append(command[i + 1])
            i += 2
            continue

        # Regular character
        buf.append(ch)
        i += 1

    return "".join(buf), i


# ---------------------------------------------------------------------------
# Word parser — decompose raw word text into WordParts
# ---------------------------------------------------------------------------

def _parse_word_parts(raw: str) -> Word:
    """Decompose raw word text (from the tokenizer) into a :class:`Word`."""
    parts: list[WordPart] = []
    i = 0
    n = len(raw)
    bare_buf: list[str] = []

    def flush_bare():
        nonlocal bare_buf
        if bare_buf:
            parts.append(WordPart("".join(bare_buf), PartKind.BARE))
            bare_buf.clear()

    while i < n:
        ch = raw[i]

        if ch == "'":
            flush_bare()
            i += 1
            sq = []
            while i < n and raw[i] != "'":
                sq.append(raw[i])
                i += 1
            if i < n:
                i += 1  # skip closing '
            parts.append(WordPart("".join(sq), PartKind.SINGLE_QUOTED))
            continue

        if ch == '"':
            flush_bare()
            i += 1
            dq_parts: list[WordPart] = []
            dq_buf: list[str] = []
            while i < n and raw[i] != '"':
                if raw[i] == "\\" and i + 1 < n:
                    dq_buf.append(raw[i + 1])
                    i += 2
                elif raw[i] == "$":
                    m = _VAR_RE.match(raw, i)
                    if m:
                        if dq_buf:
                            dq_parts.append(WordPart("".join(dq_buf), PartKind.DOUBLE_QUOTED))
                            dq_buf.clear()
                        dq_parts.append(WordPart(m.group(1), PartKind.VAR))
                        i = m.end()
                        continue
                    dq_buf.append("$")
                    i += 1
                else:
                    dq_buf.append(raw[i])
                    i += 1
            if i < n:
                i += 1  # skip closing "
            if dq_buf:
                dq_parts.append(WordPart("".join(dq_buf), PartKind.DOUBLE_QUOTED))
            # Merge the double-quoted parts — they're all inside the same "..." span
            parts.extend(dq_parts)
            continue

        if ch == "$":
            m = _VAR_RE.match(raw, i)
            if m:
                flush_bare()
                parts.append(WordPart(m.group(1), PartKind.VAR))
                i = m.end()
                continue
            # Literal $
            bare_buf.append("$")
            i += 1
            continue

        bare_buf.append(ch)
        i += 1

    flush_bare()
    return Word(tuple(parts))


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


_OP_MAP = {
    "PIPE": "|",
    "OR_IF": "||",
    "AND_IF": "&&",
    "SEMI": ";",
    "LESS": "<",
    "GREAT": ">",
    "DGREAT": ">>",
    "GREATERR": "2>",
    "DGREATERR": "2>>",
    "GREATAND_OUT": "1>&2",
    "GREATAND_ERR": "2>&1",
}

_REDIR_OPS = {"LESS", "GREAT", "DGREAT", "GREATERR", "DGREATERR",
              "GREATAND_OUT", "GREATAND_ERR"}

_LINK_OPS = {"OR_IF", "AND_IF"}


def parse(command: str, env: Optional[Mapping[str, str]] = None) -> ProgramNode:
    """Parse a shell *command* string into a :class:`ProgramNode`.

    Raises :class:`ParseError` on invalid syntax or out-of-scope constructs.
    *env* is accepted for API compatibility but is not used during parsing
    (expansion happens later via ``Word.expand()``).
    """
    tokens = _tokenize(command)
    if not tokens:
        raise ParseError("empty command")

    pos = 0
    n = len(tokens)

    def peek():
        if pos < n:
            return tokens[pos]
        return None

    def advance():
        nonlocal pos
        t = tokens[pos]
        pos += 1
        return t

    def expect(kind):
        t = peek()
        if t is None:
            raise ParseError(f"expected {kind}, got end of command")
        if t[0] != kind:
            raise ParseError(f"expected {kind}, got {t[0]} ({t[1]!r})")
        return advance()

    # Parse a single redirect
    def parse_redirect() -> RedirectSpec:
        t = advance()
        kind, val = t
        op = _OP_MAP.get(kind, val)

        if kind in ("GREATAND_OUT", "GREATAND_ERR"):
            # These are self-contained: 1>&2 or 2>&1
            if kind == "GREATAND_OUT":
                return RedirectSpec(fd=1, op="1>&2", target="2")
            else:
                return RedirectSpec(fd=2, op="2>&1", target="1")

        if kind == "LESS":
            t2 = expect("WORD")
            return RedirectSpec(fd=0, op="<", target=t2[1])

        if kind in ("GREAT", "DGREAT"):
            t2 = expect("WORD")
            return RedirectSpec(fd=1, op=op, target=t2[1])

        if kind in ("GREATERR", "DGREATERR"):
            t2 = expect("WORD")
            return RedirectSpec(fd=2, op=op, target=t2[1])

        raise ParseError(f"unexpected redirect operator {kind}")

    # Parse a single command
    def parse_command() -> CommandNode:
        argv: list[Word] = []
        redirects: list[RedirectSpec] = []
        assignments: list[tuple[str, str]] = []

        while True:
            t = peek()
            if t is None:
                break
            kind, val = t

            if kind in _REDIR_OPS:
                redirects.append(parse_redirect())
                continue

            if kind in ("PIPE", "OR_IF", "AND_IF", "SEMI"):
                break

            if kind == "WORD":
                advance()
                # Check if this word is an assignment prefix (only for the FIRST word)
                m = _ASSIGN_RE.match(val)
                if m and not argv and not redirects:
                    assignments.append((m.group(1), m.group(2)))
                    continue
                argv.append(_parse_word_parts(val))
                continue

            # Unknown token
            raise ParseError(f"unexpected token {kind}")

        return CommandNode(
            argv=tuple(argv),
            redirects=tuple(redirects),
            assignments=tuple(assignments),
        )

    # Parse a pipeline (1-2 commands joined by |)
    def parse_pipeline() -> PipelineNode:
        cmds = [parse_command()]

        while True:
            t = peek()
            if t is None or t[0] != "PIPE":
                break
            advance()  # consume |
            if len(cmds) >= 2:
                raise ParseError(
                    "multi-pipe pipelines (>2 stages) are not supported in rattan"
                )
            cmds.append(parse_command())

        return PipelineNode(commands=tuple(cmds))

    # Parse an and-or list (pipelines joined by && or ||)
    def parse_andor() -> AndOrNode:
        pipelines = [parse_pipeline()]
        ops: list[str] = []

        while True:
            t = peek()
            if t is None or t[0] not in _LINK_OPS:
                break
            kind, _ = advance()
            ops.append("&&" if kind == "AND_IF" else "||")
            pipelines.append(parse_pipeline())

        return AndOrNode(pipelines=tuple(pipelines), ops=tuple(ops))

    # Parse the full program (and-or lists joined by ;)
    andors = [parse_andor()]

    while True:
        t = peek()
        if t is None:
            break
        if t[0] != "SEMI":
            raise ParseError(f"expected ';' or end of command, got {t[0]} ({t[1]!r})")
        advance()  # consume ;
        t = peek()
        if t is None:
            break  # trailing ; is ok
        andors.append(parse_andor())

    # Check for trailing garbage
    if peek() is not None:
        raise ParseError(f"unexpected token after command: {peek()}")

    return ProgramNode(andors=tuple(andors))
