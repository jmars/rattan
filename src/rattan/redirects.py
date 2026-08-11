"""Redirect planning + validation.

Builds an :class:`FdPlan` from a parsed command and validates that all
redirect targets resolve inside the container roots ``(/workspace, /tmp)``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

from rattan.parser import CommandNode, RedirectSpec, ParseError


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class FdPlan:
    """File-descriptor plan for a single command invocation.

    ``stdin`` / ``stdout`` / ``stderr`` are either ``None`` (use the default
    from the parent) or a filesystem path that will be opened by the executor.

    ``extra_opens`` is a list of ``(fd, path, flags)`` tuples for explicit
    fd-based redirects.

    ``shared_read_fd`` is set when multiple processes in a pipeline need to
    read from the same pipe fd (not used in M3 single-command path).
    """
    stdin: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    extra_opens: list = field(default_factory=list)
    shared_read_fd: Optional[int] = None


@dataclass(frozen=True)
class FdDefaults:
    """Default fd targets when no redirect is specified."""
    stdin: Optional[int] = None   # None = inherit from parent
    stdout: Optional[int] = None
    stderr: Optional[int] = None


# Default container roots for redirect target validation.
CONTAINER_ROOTS = ("/workspace", "/tmp")


# ---------------------------------------------------------------------------
# Lexical path resolution
# ---------------------------------------------------------------------------


def _is_under(path: str, root: str) -> bool:
    """Return True if *path* is lexically under *root* (no symlink resolution)."""
    # Normalize both paths
    norm = os.path.normpath(path)
    root_norm = os.path.normpath(root)
    if norm == root_norm:
        return True
    return norm.startswith(root_norm + os.sep)


def _validate_target(target: str, roots: tuple[str, ...] = CONTAINER_ROOTS):
    """Raise :class:`ParseError` if *target* does not resolve inside *roots*."""
    for root in roots:
        if _is_under(target, root):
            return
    raise ParseError(
        f"redirect target must be under {' or '.join(roots)}, "
        f"got {target!r}"
    )


# ---------------------------------------------------------------------------
# Redirect plan
# ---------------------------------------------------------------------------


@dataclass
class RedirectPlan:
    """A resolved plan of redirections for a command.

    Constructed from a :class:`CommandNode`'s redirect specs and applied
    against the container root constraints.
    """
    specs: tuple[RedirectSpec, ...]

    def apply(
        self,
        defaults: FdDefaults,
        *,
        roots: tuple[str, ...] = CONTAINER_ROOTS,
    ) -> FdPlan:
        """Resolve this plan against *defaults* and *roots*.

        Returns a :class:`FdPlan`.  Raises :class:`ParseError` if any redirect
        target escapes the container roots.
        """
        plan = FdPlan()
        used_fds: set[int] = set()

        for spec in self.specs:
            fd = spec.fd
            if fd is None:
                fd = 0 if spec.op == "<" else 1
            if fd in used_fds:
                raise ParseError(
                    f"duplicate redirect for fd {fd}"
                )
            used_fds.add(fd)

            if spec.op in ("<", ">", ">>", "2>", "2>>"):
                # File-based redirect
                _validate_target(spec.target, roots=roots)
                if spec.op == "<":
                    plan.stdin = spec.target
                elif spec.op in (">", ">>", "2>", "2>>"):
                    if fd == 1:
                        plan.stdout = spec.target
                    elif fd == 2:
                        plan.stderr = spec.target
                    else:
                        # M3 doesn't do arbitrary fd-to-file; only 0/1/2
                        raise ParseError(
                            f"redirect of fd {fd} to file is not supported"
                        )
            elif spec.op in ("1>&2", "2>&1"):
                # Merge redirect
                if spec.op == "1>&2":
                    plan.stdout = "&2"
                    plan.stderr = None  # stderr inherits, stdout goes to stderr
                elif spec.op == "2>&1":
                    plan.stderr = "&1"
                    plan.stdout = None  # stdout inherits, stderr goes to stdout
            else:
                raise ParseError(f"unsupported redirect operator {spec.op!r}")

        return plan
