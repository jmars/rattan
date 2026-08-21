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
    from the parent), a container filesystem path, or a merge marker
    (``"&1"`` / ``"&2"``).

    ``extra_opens`` is a list of ``(fd, path, flags)`` tuples for explicit
    fd-based redirects.

    ``shared_read_fd`` is set when multiple processes in a pipeline need to
    read from the same pipe fd (not used in M3 single-command path).

    Host-side redirect application fields (populated by the executor at build
    time; ``None`` / empty until ``_resolve_fd_plan_host`` runs):

    * ``host_stdin`` / ``host_stdout`` / ``host_stderr``: host filesystem
      paths to open and pass to ``Popen``.
    * ``stdout_append`` / ``stderr_append``: open in append mode (``>>``).
    * ``extra_binds``: additional ``--bind`` argv fragments for bwrap
      (list of ``[flag, host_path, mnt]`` sublists).
    * ``cleanup_paths``: host temp files to remove after the invocation.
    """
    stdin: Optional[str] = None
    stdout: Optional[str] = None
    stderr: Optional[str] = None
    extra_opens: list = field(default_factory=list)
    shared_read_fd: Optional[int] = None
    # Host-side redirect application (populated by executor at build time)
    host_stdin: Optional[str] = None
    host_stdout: Optional[str] = None
    host_stderr: Optional[str] = None
    stdout_append: bool = False
    stderr_append: bool = False
    extra_binds: list = field(default_factory=list)
    cleanup_paths: list = field(default_factory=list)


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
        base: Optional[str] = None,
    ) -> FdPlan:
        """Resolve this plan against *defaults* and *roots*.

        *base* is an optional container working directory (e.g. ``"/workspace"``).
        When set, relative redirect targets are resolved against it before
        validation.  Absolute targets are unaffected.

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
                # Resolve relative targets against *base* before validation
                target = spec.target
                if base and not os.path.isabs(target):
                    target = os.path.normpath(os.path.join(base, target))
                # File-based redirect
                _validate_target(target, roots=roots)
                if spec.op == "<":
                    plan.stdin = target
                elif spec.op in (">", ">>", "2>", "2>>"):
                    if fd == 1:
                        plan.stdout = target
                        plan.stdout_append = spec.op == ">>"
                    elif fd == 2:
                        plan.stderr = target
                        plan.stderr_append = spec.op == "2>>"
                    else:
                        # M3 doesn't do arbitrary fd-to-file; only 0/1/2
                        raise ParseError(
                            f"redirect of fd {fd} to file is not supported"
                        )
            elif spec.op in ("1>&2", "2>&1"):
                # Merge redirect — the merging fd goes to wherever the target
                # fd ends up.  Do NOT clear the target fd: a prior file redirect
                # may have set it (e.g. ``cmd > f.txt 2>&1``).
                if spec.op == "1>&2":
                    plan.stdout = "&2"
                elif spec.op == "2>&1":
                    plan.stderr = "&1"
            else:
                raise ParseError(f"unsupported redirect operator {spec.op!r}")

        return plan
