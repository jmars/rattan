"""Container-path containment validators.

Roots are **container paths** (``/workspace``, ``/tmp``). These validators
reject a path (working directory, redirect target) that resolves outside the
allowed container roots, using the ``_contained_in_any`` symlink-escape
discipline: relative targets are always relative to the working directory and
are never re-interpreted against another root (that would let a work-dir
symlink escape by re-resolving under another root).
"""

from __future__ import annotations

import os

# Container-path roots that agent commands may read/write.
CONTAINER_ROOTS = ("/workspace", "/tmp")


def _contained_path(target: str, root: str) -> str | None:
    """Return *target* resolved if it is contained within *root*, else None.

    Uses realpath so a symlink that points outside *root* is rejected.
    """
    resolved = os.path.realpath(target)
    root_resolved = os.path.realpath(root)
    if resolved == root_resolved or resolved.startswith(root_resolved + os.sep):
        return resolved
    return None


def contained_in_any(target: str, roots: tuple[str, ...]) -> str | None:
    """Resolve *target* against the first root that contains it, else None.

    - A relative target is resolved against the FIRST root only (the working
      directory), never against later roots — prevents symlink-escape via
      re-resolution under another root.
    - An absolute target is checked against every root.
    """
    if not target:
        return None
    if not roots:
        return None
    # First root for relative targets
    cand = _contained_path(target, roots[0])
    if cand is not None:
        return cand
    if not os.path.isabs(target):
        return None
    for root in roots[1:]:
        cand = _contained_path(target, root)
        if cand is not None:
            return cand
    return None


def validate_cwd(cwd: str, roots: tuple[str, ...] = CONTAINER_ROOTS) -> str:
    """Validate a container working directory.

    Returns the resolved absolute container path. Raises ``ValueError`` if it
    is empty, relative (must be absolute container path), or outside the roots.
    """
    if not cwd:
        raise ValueError("cwd must not be empty")
    if not os.path.isabs(cwd):
        raise ValueError(f"cwd must be an absolute container path, got {cwd!r}")
    resolved = contained_in_any(cwd, roots)
    if resolved is None:
        raise ValueError(
            f"cwd {cwd!r} must be under one of: {', '.join(roots)}"
        )
    return resolved


def validate_redirect_target(
    path: str, roots: tuple[str, ...] = CONTAINER_ROOTS
) -> str:
    """Validate a redirect target (container path).

    Returns the resolved absolute container path. Raises ``ValueError`` if the
    target is outside the roots.
    """
    if not path:
        raise ValueError("redirect target must not be empty")
    resolved = contained_in_any(path, roots)
    if resolved is None:
        raise ValueError(
            f"redirect target {path!r} must be under one of: {', '.join(roots)}"
        )
    return resolved
