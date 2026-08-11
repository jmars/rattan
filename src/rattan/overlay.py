"""Overlay lower/upper/work provisioning + bwrap ``--overlay`` argv builder."""

from __future__ import annotations

from rattan.layers import Session, lower_stack


def provision(session: Session):
    """Ensure the session upper + work directories exist (idempotent)."""
    import os

    os.makedirs(session.upper, exist_ok=True)
    os.makedirs(session.work, exist_ok=True)
    os.makedirs(session.workspace, exist_ok=True)


def lower_argv(session: Session) -> list[str]:
    """Build the ``--overlay-src`` argv fragments for bwrap.

    Returns a flat list like
    ``["--overlay-src", base, "--overlay-src", layer1, ...]``.
    """
    lowers = lower_stack(session)
    argv: list[str] = []
    for lower in lowers:
        argv.extend(["--overlay-src", lower])
    return argv


def overlay_argv(session: Session, dest: str = "/") -> list[str]:
    """Build the ``--overlay`` argv fragment for bwrap.

    Returns ``["--overlay", <upper>, <work>, <dest>]``.
    """
    return ["--overlay", session.upper, session.work, dest]

