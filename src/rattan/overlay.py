"""Overlay lower/upper/work provisioning + bwrap ``--overlay`` argv builder."""

from __future__ import annotations

from rattan.layers import Session, lower_stack


def provision(session: Session):
    """Ensure the session upper + work directories exist (idempotent)."""
    import os

    os.makedirs(session.upper, exist_ok=True)
    os.makedirs(session.work, exist_ok=True)
    os.makedirs(session.workspace, exist_ok=True)


def lower_argv(session: Session, extra_lowers: list[str] | None = None) -> list[str]:
    """Build the ``--overlay-src`` argv fragments for bwrap.

    Returns a flat list like
    ``["--overlay-src", base, "--overlay-src", layer1, ...]``.

    *extra_lowers* (optional) appends additional lower directories after the
    committed layer stack — used by background jobs to layer a reflink snapshot
    of the live session upper on top of the committed layers.
    """
    lowers = list(lower_stack(session))
    if extra_lowers:
        lowers.extend(extra_lowers)
    argv: list[str] = []
    for lower in lowers:
        argv.extend(["--overlay-src", lower])
    return argv


def overlay_argv(
    session: Session,
    dest: str = "/",
    upper: str | None = None,
    work: str | None = None,
) -> list[str]:
    """Build the ``--overlay`` argv fragment for bwrap.

    Returns ``["--overlay", <upper>, <work>, <dest>]``. When *upper*/*work* are
    given they override ``session.upper``/``session.work`` (used by background
    jobs which run on their own private upper/work dirs).
    """
    return ["--overlay", upper or session.upper, work or session.work, dest]

