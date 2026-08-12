"""Per-command seccomp / Landlock policy tables.

Defines the exact promise set and Landlock spec that stage3 receives for each
trusted command.  The policy is resolved from a static lookup table keyed by
the command basename.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Baseline (shared by every agent-mode command)
# ---------------------------------------------------------------------------

# Must EXACTLY match the ``BASELINE_PROMISES`` #define in stage3.c.
AGENT_BASELINE_PROMISES = (
    "stdio rpath wpath cpath flock exec prot_exec proc recvfd"
)

# Landlock paths that are always unveiled in agent mode.
# `/:r` reveals the root directory so `ls /` works; specific subdirs are then
# narrowed (e.g. /workspace:rwc, /usr:rx). Landlock unions rules per-path so
# the more specific entries take effect for their subtrees.
AGENT_BASELINE_LANDLOCK = (
    "/:r;/workspace:rwc;/tmp:rwc;/usr:rx;/bin:rx;/lib:rx;/lib64:rx;"
    "/proc:r;/etc:r;/dev:rwc"
)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class CommandPolicy:
    """Per-command overrides on top of the agent baseline."""
    extra_promises: str = ""
    extra_landlock: str = ""
    rlimits: str = ""
    allow_ptrace: bool = False


@dataclass(frozen=True)
class ResolvedPolicy:
    """The fully-resolved policy for a single command invocation."""
    promises: str
    landlock_spec: str
    rlimits: str
    allow_ptrace: bool
    # Extra pledge tokens (beyond `promises`) passed to stage3 via
    # RATTAN_EXTRA_PROMISES so tools like git (sendfd) / gcc (prot_exec) get the
    # pledges they need without widening the shared baseline.
    extra_promises: str = ""

    @property
    def full_landlock_spec(self) -> str:
        """Return the landlock spec with baseline pre-pended."""
        if self.landlock_spec:
            return AGENT_BASELINE_LANDLOCK + ";" + self.landlock_spec
        return AGENT_BASELINE_LANDLOCK


# ---------------------------------------------------------------------------
# Policy table
# ---------------------------------------------------------------------------

POLICY_TABLE: dict[str, CommandPolicy] = {
    "git": CommandPolicy(
        extra_promises="sendfd",
        extra_landlock="",
    ),
    "python3": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "python": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "gdb": CommandPolicy(
        extra_promises="",
        extra_landlock="",
        allow_ptrace=True,
    ),
    "bash": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "sh": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "ls": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "cat": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "echo": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "grep": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "sed": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "awk": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "find": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "make": CommandPolicy(
        extra_promises="",
        extra_landlock="",
    ),
    "gcc": CommandPolicy(
        extra_promises="prot_exec",
        extra_landlock="",
    ),
    "cc": CommandPolicy(
        extra_promises="prot_exec",
        extra_landlock="",
    ),
    "g++": CommandPolicy(
        extra_promises="prot_exec",
        extra_landlock="",
    ),
}


def resolve(command: str, mode: str = "agent") -> ResolvedPolicy:
    """Resolve the policy for *command*.

    *command* is the raw command string; we look up its basename in
    :data:`POLICY_TABLE`.  Unknown commands get the bare baseline.

    *mode* must be ``"agent"`` for now (provisioning arrives in M4).
    """
    if mode != "agent":
        raise ValueError(f"unsupported mode {mode!r} (only 'agent' in M3)")

    # Extract the first word / basename for lookup
    argv0 = command.split()[0] if command.strip() else ""
    basename = os.path.basename(argv0) if argv0 else ""

    cp = POLICY_TABLE.get(basename, CommandPolicy())

    return ResolvedPolicy(
        promises=AGENT_BASELINE_PROMISES,
        landlock_spec=cp.extra_landlock,
        rlimits=cp.rlimits,
        allow_ptrace=cp.allow_ptrace,
        extra_promises=cp.extra_promises,
    )


def resolve_pipeline(command_strings: list[str], mode: str = "agent") -> ResolvedPolicy:
    """Resolve a single combined policy for a pipeline of commands.

    A pipeline is executed inside ONE sandbox (via ``/bin/sh -c``), so its
    seccomp/Landlock policy must be the **union** of every stage's needs: the
    union of ``extra_promises`` (pledge tokens), the joined ``extra_landlock``
    specs, the union of rlimits, and ``allow_ptrace`` if any stage needs it.
    The shared baseline is unchanged.
    """
    if mode != "agent":
        raise ValueError(f"unsupported mode {mode!r} (only 'agent' in M3)")

    extra_promises: set[str] = set()
    landlock: list[str] = []
    rlimits: list[str] = []
    allow_ptrace = False

    for cs in command_strings:
        rp = resolve(cs, mode=mode)
        if rp.extra_promises:
            extra_promises.update(rp.extra_promises.split())
        if rp.landlock_spec:
            landlock.append(rp.landlock_spec)
        if rp.rlimits:
            rlimits.append(rp.rlimits)
        allow_ptrace = allow_ptrace or rp.allow_ptrace

    return ResolvedPolicy(
        promises=AGENT_BASELINE_PROMISES,
        landlock_spec=";".join(landlock),
        rlimits=";".join(rlimits),
        allow_ptrace=allow_ptrace,
        extra_promises=" ".join(sorted(extra_promises)),
    )


def stage3_env(resolved: ResolvedPolicy) -> dict[str, str]:
    """Build the extra environment variables that stage3 reads.

    ``RATTAN_EXTRA_PROMISES`` (extra pledge tokens merged by stage3),
    ``RATTAN_ALLOW_PTRACE``, ``RATTAN_RLIMITS``.
    """
    env: dict[str, str] = {}
    if resolved.extra_promises:
        env["RATTAN_EXTRA_PROMISES"] = resolved.extra_promises
    if resolved.allow_ptrace:
        env["RATTAN_ALLOW_PTRACE"] = "1"
    if resolved.rlimits:
        env["RATTAN_RLIMITS"] = resolved.rlimits
    return env
