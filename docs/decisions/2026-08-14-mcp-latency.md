# Decision — Persistent-sandbox latency optimization is NO-GO

**Status:** Accepted (2026-08-14)

**Context:** Reduce the latency of MCP task executions (`shell_run`). An
investigation (consultant) proved the Python-side per-command path is ~20µs —
negligible. The real cost is the fresh `bwrap` subprocess spawned per command
(namespace unshare + overlay mount + `/proc` `/dev` + stage3 double-exec). A set
of contained optimizations was implemented, reviewed, and merged (see below).
The only change that would cut *steady-state* per-command latency further is a
**persistent per-session sandbox / hot pool** that amortizes the `bwrap` setup
across commands. That proposal conflicts with security-invariant #4 ("no
persistent container / its own bwrap invocation per command / no setns") and
load-bearing decision #1 of `docs/architecture.md` §1 ("per-command bwrap over
a persistent container", defended by five explicit reasons).

**Investigation:** The persistent-sandbox design was routed to the advisor
(consultant escalation). The advisor produced a complete design — amended
Invariant #4 language, a fork-based per-session mount-ns+userns *holder*
architecture, 8 new enforcement tests, and a `glm-coder` implementer tier —
**gated on a host-side measurement** of the real `bwrap` cost and end-to-end
`shell_run` latency.

**Measurement (host, `/mnt/data/rattan/rootfs/base`, N=100):**

| Probe | /call |
|---|---|
| raw `bwrap --unshare-all` (userns+ns floor) | ~4.0 ms |
| + overlay mount of base | ~4.6 ms |
| + stage3 (full per-command path) | ~4.9 ms |
| **End-to-end `shell_run` (echo hello, n=50)** | **p50 2.6 ms / p99 3.7 ms** |

Decomposition: userns creation dominates (~4.0 ms); overlay mount ~0.6 ms;
stage3 double-exec only ~0.3 ms (and stage3 must run per command regardless).

**Gate evaluation (advisor's criteria):**
- (a) userns+overlay together = 4.6 ms ≥ 3 ms and > 2×stage3 (0.6 ms) — **PASS**
- (b) end-to-end `shell_run` p50 ≥ 8 ms — **FAIL** (measured 2.6 ms, far below)
- (c) team accepts a root-in-userns holder between commands — moot (b failed)

**Decision: NO-GO.** The end-to-end user-visible latency is already ~2.6 ms
p50 / 3.7 ms p99 — excellent. Relaxing security-invariant #4 (which requires a
root-in-userns holder process, explicitly forbidden by `architecture.md:52`) is
**not justified** for an unquantified further gain. No invariant is amended; no
architectural change is made.

**What was shipped instead (merged `main` 542643a):**
- `shell_list` 30s TTL cache (removes a full `bwrap`+`pacman -Qq` subprocess per call)
- Minimal container env for `bwrap` subprocesses (drops ~50 leaked host env keys)
- Per-session overlay mount/teardown serialization lock (replaces blind EBUSY sleep-retries)
- `RATTAN_TIMING=1` opt-in per-stage timing diagnostic

**Follow-up:** If latency requirements ever tighten (well below ~2.6 ms p50), the
holder design in memory (`handoff-persistent-sandbox-plan`) is the documented
path — but it requires re-running the measurement gate after any major change
and explicit acceptance of a root-in-userns holder process.

## Related docs
- `docs/architecture.md` §1 (decision #1: per-command bwrap over persistent container)
- `docs/security-invariants.md` Invariant #4
- `docs/implementation-plan.md`
