# Rattan — Implementation Plan

Breaking the architecture in `docs/architecture.md` into concrete, buildable
milestones and tickets. Each ticket is code-level and ends in a verifiable
result. Milestones are ordered to de-risk the hard unknowns first (bwrap
overlay API, stage3 layering) before committing to the full tool surface.

**Sequencing principle:** verify the riskiest assumptions (does the host
actually support what we need? does the `stage3` layering actually hold?) in a
spike before writing production code around them. The architecture has three
load-bearing unknowns that MUST be proven in M1 before anything else:

1. Does the installed bwrap support a **persistent upperdir** via `--overlay`,
   or do we need the `stage2` `mount -t overlay` fallback?
2. Do Landlock → seccomp ordering and `PR_SET_NO_NEW_PRIVS` actually behave as
   designed in `stage3` on this kernel?
3. Can bwrap mount an overlay with a multi-layer lower stack unprivileged on
   this host?

These are answered by a throwaway spike at the start of M1. If any fails, stop
and re-plan that piece before proceeding.

---

## M0 — Repo scaffolding + host capability probe

**Goal:** standing repo layout, CI-visible, with a one-shot capability probe
that gate-keeps startup.

### Tickets

- **M0.1 — Skeleton layout.** Create the directory tree in §6 of
  `architecture.md`, `pyproject.toml` (project `rattan`, entry point
  `mcp run`), empty module stubs, `Makefile` with `stage3`, `bootstrap-rootfs`,
  `verify`, `test` targets. No logic yet; just structure + imports resolve.
- **M0.2 — `capabilities.py` host probe.** Implement one-shot probe:
  - kernel version (`os.uname`)
  - `kernel.unprivileged_userns_clone` (read `/proc/sys/kernel/...`)
  - Landlock ABI (`LANDLOCK_CREATE_RULESET` via `landlock_create_ruleset`),
    plus which access sets are handled
  - `bwrap --version`
  - overlay-in-userns support (probe: try `mount -t overlay` in a throwaway
    userns)
  - reflink support on the data dir (`stat -f -c %T`)
  - LSM stack includes `landlock` (read `/sys/kernel/security/lsm`)
  - Cache results; `env_status` reads the cache.
- **M0.3 — Startup gate.** The server refuses to start (clear error listing the
  missing feature + remediation) if any *required* capability is absent:
  userns enabled, landlock present, bwrap installed, kernel ≥ 6.2. Optional
  features (reflink, Landlock net) are reported but not blocking.
- **M0.4 — `tests/test_capabilities.py`.** Unit-test the probe parsing with
  mocked `/proc`/`/sys` reads; integration-test the real probe (skipped if
  probe unavailable in CI).

**Verification:** `python3 -m rattan` starts and `env_status` returns the
capability table on this host.

---

## M1 — Spike + `stage3` inner binary

**Goal:** prove the three load-bearing unknowns and produce the working inner
security layer.

### Tickets

- **M1.1 — SPIKE: bwrap overlay persistence.** Throwaway script that tests:
  (a) does `bwrap --overlay <lower> <upper> <work> / ...` persist writes to
  `<upper>` across two separate bwrap invocations on the installed bwrap
  version? (b) if not, does the `stage2` fallback (`bwrap ... --mount-proc ...`
  then `mount -t overlay` as root-in-userns before exec) work? **Output:** a
  short doc (in `docs/` or a comment) recording which path is viable on this
  host, and which bwrap flags. Do NOT build the production overlay path until
  this is answered.
- **M1.2 — SPIKE: multi-layer lower stack.** Verify overlay accepts a
  lower=base+layer1+layer2 stack unprivileged, and that lookup order/visibility
  is correct. **Output:** confirmation + recorded flags.
- **M1.3 — `stage3.c` skeleton.** Static musl C binary implementing the fixed
  sequence with a `--verify` self-test mode:
  `PR_SET_NO_NEW_PRIVS` → Landlock (ruleset from a spec, add rules,
  `restrict_self`) → seccomp (static per-mode whitelist) → setrlimits → execvp.
  Config via argv (before `--`) + env, all server-controlled. `--verify` mode
  runs the sequence then reports success/failure and the resulting
  `/proc/self/status` Seccomp + Landlock lines instead of exec'ing, for tests.
- **M1.4 — `stage3.c` landlock/seccomp correctness.** Tests (unit + a real
  spawn): assert seccomp line shows filter, a denied write fails, a denied
  syscall (e.g. `keyctl`) is blocked, `execvp` still succeeds. Assert the
  ordering invariant is structurally enforced (landlock code before seccomp
  code, no early return between).
- **M1.5 — Per-command policy extension.** Implement the env-var override for
  trusted tools (e.g. gdb gets `ptrace`; `ulimit` gets `setrlimit`) — the
  `SANDBOX_NO_PLEDGE`-analog. Start with the empty/no-extra case working, wire
  the override plumbing.

**Verification:** `make stage3 && bin/stage3 --verify` succeeds on this host,
showing Seccomp + Landlock active. Spike docs recorded.

---

## M2 — Base rootfs bootstrap

**Goal:** a reproducible, immutable Arch rootfs that the sandbox runs against.

### Tickets

- **M2.1 — `vendor/` pinning.** Add `archlinux-bootstrap-x86_64.tar.zst`
  (LFS-tracked) + a pinned `mirrorlist`. Record release version + hash in a
  README or manifest.
- **M2.2 — `bin/bootstrap-rootfs.sh`.** Idempotent script:
  1. extract tarball into `<data-dir>/rootfs/base` (strip `root.x86_64/`)
  2. install pinned mirrorlist
  3. enter via `bwrap --unshare-all --share-net --uid 0 --gid 0 --bind
     <rootfs> / --proc /proc --dev /dev ... -- /usr/bin/pacman-key --init`
     then `--populate archlinux`
  4. `pacman -Sy`; `pacman -S --needed base` (baseline; `base-devel` optional)
  5. `chmod -R a-w <rootfs>/base`
  6. write `MANIFEST.sha256`
  Re-run safe; skips if manifest present and valid.
- **M2.3 — Manifest check on startup.** `config.py`/`layers.py` validates the
  base manifest hash at startup; refuse to run if the base drifted.
- **M2.4 — `docs/bootstrap.md`.** Record the recipe, the sysctl prerequisite
  (`kernel.unprivileged_userns_clone=1`), and troubleshooting.

**Verification:** `make bootstrap-rootfs` produces a base with working
`pacman-key`, and `bin/stage3` can `ls /` inside it via a manual bwrap run.

---

## M3 — Overlay + commit/discard + `env_*` + `shell_run`

**Goal:** the core agent-mode loop: run a command in the container, discard
changes by default, commit on demand.

### Tickets

- **M3.1 — `layers.py`.** Session layer stack: create session upperdir/workdir;
  track active stack (base + committed layers); content-addressed commit
  (rsync or reflink per probe); rollback (truncate stack); GC (refcount on
  layers). Unit tests for stack math + commit/rollback/gc with a stub
  filesystem.
- **M3.2 — `overlay.py`.** Provision lower/upper/work; build the overlay argv
  (bwrap `--overlay` if M1.1 proved it, else the `stage2` mount fallback). Test
  the argv builder.
- **M3.3 — `parser.py` + `redirects.py`.** Clean-room AST command parser
  (AST-native only — do NOT reintroduce the two-parser-path split of the prior
  project). Redirect planning + validation. Roots are **container paths**
  (`/workspace`, `/tmp`), not host paths. Differential tests against a golden
  spec.
- **M3.4 — `bwrap.py`.** Agent-mode argv builder: `--unshare-net`, uid 1000,
  RO base, overlay, `/workspace` bind, `/proc /dev /sys /tmp`, stage3 as
  `/init`. Test the exact argv.
- **M3.5 — `policy.py`.** Per-command seccomp/landlock tables for agent mode +
  the per-command override plumbing (from M1.5). Test that policy maps a command
  to the right stage3 PROMISES + LANDLOCK_SPEC.
- **M3.6 — `executor.py` + `server.py`.** `shell_run` foreground path: build
  Invocation, spawn bwrap, structured return `{rc, skipped, stages, output}`.
  Wire `env_status` / `env_reset` / `env_discard` / `env_commit` /
  `env_snapshot_list` / `env_rollback` / `env_gc`. All `@mcp.tool` registered.
- **M3.7 — Session GC on daemon exit.** On shutdown, orphaned-session sweep
  (dead lockfile PID → archive/remove). Default discard holds.
- **M3.8 — `tests/test_e2e.py`.** Full round-trip: `shell_run("echo hi")` →
  stdout; write file → `env_status` shows dirty → `env_discard` → file gone;
  write → `env_commit` → file survives reset; `env_rollback` restores prior.
  Plus `tests/test_layers.py`, `tests/test_bwrap_modes.py`.

**Verification:** end-to-end agent-mode round-trip passes: run, dirty, discard
(default), commit, rollback all behave per the invariants. Network is denied in
agent mode (`curl https://example.com` → network unreachable).

---

## M4 — pacman provisioning mode

**Goal:** a working `pacman` inside the container, isolated from agent mode.

### Tickets

- **M4.1 — `pacman.py` + provisioning argv.** `bwrap.py` provisioning-mode
  builder: `--share-net`, uid 0/0, minimal seccomp, landlock applied to
  `/workspace` + host binds but NOT `/`, `/dev/urandom` bound, resolv.conf
  bound. `pacman_install(packages, refresh, mirror)` + `pacman_run(args)`.
- **M4.2 — Mirror validation.** Allowlist regex for `mirror=<url>` (HTTPS +
  known Arch mirror domains). Test the regex rejects arbitrary URLs.
- **M4.3 — Provisioning landlock scope.** Verify pacman can write `/usr`,
  `/var/lib/pacman`, `/etc/pacman.d` but NOT outside the container upperdir
  (write to host binds blocked). Tests.
- **M4.4 — `tests/test_pacman.py`.** Install a small package (e.g. `hello`
  `tree`), verify it lands in the upperdir, verify a subsequent agent-mode
  `shell_run` sees it, verify it's lost on discard unless committed.

**Verification:** `pacman_install(["hello"])` succeeds in provisioning mode;
agent mode cannot reach network; the installed package is visible to agent mode
and correctly discarded/committed.

---

## M5 — Background jobs + full tool surface + hardening

**Goal:** complete tool surface, background job lifecycle, and final security
review.

### Tickets

- **M5.1 — `jobs.py` + `bgdriver.py`.** Background lifecycle: `shell_job_start`
  / status / wait / output / kill / list. Each job = its own detached bwrap
  subprocess (`start_new_session=True`), sharing the session upperdir, raw
  subprocess (not inside a pledged parent). Reaper thread polls the registry.
  Carry the prior project's reaper discipline (close parent handles first,
  register PIDs under lock, then start reaper).
- **M5.2 — `bind_host_dir`.** Per-call/per-session host-dir bind with
  `mode="ro"|"rw"`; forbidden-path validation (`$HOME`, `~/.config`,
  `~/.local`, `~/.cache`, `/etc`, `/proc`, `/sys`); realpath-is-dir check;
  `rw` requires the path in the landlock RW set. Fuzz tests with malicious
  paths.
- **M5.3 — `contain.py` + redirect hardening.** Container-path containment
  validators; reject redirect targets under protected paths before spawn.
  Carry the `_contained_in_any` symlink-escape discipline, roots = container
  paths.
- **M5.4 — Invariant tests.** Automated checks for each of the 12 security
  invariants in `architecture.md` (e.g. network denied, base RO, discard
  default, no shared ns across two concurrent sessions).
- **M5.5 — `docs/security-invariants.md`.** Write the invariant + gotcha doc
  (content exists in architecture.md; promote to its own file with test
  cross-references).
- **M5.6 — `make verify`.** Full gate: capability probe + bwrap launch +
  landlock/seccomp assert + overlay assert + smoke `shell_run("ls /")`.
- **M5.7 — Full test suite green.** `python3 -m unittest discover -s tests -v`.

**Verification:** all tools registered and functional; background jobs survive
MCP-call teardown; 12 invariant tests pass; full suite green.

---

## Milestone dependency graph

```
M0 ──► M1 ──► M2 ──► M3 ──► M4 ──► M5
       │       │
       │       └──────► M3 (needs bootstrapped base)
       └─ M1 spike gates M3 (overlay path) and M4 (no — M4 needs M3's env/commit)
```

- M1 must complete (spike + stage3) before M3's overlay path is finalized.
- M2 must complete before M3 can run real commands.
- M3 before M4 (M4 reuses env/commit + the spawn path).
- M5 last (builds on the full M3/M4 surface).

---

## Risk register

| Risk | Impact | Mitigation |
|---|---|---|
| Installed bwrap lacks persistent `--overlay` | M3 overlay path wrong | M1.1 spike decides before M3; `stage2` fallback designed |
| Landlock/seccomp ordering or NO_NEW_PRIVS misbehaves on kernel 7.1 | stage3 broken | M1.3/M1.4 prove it in a spike-style verify |
| `pacman -S base` churn makes first commit huge | slow first commit | base is provisioned BEFORE any session; session upperdir starts empty |
| Arch rolling-release drift between bootstrap and later | manifest mismatch | pinned tarball + manifest hash; re-bootstrap is documented |
| ext4 (no reflink) → commits copy full diff | slower commits on this host | probe + `rsync -aHAX`; `--squash` relief; acceptable for v1 |
| Landlock ABI < 3 (no TRUNCATE) | truncation bypass | startup gate warns; mask handled set |

---

## Definition of done

- `make verify` passes on this host (capability gate + stage3 layering +
  overlay + smoke `shell_run`).
- All 12 security invariants have an automated test that passes.
- Agent mode has no network; only provisioning mode does.
- Discard is default; commit/rollback work and are only reachable via explicit
  `env_*` tools.
- Full unittest suite green.
- `docs/architecture.md`, `docs/security-invariants.md`, `docs/bootstrap.md`
  committed and accurate.
