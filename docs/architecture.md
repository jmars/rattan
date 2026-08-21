# Rattan — Architecture

Rattan is a greenfield MCP server providing a shell sandbox: an Arch Linux
rootfs with a working `pacman`, layered on **seccomp (pledge-style) + user
namespaces + bubblewrap + Landlock + overlayfs**. Agent changes to the container
are lost unless an explicit `env_commit` is requested (a Vibe user prompt / MCP
call — never auto-accepted). One daemon (or one persistent environment) per MCP
instance.

This is a **fresh, clean-room build** — not a refactor of the prior
`shell-sandbox-mcp` project. That project is used only as a *convention
reference* (FastMCP tool shape, job lifecycle, path-containment discipline).

---

## TL;DR

Build it as **a Python FastMCP server that manages a per-session overlay
upperdir on disk and spawns a fresh bubblewrap (bwrap) invocation per command**.
Each `bwrap` run is wrapped by a tiny static C binary (`stage3`) that applies
`PR_SET_NO_NEW_PRIVS → Landlock → seccomp → rlimits → execvp`. The MCP server
itself is the long-lived daemon; the container is **never** long-lived. Pacman
gets its own **provisioning mode** (root-in-userns + network) as a first-class
MCP tool, completely separate from **agent mode** (own UID, `--unshare-net`,
landlock + seccomp). Discard is default; commit = rsync/reflink the upperdir
into a new lower layer.

Three load-bearing decisions, each justified below:

1. **per-command bwrap over a persistent container**
2. **pacman-as-provisioning-tool over pacman-as-allowed-command**
3. **commit-as-new-layer over flatten-into-base**

---

## 1. Process / lifecycle model

### Primary: persistent-overlay-upperdir + on-demand bwrap-per-command

What persists (in the MCP server process, lifetime = the MCP connection):

- **Session id** + overlay upperdir/workdir paths under `<data-dir>/sessions/<sid>/`
- **Layer stack** (base + zero or more committed layers) used as the overlay lower
- **Job registry** (PID, log path, status, exit code) for background jobs
- **Capability probe results** (Landlock ABI, bwrap version, reflink support) — one-shot at startup
- **Cached parsed command policy** (per-command pledge/landlock plan)

What does **not** persist:

- A long-running container, init, or supervisor
- A mount namespace held open across commands
- Any process running root-in-userns between commands

What spawns per command:

- **Foreground (`shell_run`)**: `Popen(bwrap argv ...)`, block, return
  `{rc, skipped, stages, output}`. ~10–30ms overhead per call (bwrap user +
  mount ns creation), negligible vs the 60s client cap.
- **Background (`shell_job_start`)**: same argv but `start_new_session=True` and
  stdout→log file. Detached; survives the parent MCP call's teardown. Reaper
  thread polls the registry. Raw subprocess, **not** inside an already-sandboxed
  parent (critical because of the nested-pledge-inheritance fact: a pledge'd
  parent cannot correctly spawn pledge'd children).

### Why not (a) persistent container + init/supervisor

This is the "enter userns once, setns per call" anti-pattern. It loses because:

1. **Shared mount namespace across commands** widens attack surface — one
   compromised command can pollute the mount table, leaving traps for the next.
2. **Discard semantics get ugly**: if the container writes the upperdir, you
   can't tear down the upperdir without tearing down the container, which kills
   in-flight background jobs.
3. **A supervisor inside the container is attack surface**: it enforces policy
   on every exec while running privileged (root-in-userns) and receiving
   user-controlled input.
4. **Zombie reaping** becomes a real problem requiring a real init.
5. **Per-command policy differences** (agent vs provisioning; gdb's `ptrace`;
   `ulimit`'s `setrlimit`) are far cleaner when each command gets its own fresh
   bwrap with its own argv.

### Why not (c) hybrid

A hybrid ("persistent supervisor for state, on-demand policy per command")
collapses to (b) in practice: if state is held by the MCP server and policy is
per-command, the supervisor has nothing to do. Skip it.

### Discard-on-no-commit interaction with in-flight session

- The upperdir lives on **disk**, not tmpfs (pacman packages can be hundreds of
  MB; tmpfs OOM risk is real). Discard = `rm -rf <session-dir>` at session end.
- On daemon crash the upperdir is orphaned; next startup runs a `sessions/` GC
  sweep removing dead (lockfile PID dead) sessions.
- In-flight background jobs at session end: best-effort SIGTERM + grace, then
  SIGKILL. The bwrap subprocess and its namespace die with the job.

---

## 2. Layering order for an agent command

Outermost → innermost. **No privileged window where user code runs.**

```
┌─────────────────────────────────────────────────────────────────┐
│ MCP server (Python, uid=1000, NO pledge/landlock)                │
│   builds bwrap argv from validated user command                  │
│   Popen(argv=[bwrap, ...], env={SANDBOX_*: controlled})          │
└────────────────────────────┬─────────────────────────────────────┘
                             │ exec(bwrap)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ bwrap binary (host /usr/bin/bwrap)                              │
│   --unshare-user --unshare-pid --unshare-ipc --unshare-uts      │
│   --unshare-net           ← AGENT MODE: no network               │
│   --uid 1000 --gid 1000   ← agent mode; (provisioning uses 0/0) │
│   --overlay-src <base-rootfs>        ← immutable lower[0]       │
│   --overlay-src <layer-1> ...        ← committed layers (bottom)│
│   --overlay <upper> <work> /         ← writable overlay at /    │
│   --proc /proc --dev /dev                                       │
│   --ro-bind <stage3-binary> /init                                │
│   -- /init PROMISES LANDLOCK_SPEC -- <user-cmd> <args>           │
│                                                                  │
│ At this point: new user/mount/pid/uts/ipc/net ns exists.        │
│ stage3 is OUR trusted code running as uid 1000 (or 0/0 in prov).│
│ NO user code has run yet.                                       │
└────────────────────────────┬─────────────────────────────────────┘
                             │ exec(/init)
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ stage3 binary (NEW, static musl C, ~few hundred lines)          │
│   1. read PROMISES/LANDLOCK_SPEC/RLIMIT_* from argv+env         │
│      (ALL controlled by MCP server — user command is past --)   │
│   2. prctl(PR_SET_NO_NEW_PRIVS, 1)     ← one-way door           │
│   3. landlock_create_ruleset + add_rule×N + restrict_self       │
│      (LANDLOCK BEFORE SECCOMP — reverse deadlocks: seccomp      │
│      blocks landlock syscalls; verified in prior landlock plan) │
│   4. seccomp filter install (pledge-style syscall whitelist)    │
│   5. setrlimit×N (rlimits from env, before exec so child inherits) │
│   6. execvp(<user-cmd>, <args>)                                 │
│                                                                  │
│ Between restrict_self and execvp: only exec-related reads.       │
│ Handled set deliberately excludes READ_FILE/READ_DIR/EXECUTE so │
│ exec still works.                                                │
└────────────────────────────┬─────────────────────────────────────┘
                             │ execvp
                             ▼
                  ┌────────────────────┐
                  │ user command       │  ← all four layers active:
                  │ (e.g. bash -c ...) │     userns, bwrap namespaces,
                  └────────────────────┘     landlock, seccomp
```

> **bwrap overlay mechanics (validated in M3 spike):** the base rootfs and each
> committed layer are declared as overlay *lowers* via repeated
> `--overlay-src <path>`; the session's writable upperdir is mounted at `/` with
> `--overlay <upper> <work> /`. The base is **not** a separate `--ro-bind /`
> (that would make `/` read-only and the overlay could not mount). `bin/stage3`
> is bound read-only at `/init` (bwrap creates the file mountpoint on the
> overlay root).

### How the Arch env becomes visible

bwrap builds the visible filesystem before exec'ing `/init`:

- `/` = overlay(base + committed-layers, upperdir, workdir) — pacman-installed
  files appear here; writes land in the session upperdir
- `/proc`, `/dev`, `/dev/pts` (for tty), `/sys` (read-only) — bound by bwrap
- `/tmp` = part of the session overlay upperdir (persists across commands;
  writes captured by commit)
- `/workspace` = a directory inside the session upperdir (seeded empty at session
  creation); part of the overlay, so writes there are captured by commit. Explicit
  host-dir binds arrive in M5 (`bind_host_dir`).
- `/etc/resolv.conf` = **not** bound in agent mode (network is unshared anyway);
  bound in provisioning mode

### Two notes on the layering

- **userns is scaffolding only.** bwrap needs userns to do overlayfs mounts
  unprivileged. Once mounted, userns is *not* what protects us — Landlock +
  seccomp are. If a kernel bug lets you escape userns, you're still bound by the
  thread's landlock domain and seccomp filter (both persist across ns changes).
- **The bwrap `--overlay` API surface is version-sensitive.** Verify the exact
  bwrap version supports persistent upperdir specification (some versions only
  do per-process tmpfs upper). Fallback: a thin `stage2` wrapper that does
  `mount -t overlay` itself before exec'ing the user command — userns has
  allowed overlay mounts since kernel 5.11.

---

## 3. pacman + network tension — the split

### Recommendation: strict two-mode split, pacman as a first-class provisioning tool

| | **Agent mode** (`shell_run`, `shell_job_*`) | **Provisioning mode** (`pacman_install`, `pacman_run`) |
|---|---|---|
| UID in userns | 1000 (own) | 0/0 (root-in-userns) |
| Network | `--unshare-net` (no network at all) | `--share-net` (full host net) |
| Landlock | full: `/workspace` RW, `/tmp` RW, everything else RO via overlay | **not applied** (stage3 skipped — Landlock's deny-by-default model can't express "restrict `/workspace` but leave `/` open") |
| seccomp | full pledge-style whitelist | **not applied** (stage3 skipped; isolation = userns + bwrap + overlay, no host binds reachable) |
| Triggered by | every agent command | only `pacman_install` / `pacman_run` MCP tools |
| Lifetime | per command | per provisioning call (fresh bwrap) |

### Why this is the right split

1. **pacman is fundamentally a privileged operation.** It modifies
   `/var/lib/pacman`, writes `/usr`, needs root. Treating it as a separate
   explicit operation keeps the policy surface auditable: there is exactly one
   path to mutate the rootfs, and it requires a distinct MCP call.
2. **`--unshare-net` is strictly stronger than Landlock TCP rules.**
   `LANDLOCK_ACCESS_NET_BIND_TCP` / `CONNECT_TCP` (ABI 4, kernel 6.10+) only
   cover **TCP** — DNS (UDP), ICMP, raw sockets, and `socket(AF_INET, ...)`
   itself bypass it. `--unshare-net` denies everything with an empty netns
   (only `lo`).
3. **The network grant is bounded in time and tool** — it exists only for the
   duration of a `pacman_install` call. No configuration gives an arbitrary
   agent command network.
4. **Provisioning isolation is userns + bwrap + overlay (no stage3).** Pacman
   runs directly under bwrap (like bootstrap) with no host bind mounts and no
   way to reach the host filesystem, so it cannot write outside the container
   upperdir even if compromised. Landlock/seccomp are skipped because Landlock's
   deny-by-default model cannot express "restrict `/workspace` but leave `/`
   open" for pacman's writes to `/usr`, `/var/lib/pacman`, `/etc`.
5. **Avoids the "agent runs pacman without my permission" footgun** — pacman
   requires a distinct tool call, so the user sees it in the tool-call trace.

### Mirror scoping

`pacman_install(packages, refresh=True, mirror=None)`:

- `mirror=None` → use the pinned `mirrorlist` vendored at bootstrap.
- `mirror=<url>` → temporarily swap `/etc/pacman.d/mirrorlist` for this call
  only. Validated against an allowlist regex (HTTPS to known Arch mirror
  domains) — never accept arbitrary URLs (DNS exfil + supply-chain).

### Future extension (not v1)

A `--share-net`-with-firewall alternative using `nft` rules in the netns to
whitelist only mirror IPs. Overkill for v1.

---

## 4. COW / commit semantics

### Base rootfs (immutable lower, shared across all sessions on this host)

- Path: `<data-dir>/rootfs/base/`
- Provisioned **once** from the official `archlinux-bootstrap-x86_64.tar.zst`
  (LFS-tracked, pinned to a known-good release).
- After bootstrap (pacman-key + initial `pacman -Sy`): `chmod -R a-w` as
  defense-in-depth. Bind-mounted **read-only** into bwrap. **Never** written by
  the running system.
- Content-addressed: hash the tree at bootstrap; record in a manifest. Drift =
  re-bootstrap.

### Per-session upperdir

- Path: `<data-dir>/sessions/<sid>/{upper,work}/`
- **On disk**, not tmpfs. btrfs if available (reflink), ext4 otherwise (copy).
- Created lazily on first command of the session.
- Overlay mount: `lower=base + committed-layers-in-stack-order,
  upper=<session>/upper, work=<session>/work`.

### Layer stack

- Each `env_commit` produces a new layer at `<data-dir>/layers/<commit-id>/`.
- The session's effective lower = `base + [committed layers in chronological
  order up to the active tip]`.
- `env_rollback(to_commit_id)` truncates the active stack to end at that commit.
- Layers are content-addressed (hash of post-commit upperdir contents) so
  identical commits dedupe.

### What "commit" means mechanically

**Primary mechanism: rsync the upperdir into a new layer directory.**

```
new_layer = <data-dir>/layers/<sha256(upperdir-contents)>/
rsync -aHAX --delete <session>/upper/ <new_layer>/
   # or: cp -a --reflink=auto (btrfs/xfs)
append <new_layer> to session.active_layer_stack
mark <session>/upper as consumed (new empty upper for next segment)
```

**Why rsync-over-reflink-by-default:**

- Reflink (`cp --reflink`) is O(1) but only works on btrfs/xfs. Probe at
  startup: `stat -f -c %T <data-dir>`.
- On ext4 (typical), use `rsync -aHAX` — preserves xattrs, acls, hardlinks,
  sparse files.
- Either way, the new layer is a stable snapshot that won't change under you.

**Why NOT flatten into base:**

- Base immutability is a core invariant (drift detection, multiple sessions,
  rollback). Flatten-into-base breaks all three.
- Layer growth is bounded by GC.

### Keeping commits small (pacman db churn)

- **Each commit is only the diff from the previous layer** (rsync of the
  upperdir = changes since last commit).
- **`env_commit --squash`** flattens all session layers into one new layer.
- **GC**: a layer is removable when no session references it and nothing is
  built on it (track a `parents` field). Periodic `env_gc` tool.
- **Reflink on btrfs**: most blocks are shared between layers anyway.

### Multi-layer overlay performance

overlayfs handles many lower layers fine (hundreds supported). Lookup is
O(depth) per open but cache-amortized. For sane usage (<50 layers/session) it's
invisible.

---

## 5. MCP tool surface

Carry-over (semantics map cleanly to the container):

- **`shell_run(command, cwd, timeout, structured)`** — foreground, agent mode.
  Returns `{rc, skipped, stages, output}`. `cwd` resolves **inside** the
  container's `/workspace` bind.
- **`shell_job_start / shell_job_status / shell_job_wait / shell_job_output /
  shell_job_kill / shell_job_list`** — background lifecycle, unchanged API.
  Each job = its own bwrap subprocess (detached), sharing the same session
  upperdir. Same reaper pattern.
- **`shell_list`** — list allowlisted commands (now reads the container's
  `/usr/bin` inventory + the policy table).
- **`@mcp.tool(description=...)`** FastMCP convention.
- **Structured return** with `stages: [{command, output, rc}]`, `skipped`, `rc`,
  `output`.

What changes vs the prior project:

- **`cwd`** is a container path (e.g. `/workspace/src`), not a host path.
  Validated against `/workspace` containment.
- **Redirect targets** must be inside `/workspace` or `/tmp` (container paths).
- **Background jobs** run in their own bwrap namespace (fresh per job), sharing
  the upperdir but each with its own mount/pid/net ns.

New (environment management):

- **`env_status`** — session id, base rootfs hash + version, active layer stack,
  upperdir size + dirty file count, network policy per mode, capability probe
  summary.
- **`env_reset`** — drop upperdir, start fresh session (new upperdir, same
  base + layer stack). Idempotent.
- **`env_discard`** — explicit "throw away pending changes." Same as `env_reset`
  semantically; separate verb for clarity in user prompts.
- **`env_commit(message?)`** — snapshot upperdir to a new layer, add to active
  stack. Returns `{commit_id, size_bytes, layer_count}`.
- **`env_snapshot_list`** — list committed layers (id, message, size, timestamp).
- **`env_rollback(to_commit_id)`** — truncate active stack.
- **`env_gc`** — remove unreferenced layers.

New (provisioning):

- **`pacman_install(packages: list[str], refresh: bool=True, mirror: str=None)`**
  — provisioning mode, networked. Returns installed list + sizes.
- **`pacman_run(args: list[str])`** — read-only pacman (`-Q`, `-Si`, `-F`,
  etc.). Still provisioning mode (uid 0 in ns) for consistency, but explicit
  no-network variant (`--unshare-net`).

New (host bind):

- **`bind_host_dir(host_path, mount_point, mode="ro"|"rw")`** — explicit
  per-call or per-session bind of a host directory into the container at
  `mount_point` (e.g. `/workspace`). Subject to:
  - Path validation rejects `$HOME`, `~/.config`, `~/.local`, `~/.cache`,
    `/etc`, `/proc`, `/sys`.
  - Resolved realpath must exist and be a directory.
  - `mode="rw"` requires the same path to be in the landlock RW set for the
    command.

#### Deferred (not v1): making commit/rollback version bound host dirs

`env_commit`/`env_rollback`/`env_reset`/`env_discard` snapshot and restore
**only the session overlay upperdir**. A bound host dir is **live write-through**:
writes go straight to the host (via `--bind`/`--ro-bind`) and are deliberately
*outside* the layer stack — never captured by commit, never reverted by
rollback/reset.

We considered extending the layer stack to *version* bound host dirs (a
git-worktree-like model: `commit` snapshots a bound dir into a layer,
`rollback`/`discard` restore it destructively). It was **rejected for v1 as
needless complexity**; reconsider if a concrete need appears. The design
tensions that made it expensive, for the record:

- **Restore is destructive to the host.** `rollback`/`discard` would rsync an
  older snapshot over a *live* host directory (data-loss risk the user must
  explicitly accept), and could race a concurrent commit from another session
  (needs a persisted per-session rw-ownership table + lock discipline).
- **Dual-source content-addressing.** `commit_id` must hash the upper *and*
  every bound rw host dir's tree deterministically (sorted walk, same
  mode/type/sha256 format), and must not dedupe two sessions that bind the same
  host dir to different mount_points.
- **Restore cannot use the overlay.** A bound host dir is a lower-level live
  bind that *shadows* the overlay at its mount_point, so rollback can't rely on
  overlay layering; it must rsync the layer's copy back to the host explicitly.
- **Import-COW was also rejected** (host never written, explicit `bind_publish`
  to write back): the export footgun (agents won't call publish) and the slow
  full-tree copy at bind time made it a worse fit than live write-through.

If this is ever pursued, revisit the three candidate models — (1) live
write-through + destructive versioning (above), (2) import-COW into the upper
with `bind_publish`, (3) read-only overlay-lower shim (requires a bind-mount
shim in a mount namespace; unprivileged but heavier) — and pick based on
whether host-dir changes must reach the host *automatically* (1) or never touch
it (2/3).

---

## 6. Module / file layout + runtime deps

```
src/arch_sandbox_mcp/
  __init__.py
  __main__.py              # entry: mcp run
  server.py                # FastMCP facade; @mcp.tool registration; thin
  config.py                # paths, kernel feature gates, allowlists, mirrorlist, forbidden paths
  capabilities.py          # one-shot host probe: landlock abi, bwrap version,
                           #   kernel version, overlay-in-userns support, reflink fs
  parser.py                # clean-room AST command parser (AST-native only)
  redirects.py             # redirect planning + validation
  policy.py                # per-command pledge/seccomp policy tables; mode policies
  executor.py              # build Invocation; spawn bwrap; structured return; fg path
  jobs.py                  # JobStatus/JobRecord; reaper thread; PID registry
  bgdriver.py              # detached driver for shell_job_start (raw subprocess)
  layers.py                # session layer stack; commit/discard/rollback; reflink detect
  overlay.py               # lower/upper/work provisioning; bwrap --overlay builder
  bwrap.py                 # bwrap argv builder for agent vs provisioning modes; env surface
  pacman.py                # pacman_install / pacman_run; mirrorlist handling; allowlist regex
  contain.py               # path containment validators (roots = container paths)
  stage3.c                 # NEW inner binary; ~few hundred lines; static musl build
vendor/
  archlinux-bootstrap-x86_64.tar.zst   # LFS-pinned official bootstrap
  mirrorlist                            # pinned mirror list
bin/
  stage3                   # built from src/arch_sandbox_mcp/stage3.c (static musl)
  bootstrap-rootfs.sh      # extract tarball, pacman-key init, base -Sy
Makefile                   # builds stage3; bootstrap-rootfs target; verify target
docs/
  architecture.md          # this plan
  security-invariants.md   # the 12 invariants + gotchas
  bootstrap.md             # rootfs provisioning recipe
tests/
  test_capabilities.py     # host probe
  test_stage3.py           # C-level landlock+seccomp enforcement probes
  test_bwrap_modes.py      # agent vs provisioning argv construction
  test_layers.py           # commit/discard/rollback/gc
  test_pacman.py           # provisioning mode (skipped if rootfs not bootstrapped)
  test_e2e.py              # full shell_run inside container
  ... (per-module)
```

### Runtime dependencies

| Dep | Version | Why |
|---|---|---|
| Linux kernel | ≥ 6.2 (Landlock ABI 5); ≥ 5.11 (overlay in userns); 6.10+ optional (Landlock TCP, not used in v1) | Host is 7.1.5 ✓ |
| `kernel.unprivileged_userns_clone` | =1 | bwrap without setuid |
| `bwrap` | ≥ 0.10 (verify `--overlay` API) | environment layer |
| Landlock LSM | enabled | Host: `capability,landlock,lockdown,yama,bpf` ✓ |
| `python3` (host) | ≥ 3.10 | MCP server runtime |
| `mcp` package | latest | FastMCP facade |
| `rsync` (host) | any | commit snapshots |
| `pacman-key`, `gnupg` | at bootstrap only | base rootfs provisioning |
| `archlinux-bootstrap-x86_64.tar.zst` | LFS-pinned | base rootfs source |
| musl toolchain | for building `stage3` | static inner binary |

### Build/bootstrap plan

**Stage A — Toolchain + `stage3` build (minutes):**
1. Compile `src/arch_sandbox_mcp/stage3.c` against vendored musl → static binary
   at `bin/stage3`.
2. `make stage3` target. No LFS needed for the binary.

**Stage B — Base rootfs bootstrap (one-time, idempotent, ~5–15 min):**
1. Extract `vendor/archlinux-bootstrap-x86_64.tar.zst` into
   `<data-dir>/rootfs/base` (rootfs is `root.x86_64/` inside the tarball — strip).
2. Drop the pinned `vendor/mirrorlist` at
   `<data-dir>/rootfs/base/etc/pacman.d/mirrorlist`.
3. Enter via
   `bwrap --unshare-all --share-net --uid 0 --gid 0 --bind <rootfs> / --proc /proc --dev /dev ... -- /usr/bin/pacman-key --init` then `--populate archlinux`.
4. `pacman -Sy` to sync db; `pacman -S --needed base-devel` for a baseline.
5. `chmod -R a-w <data-dir>/rootfs/base` — immutability.
6. Hash tree → write `<data-dir>/rootfs/base/MANIFEST.sha256`.

**Stage C — Verify (seconds):**
1. `make verify` — probe capabilities, assert bwrap launches, assert
   landlock_restrict_self succeeds, assert overlay mounts.
2. Smoke: `python3 -m arch_sandbox_mcp` → `shell_run("ls /")` → Arch rootfs layout.

**Stage D — Test (seconds):**
- Full unittest suite under `python3 -m unittest discover -s tests -v`.

---

## 7. Security invariants

The "what must never be true." Each is enforceable and testable.

1. **User command code never runs in a root-in-userns pre-seccomp window.**
   Stage3 applies all layers before `execvp`. The only ops between
   `restrict_self`/`seccomp_install` and `execvp` are exec-related reads.
2. **Landlock is always applied before seccomp.** Reverse order deadlocks.
3. **`PR_SET_NO_NEW_PRIVS` is set unconditionally before landlock + seccomp.**
   One-way door.
4. **No shared mount namespace across MCP clients.** Each session = its own
   upperdir = its own bwrap invocation per command. No `setns`. No persistent
   container.
5. **Discard is default.** Upperdir is removed at session end unless
   `env_commit` was called.
6. **Commit only via explicit tool call.** `env_commit` is a distinct MCP tool;
   never auto-commit.
7. **Network is unshared by default in agent mode.** Only provisioning mode
   shares net.
8. **Trusted paths are never widened by client input.** All bind sources, env
   vars, and policy decisions come from the MCP server's controlled surface.
   The sandboxed file tools (`rattan_read_file`/`rattan_write_file`/`rattan_edit`/
   `rattan_grep`) extend this: they accept container paths under `/workspace` or
   `/tmp` only, validated lexically on the host **and** re-resolved inside the
   sandbox (via `realpath`) so a container-side symlink pointing outside the roots
   (e.g. `/workspace/evil -> /etc/passwd`) is rejected before any read/write.
9. **The base rootfs lower layer is never writable.** Bind RO + `chmod -R a-w` +
   manifest hash check at startup.
10. **Stage3 blocks post-setup privileged syscalls.** Seccomp denies `keyctl`,
    `add_key`, `request_key`, `ptrace` (unless gdb mode), `unshare` (re-entry),
    `setns`, `mount`, `pivot_root`, `umount2`, `reboot`. Even root-in-userns
    can't escalate.
11. **Bind-source path validation rejects `$HOME`, `~/.config`, `~/.local`,
    `~/.cache`, `/etc`, `/proc`, `/sys`, and any non-directory.**
12. **MCP server itself runs without pledge/landlock.** It needs `clone`,
    `unshare`, `mount`, `execve` to spawn bwrap. Safe because the server is the
    trusted orchestrator and never executes user code itself.

### Failure modes / known gotchas

| Gotcha | Mitigation |
|---|---|
| **Landlock union-within-layer** (rules union; can't subtract) | Sidestepped: agent landlock rules govern container-internal paths (`/workspace`, `/tmp`), not host paths under a writable ancestor. |
| **Nested pledge inheritance** (seccomp BPF AND-inherits; landlock domains intersect) | Background jobs spawn as raw bwrap subprocesses (not inside an already-pledged parent). |
| **overlayfs upperdir on tmpfs → OOM** under pacman churn | Upperdir on disk by default; tmpfs only for `/tmp` inside the container. |
| **bwrap + userns kernel config** | Probe at startup; refuse if `kernel.unprivileged_userns_clone=0`. |
| **pacman needs /proc and time** | Provisioning mode mounts /proc, shares time ns. |
| **Landlock ABI drift** | Probe abi; mask handled set; log loudly if abi<3 (loses TRUNCATE). |
| **reflink only on btrfs/xfs** | Probe `stat -f -c %T`; fall back to `rsync`. |
| **bwrap version drift** | Pin minimum; probe `bwrap --version`; verify `--overlay` persistent upperdir (else stage2 `mount -t overlay`). |
| **pacman gpg needs randomness** | Bind `/dev/urandom` RO into provisioning bwrap. |
| **Zombie reaping in provisioning mode** | bwrap `--die-with-parent`; pacman reaps script children. |
| **Background job survival across MCP teardown** | `start_new_session=True`; bwrap is the job PID. |
| **Landlock and overlayfs interaction** | Landlock sees post-overlay view — a rule on `/etc` denies writes through the overlay (desired). |
| **Redirect write via `>` before landlock applied** | Validate redirect targets under protected paths before spawning bwrap. |
| **Pledge token gaps for tools** (`waitid` for git-lfs, `ptrace` for gdb, `setrlimit` for `ulimit`) | Per-command override env vars for specific trusted tools. |
| **TIME namespace + pacman-key** | Provisioning keeps time shared; agent may unshare. |

---

## Open questions / to verify on first implementation

1. **Exact bwrap `--overlay` API** for persistent upperdir on the installed
   bwrap version. May need a `stage2` wrapper doing `mount -t overlay` directly.
2. **overlayfs lower-stack depth** before lookup latency matters. Perf test +
   `env_commit --squash` relief valve.
3. **stage3 seccomp filter generator**: static per-mode table in C vs generated
   from a Python policy table at build time. Lean: small static per-mode table +
   per-command extension via env.
4. **Should agent mode unshare time?** Default no (leaves it shared) until a real
   issue.
5. **Landlock network rules in v2** (kernel 7.1, ABI 5+): TCP rules as a second
   layer of defense in provisioning mode. Not v1.
