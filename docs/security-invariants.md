# Rattan — Security Invariants

The "what must never be true" guarantees of the rattan sandbox. Each invariant
is enforceable and mapped to an automated test. See `docs/architecture.md` §7
for the source design.

1. **User command code never runs in a root-in-userns pre-seccomp window.**
   Stage3 applies all layers before `execvp`. Tested by `bin/stage3 --verify`
   (asserts `Seccomp: 2` + `Landlock` enforced) and `tests/test_stage3.py`.

2. **Landlock is always applied before seccomp.** Reverse order deadlocks.
   Structurally enforced in `stage3.c::setup_layers` (no early return between
   the four calls). Tested by `tests/test_stage3.py::TestNoEarlyReturnStructurally`
   and `reverse_order_probe` (empirically proves pledge-then-unveil → EPERM).

3. **`PR_SET_NO_NEW_PRIVS` is set unconditionally before landlock + seccomp.**
   One-way door. Tested by `bin/stage3 --verify` (`NoNewPrivs: 1`) and
   `tests/test_stage3.py::TestVerifyBaseline`.

4. **No shared mount namespace across MCP clients.** Each session = its own
   upperdir = its own bwrap invocation per command. No `setns`, no persistent
   container. Tested by `tests/test_invariants.py::TestInvariant4_NoSharedMountNS`.

5. **Discard is default.** Upperdir is removed at session end unless
   `env_commit` was called. Tested by
   `tests/test_invariants.py::TestInvariant5_DiscardDefault` (unit + e2e) and
   `tests/test_e2e.py::test_discard_default`.

6. **Commit only via explicit tool call.** `env_commit` is a distinct MCP tool;
   never auto-commit. Tested by
   `tests/test_invariants.py::TestInvariant6_CommitExplicitOnly` (unit + e2e).

7. **Network is unshared by default in agent mode.** Only provisioning mode
   shares net. Tested by `tests/test_e2e.py::test_network_denied`,
   `tests/test_invariants.py::TestInvariantsE2E::test_invariant7_network_unshared_agent`,
   and `tests/test_bwrap_modes.py` (agent argv has no `--share-net`).

8. **Trusted paths are never widened by client input.** All bind sources, env
   vars, and policy decisions come from the MCP server's controlled surface.
   Tested by `tests/test_invariants.py::TestInvariant8_TrustedPaths` and
   `tests/test_pacman.py::TestMirrorValidation` (mirror allowlist).

9. **The base rootfs lower layer is never writable.** Bind RO + `chmod -R a-w` +
   manifest hash check at startup. Tested by
   `tests/test_invariants.py::TestInvariant9_BaseNeverWritable`,
   `tests/test_bootstrap.py` (manifest validation), and
   `config.validate_base_manifest()` (startup gate).

10. **Stage3 blocks post-setup privileged syscalls.** Seccomp denies `keyctl`,
    `add_key`, `request_key`, `ptrace` (unless gdb mode), `unshare` (re-entry),
    `setns`, `mount`, `pivot_root`, `umount2`, `reboot`. Tested by
    `tests/test_stage3.py` (keyctl/ptrace/mount/unshare denial probes).

11. **Bind-source path validation rejects everything except user data dirs.**
    Only a non-hidden subdir under `$HOME` (e.g. `~/projects/foo`) can be bound.
    Rejected: `/`, all system dirs (`/etc /proc /sys /usr /var /boot /dev /run
    /bin /lib /root /tmp /opt /srv /mnt /media`), another user's home, `$HOME`
    itself and every hidden `$HOME/.*` subtree (`.ssh`, `.config`, `.local`,
    `.cache`, ...), the rattan data dir, and any non-directory. Tested by
    `tests/test_invariants.py::TestInvariant8_TrustedPaths` and the
    `bind_host_dir` tool (fuzzable via malicious paths).

12. **MCP server itself runs without pledge/landlock.** It needs `clone`,
    `unshare`, `mount`, `execve` to spawn bwrap. Safe because the server is the
    trusted orchestrator and never executes user code itself. This is a
    property of the design (the Python server is never wrapped in stage3);
    enforced by the architecture and not user-reachable.

## Failure modes / gotchas

| Gotcha | Mitigation |
|---|---|
| **Landlock union-within-layer** (rules union; can't subtract) | Agent landlock rules govern container-internal paths (`/workspace`, `/tmp`), not host paths under a writable ancestor. |
| **Nested pledge inheritance** (seccomp BPF AND-inherits; landlock domains intersect) | Background jobs spawn as raw bwrap subprocesses (not inside an already-pledged parent); the MCP server is never pledged. |
| **overlayfs upperdir on tmpfs → OOM** under pacman churn | Upperdir on disk by default (never tmpfs). |
| **bwrap + userns kernel config** | Probe at startup; refuse if `kernel.unprivileged_userns_clone=0`. |
| **Landlock ABI drift** | Probe abi; mask handled set; log loudly if abi < 3. |
| **pacman download sandbox breaks in userns** | `bin/bootstrap-rootfs.sh` disables `DownloadUser`/sandbox in the base `pacman.conf`. |
| **Background job survival across MCP teardown** | `start_new_session=True`; bwrap is the job PID; reaper polls the registry. |
| **Redirect write via `>` before landlock applied** | `redirects.py` validates redirect targets under container roots before spawning bwrap. |
| **Pledge token gaps for tools** (`ptrace` for gdb, `setrlimit` for `ulimit`) | Per-command overrides (`RATTAN_ALLOW_PTRACE`, etc.) for specific trusted tools. |
