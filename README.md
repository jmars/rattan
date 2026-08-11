# Rattan

An MCP server that runs commands inside an Arch Linux sandbox: seccomp
(pledge-style) + user namespaces + bubblewrap + Landlock + overlayfs. Agent
changes are discarded unless you call `env_commit`.

Implemented: host capability probe, a C `stage3` inner binary (no_new_privs →
Landlock → seccomp), a bootstrapped Arch rootfs with pacman, content-addressed
overlay commits, and 18 MCP tools.

```
┌───────────────┐   stdio    ┌────────────────────────────────────────────┐
│  MCP client   │ ◀────────▶ │  rattan server (Python, trusted, unpledged) │
│  (agent/LLM)  │            └────────────────────────────────────────────┘
                                      │
                              bwrap + overlayfs
                                      │
                 ┌────────────────────┼─────────────────────┐
                 ▼                    ▼                     ▼
        ┌────────────────┐   ┌────────────────┐   ┌──────────────────┐
        │ base rootfs    │   │ committed      │   │ session upperdir │
        │ (read-only)    │   │ layers (COW)   │   │ (writable,       │
        │                │   │                │   │  discard default)│
        └────────────────┘   └────────────────┘   └──────────────────┘
                            ┌───────────────────────────────┐
                            │  /init = stage3 (C binary)     │
                            │  no_new_privs → Landlock →     │
                            │  seccomp → execvp(user cmd)    │
                            └───────────────────────────────┘
```

## Security

Layers, outermost to innermost:

- **user namespaces** — commands run as unprivileged uid/gid 1000
- **bubblewrap `--unshare-all`** — separate mount/PID/IPC/UTS/network namespaces;
  network denied in agent mode
- **overlayfs COW** — read-only base rootfs + committed layers; writes land in a
  session-only upperdir
- **stage3 (`/init`)** — applies no_new_privs, Landlock, rlimits, seccomp before
  `execvp`

stage3 denies `keyctl`, `add_key`, `request_key`, `ptrace` (unless gdb),
`unshare`, `setns`, `mount`, `pivot_root`, `umount2`, `reboot`.

It's a containment tool, not a malware sandbox: the host kernel and host tools
are trusted. Network is only available to `pacman_install` (provisioning).
Redirects (`cmd > file`) are parsed but not applied to `shell_run` yet.

Enforceable invariants, each with a test: `docs/security-invariants.md`.

## Requirements

- Linux ≥ 6.2, unprivileged userns enabled, Landlock active, bubblewrap,
  overlayfs
- Python ≥ 3.10

`make verify` checks all of it.

## Build

```bash
git clone https://github.com/jmars/rattan.git && cd rattan
python3 -m venv .venv && .venv/bin/pip install -e .
make stage3            # needs cosmocc + assimilate on PATH
make bootstrap-rootfs  # base Arch rootfs → ~/.local/share/rattan/rootfs/base
make verify
```

## Run

```bash
rattan --probe   # host capability check
rattan           # MCP server over stdio
```

MCP client config:

```json
{ "mcpServers": { "rattan": {
  "command": "/path/to/rattan/.venv/bin/rattan",
  "args": []
}}}
```

## Tools (18)

- command execution: `shell_run`, `shell_list`
- environment: `env_status`, `env_reset`/`env_discard`, `env_commit`,
  `env_snapshot_list`, `env_rollback`, `env_gc`
- packages: `pacman_install`, `pacman_run`
- background jobs: `shell_job_start`, `shell_job_status`, `shell_job_wait`,
  `shell_job_output`, `shell_job_kill`, `shell_job_list`
- host access: `bind_host_dir`

## Examples

```text
shell_run(command="uname -a", structured=False)
# "Linux rattan ... GNU/Linux"

pacman_install(packages=["tree"])   # network
shell_run(command="tree /workspace")
env_discard()                        # tree is gone again

env_commit(message="added tree")     # → {commit_id, ...}
env_snapshot_list()
env_rollback(to_commit_id="...")
env_gc()

pacman_run(args=["-Q", "tree"])      # read-only, no network

shell_job_start(command="make -j4", cwd="/workspace")
shell_job_wait(job_id=1)

bind_host_dir(host_path="/home/me/data", mount_point="/mnt/data", mode="ro")
```

`bind_host_dir` rejects `/`, `$HOME`, `/etc`, `/proc`, `/sys`, and the rattan
data dir.

## Verify

```bash
make verify   # host gate: capability probe, bwrap, stage3, overlay, shell_run
make test     # 187 tests
```

## Docs

`docs/architecture.md` · `docs/implementation-plan.md` ·
`docs/security-invariants.md` · `docs/bootstrap.md`
