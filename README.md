# Rattan

A greenfield **MCP server** that exposes a safe, disposable **Arch Linux shell
sandbox** to an LLM agent. Every command runs inside a fresh bubblewrap
container with an Arch rootfs layered on top of **seccomp (pledge-style) +
user namespaces + Landlock + overlayfs**. Agent changes are **discarded by
default** unless you explicitly commit them — a running agent cannot leave
anything behind without your say-so.

Implemented end-to-end: host capability probe, a custom C `stage3` inner
security binary (no_new_privs → Landlock → seccomp), a bootstrapped Arch rootfs
with working `pacman` provisioning, content-addressed overlay commits, and 18
MCP tools.

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

## Features

- **Fully isolated, ephemeral shell** — `shell_run` runs a command in a
  throwaway bwrap + overlay container each time.
- **Discard by default** — nothing persists unless you call `env_commit`.
- **Content-addressed commits** — `env_commit` snapshots the overlay upperdir
  into an immutable, deduplicated layer; `env_rollback` truncates the stack;
  `env_gc` collects unreferenced layers.
- **Real package manager** — `pacman_install` provisions packages into the
  session (Arch mirrors, signature-verified); `pacman_run` for read-only queries.
- **Background jobs** — long-running commands via `shell_job_*` (start / status /
  wait / output / kill / list).
- **Controlled host access** — `bind_host_dir` exposes a host directory into the
  container only after strict path validation.
- **Startup gate** — refuses to start if any required host capability is missing
  (`make verify` / `rattan --probe`).

## How secure is it?

Security is layered: even if one layer fails, the others still constrain the
agent. The full list of enforceable invariants is in
[`docs/security-invariants.md`](docs/security-invariants.md); the summary is:

| Layer | What it does |
|---|---|
| **User namespaces** | Commands run as unprivileged uid/gid 1000 inside their own userns; no host privileges. |
| **bubblewrap** | `--unshare-all` — isolates mount, PID, IPC, UTS, and **network** namespaces. Agent mode is **network-denied** by default; only `pacman_install` (provisioning) shares the network. |
| **overlayfs COW** | A read-only base rootfs + committed layers; writes land in a session-only upperdir. The base is `chmod -R a-w` and verified by a startup manifest hash check. |
| **stage3 C binary (`/init`)** | The innermost gate. Applies, **in order**: `PR_SET_NO_NEW_PRIVS` → Landlock unveil → rlimits → seccomp/pledge — *before* ever `execvp`'ing the user command. |
| **Landlock** | Filesystem access is limited to a per-command spec (`/workspace:rwc`, `/usr:rx`, `/etc:r`, …). |
| **seccomp (pledge-style)** | Syscall whitelist denies `keyctl`, `add_key`, `request_key`, `ptrace` (unless gdb mode), `unshare`, `setns`, `mount`, `pivot_root`, `umount2`, `reboot`, and more. |

Key guarantees:

1. **User code never runs in a pre-seccomp window** — stage3 finishes all
   hardening before `execvp` (verified by `bin/stage3 --verify` asserting
   `Seccomp: 2` + `Landlock`).
2. **No privilege escalation to the host** — the agent is root-in-userns with a
   *deny-list of every dangerous syscall*; it can't mount, unshare, ptrace, or
   reach the host network or filesystem.
3. **No cross-session contamination** — each session is its own upperdir, and
   commit identity includes workspace content so sessions never dedupe-merge.
4. **Trusted surface only** — host bind sources, env vars, and pacman args are
   validated/allowlisted by the server (e.g. `bind_host_dir` rejects `/`,
   `$HOME`, `/etc`, `/proc`, `/sys` and the rattan data dir; `pacman_run` only
   accepts read-only query flags).

**What it does *not* do** (design boundaries): it is a *containment* tool, not a
malware sandbox — it assumes the host kernel and host tools are trusted, and it
cannot defend against a compromised host kernel. Network is available only in
provisioning mode (for `pacman_install`). Redirects (`cmd > file`) are parsed
and validated but not yet applied to `shell_run`'s output plumbing — a known
limitation.

## Host requirements

- **Linux ≥ 6.2** (for Landlock ABI; the probe checks ≥ 6.2)
- **Unprivileged user namespaces enabled** (`kernel.unprivileged_userns_clone=1`)
- **Landlock LSM active** (add `lsm=landlock` to the kernel command line if needed)
- **bubblewrap** (`bwrap` on PATH)
- **overlayfs** support in the running kernel
- **Python ≥ 3.10** with `mcp` (installed in the venv below)

`make verify` runs the full host gate and tells you exactly what's missing.

## Install & build

```bash
git clone https://github.com/jmars/rattan.git
cd rattan

# 1. Python env
python3 -m venv .venv
.venv/bin/pip install -e .

# 2. Build the stage3 C security binary (needs cosmocc + assimilate on PATH)
make stage3

# 3. Bootstrap the Arch base rootfs (downloads the Arch bootstrap tarball;
#    creates the read-only base at ~/.local/share/rattan/rootfs/base)
make bootstrap-rootfs

# 4. Verify the host + toolchain all work
make verify
```

## Run

The package installs a `rattan` console script (equivalent to
`.venv/bin/python -m rattan`).

```bash
# Host capability probe / startup gate (works even without mcp installed)
rattan --probe

# Start the MCP server over stdio
rattan
```

## Configure an MCP client

Rattan speaks the MCP protocol over **stdio**. In your MCP client's config
(e.g. Claude Desktop / a generic MCP host):

```json
{
  "mcpServers": {
    "rattan": {
      "command": "/absolute/path/to/rattan/.venv/bin/rattan",
      "args": []
    }
  }
}
```

The server runs a startup gate before registering tools — if a required host
capability is missing it refuses to start (run `rattan --probe` to see why).

## Tool surface (18 tools)

| Category | Tools |
|---|---|
| **Command execution** | `shell_run`, `shell_list` |
| **Environment lifecycle** | `env_status`, `env_reset` / `env_discard`, `env_commit`, `env_snapshot_list`, `env_rollback`, `env_gc` |
| **Package management** | `pacman_install`, `pacman_run` |
| **Background jobs** | `shell_job_start`, `shell_job_status`, `shell_job_wait`, `shell_job_output`, `shell_job_kill`, `shell_job_list` |
| **Host access** | `bind_host_dir` |

## Usage examples

**Run a command** (returns `{rc, output, stages}`):

```
shell_run(command="ls -la /", cwd="/workspace", timeout=30)
# → {rc: 0, output: "total ...\ndrwxr-xr-x ... usr ...", ...}
```

```
shell_run(command="uname -a", structured=False)
# → "Linux ... x86_64 GNU/Linux"
```

**Packages don't persist unless you commit them:**

```
pacman_install(packages=["tree"], refresh=True)   # provisioning, network
shell_run(command="tree /workspace")              # now available
env_discard()                                     # forget everything (default)
shell_run(command="tree /workspace")              # "tree: command not found"
```

**Commit a snapshot and roll back:**

```
env_commit(message="added tree")                  # → {commit_id: "...", layer_count: 1}
env_snapshot_list()                               # → [{commit_id, message, ...}]
env_rollback(to_commit_id="<id>")                 # truncate the stack
env_gc()                                          # free unreferenced layers
```

**Read-only pacman queries (no network):**

```
pacman_run(args=["-Q", "tree"])    # installed? version?
pacman_run(args=["-Si", "bash"])   # sync info for a package
pacman_run(args=["-F", "/bin/ls"]) # which package owns a file
```

**Long-running background work:**

```
shell_job_start(command="make -j4 build", cwd="/workspace", timeout=300)
# → {job_id: 1, pid: ..., status: "running"}
shell_job_status(job_id=1)
shell_job_wait(job_id=1)
shell_job_output(job_id=1)
shell_job_kill(job_id=1)
```

**Expose a host directory read-only (validated):**

```
bind_host_dir(host_path="/home/me/data", mount_point="/mnt/data", mode="ro")
# → {status: "bound", host_path: ..., mount_point: "/mnt/data", mode: "ro"}
```

Binding `/`, `$HOME`, `/etc`, `/proc`, `/sys`, or the rattan data dir is
rejected with an error.

## Verification

```bash
make verify   # host gate: capability probe, bwrap, stage3 landlock+seccomp,
              # overlay mount, and a real shell_run("ls /")
make test     # full unittest suite (187 tests)
make lint     # syntax check
```

## Docs

- **[`docs/architecture.md`](docs/architecture.md)** — full architecture: layering,
  process/lifecycle model, pacman provisioning split, COW/commit semantics, MCP
  tool surface, module layout, security invariants.
- **[`docs/implementation-plan.md`](docs/implementation-plan.md)** — the build plan:
  milestones (M0–M6), code-level tickets, dependency graph, risk register.
- **[`docs/security-invariants.md`](docs/security-invariants.md)** — the "what must
  never be true" guarantees, each mapped to an automated test.
- **[`docs/bootstrap.md`](docs/bootstrap.md)** — base rootfs bootstrap notes.

## Status

**Implemented.** All milestones M0–M6 are complete and `make verify` passes on a
supported host. The repository is a public greenfield project; see the
implementation plan for the full build history.
