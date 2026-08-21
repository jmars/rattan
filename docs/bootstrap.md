# Rattan — base rootfs bootstrap

This document describes how the immutable Arch Linux base rootfs is built and
maintained. It is a prerequisite for M3+ (the sandbox runs commands against this
rootfs).

## Prerequisites

| Requirement | Why | Check |
|---|---|---|
| Linux kernel ≥ 6.2 | Landlock ABI 5 | `uname -r` |
| `kernel.unprivileged_userns_clone=1` | bwrap without setuid | `cat /proc/sys/kernel/unprivileged_userns_clone` |
| `bwrap` ≥ 0.10 | namespaces + overlay | `bwrap --version` |
| `zstd` | decompress the tarball | `zstd --version` |
| `bsdtar` (recommended) | extracts the official tarball cleanly (GNU tar warns on its xattr headers) | `bsdtar --version` |
| Internet access | download packages from mirrors | — |
| ~2 GB free under the data dir | rootfs + package cache | `df -h ~` |

Enable userns if it is off (persist in `/etc/sysctl.d/`):

```sh
sudo sysctl kernel.unprivileged_userns_clone=1
```

## Quick start

```sh
make bootstrap-rootfs
```

One command. Idempotent: re-running skips if the base manifest validates, and
re-bootstraps if the base has drifted.

## What happens

`bin/bootstrap-rootfs.sh`:

1. **Extract** `vendor/archlinux-bootstrap-x86_64.tar.zst` into
   `<data-dir>/rootfs/base`, stripping the `root.x86_64/` prefix.
2. **Install** the pinned `vendor/mirrorlist` into `etc/pacman.d/mirrorlist`.
3. **Enter via bwrap** (root-in-userns, shared net, writable bind of the base):
   - `pacman-key --init`
   - `pacman-key --populate archlinux`
   - `pacman -Sy`
   - `pacman -S --needed base`
5. **Add the sandbox user** (uid/gid 1000, home `/workspace`, shell bash) to
   `etc/passwd` and `etc/group` — otherwise `whoami`/`id` fail with
   "cannot find name for user ID 1000".
6. **Install custom files** from `vendor/rootfs-extra/` (verbatim copy into the base).
7. **Immutable**: `chmod -R a-w <base>`.
8. **Write** `MANIFEST.sha256` (one sha256 line per file, relative to base).

## Where files land

- Default data dir: `~/.local/share/rattan/`
- Base rootfs: `~/.local/share/rattan/rootfs/base/`
- Manifest: `~/.local/share/rattan/rootfs/base/MANIFEST.sha256`
- Override the data dir with `RATTAN_DATA_DIR=/some/other/path`.

## Personal rootfs config (external)

You can extend the base rootfs **without forking the repo**. `bootstrap-rootfs.sh`
sources an optional external config file (default `$HOME/.config/rattan/rootfs.env`,
override with `RATTAN_ROOTFS_CONFIG`), which may set:

- `ROOTFS_EXTRA_PACKAGES` — extra pacman packages (space-separated) installed
  alongside `base`. Example: `ROOTFS_EXTRA_PACKAGES="base-devel git musl mcpp"`.
- `ROOTFS_EXTRA_DIRS` — extra directories copied verbatim into the base, in
  addition to `vendor/rootfs-extra/`. Useful for a prebuilt binary that isn't a
  pacman package (e.g. souffle, which is AUR-only). The directory layout mirrors
  the base rootfs, e.g. `~/rattan-rootfs-extra/usr/local/bin/souffle` →
  `<base>/usr/local/bin/souffle`.

Example config (`~/.config/rattan/rootfs.env`):

```sh
ROOTFS_EXTRA_PACKAGES="base-devel git musl mcpp"
ROOTFS_EXTRA_DIRS="$HOME/rattan-rootfs-extra"
```

The config file is **sourced** by the bootstrap script and runs on your own host,
so keep it trusted. Files from these dirs are included in `MANIFEST.sha256` and
locked read-only like the rest of the base.

## Adding non-pacman files (`vendor/rootfs-extra`)

The base rootfs is built from pacman packages plus anything under
`vendor/rootfs-extra/`, which is copied verbatim into the base during bootstrap
(before the manifest is written and the base is locked read-only). This is how
you add a prebuilt binary, config, or data that isn't from a pacman package.

Layout mirrors the base rootfs:

```
vendor/rootfs-extra/usr/local/bin/mytool   →  <base>/usr/local/bin/mytool
vendor/rootfs-extra/etc/motd               →  <base>/etc/motd
```

These files are included in `MANIFEST.sha256` (integrity-checked at startup —
mtime fast path by default, full `sha256sum` verification when
`RATTAN_VERIFY_BASE=1` is set) and are immutable, so the agent can execute but
never modify them (they live in the read-only overlay lower layer).

To apply after a change:

```sh
# drop files under vendor/rootfs-extra/, then rebuild the base
rm -rf ~/.local/share/rattan/rootfs/base && make bootstrap-rootfs

# or patch an already-built base without a full re-download:
BASE=~/.local/share/rattan/rootfs/base
chmod -R u+w "$BASE"
cp -a vendor/rootfs-extra/. "$BASE/"
(cd "$BASE" && find . -type f -not -name 'MANIFEST.sha256' -print0 \
    | sort -z | xargs -0 sha256sum > MANIFEST.sha256)
chmod -R a-w "$BASE"
```

The directory is kept in git via `.gitkeep`; delete it once you add a real file.

## Idempotency

Re-running `make bootstrap-rootfs` is safe:

- If `MANIFEST.sha256` exists **and** `sha256sum -c` passes → skip (base intact).
- If the manifest exists but fails validation → `chmod -R u+w` the base, then
  re-extract and rebuild from scratch.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `pacman-key --init` hangs | entropy starvation (headless server) | install `haveged`/`rngd` on the host, or wait |
| `pacman -Sy` 404 | mirrorlist stale | update `vendor/mirrorlist` and re-run |
| `pacman -Sy`: `failed to chown temporary download directory ... Invalid argument` | pacman 7.x download sandbox (`DownloadUser = alpm`) chowns to an unmapped uid in userns | the script disables it (see below) |
| `pacman -Sy`: `switching to sandbox user ... failed` | pacman sandbox `setuid` fails in userns | the script disables it (see below) |
| `bwrap: No such file or directory` | bwrap not installed | `sudo pacman -S bubblewrap` |
| `Operation not permitted` on unshare | `unprivileged_userns_clone=0` | `sudo sysctl kernel.unprivileged_userns_clone=1` |
| `Disk full` | insufficient space | free ~2 GB under the data dir |
| startup: `Base rootfs not bootstrapped` | never bootstrapped | `make bootstrap-rootfs` |
| startup: `integrity check FAILED` | base drifted / corrupted | `make bootstrap-rootfs` |
| suspect silent drift (deletion / `touch -r`) | startup uses the cheap mtime fast path | re-verify with `RATTAN_VERIFY_BASE=1 make test` or run `make bootstrap-rootfs` |

> **`RATTAN_VERIFY_BASE`:** startup validates the base rootfs with a cheap
> mtime fast path by default (it misses pure deletions and mtime-preserving
> tampering). Set `RATTAN_VERIFY_BASE=1` to force the full `sha256sum -c`
> verification — e.g. when you suspect the base has silently drifted.

> **pacman sandbox in userns:** pacman ≥ 7.0 ships a download sandbox that
> `chown`s the temp download dir to `alpm` and drops privileges via
> `setuid`/`setgid`. Inside a user namespace these fail with `EINVAL`/`EPERM`
> (the uid is unmapped). `bin/bootstrap-rootfs.sh` disables it by commenting out
> `DownloadUser = alpm` and enabling `DisableSandboxFilesystem` +
> `DisableSandboxSyscalls` in the rootfs's `pacman.conf`.

## Updating the pinned release

1. Download the new `archlinux-bootstrap-x86_64.tar.zst` and
   `sha256sums.txt` from https://archlinux.org/iso/latest/.
2. Verify: `sha256sum -c sha256sums.txt --ignore-missing`.
3. Replace `vendor/archlinux-bootstrap-x86_64.tar.zst` (Git LFS).
4. Update `vendor/README.md` (release version + hash).
5. Update `vendor/mirrorlist` if needed.
6. Commit; re-run `make bootstrap-rootfs`.

## Verification

After bootstrapping:

```sh
# capability gate passes (M0)
make verify

# the rootfs is usable inside bwrap
bwrap --unshare-all --uid 0 --gid 0 --ro-bind "$HOME/.local/share/rattan/rootfs/base" / \
  --proc /proc --dev /dev -- /usr/bin/ls /
```
This should print an Arch rootfs layout (`usr/`, `etc/`, `var/`, `bin -> usr/bin`).
