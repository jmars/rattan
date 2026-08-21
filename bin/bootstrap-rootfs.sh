#!/usr/bin/env bash
#
# bootstrap-rootfs.sh — bootstrap the immutable Arch base rootfs.
#
# Idempotent. Re-running is safe: it skips if <base>/MANIFEST.sha256 exists and
# validates; if the manifest is present but invalid (base drifted), it
# re-bootstraps from scratch.
#
# Steps:
#   1. extract vendor/archlinux-bootstrap-x86_64.tar.zst into
#      <data-dir>/rootfs/base (stripping the root.x86_64/ prefix)
#   2. install the pinned vendor/mirrorlist
#   3. enter via bwrap: pacman-key --init + --populate archlinux
#   4. pacman -Sy; pacman -S --needed base
#   5. chmod -R a-w <base> (immutability)
#   6. write MANIFEST.sha256
#
# Prerequisites: kernel >= 6.2, kernel.unprivileged_userns_clone=1, bwrap,
# zstd, and internet access. See docs/bootstrap.md.
set -euo pipefail

# === Configuration (paths relative to repo root) =============================
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DATA_DIR="${RATTAN_DATA_DIR:-$HOME/.local/share/rattan}"
BASE="${DATA_DIR}/rootfs/base"
TARBALL="${REPO_ROOT}/vendor/archlinux-bootstrap-x86_64.tar.zst"
MIRRORLIST_SRC="${REPO_ROOT}/vendor/mirrorlist"
MANIFEST="${BASE}/MANIFEST.sha256"

# === Helpers =================================================================
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
green() { printf '\033[32m%s\033[0m\n' "$*"; }
die()   { red "ERROR: $*"; exit 1; }

# === Personal rootfs config (external, optional) =============================
# A user may extend the base rootfs without modifying the repo (so rattan's
# main branch stays generic and needs no personal fork). Point RATTAN_ROOTFS_CONFIG
# at a shell file that may set:
#   ROOTFS_EXTRA_PACKAGES   — extra pacman packages (space-separated), installed
#                             alongside `base` (e.g. "base-devel git musl mcpp").
#   ROOTFS_EXTRA_DIRS       — extra directories copied verbatim into the base
#                             rootfs, in addition to vendor/rootfs-extra (e.g. a
#                             dir holding a prebuilt binary under usr/local/bin).
# Defaults to $HOME/.config/rattan/rootfs.env. The file is sourced; keep it
# trusted (it runs on your own host when you bootstrap).
ROOTFS_CONFIG="${RATTAN_ROOTFS_CONFIG:-$HOME/.config/rattan/rootfs.env}"
if [ -f "$ROOTFS_CONFIG" ]; then
    # shellcheck disable=SC1090
    . "$ROOTFS_CONFIG"
    green "Loaded rootfs config: $ROOTFS_CONFIG"
else
    green "No rootfs config at $ROOTFS_CONFIG; using defaults."
fi
ROOTFS_EXTRA_PACKAGES="${ROOTFS_EXTRA_PACKAGES:-}"
ROOTFS_EXTRA_DIRS="${ROOTFS_EXTRA_DIRS:-}"
# Baseline packages: always `base`, plus any configured extras.
INSTALL_PACKAGES="base ${ROOTFS_EXTRA_PACKAGES}"
INSTALL_PACKAGES="${INSTALL_PACKAGES%"${INSTALL_PACKAGES##*[![:space:]]}"}"  # trim trailing ws

# === Preflight ===============================================================
command -v bwrap >/dev/null 2>&1 || die "bwrap not found. Install: sudo pacman -S bubblewrap"
command -v zstd  >/dev/null 2>&1 || die "zstd not found. Install: sudo pacman -S zstd"
[ -f "$TARBALL" ]        || die "tarball not found: $TARBALL"
[ -f "$MIRRORLIST_SRC" ] || die "mirrorlist not found: $MIRRORLIST_SRC"

# === Idempotency check =======================================================
if [ -f "$MANIFEST" ]; then
    if (cd "$BASE" && sha256sum -c "$MANIFEST" --status 2>/dev/null); then
        green "Base rootfs already bootstrapped and manifest is valid. Skipping."
        exit 0
    fi
    green "Manifest exists but is invalid — re-bootstrapping..."
    chmod -R u+w "$BASE" 2>/dev/null || true
fi

# === Extract tarball =========================================================
green "Extracting bootstrap tarball (this may take a minute)..."
rm -rf "$BASE"
mkdir -p "$BASE"
if command -v bsdtar >/dev/null 2>&1; then
    # Strip the root.x86_64/ prefix while extracting.
    zstd -d -c "$TARBALL" | bsdtar -xf - --strip-components=1 -C "$BASE" \
        || die "Extraction failed."
else
    zstd -d -c "$TARBALL" | tar -x --strip-components=1 --warning=no-unknown-keyword -C "$BASE" \
        || die "Extraction failed."
fi
# Sanity: the extracted tree must have usr/bin/bash and usr/bin/pacman.
[ -x "$BASE/usr/bin/bash" ]  || die "extract produced no usr/bin/bash (broken tarball?)"
[ -x "$BASE/usr/bin/pacman" ] || die "extract produced no usr/bin/pacman (broken tarball?)"

# === Install pinned mirrorlist ===============================================
cp "$MIRRORLIST_SRC" "$BASE/etc/pacman.d/mirrorlist"

# === Ensure key directories exist ============================================
mkdir -p "$BASE/var/lib/pacman" "$BASE/var/cache/pacman/pkg"

# === Disable pacman sandbox (breaks in userns) ==============================
# pacman 7.x ships a download sandbox that chowns the temp download dir to
# `alpm` and drops privileges via setuid/setgid. Inside a user namespace the
# uid is unmapped and the chown/setuid fails with EINVAL/EPERM. Disable it so
# pacman runs as root-in-userns directly.
sed -i 's/^DownloadUser = alpm/#DownloadUser = alpm/' "$BASE/etc/pacman.conf"
sed -i 's/^#DisableSandboxFilesystem/DisableSandboxFilesystem/' "$BASE/etc/pacman.conf"
sed -i 's/^#DisableSandboxSyscalls/DisableSandboxSyscalls/' "$BASE/etc/pacman.conf"

# === bwrap: pacman-key init + populate + pacman -Sy + -S base ================
green "Initializing pacman keyring and installing base inside bwrap..."
bwrap \
    --unshare-all \
    --share-net \
    --uid 0 --gid 0 \
    --bind "$BASE" / \
    --proc /proc \
    --dev /dev \
    --tmpfs /tmp \
    --ro-bind /etc/resolv.conf /etc/resolv.conf \
    -- /usr/bin/bash -c '
        set -euo pipefail
        echo "→ pacman-key --init"
        pacman-key --init
        echo "→ pacman-key --populate archlinux"
        pacman-key --populate archlinux
        echo "→ pacman -Sy (refresh package databases)"
        pacman -Sy --noconfirm
        echo "→ pacman -S --needed'"${INSTALL_PACKAGES:+ $INSTALL_PACKAGES}"' (install baseline packages)"
        pacman -S --needed --noconfirm '"${INSTALL_PACKAGES}"'
        echo "→ Bootstrap install complete."
    ' || die "bwrap bootstrap failed."

# === Add the sandbox user (uid 1000) =========================================
# Agent commands run as uid/gid 1000 inside a user namespace. The Arch base
# rootfs ships no account with that uid, so `whoami`/`id`/`getpwuid` fail with
# "cannot find name for user ID 1000". Add a `user` account (home /workspace,
# shell bash) and a matching group so identity lookups work. Append (do not
# overwrite) so the base package accounts are preserved.
if ! grep -q '^user:' "$BASE/etc/passwd"; then
    printf 'user:x:1000:1000:rattan sandbox user:/workspace:/usr/bin/bash\n' \
        >> "$BASE/etc/passwd"
fi
if ! grep -q '^user:' "$BASE/etc/group"; then
    printf 'user:x:1000:\n' >> "$BASE/etc/group"
fi

# === Install custom non-pacman files (vendor/rootfs-extra + config dirs) ======
# Any tree under vendor/rootfs-extra is copied verbatim into the base rootfs.
# Place static artifacts (e.g. a prebuilt binary under usr/local/bin) here so
# they are baked into the immutable base and present in every session. This must
# run BEFORE the manifest is written so the extra files are integrity-checked
# too, and before `chmod -R a-w` so they are locked read-only like the rest.
# Additional directories from the external config (ROOTFS_EXTRA_DIRS) are copied
# the same way, so personal prebuilt binaries can be added without forking the
# repo.
ROOTFS_EXTRA="${REPO_ROOT}/vendor/rootfs-extra"
# The base root dir may be left non-writable by the pacman step; the extra-file
# copy creates entries at the root, so ensure it is writable first.
chmod u+w "$BASE" 2>/dev/null || true
copy_rootfs_dir() {
    local src="$1"
    if [ -d "$src" ] && [ -n "$(find "$src" -mindepth 1 -print -quit)" ]; then
        green "Installing custom rootfs files from $src"
        cp -a "$src/." "$BASE/"
    fi
}
copy_rootfs_dir "$ROOTFS_EXTRA"
for extra_dir in $ROOTFS_EXTRA_DIRS; do
    # shellcheck disable=SC2086
    copy_rootfs_dir "$(eval echo "$extra_dir")"
done

# === Write manifest (BEFORE making base read-only) ===========================
green "Writing MANIFEST.sha256..."
# Ensure every file/dir is readable by the owner so find/sha256sum can traverse
# it. The Arch tarball ships some paths with mode 000 (e.g. the tpm2-tss
# keystore) that would otherwise block the manifest walk.
chmod -R u+rX "$BASE"
(
    cd "$BASE"
    find . -type f -not -name 'MANIFEST.sha256' -print0 \
        | sort -z \
        | xargs -0 sha256sum \
        > "$MANIFEST"
)

# === Immutability ============================================================
green "Making base rootfs read-only (chmod -R a-w)..."
chmod -R a-w "$BASE"

green "Bootstrap complete. Base rootfs at: $BASE"
green "Manifest at: $MANIFEST"
