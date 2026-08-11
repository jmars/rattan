# Rattan — vendored bootstrap artifacts

## archlinux-bootstrap-x86_64.tar.zst

- **Release:** 2026.08.01
- **Source:** https://archlinux.org/iso/latest/
- **SHA256:** `9600cef264af08899eff8f8b9bb2dd141c748a0038b651256d335e489a8dd2f6`
- **Verified against:** `sha256sums.txt` from the official release page.
- **Storage:** Git LFS (pointer in repo, blob in `.git/lfs/objects`).

This is the official Arch Linux bootstrap rootfs. It contains a minimal set of
packages including `pacman`, `pacman-key`, `archlinux-keyring`, `glibc`, `bash`,
and `coreutils`. The internal prefix `root.x86_64/` is stripped during
extraction by `bin/bootstrap-rootfs.sh`.

## mirrorlist

Pinned HTTPS mirror list used during bootstrap. Matched to the 2026.08.01
release snapshot. Never used for runtime provisioning (M4 uses its own
validated mirror list).

## Updating

1. Download the new `archlinux-bootstrap-x86_64.tar.zst` and its
   `sha256sums.txt` from https://archlinux.org/iso/latest/.
2. Verify: `sha256sum -c sha256sums.txt --ignore-missing`.
3. Replace `vendor/archlinux-bootstrap-x86_64.tar.zst`.
4. Update this README with the new release version + hash.
5. Update `vendor/mirrorlist` if the mirror landscape changed.
6. Commit; re-run `make bootstrap-rootfs`.
