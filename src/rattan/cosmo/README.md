# Vendored cosmocc pledge

This directory contains a vendored copy of the Cosmopolitan Libc `pledge()`
seccomp filter builder, with a single rattan patch.

## Files

- **`pledge-linux.c`** — upstream `libc/calls/pledge-linux.c`
  (Copyright 2022 Justine Alexandra Roberts Tunney, MIT/ISC permissive; see
  its header). Copied verbatim from the Cosmopolitan repo, with one patch: the
  read-only xattr syscalls (`getxattr`, `lgetxattr`, `fgetxattr`, `listxattr`,
  `llistxattr`, `flistxattr`) added to `kPledgeRpath`.
- **`pledge-rattan.c`** — a thin wrapper that supplies the cosmocc-internal
  macros/headers (`_COSMO_SOURCE`, `__privileged`, `notpossible`, …) so
  `pledge-linux.c` can be compiled standalone, and `#include`s it.

## Why

cosmocc's `pledge()` emits a single seccomp BPF filter whose 23-token
allowlist includes **no** xattr syscall. coreutils `ls -l` / `id` call
`llistxattr`/`listxattr`/`getxattr` to detect ACLs and security labels.
Because seccomp returns the most-restrictive action across all filters, an
extra allow-filter cannot be layered on top of pledge — the filter itself must
allow them. We vendor the builder, add the read-only xattr queries to `rpath`,
and link it into stage3 before the cosmocc libc so the linker uses our
`sys_pledge_linux`/`kPledge` instead of the precompiled ones.

The patch is additive and read-only (metadata queries equivalent to the
`stat`/`readdir` already allowed by `rpath`); it widens no sandbox surface.

## Keeping it fresh

To re-sync with upstream:

```sh
curl -sL -o pledge-linux.c \
  https://raw.githubusercontent.com/jart/cosmopolitan/master/libc/calls/pledge-linux.c
# re-apply the xattr block in kPledgeRpath
```
