/* pledge-rattan.c — vendored cosmocc pledge() BPF builder, rattan-patched.
 *
 * This is a thin wrapper around the vendored `pledge-linux.c`
 * (Copyright 2022 Justine Alexandra Roberts Tunney, MIT / ISC permissive
 * license; see the license header in `pledge-linux.c`). It supplies the
 * cosmocc-internal macros and headers that the vendored file expects so it can
 * be compiled standalone as part of stage3.
 *
 * WHY VENDOR: cosmocc's `pledge()` builds a single seccomp BPF filter, and its
 * 23-token allowlist does NOT include any xattr syscall. coreutils `ls -l` /
 * `id` call `llistxattr`/`listxattr`/`getxattr` to detect ACLs and security
 * labels, and seccomp returns ERRNO (most-restrictive-across-filters), so an
 * extra allow-filter cannot be layered on top. The only way to let read-only
 * xattr queries through is to modify the pledge allowlist itself. We vendor
 * the MIT-licensed builder, add the read-only xattr syscalls to `rpath`
 * (`pledge-linux.c::kPledgeRpath`), and link this object into stage3 *before*
 * the cosmocc libc so the linker uses our `sys_pledge_linux`/`kPledge` instead
 * of the precompiled one.
 *
 * The vendored file must be compiled with `_COSMO_SOURCE` and the cosmocc
 * internal headers on the include path (provided by `cosmocc`).
 */

#define _COSMO_SOURCE
#ifndef __privileged
#define __privileged
#endif
#ifndef notpossible
#define notpossible __builtin_trap()
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <libc/sysv/consts/nrlinux.h>
#include <libc/macros.h>
#include <libc/intrin/likely.h>
#include <libc/intrin/bsr.h>
#include <libc/calls/struct/filter.internal.h>
#include <libc/calls/struct/seccomp.internal.h>
#include <libc/calls/struct/bpf.internal.h>
#include <libc/intrin/promises.h>
#include "pledge-linux.c"
