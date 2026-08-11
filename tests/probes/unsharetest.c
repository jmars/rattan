/* unsharetest.c — probe: calls unshare(2) syscall, reports rc + errno.
 *
 * Used by stage3 tests to verify that seccomp denies unshare when
 * the pledge set does not include it.
 *
 * Expected: blocked (EPERM) under stage3, fails with EPERM or EINVAL
 * when run standalone (unshare needs CAP_SYS_ADMIN outside userns).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sched.h>

#ifndef __NR_unshare
#define __NR_unshare 166
#endif
/* cosmocc does not define CLONE_NEWUSER in <sched.h>; provide it explicitly. */
#ifndef CLONE_NEWUSER
#define CLONE_NEWUSER 0x10000000
#endif

int main(void) {
    long rc = syscall(__NR_unshare, CLONE_NEWUSER);
    int e = errno;
    printf("unshare rc=%ld errno=%d (%s)\n", rc, e, strerror(e));
    return (rc < 0 && e != EPERM) ? 0 : 1;
}
