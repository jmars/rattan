/* mounttest.c — probe: calls mount(2) syscall, reports rc + errno.
 *
 * Used by stage3 tests to verify that seccomp denies mount when
 * the pledge set does not include it.
 *
 * Expected: blocked (EPERM) under stage3, fails with other error
 * when run standalone (EINVAL/EACCES for invalid args).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_mount
#define __NR_mount 165
#endif

int main(void) {
    long rc = syscall(__NR_mount, "none", "/nonexistent", "tmpfs", 0, NULL);
    int e = errno;
    printf("mount rc=%ld errno=%d (%s)\n", rc, e, strerror(e));
    return (rc < 0) ? 1 : 0;
}
