/* keytest.c — probe: calls keyctl(2) syscall, reports rc + errno.
 *
 * Used by stage3 tests to verify that seccomp denies the keyctl syscall
 * when the pledge set does not include it.
 *
 * Expected: blocked (EPERM or killed) under stage3, succeeds or fails
 * with non-EPERM errno when run standalone.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>

#ifndef __NR_keyctl
#define __NR_keyctl 250
#endif

int main(void) {
    long rc = syscall(__NR_keyctl, 0, 0, 0, 0);
    int e = errno;
    printf("keyctl rc=%ld errno=%d (%s)\n", rc, e, strerror(e));
    return (rc < 0) ? 1 : 0;
}
