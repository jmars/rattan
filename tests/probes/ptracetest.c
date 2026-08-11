/* ptracetest.c — probe: calls ptrace(2) syscall, reports rc + errno.
 *
 * Used by stage3 tests to verify that seccomp denies ptrace when
 * the pledge set does not include it (and RATTAN_ALLOW_PTRACE is not set).
 *
 * Expected: blocked (EPERM) under stage3, succeeds/fails with other
 * error when run standalone.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>

#ifndef __NR_ptrace
#define __NR_ptrace 101
#endif

int main(void) {
    /* PTRACE_TRACEME = 0 — attach to self, which ptrace must allow or deny */
    long rc = syscall(__NR_ptrace, PTRACE_TRACEME, 0, 0, 0);
    int e = errno;
    printf("ptrace rc=%ld errno=%d (%s)\n", rc, e, strerror(e));
    return (rc < 0) ? 1 : 0;
}
