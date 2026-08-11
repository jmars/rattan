/* reverse_order_probe.c — probe: calls pledge() then unveil(), reports rc+errno.
 *
 * Empirically proves that pledge-before-unveil fails: seccomp blocks
 * the landlock syscalls needed by unveil, so unveil returns EPERM.
 *
 * Must be compiled with cosmocc (Cosmopolitan libc) which provides
 * pledge() and unveil() via <libc/calls/calls.h>.
 *
 * IMPORTANT: the pledge set here must NOT include the "unveil" token — that
 * token grants the landlock syscalls, which would make unveil succeed even
 * after pledge and defeat the test. A normal agent promise set ("stdio rpath
 * exec ...") does not include it, so unveil-after-pledge fails with EPERM.
 *
 * Expected: unveil returns -1 with errno EPERM (1). Exit code 1 on success
 * (unveil correctly denied), 0 on unexpected success.
 */

#define _COSMO_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <libc/calls/calls.h>

int main(void) {
    /* pledge WITHOUT the "unveil" token — installs a seccomp filter that
     * blocks the landlock syscalls (landlock_create_ruleset / add_rule /
     * restrict_self). */
    if (pledge("stdio rpath exec", NULL) != 0) {
        fprintf(stderr, "pledge failed: %s\n", strerror(errno));
        return 2;
    }

    /* Then, unveil — should fail because seccomp blocks Landlock syscalls */
    if (unveil("/tmp", "rwc") != 0) {
        int e = errno;
        printf("unveil-after-pledge: errno=%d (%s)\n", e, strerror(e));
        /* Expected: EPERM (1) or ENOSYS */
        return 1;
    }

    /* If unveil succeeds, lock it (shouldn't happen in correct order) */
    unveil(NULL, NULL);
    printf("unveil-after-pledge: SUCCEEDED (unexpected)\n");
    return 0;
}
