/* stage3.c — rattan inner security binary
 *
 * Applies four hardening layers before exec'ing the user command:
 *   1. PR_SET_NO_NEW_PRIVS  (no privilege escalation — one-way door)
 *   2. Landlock              (filesystem access control, via cosmocc unveil())
 *   3. setrlimit             (resource limits)
 *   4. seccomp               (syscall whitelist, via cosmocc pledge())
 *
 * SEQUENCE: setup_nonewprivs -> apply_unveil -> apply_rlimits -> apply_pledge
 *           -> do_exec
 *
 * LANDLOCK-BEFORE-SECCOMP invariant (architecture §2, invariant #2): veil
 * (Landlock) MUST be installed before pledge (seccomp). Reverse order
 * deadlocks — the seccomp filter blocks the landlock_restrict syscall. This
 * was validated empirically with cosmocc 4.0.2: pledge() then unveil() returns
 * EPERM; unveil() then pledge() succeeds.
 *
 * DEVIATION from architecture §2 (setrlimit AFTER seccomp): rlimits are
 * applied BEFORE pledge. Reason: cosmocc's pledge blocks setrlimit (EPERM).
 * This is safe because PR_SET_NO_NEW_PRIVS is already active — after that
 * point setrlimit can only LOWER limits and cannot grant new privileges, so
 * ordering it before pledge violates no invariant.
 *
 * INVARIANT-10 delta: stage3's seccomp (via cosmocc pledge) denies keyctl,
 * add_key, request_key, ptrace, unshare, setns, mount, pivot_root, umount2,
 * reboot by default. These syscalls belong to NO pledge token in cosmocc's
 * 23-token set, so the default-deny whitelist blocks them regardless of the
 * promise string. ptrace can be opted-in per-command via RATTAN_ALLOW_PTRACE=1
 * (which skips pledge entirely — see apply_pledge).
 *
 * USAGE:
 *   stage3 PROMISES LANDLOCK_SPEC [--verify] -- cmd [args...]
 *   stage3 stdio rpath exec /tmp:rwc --verify
 *   stage3 stdio rpath exec /tmp:rwc -- /bin/echo hello
 *
 * PROMISES is a space-joined pledge token string (e.g. "stdio rpath exec").
 * LANDLOCK_SPEC is "path:perms;path:perms;..." where perms is an unveil perm
 * string (r/rw/rwc/rx...). Empty spec = no rules (still locks).
 *
 * ENVIRONMENT (all server-controlled; the user command is past "--"):
 *   RATTAN_EXTRA_PROMISES    space-joined extra pledge tokens appended to PROMISES
 *   RATTAN_RLIMITS           RESOURCE=soft:hard,RESOURCE=soft:hard,...
 *   RATTAN_ALLOW_PTRACE=1    skip seccomp entirely (for gdb / trusted tools)
 *   RATTAN_ALLOW_SETRLIMIT=1 no-op stub (reserved; TODO(M5))
 *
 * --verify MODE: runs the full layer sequence, then instead of exec prints the
 * relevant /proc/self/status lines (NoNewPrivs / Seccomp / Seccomp_filters /
 * Landlock) plus a summary, and exits 0 on success, 1 on any discrepancy.
 *
 * Compiled with cosmocc (Cosmopolitan libc 4.0.2). Uses the high-level
 * pledge()/unveil() APIs (mapped to seccomp BPF and Landlock respectively).
 * The exact BPF bytecode emitted by pledge() is cosmocc-internal and not
 * byte-audited here; behavior is validated empirically in tests/test_stage3.py.
 */

#define _COSMO_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <libc/calls/calls.h>

#define MAX_RULES 64
#define MAX_ENV 256

/* Landlock behavioral probe paths used by --verify mode. */
#define LL_VERIFY_DIR "/tmp/rattan-verify"
#define LL_VERIFY_OK  "/tmp/rattan-verify/rattan-verify-ok"
#define LL_VERIFY_NO  "/tmp/rattan-verify-sibling"

/* Default promise set applied when no PROMISES arg is given. */
/* Baseline promise set applied when no PROMISES arg is given.
 * NOTE: `prot_exec` is required — cosmocc's `exec` token permits execve() but
 * NOT mmap(PROT_EXEC)/mprotect, so without prot_exec a dynamically-linked
 * binary cannot load its shared libraries (fails with "error while loading
 * shared libraries ... failed to map segment"). */
#define BASELINE_PROMISES "stdio rpath wpath cpath flock exec prot_exec proc recvfd"

/* Known pledge tokens (cosmocc's 23-token set). Used to validate extra
 * promises defensively — a typo in RATTAN_EXTRA_PROMISES should not silently
 * grant nothing (or worse, an unintended token). */
static const char *KNOWN_TOKENS[] = {
    "stdio", "rpath", "wpath", "cpath", "dpath", "flock", "fattr", "inet",
    "unix",  "dns",   "tty",   "recvfd", "proc",  "exec",  "id",   "unveil",
    "sendfd", "settime", "prot_exec", "vminfo", "tmppath", "chown", "anet",
    NULL,
};

struct rule {
    const char *path;
    const char *perms;
};

struct stage3_config {
    const char *promises;      /* space-joined base pledge tokens (argv)  */
    const char *landlock_spec; /* "path:perms;..." (argv)                 */
    const char *extra_promises;/* RATTAN_EXTRA_PROMISES or NULL           */
    const char *rlimits;       /* RATTAN_RLIMITS or NULL                  */
    int         allow_ptrace;  /* RATTAN_ALLOW_PTRACE=1                   */
    int         allow_setrlimit; /* RATTAN_ALLOW_SETRLIMIT=1 (no-op stub) */
    int         verify_mode;   /* --verify present                         */
    char       **cmd_argv;     /* past "--"                               */
    struct rule rules[MAX_RULES];
    int         n_rules;
};

/* ---------------------------------------------------------------------------
 * Error handling: any setup-layer failure dies loudly and NEVER execs with
 * partial hardening.
 * ------------------------------------------------------------------------- */

static void die(int errnum, const char *fmt, ...) {
    va_list ap;
    fputs("stage3: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (errnum != 0)
        fprintf(stderr, ": %s", strerror(errnum));
    fputc('\n', stderr);
    _exit(1);
}

/* ---------------------------------------------------------------------------
 * Config parsing
 * ------------------------------------------------------------------------- */

static int token_in_known_set(const char *tok) {
    for (int i = 0; KNOWN_TOKENS[i]; i++)
        if (strcmp(tok, KNOWN_TOKENS[i]) == 0)
            return 1;
    return 0;
}

/* Parse LANDLOCK_SPEC "path:perms;path:perms;..." into cfg->rules[].
 * A path without ':' defaults to perms "r". Empty tokens are skipped.
 * On any malformed entry, die(). */
static void parse_landlock_spec(struct stage3_config *cfg) {
    const char *spec = cfg->landlock_spec;
    if (!spec || !*spec)
        return;
    char buf[MAX_ENV];
    if (strlen(spec) >= sizeof(buf))
        die(0, "LANDLOCK_SPEC too long");
    strcpy(buf, spec);
    char *save = NULL;
    char *entry = strtok_r(buf, ";", &save);
    while (entry) {
        if (*entry && cfg->n_rules < MAX_RULES) {
            char *colon = strchr(entry, ':');
            if (colon) {
                *colon = '\0';
                cfg->rules[cfg->n_rules].path = strdup(entry);
                cfg->rules[cfg->n_rules].perms = strdup(colon + 1);
            } else {
                cfg->rules[cfg->n_rules].path = strdup(entry);
                cfg->rules[cfg->n_rules].perms = strdup("r");
            }
            if (!cfg->rules[cfg->n_rules].path || !cfg->rules[cfg->n_rules].perms)
                die(0, "out of memory parsing LANDLOCK_SPEC");
            cfg->n_rules++;
        }
        entry = strtok_r(NULL, ";", &save);
    }
}

/* Validate + dedupe extra promise tokens. Returns a freshly allocated string
 * containing the validated tokens space-joined, or NULL if empty. dies() on an
 * unknown token or if the total is too long. */
static char *validate_extra_promises(const char *extra) {
    if (!extra || !*extra)
        return NULL;
    if (strlen(extra) > 200)
        die(0, "RATTAN_EXTRA_PROMISES too long (max 200 chars)");
    char buf[256];
    char out[256];
    if (strlen(extra) >= sizeof(buf))
        die(0, "RATTAN_EXTRA_PROMISES too long");
    strcpy(buf, extra);
    out[0] = '\0';
    char *save = NULL;
    char *tok = strtok_r(buf, " \t", &save);
    while (tok) {
        if (!token_in_known_set(tok))
            die(0, "unknown pledge token '%s' in RATTAN_EXTRA_PROMISES", tok);
        /* dedupe: skip if already present in out */
        int dup = 0;
        char *csave = NULL;
        char probe[256];
        strcpy(probe, out);
        char *p = strtok_r(probe, " \t", &csave);
        while (p) {
            if (strcmp(p, tok) == 0) { dup = 1; break; }
            p = strtok_r(NULL, " \t", &csave);
        }
        if (!dup) {
            if (out[0]) strncat(out, " ", sizeof(out) - strlen(out) - 1);
            strncat(out, tok, sizeof(out) - strlen(out) - 1);
        }
        tok = strtok_r(NULL, " \t", &save);
    }
    return out[0] ? strdup(out) : NULL;
}

static void parse_config(int argc, char **argv, struct stage3_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->promises = BASELINE_PROMISES;
    cfg->landlock_spec = "";

    /* We accept both a single quoted PROMISES arg and a space-joined PROMISES
     * passed as multiple argv words, followed by LANDLOCK_SPEC, then an
     * optional "--verify", then "--" and the user command. We scan for the
     * first "--" (user command) or "--verify" flag. Everything before it that
     * is not a flag contributes to [promises...; landlock_spec]. The LAST
     * non-flag word is LANDLOCK_SPEC; all preceding non-flag words are
     * space-joined into PROMISES. */
    int i = 1;
    /* Collect non-flag words into a temp array. */
    const char *words[64];
    int nwords = 0;
    for (; i < argc; i++) {
        if (strcmp(argv[i], "--") == 0) {
            cfg->cmd_argv = &argv[i + 1];
            break;
        }
        if (strcmp(argv[i], "--verify") == 0) {
            cfg->verify_mode = 1;
            continue;
        }
        if (nwords < 64)
            words[nwords++] = argv[i];
    }
    if (cfg->cmd_argv == NULL) {
        /* No "--" found. If --verify present, that's fine (no user command). */
        if (!cfg->verify_mode)
            die(0, "usage: stage3 PROMISES LANDLOCK_SPEC [--verify] -- cmd [args]");
    }

    /* Classify words: a token containing ':' is a LANDLOCK_SPEC entry;
     * everything else is a pledge promise token. This handles both forms:
     *   stage3 stdio rpath exec /tmp:rwc --verify      (tokens + spec entry)
     *   stage3 "stdio rpath exec" /tmp:rwc --verify    (quoted promises + spec)
     *   stage3 "stdio rpath exec" --verify             (promises, empty spec)
     * A word like "/tmp:rwc" (contains ':') goes to the spec; bare words join
     * the promise string. */
    static char promises_buf[256];
    promises_buf[0] = '\0';
    static char spec_buf[256];
    spec_buf[0] = '\0';
    for (int k = 0; k < nwords; k++) {
        if (strchr(words[k], ':')) {
            /* landlock spec fragment */
            if (spec_buf[0]) strncat(spec_buf, ";", sizeof(spec_buf) - strlen(spec_buf) - 1);
            strncat(spec_buf, words[k], sizeof(spec_buf) - strlen(spec_buf) - 1);
        } else {
            if (promises_buf[0]) strncat(promises_buf, " ", sizeof(promises_buf) - strlen(promises_buf) - 1);
            strncat(promises_buf, words[k], sizeof(promises_buf) - strlen(promises_buf) - 1);
        }
    }
    if (spec_buf[0])
        cfg->landlock_spec = spec_buf;

    /* --verify runs the binary's OWN probes (reading /proc/self/status, writing
     * to the landlock probe dirs) rather than a user command. So in verify mode
     * we use a FIXED internal config — the full baseline promise set and a
     * minimal landlock spec that unveils ONLY /proc (read) and the probe dir
     * (rwc). Using a fixed spec is what makes the landlock behavioral check
     * deterministic: the sibling path (/tmp/rattan-verify-sibling) is always
     * outside the unveiled set, so landlock must deny it. The caller's promises
     * and spec are ignored in verify mode. */
    if (cfg->verify_mode) {
        cfg->promises = BASELINE_PROMISES;
        cfg->landlock_spec = ""; /* reset; probe dirs added below */
    } else if (promises_buf[0]) {
        cfg->promises = promises_buf;
    }

    /* In verify mode, ensure the landlock behavioral probe path exists and is
     * unveiled (rwc), and that /proc is readable for the status lines. If the
     * caller's spec already covers them, this is a harmless no-op (dedupe not
     * needed — unveil with an already-covered path is fine). */
    if (cfg->verify_mode) {
        mkdir(LL_VERIFY_DIR, 0700); /* ensure the probe dir exists */
        if (cfg->n_rules < MAX_RULES) {
            cfg->rules[cfg->n_rules].path = strdup("/proc");
            cfg->rules[cfg->n_rules].perms = strdup("r");
            cfg->n_rules++;
        }
        if (cfg->n_rules < MAX_RULES) {
            cfg->rules[cfg->n_rules].path = strdup(LL_VERIFY_DIR);
            cfg->rules[cfg->n_rules].perms = strdup("rwc");
            cfg->n_rules++;
        }
    }

    /* Environment overrides. */
    const char *ep = getenv("RATTAN_EXTRA_PROMISES");
    cfg->extra_promises = validate_extra_promises(ep);
    cfg->rlimits = getenv("RATTAN_RLIMITS");
    const char *pt = getenv("RATTAN_ALLOW_PTRACE");
    cfg->allow_ptrace = pt && *pt && *pt != '0';
    const char *sr = getenv("RATTAN_ALLOW_SETRLIMIT");
    cfg->allow_setrlimit = sr && *sr && *sr != '0'; /* no-op stub (TODO M5) */

    parse_landlock_spec(cfg);
}

/* ---------------------------------------------------------------------------
 * Layer setup — each function dies() on failure and never returns except on
 * success. setup_layers() calls them strictly in order with NO early return
 * between them (structural enforcement of the ordering invariant).
 * ------------------------------------------------------------------------- */

static void setup_nonewprivs(void) {
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
        die(errno, "PR_SET_NO_NEW_PRIVS");
}

static void apply_unveil(const struct stage3_config *cfg) {
    for (int i = 0; i < cfg->n_rules; i++) {
        if (unveil(cfg->rules[i].path, cfg->rules[i].perms) < 0)
            die(errno, "unveil(%s, %s)", cfg->rules[i].path, cfg->rules[i].perms);
    }
    /* Lock: no further unveil() calls allowed. */
    if (unveil(NULL, NULL) < 0)
        die(errno, "unveil(NULL,NULL) lock");
}

static void apply_rlimits(const struct stage3_config *cfg) {
    if (!cfg->rlimits || !*cfg->rlimits)
        return;
    char buf[MAX_ENV];
    if (strlen(cfg->rlimits) >= sizeof(buf))
        die(0, "RATTAN_RLIMITS too long");
    strcpy(buf, cfg->rlimits);
    char *save = NULL;
    char *entry = strtok_r(buf, ",", &save);
    while (entry) {
        char *eq = strchr(entry, '=');
        char *colon = eq ? strchr(eq + 1, ':') : NULL;
        if (!eq || !colon)
            die(0, "malformed RATTAN_RLIMITS entry '%s' (want RES=soft:hard)", entry);
        *eq = '\0';
        *colon = '\0';
        const char *resname = entry;
        const char *soft = eq + 1;
        const char *hard = colon + 1;
        int res = -1;
        if (!strcmp(resname, "AS")) res = RLIMIT_AS;
        else if (!strcmp(resname, "CORE")) res = RLIMIT_CORE;
        else if (!strcmp(resname, "CPU")) res = RLIMIT_CPU;
        else if (!strcmp(resname, "DATA")) res = RLIMIT_DATA;
        else if (!strcmp(resname, "FSIZE")) res = RLIMIT_FSIZE;
        else if (!strcmp(resname, "LOCKS")) res = RLIMIT_LOCKS;
        else if (!strcmp(resname, "MEMLOCK")) res = RLIMIT_MEMLOCK;
        else if (!strcmp(resname, "NOFILE")) res = RLIMIT_NOFILE;
        else if (!strcmp(resname, "NPROC")) res = RLIMIT_NPROC;
        else if (!strcmp(resname, "RSS")) res = RLIMIT_RSS;
        else if (!strcmp(resname, "STACK")) res = RLIMIT_STACK;
        else die(0, "unknown rlimit resource '%s'", resname);
        struct rlimit lim;
        lim.rlim_cur = strtoull(soft, NULL, 10);
        lim.rlim_max = strtoull(hard, NULL, 10);
        if (setrlimit(res, &lim) < 0)
            die(errno, "setrlimit(%s)", resname);
        entry = strtok_r(NULL, ",", &save);
    }
}

static void apply_pledge(const struct stage3_config *cfg) {
    /* RATTAN_ALLOW_PTRACE=1: skip pledge entirely. Linux seccomp BPF filters
     * AND across fork/exec and cannot be relaxed by a child, so there is no
     * way to grant ptrace on top of pledge — the only safe way to allow ptrace
     * (for gdb) is to not install pledge at all. bwrap + Landlock + userns
     * remain active as the remaining hardening layers. */
    if (cfg->allow_ptrace) {
        fprintf(stderr, "stage3: RATTAN_ALLOW_PTRACE=1 — seccomp skipped\n");
        return;
    }

    char merged[512];
    if (cfg->extra_promises && *cfg->extra_promises)
        snprintf(merged, sizeof(merged), "%s %s", cfg->promises, cfg->extra_promises);
    else
        snprintf(merged, sizeof(merged), "%s", cfg->promises);

    if (pledge(merged, NULL) < 0)
        die(errno, "pledge(\"%s\")", merged);
}

/* setup_layers — THE ordering invariant, structurally enforced.
 *
 * The four calls below must appear in exactly this order with no early return
 * (no `return`, no `goto`) between them. Each sub-call dies() on failure, so a
 * user command is NEVER exec'd with partial hardening. This function body is
 * asserted by tests/test_stage3.py (test_no_early_return_structurally), so it
 * must not be reordered or given an early-return path.
 */
static void setup_layers(const struct stage3_config *cfg) {
    setup_nonewprivs();
    apply_unveil(cfg);
    apply_rlimits(cfg);
    apply_pledge(cfg);
}

/* ---------------------------------------------------------------------------
 * --verify mode
 * ------------------------------------------------------------------------- */

/* Print /proc/self/status lines matching the given prefix (e.g. "Seccomp").
 * Returns the numeric value parsed from the line, or -1 if absent. */
static long status_field(const char *prefix) {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f)
        die(errno, "cannot open /proc/self/status");
    char line[256];
    long val = -1;
    while (fgets(line, sizeof(line), f)) {
        size_t plen = strlen(prefix);
        if (strncmp(line, prefix, plen) == 0) {
            fputs(line, stdout);
            /* parse trailing integer */
            const char *p = line + plen;
            while (*p && (*p == ':' || *p == ' ' || *p == '\t')) p++;
            val = atol(p);
            break;
        }
    }
    fclose(f);
    return val;
}

/* Behavioral Landlock check.
 *
 * /proc/self/status has NO "Landlock:" field on kernel 7.1 (the domain count is
 * only exposed via AUDIT_LANDLOCK_DOMAIN, not the status file). So we assert
 * Landlock enforcement behaviorally, in two steps after the domain is locked:
 *   (a) write to an UNVEILED path  (/tmp/rattan-verify/ok)  -> must succeed
 *   (b) write to a NON-unveiled path on a host-writable fs (/tmp/rattan-verify-
 *       sibling) -> must fail with EACCES
 * (a) proves the unveiled path is usable; (b) proves the domain actually denies
 * paths not in the unveiled set. Because /tmp is world-writable on the host, the
 * (b) failure is due to Landlock, not host permissions. Requires the caller's
 * LANDLOCK_SPEC (or verify's default) to include /tmp/rattan-verify with rwc.
 * Returns 1 if enforced, 0 if not. */
static int landlock_enforced(void) {
    int fd = open(LL_VERIFY_OK, O_WRONLY | O_CREAT, 0600);
    int ok_errno = errno;
    int ok = fd >= 0;
    if (fd >= 0) {
        close(fd);
        unlink(LL_VERIFY_OK);
    }

    fd = open(LL_VERIFY_NO, O_WRONLY | O_CREAT, 0600);
    int denied = (fd < 0) && (errno == EACCES || errno == EPERM);
    if (fd >= 0) {
        close(fd);
        unlink(LL_VERIFY_NO);
    }

    if (!ok) {
        printf("Landlock: ambiguous (unveiled write to %s failed errno=%d %s)\n",
               LL_VERIFY_OK, ok_errno, strerror(ok_errno));
        return 0;
    }
    if (denied) {
        printf("Landlock: enforced (unveiled write ok; non-unveiled write to %s denied)\n",
               LL_VERIFY_NO);
        return 1;
    }
    printf("Landlock: not enforced (non-unveiled write to %s was allowed)\n",
           LL_VERIFY_NO);
    return 0;
}

static int run_verify(void) {
    printf("stage3: verify mode\n");
    printf("stage3: layers applied (nnprivs, unveil, rlimits, pledge) OK\n");
    long nnprivs = status_field("NoNewPrivs");
    long seccomp = status_field("Seccomp");
    long filters = status_field("Seccomp_filters");
    int landlock = landlock_enforced();

    int ok = 1;
    if (nnprivs != 1) { printf("stage3: VERIFY FAILED: NoNewPrivs expected 1, got %ld\n", nnprivs); ok = 0; }
    if (seccomp != 2) { printf("stage3: VERIFY FAILED: Seccomp expected 2 (FILTER), got %ld\n", seccomp); ok = 0; }
    if (filters < 1)  { printf("stage3: VERIFY FAILED: Seccomp_filters expected >=1, got %ld\n", filters); ok = 0; }
    if (!landlock)    { printf("stage3: VERIFY FAILED: Landlock not enforced\n"); ok = 0; }
    if (ok)
        printf("stage3: VERIFY OK\n");
    return ok ? 0 : 1;
}

/* ---------------------------------------------------------------------------
 * exec
 * ------------------------------------------------------------------------- */

static void do_exec(const struct stage3_config *cfg) {
    if (!cfg->cmd_argv || !cfg->cmd_argv[0])
        die(0, "no command to exec (missing '--')");
    execvp(cfg->cmd_argv[0], cfg->cmd_argv);
    die(errno, "execvp(%s)", cfg->cmd_argv[0]);
}

/* ---------------------------------------------------------------------------
 * main
 * ------------------------------------------------------------------------- */

int main(int argc, char **argv, char **envp) {
    (void)envp;
    struct stage3_config cfg;
    parse_config(argc, argv, &cfg);

    /* The ordering invariant, structurally enforced inside setup_layers(): no
     * early return between the four calls, each dies() on failure, so a user
     * command is NEVER exec'd with partial hardening. */
    setup_layers(&cfg);

    if (cfg.verify_mode)
        return run_verify();

    do_exec(&cfg); /* not reached */
    return 0;
}
