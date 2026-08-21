#!/usr/bin/env bash
#
# verify.sh — the full rattan gate (M5.6):
#   1. capability probe + startup gate (--probe)
#   2. bwrap launch sanity
#   3. landlock + seccomp assert (stage3 --verify)
#   4. overlay assert (bwrap mounts the base overlay)
#   5. smoke shell_run("ls /")
#
# Exits non-zero on any failure.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV_PY="$REPO_ROOT/.venv/bin/python"
export PYTHONPATH="$REPO_ROOT/src"

say() { printf '\033[32m[verify]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[verify] FAILED: %s\033[0m\n' "$*"; exit 1; }

# 1. Capability probe + startup gate
say "1/5 capability probe"
"$VENV_PY" -m palisade --probe >/dev/null 2>&1 \
    || fail "capability probe (make verify prereq) failed"
say "   ok"

# 2. bwrap launch sanity
say "2/5 bwrap launch"
bwrap --unshare-all --uid 1000 --gid 1000 --ro-bind / / -- /bin/true \
    || fail "bwrap cannot launch"
say "   ok"

# 3. Landlock + seccomp assert via stage3 --verify
say "3/5 stage3 --verify (landlock + seccomp + no_new_privs)"
STAGE3="$REPO_ROOT/bin/stage3"
[ -x "$STAGE3" ] || fail "bin/stage3 not built — run 'make stage3'"
out="$("$STAGE3" "stdio rpath exec" --verify)" \
    || fail "stage3 --verify exited non-zero"
echo "$out" | grep -q "VERIFY OK" \
    || fail "stage3 --verify did not report VERIFY OK"
echo "$out" | grep -q "Seccomp:	2" \
    || fail "stage3 Seccomp not 2 (filter)"
echo "$out" | grep -q "Landlock: enforced" \
    || fail "stage3 Landlock not enforced"
say "   ok"

# 4. Overlay assert: bwrap mounts the base rootfs overlay at /
say "4/5 overlay mount"
BASE="${RATTAN_DATA_DIR:-$HOME/.local/share/rattan}/rootfs/base"
[ -d "$BASE" ] || fail "base rootfs not bootstrapped — run 'make bootstrap-rootfs'"
D=$(mktemp -d /tmp/rattan-verify.XXXX)
mkdir -p "$D/upper/workspace" "$D/work"
bwrap --unshare-all --uid 1000 --gid 1000 \
    --overlay-src "$BASE" --overlay "$D/upper" "$D/work" / \
    --proc /proc --dev /dev --tmpfs /tmp \
    -- /usr/bin/test -d /usr/bin \
    || { rm -rf "$D"; fail "overlay mount at / did not expose base /usr/bin"; }
rm -rf "$D"
say "   ok"

# 5. Smoke: shell_run("ls /") returns an Arch rootfs
say "5/5 shell_run('ls /') smoke"
smoke="$("$VENV_PY" -c '
import os, tempfile
from unittest import mock
from palisade import config, sessions, layers
tmp = tempfile.mkdtemp(prefix="rattan-verify-")
with mock.patch.object(config, "data_dir", return_value=tmp), \
     mock.patch.object(config, "layers_dir", lambda: os.path.join(tmp,"layers")), \
     mock.patch.object(config, "sessions_dir", lambda: os.path.join(tmp,"sessions")), \
     mock.patch.object(config, "index_lock_path", lambda: os.path.join(tmp,"layers","index.lock")), \
     mock.patch.object(config, "base_rootfs_path", lambda: os.path.join(os.environ.get("RATTAN_DATA_DIR", os.path.join(os.environ["HOME"],".local","share","rattan")), "rootfs", "base")):
    from palisade.executor import execute_program
    from palisade.parser import parse
    s = sessions.get_or_create(sid="verify")
    from palisade.overlay import provision; provision(s)
    env = {"HOME":"/workspace","PATH":"/usr/bin:/bin","USER":"rattan","TERM":"dumb","LANG":"C.UTF-8"}
    r = execute_program(parse("ls /"), s, env, "/workspace", 30)
    if r["rc"] != 0: raise SystemExit(1)
    out = r["output"]
    assert "usr" in out and "etc" in out, out
    layers.destroy(s)
import shutil; shutil.rmtree(tmp, ignore_errors=True)
print("ok")
' 2>&1)" || fail "shell_run('ls /') smoke failed"
echo "$smoke" | tail -1
say "ALL CHECKS PASSED"
