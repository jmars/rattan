"""Host capability probe for rattan.

Dependency-light: stdlib only (no ``mcp`` import), so the ``--probe`` CLI can run
even where the MCP stack is not installed.

Each probe is a separate, mockable function returning a :class:`Capability`.
``probe_all()`` returns a :class:`CapabilityTable`; ``get_capabilities`` reads or
builds a cached copy consumed by ``env_status`` and the startup gate.
"""

from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass

from rattan import config

# ---------------------------------------------------------------------------
# Remediation strings (shown when a required capability is missing).
# ---------------------------------------------------------------------------

_REMEDIATION = {
    "kernel_version": "This sandbox needs Linux >= 6.2. Upgrade the host kernel.",
    "userns_enabled": (
        "Enable unprivileged user namespaces: "
        "sudo sysctl kernel.unprivileged_userns_clone=1"
    ),
    "landlock_present": (
        "Enable the Landlock LSM: add lsm=landlock to the kernel command line."
    ),
    "bwrap_version": "Install bubblewrap: sudo pacman -S bubblewrap",
    "landlock_abi": "",
    "overlay_in_userns": "",
    "reflink_support": (
        "Reflink is optional; commits fall back to rsync on non-btrfs/xfs "
        "filesystems."
    ),
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class Capability:
    """A single probe result."""

    name: str
    available: bool
    detail: str = ""
    required: bool = False
    remediation: str = ""


class CapabilityTable:
    """Ordered collection of probe results keyed by capability name."""

    def __init__(self, capabilities):
        self._caps = dict(capabilities)

    def get(self, name):
        return self._caps.get(name)

    def __iter__(self):
        return iter(self._caps.values())

    def __len__(self):
        return len(self._caps)

    def __contains__(self, name):
        return name in self._caps

    def to_dict(self):
        return {name: asdict(cap) for name, cap in self._caps.items()}

    def missing_required(self):
        """List of required capabilities that are not currently available."""
        return [c for c in self._caps.values() if c.required and not c.available]


def assert_required_present(table):
    """Raise a RuntimeError listing every missing required capability."""
    missing = table.missing_required()
    if not missing:
        return
    lines = ["Refusing to start: missing required capabilities:"]
    for c in missing:
        rem = f" {c.remediation}" if c.remediation else ""
        lines.append(f"  - {c.name}: {c.detail}{rem}")
    raise RuntimeError("\n".join(lines))


# ---------------------------------------------------------------------------
# Probes (each independently mockable)
# ---------------------------------------------------------------------------


def kernel_version(version_string=None):
    """available = running kernel >= 6.2 (Landlock ABI 5)."""
    if version_string is None:
        version_string = os.uname().release
    m = re.match(r"(\d+)\.(\d+)", version_string)
    if not m:
        return Capability(
            "kernel_version",
            False,
            f"cannot parse kernel version {version_string!r}",
            required=True,
            remediation=_REMEDIATION["kernel_version"],
        )
    major, minor = int(m.group(1)), int(m.group(2))
    available = (major, minor) >= (6, 2)
    detail = f"kernel {version_string} ({'ok' if available else 'need >= 6.2'})"
    return Capability(
        "kernel_version",
        available,
        detail,
        required=True,
        remediation=_REMEDIATION["kernel_version"],
    )


_USERSN_SYSCTL = "/proc/sys/kernel/unprivileged_userns_clone"


def userns_enabled(path=_USERSN_SYSCTL):
    """available = unprivileged user namespaces are enabled.

    The canonical signal is the ``kernel.unprivileged_userns_clone`` sysctl
    (Debian/Arch). Some kernels (e.g. openSUSE's ``-default``) enable
    unprivileged userns unconditionally and expose **no** sysctl file at all.
    For those, missing file is NOT "disabled" — fall back to a live runtime
    probe (``unshare --user --map-root-user``) so a working kernel isn't
    falsely rejected by the startup gate.
    """
    try:
        with open(path) as f:
            val = f.read().strip()
    except FileNotFoundError:
        # Sysctl absent -> kernel may still allow unprivileged userns. Probe it.
        return _userns_runtime_probe(path)
    except OSError as e:
        return Capability(
            "userns_enabled",
            False,
            f"cannot read {path}: {e}",
            required=True,
            remediation=_REMEDIATION["userns_enabled"],
        )
    available = val == "1"
    detail = (
        "unprivileged userns enabled"
        if available
        else f"kernel.unprivileged_userns_clone={val!r} (want 1)"
    )
    return Capability(
        "userns_enabled",
        available,
        detail,
        required=True,
        remediation=_REMEDIATION["userns_enabled"],
    )


def _userns_runtime_probe(path):
    """Fall back to a live unprivileged-userns probe when the sysctl is absent.

    ``unshare --user --map-root-user`` requires unprivileged userns; rc==0
    proves the kernel allows it. ``unshare`` ships in util-linux.
    """
    try:
        out = subprocess.run(
            ["unshare", "--user", "--map-root-user", "true"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        return Capability(
            "userns_enabled",
            False,
            f"no {path} and 'unshare' not found; cannot confirm userns",
            required=True,
            remediation=_REMEDIATION["userns_enabled"],
        )
    except (OSError, subprocess.SubprocessError) as e:
        return Capability(
            "userns_enabled",
            False,
            f"no {path} and userns runtime probe failed: {e}",
            required=True,
            remediation=_REMEDIATION["userns_enabled"],
        )
    if out.returncode == 0:
        return Capability(
            "userns_enabled",
            True,
            f"{path} absent; unprivileged userns confirmed via unshare probe",
            required=True,
            remediation=_REMEDIATION["userns_enabled"],
        )
    return Capability(
        "userns_enabled",
        False,
        f"no {path} and unshare probe failed (rc={out.returncode}): {out.stderr.strip()[:120]}",
        required=True,
        remediation=_REMEDIATION["userns_enabled"],
    )


_LSM_FILE = "/sys/kernel/security/lsm"


def landlock_present(path=_LSM_FILE):
    """available = 'landlock' appears in the active LSM stack."""
    try:
        with open(path) as f:
            content = f.read()
    except OSError as e:
        return Capability(
            "landlock_present",
            False,
            f"cannot read {path}: {e}",
            required=True,
            remediation=_REMEDIATION["landlock_present"],
        )
    lsms = [x.strip() for x in re.split(r"[\n,]", content) if x.strip()]
    available = "landlock" in lsms
    detail = (
        "Landlock LSM present"
        if available
        else f"landlock not in LSM stack: {content.strip()}"
    )
    return Capability(
        "landlock_present",
        available,
        detail,
        required=True,
        remediation=_REMEDIATION["landlock_present"],
    )


_LANDLOCK_CREATE_RULESET_SYSCALL = 444  # x86_64


def _create_ruleset_fd(handled_fs=0, handled_net=0):
    """Thin ctypes wrapper for landlock_create_ruleset(2).

    Returns a non-negative fd on success, -1 otherwise (ENOSYS / EINVAL /
    EOPNOTSUPP etc.). Never raises on a missing syscall.
    """
    libc = ctypes.CDLL(None, use_errno=True)

    class RulesetAttr(ctypes.Structure):
        _fields_ = [
            ("handled_access_fs", ctypes.c_uint64),
            ("handled_access_net", ctypes.c_uint64),
            ("scoped", ctypes.c_uint64),
        ]

    attr = RulesetAttr(handled_fs, handled_net, 0)
    fn = libc.syscall
    fn.restype = ctypes.c_long
    return fn(
        _LANDLOCK_CREATE_RULESET_SYSCALL,
        ctypes.byref(attr),
        ctypes.sizeof(attr),
        0,
    )


def _abi_for(max_fs_bit, net_ok):
    """Best-effort ABI number from the highest accepted FS bit + NET support."""
    if max_fs_bit >= 15:  # IOCTL_DEV / scope (kernel 6.11+)
        abi = 5
    elif max_fs_bit >= 14:  # TRUNCATE (kernel 6.2) -> ABI 3
        abi = 3
    elif max_fs_bit >= 13:  # REFER (kernel 5.19) -> ABI 2
        abi = 2
    elif max_fs_bit >= 0:  # kernel 5.13 -> ABI 1
        abi = 1
    else:
        abi = 0
    if net_ok:  # NET bind/connect (kernel 6.10) -> ABI 4
        abi = max(abi, 4)
    return abi


def _close(fd):
    try:
        os.close(fd)
    except OSError:
        pass


def landlock_abi():
    """Report the Landlock ABI and which access sets (FS/NET) are handled."""
    try:
        max_fs_bit = -1
        for bit in range(17, -1, -1):
            fd = _create_ruleset_fd(handled_fs=1 << bit)
            if fd >= 0:
                max_fs_bit = bit
                _close(fd)
                break
        net_fd = _create_ruleset_fd(handled_net=1 << 0)
        net_ok = net_fd >= 0
        if net_fd >= 0:
            _close(net_fd)
        abi = _abi_for(max_fs_bit, net_ok)
        sets = []
        if max_fs_bit >= 0:
            sets.append("FS")
        if net_ok:
            sets.append("NET")
        handled = ", ".join(sets) if sets else "none"
        detail = f"Landlock ABI {abi}; access sets handled: {handled}"
        return Capability(
            "landlock_abi",
            abi > 0,
            detail,
            required=False,
            remediation=_REMEDIATION["landlock_abi"],
        )
    except Exception as e:  # noqa: BLE001 - probe must never crash
        return Capability(
            "landlock_abi",
            False,
            f"probe failed: {e}",
            required=False,
            remediation=_REMEDIATION["landlock_abi"],
        )


def bwrap_version():
    """available = bubblewrap is installed and its version parses."""
    try:
        out = subprocess.run(
            ["bwrap", "--version"], capture_output=True, text=True, timeout=10
        )
    except (OSError, subprocess.SubprocessError) as e:
        return Capability(
            "bwrap_version",
            False,
            f"bwrap not runnable: {e}",
            required=True,
            remediation=_REMEDIATION["bwrap_version"],
        )
    text = (out.stdout or "") + "\n" + (out.stderr or "")
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", text)
    if out.returncode != 0 or not m:
        return Capability(
            "bwrap_version",
            False,
            f"bwrap --version returned rc={out.returncode}: {text.strip()[:120]}",
            required=True,
            remediation=_REMEDIATION["bwrap_version"],
        )
    return Capability(
        "bwrap_version",
        True,
        f"bwrap {m.group(1)}",
        required=True,
        remediation=_REMEDIATION["bwrap_version"],
    )


def overlay_in_userns():
    """Best-effort overlay-in-userns support probe.

    If bwrap is present, attempt a real throwaway overlay mount through it;
    otherwise fall back to checking /proc/filesystems. Never crashes: any failure
    is reported as unavailable with an explanatory detail.
    """
    if shutil.which("bwrap"):
        try:
            with tempfile.TemporaryDirectory(prefix="rattan-overlay-") as td:
                low = os.path.join(td, "low")
                up = os.path.join(td, "up")
                work = os.path.join(td, "work")
                for p in (low, up, work):
                    os.makedirs(p, exist_ok=True)
                # bwrap --overlay-src / --overlay take HOST paths for the
                # lower/upper/work dirs; only DEST is a sandbox path. Bind the
                # whole root RO (like agent mode) so /bin exists, put the overlay
                # mountpoint under a writable tmpfs, and exec a shell that writes
                # through the overlay to prove the upperdir is writable+persistent.
                cmd = [
                    "bwrap",
                    "--unshare-all",
                    "--uid", "0",
                    "--gid", "0",
                    "--ro-bind", "/", "/",
                    "--tmpfs", "/tmp",
                    "--dir", "/tmp/dst",
                    "--overlay-src", low,
                    "--overlay", up, work, "/tmp/dst",
                    "--", "/bin/sh", "-c",
                    f"echo probe > /tmp/dst/.rattan-probe && cat /tmp/dst/.rattan-probe",
                ]
                r = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=10
                )
                if r.returncode == 0:
                    return Capability(
                        "overlay_in_userns",
                        True,
                        "overlay mounted in userns via bwrap",
                        required=False,
                    )
                detail = (
                    "overlay mount via bwrap failed "
                    f"(rc={r.returncode}): {r.stderr.strip()[:200]}"
                )
        except subprocess.TimeoutExpired:
            detail = "overlay probe timed out (10s)"
        except Exception as e:  # noqa: BLE001 - probe must never crash
            detail = f"probe failed: {e}"
    else:
        try:
            with open("/proc/filesystems") as f:
                content = f.read()
            if "overlay" in content.split():
                return Capability(
                    "overlay_in_userns",
                    True,
                    "overlay listed in /proc/filesystems",
                    required=False,
                )
            detail = "overlay not listed in /proc/filesystems"
        except OSError as e:
            detail = f"probe failed: {e}"
    return Capability("overlay_in_userns", False, detail, required=False)


def _unescape(s):
    return (
        s.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


def _fs_type(path):
    """Return the filesystem type string for the filesystem holding ``path``."""
    # Fast path: Python 3.13+ exposes st_fstype on os.statvfs.
    try:
        st = os.statvfs(path)
        fst = getattr(st, "st_fstype", None)
        if fst:
            return fst
    except (OSError, AttributeError):
        pass
    # Reliable stdlib fallback: longest mount prefix in /proc/mounts.
    real = os.path.realpath(path)
    best, best_len = None, -1
    try:
        with open("/proc/mounts") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 3:
                    continue
                mnt, fstype = _unescape(parts[1]), parts[2]
                base = mnt.rstrip("/") or "/"
                if real == base or real.startswith(base + "/"):
                    if len(base) > best_len:
                        best, best_len = fstype, len(base)
    except OSError:
        pass
    if best:
        return best
    try:
        out = subprocess.run(
            ["stat", "-f", "-c", "%T", path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if out.returncode == 0 and out.stdout.strip():
            return out.stdout.strip()
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


def classify_reflink(fs_type):
    """Reusable classification: reflink is available on btrfs/xfs."""
    return fs_type in {"btrfs", "xfs"}


def reflink_support(path=None):
    """available = data filesystem supports reflink (btrfs/xfs). Optional."""
    path = path or os.getcwd()
    p = path
    while not os.path.exists(p):
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    fs = _fs_type(p)
    available = classify_reflink(fs)
    detail = f"filesystem type: {fs}"
    return Capability(
        "reflink_support",
        available,
        detail,
        required=False,
        remediation=_REMEDIATION["reflink_support"],
    )


# ---------------------------------------------------------------------------
# Aggregation + caching
# ---------------------------------------------------------------------------


def probe_all():
    """Run every probe and return a :class:`CapabilityTable`."""
    caps = {
        "kernel_version": kernel_version(),
        "userns_enabled": userns_enabled(),
        "landlock_present": landlock_present(),
        "landlock_abi": landlock_abi(),
        "bwrap_version": bwrap_version(),
        "overlay_in_userns": overlay_in_userns(),
        "reflink_support": reflink_support(config.data_dir()),
    }
    return CapabilityTable(caps)


def load_cache(cache_path=None):
    """Load a previously saved capability table, or None if unreadable."""
    cache_path = cache_path or config.cache_path()
    try:
        with open(cache_path) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    caps = {}
    for name, d in data.items():
        try:
            caps[name] = Capability(**d)
        except TypeError:
            return None
    return CapabilityTable(caps)


def save_cache(table, cache_path=None):
    """Best-effort JSON persistence of a capability table. Never raises."""
    cache_path = cache_path or config.cache_path()
    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
        with open(cache_path, "w") as f:
            json.dump(table.to_dict(), f, indent=2)
        return True
    except OSError:
        return False


def get_capabilities(refresh=False, cache_path=None):
    """Return a capability table, reusing a fresh cache entry when possible.

    When ``refresh`` is False and a cache file exists whose mtime is younger than
    ``config.CACHE_TTL``, the cached table is returned; otherwise the host is
    probed fresh and the result cached.
    """
    if not refresh:
        cache_path = cache_path or config.cache_path()
        if os.path.exists(cache_path):
            try:
                age = time.time() - os.path.getmtime(cache_path)
            except OSError:
                age = float("inf")
            if age < config.CACHE_TTL:
                cached = load_cache(cache_path)
                if cached is not None:
                    return cached
    table = probe_all()
    save_cache(table, cache_path)
    return table


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _format_table(table):
    lines = [
        f"{'Capability':<20} {'Status':<8} {'Required':<9} Detail",
        "-" * 80,
    ]
    for cap in table:
        status = "OK" if cap.available else "MISSING"
        req = "required" if cap.required else "optional"
        lines.append(f"{cap.name:<20} {status:<8} {req:<9} {cap.detail}")
    return "\n".join(lines)


def cli_main(argv=None):
    """Run the probe + gate and print a human-readable table.

    Returns 0 if all required capabilities are present, non-zero otherwise.
    """
    args = list(sys.argv[1:] if argv is None else argv)
    refresh = "--refresh" in args
    table = get_capabilities(refresh=refresh)
    print(_format_table(table))
    missing = table.missing_required()
    if missing:
        print("\nMISSING REQUIRED CAPABILITIES:", file=sys.stderr)
        for c in missing:
            rem = f" {c.remediation}" if c.remediation else ""
            print(f"  - {c.name}: {c.detail}{rem}", file=sys.stderr)
        return 1
    print("\nAll required capabilities present.")
    return 0
