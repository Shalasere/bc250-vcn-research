#!/usr/bin/env python3
"""
CCP MEMTYPE_LOCAL Probe — Tests whether host-submitted CCP PASSTHROUGH
descriptors can target PSP SRAM (mem_type=2) on BC-250.

NON-DESTRUCTIVE: Only attempts READ from PSP SRAM. No writes to PSP SRAM.
SAFE: Worst case is a CCP error or timeout. No flash, no reboot, no brick risk.

Phases:
  1. BAR2 recon — read CCP global + queue registers
  2. DMA buffer allocation — ring + data pages via anonymous mmap + pagemap
  3. Queue init — configure an idle CCP queue
  4. System→System test — verify CCP accepts host-submitted descriptors
  5. LOCAL→System test — attempt to read PSP SRAM via MEMTYPE_LOCAL

Run: sudo python3 ccp_sram_probe.py
"""
import ctypes, ctypes.util, mmap, os, struct, sys, time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
PCI_DEV   = "0000:01:00.2"
PCI_PATH  = f"/sys/bus/pci/devices/{PCI_DEV}"
BAR2_RES  = f"{PCI_PATH}/resource2"
BAR2_SIZE = 0x100000   # 1 MB

PAGE_SIZE = 4096

# CCP global register offsets (BAR2 + 0x0000)
G_QUEUE_MASK   = 0x0000
G_QUEUE_PRIO   = 0x0004
G_REQID_CONFIG = 0x0008
G_CMD_TIMEOUT  = 0x0010
G_LSB_PUB_LO   = 0x0018
G_LSB_PUB_HI   = 0x001C
G_LSB_PRIV_LO  = 0x0020
G_LSB_PRIV_HI  = 0x0024
G_VERSION       = 0x0100
G_CONFIG_0      = 0x6000
G_TRNG_CTL      = 0x6008

# Per-queue register offsets (base = BAR2 + (qid+1)*0x1000)
Q_CONTROL    = 0x0000
Q_TAIL_LO    = 0x0004
Q_HEAD_LO    = 0x0008
Q_INT_ENABLE = 0x000C
Q_INT_STATUS = 0x0010
Q_STATUS     = 0x0100
Q_DMA_STATUS = 0x0108
Q_DMA_READ   = 0x010C
Q_DMA_WRITE  = 0x0110
Q_ABORT      = 0x0114
Q_AX_CACHE   = 0x0118

# Q_CONTROL bits
QCTL_RUN  = 0x01
QCTL_HALT = 0x02

# CCP engines / mem types
ENGINE_PASSTHRU = 5
MEMTYPE_SYSTEM  = 0
MEMTYPE_SB      = 1
MEMTYPE_LOCAL   = 2

# Descriptor ring sizing
RING_ENTRIES = 16
DESC_SIZE    = 32        # 8 dwords

# PSP SRAM
PSP_SRAM_SIZE = 0x50000  # 320 KB

# TRNG register (changes every read if PSP alive)
TRNG_OUTPUT = 0x000C

# ---------------------------------------------------------------------------
# libc helpers
# ---------------------------------------------------------------------------
_libc_name = ctypes.util.find_library("c")
_libc = ctypes.CDLL(_libc_name or "libc.so.6", use_errno=True)

MAP_PRIVATE   = 0x02
MAP_ANONYMOUS = 0x20
MAP_LOCKED    = 0x2000
MAP_POPULATE  = 0x8000
PROT_RW       = 0x01 | 0x02   # PROT_READ | PROT_WRITE

_libc.mmap.restype  = ctypes.c_void_p
_libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t,
                       ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_long]
_libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
_libc.memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]


def _alloc_locked_page():
    """Allocate one locked+populated anonymous page via libc mmap.
    Returns (ctypes void pointer, int vaddr)."""
    flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED | MAP_POPULATE
    ptr = _libc.mmap(None, PAGE_SIZE, PROT_RW, flags, -1, 0)
    if ptr == ctypes.c_void_p(-1).value or ptr is None:
        raise OSError(f"mmap failed: {os.strerror(ctypes.get_errno())}")
    # touch every cache line to guarantee residency
    arr = (ctypes.c_char * PAGE_SIZE).from_address(ptr)
    for i in range(0, PAGE_SIZE, 64):
        arr[i] = b'\x00'
    return ptr


def _virt_to_phys(vaddr):
    """Translate virtual address → physical via /proc/self/pagemap (root)."""
    fd = os.open("/proc/self/pagemap", os.O_RDONLY)
    try:
        os.lseek(fd, (vaddr // PAGE_SIZE) * 8, os.SEEK_SET)
        entry = struct.unpack("Q", os.read(fd, 8))[0]
    finally:
        os.close(fd)
    if not (entry & (1 << 63)):
        raise RuntimeError(f"Page not present for vaddr 0x{vaddr:x}")
    pfn = entry & ((1 << 55) - 1)
    if pfn == 0:
        raise RuntimeError("PFN=0 — pagemap may need CAP_SYS_ADMIN")
    return pfn * PAGE_SIZE + (vaddr % PAGE_SIZE)


def _read_page(ptr, offset, length):
    """Read bytes from a ctypes page pointer."""
    buf = (ctypes.c_char * length).from_address(ptr + offset)
    return bytes(buf)


def _write_page(ptr, offset, data):
    """Write bytes to a ctypes page pointer."""
    buf = (ctypes.c_char * len(data)).from_address(ptr + offset)
    ctypes.memmove(buf, data, len(data))


def _fill_page(ptr, byte_val, length=PAGE_SIZE):
    """Fill a page with a single byte value."""
    _libc.memset(ctypes.c_void_p(ptr), byte_val, length)

# ---------------------------------------------------------------------------
# BAR2 MMIO helpers
# ---------------------------------------------------------------------------
_bar2_mm = None

def _open_bar2():
    global _bar2_mm
    fd = os.open(BAR2_RES, os.O_RDWR | os.O_SYNC)
    _bar2_mm = mmap.mmap(fd, BAR2_SIZE, mmap.MAP_SHARED,
                         mmap.PROT_READ | mmap.PROT_WRITE)
    os.close(fd)

def r32(off):
    return struct.unpack_from("<I", _bar2_mm, off)[0]

def w32(off, val):
    struct.pack_into("<I", _bar2_mm, off, val & 0xFFFFFFFF)

# ---------------------------------------------------------------------------
# CCP descriptor builder
# ---------------------------------------------------------------------------
def passthrough_desc(src_phys, src_mem, dst_phys, dst_mem, length):
    """Build a 32-byte CCP v5 PASSTHROUGH descriptor (plain DMA copy)."""
    dw0 = ((1 << 1)                   # IOC
         | (1 << 4)                   # EOM
         | (ENGINE_PASSTHRU << 20))   # engine = 5
    dw1 = length
    dw2 = src_phys & 0xFFFFFFFF
    dw3 = ((src_phys >> 32) & 0xFFFF) | ((src_mem & 3) << 16)
    dw4 = dst_phys & 0xFFFFFFFF
    dw5 = ((dst_phys >> 32) & 0xFFFF) | ((dst_mem & 3) << 16)
    return struct.pack("<8I", dw0, dw1, dw2, dw3, dw4, dw5, 0, 0)

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    hdr = "=" * 70
    print(hdr)
    print("CCP MEMTYPE_LOCAL PROBE  —  PSP SRAM Read Test (non-destructive)")
    print(hdr)

    if os.getuid() != 0:
        sys.exit("ERROR: must run as root")
    if not os.path.exists(PCI_PATH):
        sys.exit(f"ERROR: PCI device {PCI_DEV} not found")

    # ---- enable PCI device ------------------------------------------------
    with open(f"{PCI_PATH}/enable") as f:
        if f.read().strip() == "0":
            print("[*] Enabling PCI device…")
            with open(f"{PCI_PATH}/enable", "w") as fw:
                fw.write("1")

    with open(f"{PCI_PATH}/config", "rb+") as f:
        f.seek(4)
        cmd = struct.unpack("<H", f.read(2))[0]
        need = cmd | 0x0006          # MEM_EN + BUS_MASTER
        if cmd != need:
            f.seek(4); f.write(struct.pack("<H", need))
            print(f"[*] PCI CMD 0x{cmd:04x} → 0x{need:04x}")

    # ---- Phase 1: BAR2 recon ----------------------------------------------
    print(f"\n{'—'*40}")
    print("Phase 1 — BAR2 reconnaissance")
    print(f"{'—'*40}")
    _open_bar2()

    # PSP liveness check (TRNG)
    t0 = r32(TRNG_OUTPUT)
    time.sleep(0.01)
    t1 = r32(TRNG_OUTPUT)
    trng_live = (t0 != t1) and (t0 != 0) and (t0 != 0xFFFFFFFF)
    print(f"  TRNG:   0x{t0:08x} → 0x{t1:08x}  {'(PSP alive)' if trng_live else '(static — PSP may be dead)'}")

    ver   = r32(G_VERSION)
    qmask = r32(G_QUEUE_MASK)
    qprio = r32(G_QUEUE_PRIO)
    cfg0  = r32(G_CONFIG_0)
    print(f"  Version:      0x{ver:08x}")
    print(f"  Queue mask:   0x{qmask:08x}  ({bin(qmask).count('1')} queues)")
    print(f"  Queue prio:   0x{qprio:08x}")
    print(f"  Config 0:     0x{cfg0:08x}")
    print(f"  LSB pub lo:   0x{r32(G_LSB_PUB_LO):08x}")
    print(f"  LSB priv lo:  0x{r32(G_LSB_PRIV_LO):08x}")

    dead_ccp = (ver in (0, 0xFFFFFFFF)) and (qmask in (0, 0xFFFFFFFF))
    if dead_ccp:
        print("\n  CCP registers read 0 or 0xFFFFFFFF — CCP not reachable via BAR2.")
        print("  RESULT: Gate 2 TOCTOU via CCP is DEAD (no CCP access).")
        return

    # per-queue state
    print("\n  Per-queue state:")
    pick = -1
    for qid in range(5):
        qb   = (qid + 1) * 0x1000
        ctrl = r32(qb + Q_CONTROL)
        stat = r32(qb + Q_STATUS)
        tail = r32(qb + Q_TAIL_LO)
        head = r32(qb + Q_HEAD_LO)
        dma  = r32(qb + Q_DMA_STATUS)
        run  = "RUN"  if ctrl & QCTL_RUN  else "idle"
        halt = "+HALT" if ctrl & QCTL_HALT else ""
        inm  = "✓" if qmask & (1 << qid) else "✗"
        print(f"    Q{qid}  ctrl=0x{ctrl:08x}({run}{halt})  stat=0x{stat:08x}  "
              f"tail=0x{tail:08x}  head=0x{head:08x}  dma=0x{dma:08x}  mask={inm}")
        if pick < 0 and qid > 0 and not (ctrl & QCTL_RUN):
            pick = qid
    if pick < 0:
        pick = 1
        print(f"\n  No idle queue >0 found; will attempt Q{pick}")
    else:
        print(f"\n  Selected idle queue: Q{pick}")

    # ---- Phase 2: DMA buffers ---------------------------------------------
    print(f"\n{'—'*40}")
    print("Phase 2 — DMA buffer allocation")
    print(f"{'—'*40}")

    ring_ptr = _alloc_locked_page()
    _fill_page(ring_ptr, 0)
    ring_phys = _virt_to_phys(ring_ptr)

    src_ptr = _alloc_locked_page()
    _fill_page(src_ptr, 0)
    src_phys = _virt_to_phys(src_ptr)

    dst_ptr = _alloc_locked_page()
    _fill_page(dst_ptr, 0xFF)
    dst_phys = _virt_to_phys(dst_ptr)

    for name, phys in [("ring", ring_phys), ("src", src_phys), ("dst", dst_phys)]:
        flag = " *** >4GB! ***" if phys >= 0x100000000 else ""
        print(f"  {name:5s}  phys=0x{phys:012x}{flag}")

    if any(p >= 0x100000000 for p in (ring_phys, src_phys, dst_phys)):
        print("\n  ERROR: one or more pages above 4 GB — Q_TAIL_LO is 32-bit only.")
        print("  Try again (kernel may choose different pages), or use a hugepage.")
        return

    # ---- Phase 3: queue init ----------------------------------------------
    print(f"\n{'—'*40}")
    print(f"Phase 3 — Initialize CCP queue Q{pick}")
    print(f"{'—'*40}")
    qb = (pick + 1) * 0x1000

    # halt first
    w32(qb + Q_CONTROL, QCTL_HALT)
    time.sleep(0.02)
    # clear pending interrupts
    w32(qb + Q_INT_STATUS, 0x3)

    # program ring address + size + run
    w32(qb + Q_TAIL_LO, ring_phys & 0xFFFFFFFF)
    size_val = 3   # 2^(3+1) = 16 entries
    qctrl_want = (size_val << 3) | QCTL_RUN
    w32(qb + Q_CONTROL, qctrl_want)
    w32(qb + Q_INT_ENABLE, 0x3)

    ctrl_rb = r32(qb + Q_CONTROL)
    tail_rb = r32(qb + Q_TAIL_LO)
    head_rb = r32(qb + Q_HEAD_LO)
    stat_rb = r32(qb + Q_STATUS)
    print(f"  Q_CONTROL  wrote 0x{qctrl_want:08x}  read 0x{ctrl_rb:08x}  {'✓' if ctrl_rb == qctrl_want else '✗ MISMATCH'}")
    print(f"  Q_TAIL_LO  wrote 0x{ring_phys & 0xFFFFFFFF:08x}  read 0x{tail_rb:08x}  {'✓' if tail_rb == (ring_phys & 0xFFFFFFFF) else '✗ MISMATCH'}")
    print(f"  Q_HEAD_LO  read  0x{head_rb:08x}")
    print(f"  Q_STATUS   read  0x{stat_rb:08x}")

    if ctrl_rb != qctrl_want:
        print("\n  Q_CONTROL writes don't stick — CCP queue not host-writable.")
        print("  RESULT: Gate 2 TOCTOU via CCP is DEAD (queue registers read-only).")
        return

    # descriptor submission helper
    desc_idx = 0

    def submit(desc_bytes, label, timeout_s=0.5):
        nonlocal desc_idx
        off = desc_idx * DESC_SIZE
        _write_page(ring_ptr, off, desc_bytes)

        desc_idx = (desc_idx + 1) % RING_ENTRIES
        new_tail = ring_phys + desc_idx * DESC_SIZE

        # clear int status, write new tail (doorbell)
        w32(qb + Q_INT_STATUS, 0x3)
        w32(qb + Q_TAIL_LO, new_tail & 0xFFFFFFFF)

        t0 = time.monotonic()
        deadline = t0 + timeout_s
        while time.monotonic() < deadline:
            ist = r32(qb + Q_INT_STATUS)
            if ist & 0x3:
                qs  = r32(qb + Q_STATUS)
                dma = r32(qb + Q_DMA_STATUS)
                hd  = r32(qb + Q_HEAD_LO)
                ms  = (time.monotonic() - t0) * 1000
                ok  = bool(ist & 1) and not bool(ist & 2)
                err = bool(ist & 2)
                print(f"  [{label}] int=0x{ist:x} stat=0x{qs:08x} dma=0x{dma:08x} "
                      f"head=0x{hd:08x} {ms:.1f}ms  {'OK' if ok else 'ERROR' if err else '?'}")
                return ok, err
            time.sleep(0.001)
        qs  = r32(qb + Q_STATUS)
        dma = r32(qb + Q_DMA_STATUS)
        print(f"  [{label}] TIMEOUT ({timeout_s*1000:.0f}ms)  stat=0x{qs:08x} dma=0x{dma:08x}")
        return False, False

    # ---- Phase 4: System → System test ------------------------------------
    print(f"\n{'—'*40}")
    print("Phase 4 — System→System PASSTHROUGH (sanity)")
    print(f"{'—'*40}")

    pattern = b"CCP_OK!!" * 8   # 64 bytes
    _write_page(src_ptr, 0, pattern)
    _fill_page(dst_ptr, 0xFF)

    desc = passthrough_desc(src_phys, MEMTYPE_SYSTEM,
                            dst_phys, MEMTYPE_SYSTEM, 64)
    ok, err = submit(desc, "SYS→SYS")

    if not ok:
        if err:
            print("\n  CCP rejected even System→System — host CCP queue non-functional.")
        else:
            print("\n  CCP queue timed out — not processing host descriptors.")
        print("  RESULT: Gate 2 TOCTOU via CCP is DEAD (queue non-functional).")
        return

    readback = _read_page(dst_ptr, 0, 64)
    if readback == pattern:
        print("  Data verified ✓ — CCP host queue is FUNCTIONAL")
    else:
        print(f"  DATA MISMATCH:")
        print(f"    expected: {pattern[:16].hex()}")
        print(f"    got:      {readback[:16].hex()}")
        print("  CCP completed but data wrong — investigate before continuing.")
        return

    # ---- Phase 5: LOCAL → System read test --------------------------------
    print(f"\n{'—'*40}")
    print("Phase 5 — PSP SRAM READ test (MEMTYPE_LOCAL → SYSTEM)")
    print(f"{'—'*40}")

    READ_LEN = 256
    sram_off = 0x00000    # exception vector table

    _fill_page(dst_ptr, 0xFF)

    desc = passthrough_desc(sram_off, MEMTYPE_LOCAL,
                            dst_phys, MEMTYPE_SYSTEM, READ_LEN)

    print(f"  Attempting: LOCAL(0x{sram_off:05x}) → SYSTEM(0x{dst_phys:x}), {READ_LEN}B")
    ok, err = submit(desc, "LOCAL→SYS", timeout_s=1.0)

    if err:
        print("\n  CCP ERROR — MEMTYPE_LOCAL descriptor REJECTED by hardware.")
        print("  The CCP enforces queue-level isolation on PSP SRAM.")
        print("  RESULT: Gate 2 TOCTOU via CCP MEMTYPE_LOCAL is DEAD.")
        return

    if not ok:
        print("\n  TIMEOUT — CCP hung on MEMTYPE_LOCAL descriptor.")
        print("  May need queue reset. PSP SRAM access blocked or hangs CCP.")
        # try to recover the queue
        w32(qb + Q_CONTROL, QCTL_HALT)
        time.sleep(0.05)
        w32(qb + Q_INT_STATUS, 0x3)
        print("  (Queue halted for safety.)")
        print("  RESULT: Gate 2 TOCTOU via CCP MEMTYPE_LOCAL is DEAD (timeout).")
        return

    # CCP reported success — check data
    data = _read_page(dst_ptr, 0, READ_LEN)
    all_ff = all(b == 0xFF for b in data)
    all_00 = all(b == 0x00 for b in data)
    unique = len(set(data))

    if all_ff:
        print("\n  Data all 0xFF — likely bus-error default, not real SRAM.")
        print("  CCP may have 'succeeded' but DMA went to a black hole.")
        print("  RESULT: Inconclusive — SRAM read returned default bus value.")
    elif all_00:
        print("\n  Data all 0x00 — could be zeroed SRAM or failed transfer.")
        print("  RESULT: Inconclusive.")
    else:
        print(f"\n  *** NON-TRIVIAL DATA RETURNED — {unique} unique byte values ***")
        print(f"\n  First 256 bytes from PSP SRAM offset 0x{sram_off:05x}:")
        for i in range(0, READ_LEN, 16):
            hx = " ".join(f"{b:02x}" for b in data[i:i+16])
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data[i:i+16])
            print(f"    {sram_off+i:05x}: {hx}  {asc}")

        # check for ARM exception-vector-table signature
        words = struct.unpack_from("<8I", data, 0)
        ldr_pc = sum(1 for w in words if (w & 0xFFFFF000) == 0xE59FF000)
        if ldr_pc >= 3:
            print(f"\n  ARM vector table detected ({ldr_pc}/8 LDR PC,… entries).")
            print("  THIS IS REAL PSP SRAM CONTENT!")

        print("\n  ************************************************************")
        print("  *  CCP MEMTYPE_LOCAL READ WORKS FROM HOST QUEUE            *")
        print("  *  Gate 2 TOCTOU is LIVE — PSP SRAM is host-readable.     *")
        print("  *  Next step: test MEMTYPE_LOCAL WRITE to confirm R/W.     *")
        print("  ************************************************************")

    # ---- Phase 6 (optional): try a second SRAM offset --------------------
    # Read from deeper in SRAM where the data/BSS segment lives
    # (~0x8000-0xCD00 per prior analysis) — should show different data
    if not all_ff and not all_00:
        print(f"\n{'—'*40}")
        print("Phase 6 — Second SRAM read (data region 0x8000)")
        print(f"{'—'*40}")

        _fill_page(dst_ptr, 0xFF)
        desc2 = passthrough_desc(0x8000, MEMTYPE_LOCAL,
                                 dst_phys, MEMTYPE_SYSTEM, READ_LEN)
        ok2, err2 = submit(desc2, "LOCAL(0x8000)→SYS")
        if ok2:
            data2 = _read_page(dst_ptr, 0, READ_LEN)
            if data2 != data:
                print("  Different data from offset 0x8000 — confirms real SRAM access:")
                for i in range(0, min(128, READ_LEN), 16):
                    hx = " ".join(f"{b:02x}" for b in data2[i:i+16])
                    print(f"    {0x8000+i:05x}: {hx}")

    # ---- cleanup ----------------------------------------------------------
    w32(qb + Q_CONTROL, QCTL_HALT)
    print(f"\n{'='*70}")
    print("PROBE COMPLETE")
    print(f"{'='*70}")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\nFATAL: {e}")
        import traceback; traceback.print_exc()
        sys.exit(1)
