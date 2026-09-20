#!/usr/bin/env python3
"""
Broad BAR2+BAR5 scan for CCP queue registers at non-standard offsets.
The standard CCP v5 offsets (0x0000-0x6000) read 0xFFFFFFFF on BC-250.
Check if CCP queues exist elsewhere in the 1MB BAR2 space.

Also scan BAR5 (8KB) for any queue-like registers.
"""
import mmap, os, struct, sys

PCI_DEV  = "0000:01:00.2"
PCI_PATH = f"/sys/bus/pci/devices/{PCI_DEV}"

def r32(mm, off):
    return struct.unpack_from("<I", mm, off)[0]

def scan_bar(path, size, label):
    if not os.path.exists(path):
        print(f"\n  {label}: {path} not found")
        return
    try:
        fd = os.open(path, os.O_RDWR | os.O_SYNC)
        mm = mmap.mmap(fd, size, mmap.MAP_SHARED, mmap.PROT_READ | mmap.PROT_WRITE)
        os.close(fd)
    except Exception as e:
        print(f"\n  {label}: mmap failed: {e}")
        return

    print(f"\n{'='*60}")
    print(f"{label} — {size // 1024}KB scan")
    print(f"{'='*60}")

    # Count non-0xFFFFFFFF and non-0x00000000 dwords
    live_regions = []
    run_start = None
    prev_live = False

    for off in range(0, size, 4):
        val = r32(mm, off)
        is_live = val != 0xFFFFFFFF and val != 0x00000000
        if is_live and not prev_live:
            run_start = off
        elif not is_live and prev_live:
            live_regions.append((run_start, off))
        prev_live = is_live
    if prev_live:
        live_regions.append((run_start, size))

    if not live_regions:
        print("  No non-zero/non-FF dwords found — entire BAR is dead or masked.")
        mm.close()
        return

    print(f"  {len(live_regions)} live region(s):\n")
    for start, end in live_regions:
        print(f"  --- 0x{start:05x} - 0x{end-1:05x} ({end-start} bytes) ---")
        # Dump all live dwords in this region
        for off in range(start, min(end, start + 256), 4):
            val = r32(mm, off)
            if val != 0xFFFFFFFF and val != 0x00000000:
                note = ""
                # Identify known register signatures
                if off == 0x000C:
                    note = "  <- TRNG output"
                elif 0x10000 <= off <= 0x10600:
                    names = {
                        0x10004: "PSP_CAPABILITIES",
                        0x1005C: "PSP_VERSION",
                        0x10500: "PSP_MBOX_INT",
                        0x10544: "PSP_MBOX_INTSTAT",
                        0x10568: "PSP_STATUS",
                        0x10570: "PSP_CMDRESP",
                        0x10574: "PSP_CMDBUF_LO",
                        0x10578: "PSP_CMDBUF_HI",
                    }
                    note = f"  <- {names.get(off, 'PSP reg')}"
                elif 0x10A00 <= off <= 0x10B00:
                    note = "  <- SEV zone"
                # Check for CCP version signature (0x00050000 range = CCP v5)
                if (val >> 16) == 0x0005:
                    note = f"  <- POSSIBLE CCP v5 VERSION?"
                # Check for queue-like register patterns
                if val & 0x01 and not (val & 0xFFFFFFF0):
                    note += "  [low bits only — could be Q_CONTROL?]"
                print(f"    0x{off:05x}: 0x{val:08x}{note}")
        if end - start > 256:
            remaining = (end - start - 256) // 4
            print(f"    ... ({remaining} more dwords)")

    # Special: scan for CCP version signature anywhere
    print(f"\n  Scanning full {label} for CCP version pattern...")
    found_ver = False
    for off in range(0, size, 4):
        val = r32(mm, off)
        # CCP v5 version is typically 0x00050100 or similar
        if val != 0xFFFFFFFF and val != 0 and (val >> 16) in (0x0005, 0x0006):
            print(f"    0x{off:05x}: 0x{val:08x}  <- possible CCP version")
            found_ver = True
    if not found_ver:
        print("    No CCP version signature found.")

    # Look for writable registers (write a value, read back, restore)
    # Only test the 0x0000-0x0FFF region (standard CCP global)
    if size >= 0x1000:
        print(f"\n  Write-test on first 0x200 bytes (CCP global region):")
        writable = []
        for off in range(0, 0x200, 4):
            orig = r32(mm, off)
            if orig == 0xFFFFFFFF:
                # try writing 0
                struct.pack_into("<I", mm, off, 0x00000000)
                rb = r32(mm, off)
                struct.pack_into("<I", mm, off, orig)  # restore
                if rb != 0xFFFFFFFF:
                    writable.append((off, orig, rb))
            elif orig == 0:
                struct.pack_into("<I", mm, off, 0xDEADBEEF)
                rb = r32(mm, off)
                struct.pack_into("<I", mm, off, orig)
                if rb != 0:
                    writable.append((off, orig, rb))
        if writable:
            for off, orig, rb in writable:
                print(f"    0x{off:04x}: orig=0x{orig:08x} wrote→read=0x{rb:08x} WRITABLE")
        else:
            print("    No writable registers found in CCP global region (all stuck at 0xFFFFFFFF).")

    mm.close()

def main():
    if os.getuid() != 0:
        sys.exit("Must run as root")

    # Enable device
    with open(f"{PCI_PATH}/enable") as f:
        if f.read().strip() == "0":
            with open(f"{PCI_PATH}/enable", "w") as fw:
                fw.write("1")
    with open(f"{PCI_PATH}/config", "rb+") as f:
        f.seek(4)
        cmd = struct.unpack("<H", f.read(2))[0]
        need = cmd | 0x06
        if cmd != need:
            f.seek(4); f.write(struct.pack("<H", need))

    # Get BAR info from resource file
    with open(f"{PCI_PATH}/resource") as f:
        lines = f.readlines()
    for i, line in enumerate(lines):
        parts = line.strip().split()
        if len(parts) >= 3:
            start = int(parts[0], 16)
            end = int(parts[1], 16)
            flags = int(parts[2], 16)
            if start and end:
                size = end - start + 1
                print(f"  BAR{i}: 0x{start:012x}-0x{end:012x} ({size//1024}KB) flags=0x{flags:x}")

    scan_bar(f"{PCI_PATH}/resource2", 0x100000, "BAR2")

    # BAR5 might be at resource5
    bar5_path = f"{PCI_PATH}/resource5"
    if os.path.exists(bar5_path):
        with open(f"{PCI_PATH}/resource") as f:
            lines = f.readlines()
        if len(lines) > 5:
            parts = lines[5].strip().split()
            bar5_start = int(parts[0], 16)
            bar5_end = int(parts[1], 16)
            if bar5_start and bar5_end:
                bar5_size = bar5_end - bar5_start + 1
                scan_bar(bar5_path, bar5_size, "BAR5")
    else:
        print("\n  BAR5 resource file not found")

if __name__ == "__main__":
    main()
