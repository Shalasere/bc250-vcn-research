#!/usr/bin/env python3
"""Deep analysis: SRAM size config, ABL load regions, APCB data handling in PSP_BL."""
import struct
import os

BODY_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
INTERNAL_FD = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_p300\rom\P3.00.AMD\P3.00.AMD\P3.00.AMD.FD"

with open(BODY_PATH, "rb") as f:
    body = f.read()

print("=" * 60)
print("PART 1: Context around 0x60000 (384K SRAM) references")
print("=" * 60)

# 0x60000 at +0x94B2 and 0x50000 at +0x8D1E, +0x9200, +0x948E
for label, off in [("0x50000@8D1E", 0x8D1E), ("0x50000@9200", 0x9200),
                    ("0x50000@948E", 0x948E), ("0x60000@94B2", 0x94B2)]:
    start = max(0, off - 32)
    end = min(len(body), off + 36)
    chunk = body[start:end]
    print("\n--- {} (offset 0x{:04X}) ---".format(label, off))
    print("  Hex: {}".format(chunk.hex()))
    # Show as u32 words
    for i in range(0, len(chunk) - 3, 4):
        w = struct.unpack_from("<I", chunk, i)[0]
        abs_off = start + i
        marker = " <--- HERE" if abs_off <= off < abs_off + 4 else ""
        print("  +0x{:04X}: 0x{:08X}{}".format(abs_off, w, marker))

print()
print("=" * 60)
print("PART 2: Code around the HARVEST string at +0x8406")
print("=" * 60)

# Check 64 bytes around +0x8406
off = 0x8406
start = max(0, off - 32)
end = min(len(body), off + 64)
chunk = body[start:end]
printable = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
print("ASCII: {}".format(printable))
print("Hex:   {}".format(chunk.hex()))

# Let's also look for the full word containing "HARV"
for i in range(max(0, off-64), min(len(body), off+64)):
    if body[i:i+4] == b"HARV":
        ctx = body[max(0,i-4):min(len(body), i+32)]
        s = "".join(chr(b) if 32 <= b < 127 else "." for b in ctx)
        print("HARV at +0x{:04X}: {}".format(i, s))

print()
print("=" * 60)
print("PART 3: Internal BIOS PSP directory — ABL entries + APCB")
print("=" * 60)

PSP_DIR_OFFSET = 0x8E0000
ROM_BASE = 0xFF000000

KNOWN_TYPES = {
    0x01: "PSP_BL", 0x02: "tOS", 0x08: "SMU_FW",
    0x30: "ABL0", 0x31: "ABL1", 0x32: "ABL2", 0x33: "ABL3",
    0x34: "ABL4", 0x35: "ABL5", 0x36: "ABL6", 0x37: "ABL7",
    0x50: "BL_PUBLIC_KEY", 0x51: "TOS_PUBLIC_KEY",
    0x60: "APCB_DATA", 0x61: "APCB_BACKUP", 0x63: "APCB_BACKUP2",
    0x24: "SEC_GASKET", 0x5A: "KEY_DB",
    0x0B: "SOFT_FUSE", 0x04: "NV_DATA",
}

with open(INTERNAL_FD, "rb") as f:
    f.seek(PSP_DIR_OFFSET)
    hdr = f.read(16)

magic = hdr[:4]
if magic != b"$PSP":
    print("No $PSP at 0x{:06X}, scanning...".format(PSP_DIR_OFFSET))
    # Try same offset as public build
    with open(INTERNAL_FD, "rb") as f:
        f.seek(0x820000)
        fet = f.read(64)
    print("FET at 0x820000:")
    for i in range(0, 64, 4):
        w = struct.unpack_from("<I", fet, i)[0]
        print("  +0x{:02X}: 0x{:08X}".format(i, w))

    # Check +0x14 for PSP dir pointer
    psp_ptr = struct.unpack_from("<I", fet, 0x14)[0]
    print("\nFET+0x14 = 0x{:08X}".format(psp_ptr))
    if psp_ptr >= ROM_BASE:
        flash_off = psp_ptr & 0x00FFFFFF
    else:
        flash_off = psp_ptr
    PSP_DIR_OFFSET = flash_off
    print("PSP dir at flash 0x{:06X}".format(PSP_DIR_OFFSET))

    with open(INTERNAL_FD, "rb") as f:
        f.seek(PSP_DIR_OFFSET)
        hdr = f.read(16)
    magic = hdr[:4]

if magic == b"$PSP":
    checksum, num_entries = struct.unpack_from("<II", hdr, 4)
    print("$PSP directory: {} entries".format(num_entries))

    with open(INTERNAL_FD, "rb") as f:
        f.seek(PSP_DIR_OFFSET + 16)
        entries = f.read(min(num_entries, 64) * 16)

    fw_size = os.path.getsize(INTERNAL_FD)

    abl_entries = []
    apcb_entries = []

    for i in range(min(num_entries, 64)):
        off = i * 16
        if off + 16 > len(entries):
            break
        w0 = struct.unpack_from("<I", entries, off)[0]
        esize = struct.unpack_from("<I", entries, off + 4)[0]
        eaddr = struct.unpack_from("<I", entries, off + 8)[0]

        etype = w0 & 0xFF
        subprog = (w0 >> 8) & 0xFF

        if eaddr >= ROM_BASE:
            fa = eaddr & 0x00FFFFFF
        elif eaddr < fw_size:
            fa = eaddr
        else:
            fa = None

        name = KNOWN_TYPES.get(etype, "type_0x{:02X}".format(etype))

        if 0x30 <= etype <= 0x37 or etype in (0x01, 0x02, 0x60, 0x61, 0x63):
            fa_str = "flash 0x{:06X}".format(fa) if fa is not None else "addr 0x{:08X}".format(eaddr)
            print("  #{}: {} (sub={}) size={} ({} bytes) @ {}".format(
                i, name, subprog, "0x{:X}".format(esize), esize, fa_str))

            if 0x30 <= etype <= 0x37:
                abl_entries.append((etype, name, esize, fa))
            if etype in (0x60, 0x61, 0x63):
                apcb_entries.append((etype, name, esize, fa))

            # Check header of each
            if fa is not None and fa < fw_size:
                with open(INTERNAL_FD, "rb") as f:
                    f.seek(fa)
                    entry_hdr = f.read(min(32, esize))
                print("    Header: {}".format(entry_hdr[:32].hex()))
                # Check for $PS1 signature
                if len(entry_hdr) >= 4:
                    if entry_hdr[:4] == b"$PS1" or entry_hdr[16:20] == b"$PS1":
                        print("    ** $PS1 signed **")
                    elif entry_hdr[:4] == b"APCB":
                        print("    ** APCB magic! **")

    print("\n--- ABL entry sizes (for SRAM layout estimation) ---")
    total_abl = 0
    for etype, name, esize, fa in abl_entries:
        print("  {} : {} bytes (0x{:X})".format(name, esize, esize))
        total_abl += esize
    print("  Total ABL: {} bytes (0x{:X})".format(total_abl, total_abl))

    print("\n--- APCB entries ---")
    for etype, name, esize, fa in apcb_entries:
        print("  {} : {} bytes (0x{:X}) @ flash 0x{:06X}".format(name, esize, esize, fa))
        if fa is not None and fa < fw_size:
            with open(INTERNAL_FD, "rb") as f:
                f.seek(fa)
                apcb_hdr = f.read(64)
            print("    First 64 bytes: {}".format(apcb_hdr.hex()))
            printable = "".join(chr(b) if 32 <= b < 127 else "." for b in apcb_hdr)
            print("    ASCII: {}".format(printable))

else:
    print("ERROR: No $PSP magic found at 0x{:06X}: {}".format(PSP_DIR_OFFSET, magic))

print()
print("=" * 60)
print("PART 4: Code around SVC 0x4D at +0x5F50 (near sig-verify)")
print("=" * 60)

# project-ariel says sig-verify at 0x5C90. SVC 0x4D is at 0x5F50.
# Check what function contains +0x5F50
# Find the closest function prologue before +0x5F50
closest_fn = None
for off2 in range(0, 0x5F50, 2):
    hw = struct.unpack_from("<H", body, off2)[0]
    if (hw & 0xFF00) == 0xB500 or (hw == 0xE92D and off2 + 2 < len(body)):
        if off2 + 2 < len(body):
            hw2 = struct.unpack_from("<H", body, off2 + 2)[0]
            if (hw & 0xFF00) == 0xB500 or (hw == 0xE92D and (hw2 & 0x4000)):
                closest_fn = off2

print("Closest function prologue before +0x5F50: +0x{:04X}".format(closest_fn) if closest_fn else "None found")

# Show 64 bytes around the SVC
svc_off = 0x5F50
start = max(0, svc_off - 32)
end = min(len(body), svc_off + 32)
print("Context around SVC 0x4D at +0x5F50:")
for i in range(start, end, 2):
    hw = struct.unpack_from("<H", body, i)[0]
    marker = " <--- SVC 0x4D" if i == svc_off else ""
    print("  +0x{:04X}: 0x{:04X}{}".format(i, hw, marker))

print()
print("=" * 60)
print("PART 5: Check if 0x5DE0C could be in ABL0-ABL3 loaded range")
print("=" * 60)

# PSP_BL at VA 0x0, 39360 bytes -> ends at 0x99C0
# Then PSP_BL loads ABL stages. If ABL0 loads right after PSP_BL...
# Let's see the sizes
pspbl_end = 0x99C0
print("PSP_BL ends at VA 0x{:04X}".format(pspbl_end))
print("Target VA: 0x{:05X}".format(0x5DE0C))
print("Gap: {} bytes".format(0x5DE0C - pspbl_end))
print()
print("If SRAM = 384K (0x60000): VA 0x5DE0C is at SRAM offset {} ({} from end)".format(
    0x5DE0C, 0x60000 - 0x5DE0C))
print("If SRAM = 320K (0x50000): VA 0x5DE0C is OUTSIDE SRAM")

# Given ABL4 loads at ~0x60834 per the summary, and 0x5DE0C < 0x60834:
# 0x5DE0C is 0x2A28 (10,792) bytes before ABL4's load base.
# This could be in the SRAM data region (stack, heap, APCB buffer)
print()
print("ABL4 loads at ~0x60834")
print("0x5DE0C is {} bytes BEFORE ABL4 load base".format(0x60834 - 0x5DE0C))
print("This puts 0x5DE0C in the SRAM data region between PSP_BL code and ABL4 code")
