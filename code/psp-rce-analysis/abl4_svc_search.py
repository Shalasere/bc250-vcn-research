#!/usr/bin/env python3
"""Search ABL4 binary for SVC instructions (both ARM and Thumb encoding).

ARM SVC: 0xEF000000 | imm24  → top byte 0xEF
Thumb SVC: 0xDF00 | imm8    → top byte 0xDF (in halfword)

Also: search for any mechanism ABL4 uses to call back into PSP_BL:
- Direct BLX to low addresses (0x0000-0x9000 = PSP_BL code region)
- Writes to shared-memory mailbox
- Software interrupts / co-processor instructions (MCR/MRC for CP15)
"""
import struct

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

print("ABL4 binary: {} bytes, base 0x{:05X}".format(len(abl4), ABL4_BASE))

# Search for Thumb SVC instructions (2 bytes: 0xDFxx)
print("\n=== Thumb SVC instructions (0xDFxx) ===")
thumb_svcs = []
for i in range(0, len(abl4) - 1, 2):
    hw = struct.unpack_from("<H", abl4, i)[0]
    if (hw & 0xFF00) == 0xDF00:
        imm = hw & 0xFF
        va = ABL4_BASE + i
        thumb_svcs.append((i, va, imm))
        print("  File 0x{:05X} VA 0x{:05X}: SVC #{} (0x{:02X})".format(i, va, imm, imm))

print("  Total Thumb SVCs: {}".format(len(thumb_svcs)))

# Search for ARM SVC instructions (4 bytes: 0xEFxxxxxx)
print("\n=== ARM SVC instructions (0xEFxxxxxx) ===")
arm_svcs = []
for i in range(0, len(abl4) - 3, 4):
    word = struct.unpack_from("<I", abl4, i)[0]
    if (word & 0xFF000000) == 0xEF000000:
        # Check condition code — could be conditional SVC
        cond = (word >> 28) & 0xF
        imm = word & 0xFFFFFF
        va = ABL4_BASE + i
        arm_svcs.append((i, va, imm, cond))
        cond_str = ["EQ","NE","CS","CC","MI","PL","VS","VC",
                    "HI","LS","GE","LT","GT","LE","","NV"][cond]
        print("  File 0x{:05X} VA 0x{:05X}: SVC{} #{} (0x{:06X})".format(
            i, va, cond_str, imm, imm))

print("  Total ARM SVCs: {}".format(len(arm_svcs)))

# Search for BLX to low addresses (PSP_BL range 0x0000-0x9000)
print("\n=== BLX to PSP_BL range (0x0000-0x9000) ===")
# Thumb BL/BLX: 2-instruction sequence
# First halfword: 0xF000-0xF7FF (BL prefix) or 0xF800-0xFFFF
# For simplicity, search for literal pool entries in 0x0000-0x9000 range
# that could be used as BLX targets
blx_targets = []
for i in range(0, len(abl4) - 3, 4):
    word = struct.unpack_from("<I", abl4, i)[0]
    # Check if this looks like a PSP_BL address stored in literal pool
    if 0x0000 <= word <= 0x9FFF and word != 0:
        va = ABL4_BASE + i
        # Skip if this is in the first few bytes (could be header data)
        if i < 16:
            continue
        # Check if the value looks like a function address (odd = Thumb)
        blx_targets.append((i, va, word))

if blx_targets:
    print("  Potential BLX targets to PSP_BL:")
    for off, va, target in blx_targets[:30]:
        thumb = " (Thumb)" if target & 1 else " (ARM)"
        print("    File 0x{:05X} VA 0x{:05X}: contains 0x{:05X}{}".format(
            off, va, target, thumb))
    if len(blx_targets) > 30:
        print("    ... and {} more".format(len(blx_targets) - 30))
else:
    print("  No literal pool entries pointing to PSP_BL range")

# Search for MCR/MRC instructions (coprocessor access)
print("\n=== MCR/MRC p15 instructions (system control) ===")
cp_count = 0
for i in range(0, len(abl4) - 3, 4):
    word = struct.unpack_from("<I", abl4, i)[0]
    # MCR: cond 1110 opc1 CRn Rd cp# opc2 CRm
    # Bits [27:24] = 1110, bits [11:8] = cp#
    if (word & 0x0F000F10) == 0x0E000E10:  # MCR/MRC with cp15
        cp = (word >> 8) & 0xF
        if cp == 15:
            va = ABL4_BASE + i
            is_read = (word >> 20) & 1  # MRC = read
            crn = (word >> 16) & 0xF
            crm = word & 0xF
            opc1 = (word >> 21) & 7
            opc2 = (word >> 5) & 7
            op = "MRC" if is_read else "MCR"
            print("  0x{:05X}: {} p15, {}, Rd, c{}, c{}, {}".format(
                va, op, opc1, crn, crm, opc2))
            cp_count += 1
            if cp_count >= 20:
                print("  ... (truncated)")
                break

print("\n  Total CP15 accesses: {}+".format(cp_count))

# Summary
print("\n=== SUMMARY ===")
if thumb_svcs:
    svc_nums = set(s[2] for s in thumb_svcs)
    print("  ABL4 uses Thumb SVC instructions: numbers = {}".format(
        sorted(svc_nums)))
    # Count by SVC number
    for num in sorted(svc_nums):
        count = sum(1 for s in thumb_svcs if s[2] == num)
        print("    SVC #{}: {} occurrences".format(num, count))
else:
    print("  ABL4 has NO Thumb SVC instructions")

if arm_svcs:
    print("  ABL4 uses ARM SVC instructions: {} total".format(len(arm_svcs)))
else:
    print("  ABL4 has NO ARM SVC instructions")

print("\nDone.")
