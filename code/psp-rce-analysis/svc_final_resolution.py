#!/usr/bin/env python3
"""Final resolution of the SVC vector question.

REAL vector table at 0x000:
  0x008: LDR PC → 0x298 (SVC handler)

VBAR is set to 0x100 at offset 0x04C:
  0x108: BX LR (NOP)

Question: Is VBAR ever restored to 0x000?

This script:
1. Decompile FUN_00000298 (original SVC handler at VBAR=0)
2. Search for ALL MCR p15, 0, Rx, c12, c0, 0 (VBAR writes) in both ARM and Thumb
3. Check the raw bytes around ABL4's SVC #28 calls to see actual post-SVC checks
4. Decompile FUN_000001AC (post-MMU init, jumped to from 0x0A8)
"""
import struct

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# Part 1: What's at 0x298?
print("=" * 70)
print("PART 1: SVC handler at 0x298 (VBAR=0 vector)")
print("=" * 70)

for off in range(0x298, 0x340, 4):
    word = struct.unpack_from("<I", pspbl, off)[0]
    print("  0x{:03X}: 0x{:08X}".format(off, word))

# Part 2: Search for ALL VBAR writes (MCR p15, 0, Rx, c12, c0, 0)
# ARM encoding: EE0C xF10 where x = Rd
# Thumb encoding: same bit pattern in 32-bit Thumb word
print("\n" + "=" * 70)
print("PART 2: ALL VBAR writes in PSP_BL (MCR p15, 0, Rx, c12, c0, 0)")
print("=" * 70)

# ARM MCR p15, 0, Rd, c12, c0, 0: bits [31:28]=cond, [27:24]=1110,
# [23:21]=opc1=0, [20]=0 (MCR), [19:16]=CRn=c12=1100,
# [15:12]=Rd, [11:8]=cp=1111, [7:5]=opc2=000, [4]=1, [3:0]=CRm=c0=0000
# Mask: 0x0FFF0FFF, Value: 0x0E0C0F10
# But CRn=12=0xC, so bits[19:16]=1100

for off in range(0, len(pspbl) - 3, 2):  # check every 2 bytes for Thumb
    word = struct.unpack_from("<I", pspbl, off)[0]
    # Check for MCR p15, 0, Rx, c12, c0, 0
    if (word & 0x0FFF0FFF) == 0x0E0C0F10:
        rd = (word >> 12) & 0xF
        cond = (word >> 28) & 0xF
        print("  0x{:04X}: MCR p15, 0, R{}, c12, c0, 0 (cond={})".format(off, rd, cond))

# Part 3: Check raw Thumb bytes around ABL4's SVC #28 calls
print("\n" + "=" * 70)
print("PART 3: ABL4 raw bytes around SVC #28 (0x1C) calls")
print("=" * 70)

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

# SVC #28 locations (file offsets):
# VA 0x62878 → file 0x62878-0x60834 = 0x2044
# VA 0x688A4 → file 0x688A4-0x60834 = 0x8070
# VA 0x6AFB6 → file 0x6AFB6-0x60834 = 0xA782
# VA 0x6BCCC → file 0x6BCCC-0x60834 = 0xB498

svc28_offsets = [
    (0x2044, 0x62878),
    (0x8070, 0x688A4),
    (0xA782, 0x6AFB6),
    (0xB498, 0x6BCCC),
]

for file_off, va in svc28_offsets:
    print("\n  SVC #28 at VA 0x{:05X} (file 0x{:04X}):".format(va, file_off))

    # Show 16 bytes before and 20 bytes after
    start = max(0, file_off - 16)
    end = min(len(abl4), file_off + 22)

    for i in range(start, end, 2):
        hw = struct.unpack_from("<H", abl4, i)[0]
        marker = " ← SVC #28" if i == file_off else ""
        # Basic Thumb decode
        desc = ""
        if (hw & 0xFF00) == 0xDF00:
            desc = "SVC #{}".format(hw & 0xFF)
        elif (hw & 0xFE00) == 0xB400:
            desc = "PUSH"
        elif (hw & 0xFE00) == 0xBC00:
            desc = "POP"
        elif (hw & 0xFF00) == 0x4600:
            desc = "MOV (high reg)"
        elif (hw & 0xF800) == 0x2000:
            desc = "MOV R{}, #0x{:X}".format((hw >> 8) & 7, hw & 0xFF)
        elif (hw & 0xF800) == 0x2800:
            desc = "CMP R{}, #0x{:X}".format((hw >> 8) & 7, hw & 0xFF)
        elif (hw & 0xFF00) == 0xD000:
            cond = (hw >> 8) & 0xF
            conds = ["BEQ","BNE","BCS","BCC","BMI","BPL","BVS","BVC",
                     "BHI","BLS","BGE","BLT","BGT","BLE","B","SVC"]
            offset = hw & 0xFF
            if offset & 0x80:
                offset -= 0x100
            target = (i + ABL4_BASE + 4 + offset * 2) & 0xFFFFFFFF
            desc = "{} 0x{:05X}".format(conds[cond] if cond < 15 else "?", target)
        elif hw == 0x4770:
            desc = "BX LR"
        elif hw == 0x46C0:
            desc = "NOP"
        elif (hw & 0xF800) == 0xF000:
            # 32-bit Thumb instruction (BL prefix)
            if i + 2 < len(abl4):
                hw2 = struct.unpack_from("<H", abl4, i + 2)[0]
                if (hw2 & 0xD000) == 0xD000:
                    # BL
                    s = (hw >> 10) & 1
                    imm10 = hw & 0x3FF
                    j1 = (hw2 >> 13) & 1
                    j2 = (hw2 >> 11) & 1
                    imm11 = hw2 & 0x7FF
                    i1 = (~(j1 ^ s)) & 1
                    i2 = (~(j2 ^ s)) & 1
                    imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                    if s:
                        imm32 |= 0xFE000000
                        imm32 -= 0x100000000
                    target = (i + ABL4_BASE + 4 + imm32) & 0xFFFFFFFF
                    desc = "BL 0x{:05X}".format(target)

        print("    0x{:05X}: 0x{:04X}  {}{}".format(
            i + ABL4_BASE, hw, desc, marker))

# Part 4: Check the CRITICAL sequence: what register does ABL4 check after SVC?
# Focus on the main boot function's SVC at 0x6BCCC
print("\n" + "=" * 70)
print("PART 4: Detailed decode around main SVC #28 (0x6BCCC)")
print("=" * 70)

# SVC at file 0xB498
# Show 32 bytes before and 40 bytes after
file_off = 0xB498
start = file_off - 32
end = file_off + 42

print("  Extended context (file 0x{:04X}-0x{:04X}):".format(start, end))
for i in range(start, end, 2):
    hw = struct.unpack_from("<H", abl4, i)[0]
    va = i + ABL4_BASE
    marker = " <<<" if i == file_off else ""

    # Enhanced Thumb decode
    desc = ""
    if (hw & 0xFF00) == 0xDF00:
        desc = "SVC #{}".format(hw & 0xFF)
    elif (hw & 0xFFC0) == 0x4280:
        desc = "CMP R{}, R{}".format(hw & 7, (hw >> 3) & 7)
    elif (hw & 0xF800) == 0x2800:
        desc = "CMP R{}, #0x{:X}".format((hw >> 8) & 7, hw & 0xFF)
    elif (hw & 0xF800) == 0x2000:
        desc = "MOVS R{}, #0x{:X}".format((hw >> 8) & 7, hw & 0xFF)
    elif (hw & 0xFF00) == 0xD100:
        offset = hw & 0xFF
        if offset & 0x80: offset -= 0x100
        target = va + 4 + offset * 2
        desc = "BNE 0x{:05X}".format(target)
    elif (hw & 0xFF00) == 0xD000:
        offset = hw & 0xFF
        if offset & 0x80: offset -= 0x100
        target = va + 4 + offset * 2
        desc = "BEQ 0x{:05X}".format(target)
    elif (hw & 0xFF78) == 0x4468:
        desc = "ADD SP/R{}".format(hw & 7)
    elif hw == 0x46C0:
        desc = "NOP"
    elif hw == 0x4770:
        desc = "BX LR"
    elif (hw & 0xFF87) == 0x4687:
        desc = "MOV PC, ..."
    elif (hw & 0xFE00) == 0x4600:
        lo = hw & 7
        hi = ((hw >> 4) & 8) | lo
        src = (hw >> 3) & 0xF
        desc = "MOV R{}, R{}".format(hi, src)
    elif (hw & 0xF800) == 0x9800:
        desc = "LDR R{}, [SP, #0x{:X}]".format((hw >> 8) & 7, (hw & 0xFF) * 4)
    elif (hw & 0xF800) == 0x9000:
        desc = "STR R{}, [SP, #0x{:X}]".format((hw >> 8) & 7, (hw & 0xFF) * 4)
    elif (hw & 0xF800) == 0xF000:
        # Could be 32-bit instruction
        if i + 2 < len(abl4):
            hw2 = struct.unpack_from("<H", abl4, i + 2)[0]
            desc = "[32-bit: 0x{:04X}{:04X}]".format(hw, hw2)

    print("    0x{:05X}: 0x{:04X}  {}{}".format(va, hw, desc, marker))

# Part 5: Search PSP_BL for MCR to c12 at ANY position (including Thumb)
print("\n" + "=" * 70)
print("PART 5: Exhaustive search for VBAR writes (any encoding)")
print("=" * 70)

# Search for the byte pattern 0C xF 10 in the binary
# ARM: xxEC0F10 → MCR p15, 0, R0, c12, c0, 0
# The key bytes are: 0F 10 at offset +1,+0 (LE) and 0C at +3 (LE)
# In LE: byte[0]=0x10, byte[1]=0x0F, byte[2]=0x0C, byte[3]=0xEE (ARM)
# Or in Thumb: byte[0]=0x0C, byte[1]=0xEE, byte[2]=0x10, byte[3]=0x0F

count = 0
for i in range(0, len(pspbl) - 3):
    b0, b1, b2, b3 = pspbl[i], pspbl[i+1], pspbl[i+2], pspbl[i+3]
    # ARM pattern: 10 xF 0C xE where x = Rd
    if b0 == 0x10 and (b1 & 0x0F) == 0x0F and b2 == 0x0C and (b3 & 0x0F) == 0x0E:
        rd = (b1 >> 4) & 0xF
        opc = (b3 >> 4) & 0xF
        print("  0x{:04X}: possible ARM MCR p15, Rd=R{}, c12 (byte pat)".format(i, rd))
        count += 1
    # Thumb pattern: 0C EE 10 xF
    if b0 == 0x0C and b1 == 0xEE and b2 == 0x10 and (b3 & 0x0F) == 0x0F:
        rd = (b3 >> 4) & 0xF
        print("  0x{:04X}: possible Thumb MCR p15, Rd=R{}, c12".format(i, rd))
        count += 1

print("  Total VBAR write candidates: {}".format(count))

print("\nDone.")
