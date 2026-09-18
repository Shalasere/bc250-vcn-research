#!/usr/bin/env python3
"""Find the LDR instruction in PSP_BL that loads from the literal pool at +0x0BB8 (0x5D7AC).

In Thumb-2:
  LDR.W Rd, [PC, #imm12]  (T3 encoding: 1111 1000 U101 1111 | Rt:4 imm12:12)
  LDR   Rd, [PC, #imm8<<2] (T1 encoding: 0100 1 Rd:3 imm8:8)

For T1 (narrow): PC is word-aligned, offset = imm8 * 4
  Target = (insn_addr + 4) & ~3 + imm * 4

For T3 (wide):
  First halfword: 1111 1000 U101 1111 = 0xF85F (U=0, subtract) or 0xF8DF (U=1, add)
  Second halfword: Rt:4 imm12:12
  Target = (insn_addr + 4) & ~3 ± imm12

We need to find ALL LDR instructions where target = 0x0BB8.
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

TARGET_POOL = 0x0BB8

print("Searching for LDR instructions that load from pool at 0x{:04X}...".format(TARGET_POOL))
print("Pool value: 0x{:08X} (context structure base)".format(
    struct.unpack_from("<I", pspbl, TARGET_POOL)[0]))

# Method 1: Brute-force search all possible Thumb LDR.W and LDR narrow
hits = []

for off in range(0, len(pspbl) - 3, 2):
    # Try narrow LDR Rd, [PC, #imm8*4]  (T1: 0100 1 xxx xxxx xxxx)
    hw = struct.unpack_from("<H", pspbl, off)[0]
    if (hw >> 11) == 0b01001:  # T1 LDR
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        pc_aligned = (off + 4) & ~3
        target = pc_aligned + imm8 * 4
        if target == TARGET_POOL:
            hits.append(("LDR_T1", off, rd, target))

    # Try wide LDR.W Rd, [PC, #imm12]  (T3)
    if off + 3 < len(pspbl):
        hw1 = struct.unpack_from("<H", pspbl, off)[0]
        hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]

        # LDR.W (positive offset): 0xF8DF xxxx
        if hw1 == 0xF8DF:
            rt = (hw2 >> 12) & 0xF
            imm12 = hw2 & 0xFFF
            pc_aligned = (off + 4) & ~3
            target = pc_aligned + imm12
            if target == TARGET_POOL:
                hits.append(("LDR.W+", off, rt, target))

        # LDR.W (negative offset): 0xF85F xxxx
        if hw1 == 0xF85F:
            rt = (hw2 >> 12) & 0xF
            imm12 = hw2 & 0xFFF
            pc_aligned = (off + 4) & ~3
            target = pc_aligned - imm12
            if target == TARGET_POOL:
                hits.append(("LDR.W-", off, rt, target))

print("\nFound {} LDR instructions loading from pool 0x{:04X}:".format(len(hits), TARGET_POOL))
for enc, off, reg, target in hits:
    print("  +0x{:04X}: {} R{}, [PC, #...] -> 0x{:04X}".format(off, enc, reg, target))

# Also search for the other pool entries
for pool_off, pool_val, desc in [
    (0x0BB8, 0x5D7AC, "context base"),
    (0x0BC8, 0x5D5A4, "context-0x208"),
    (0x0BCC, 0x5B13C, "SRAM addr"),
    (0x3DA0, 0x5D004, "another SRAM"),
]:
    print("\n--- Pool at +0x{:04X} (0x{:X}, {}) ---".format(pool_off, pool_val, desc))
    for off in range(0, len(pspbl) - 3, 2):
        hw = struct.unpack_from("<H", pspbl, off)[0]
        if (hw >> 11) == 0b01001:
            imm8 = hw & 0xFF
            pc_aligned = (off + 4) & ~3
            target = pc_aligned + imm8 * 4
            if target == pool_off:
                rd = (hw >> 8) & 7
                print("  +0x{:04X}: LDR_T1 R{} -> 0x{:04X}".format(off, rd, target))

        if off + 3 < len(pspbl):
            hw1 = struct.unpack_from("<H", pspbl, off)[0]
            hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]
            if hw1 == 0xF8DF:
                imm12 = hw2 & 0xFFF
                pc_aligned = (off + 4) & ~3
                target = pc_aligned + imm12
                if target == pool_off:
                    rt = (hw2 >> 12) & 0xF
                    print("  +0x{:04X}: LDR.W R{} -> 0x{:04X}".format(off, rt, target))
            if hw1 == 0xF85F:
                imm12 = hw2 & 0xFFF
                pc_aligned = (off + 4) & ~3
                target = pc_aligned - imm12
                if target == pool_off:
                    rt = (hw2 >> 12) & 0xF
                    print("  +0x{:04X}: LDR.W- R{} -> 0x{:04X}".format(off, rt, target))

# Now disassemble around each hit using capstone for context
if hits:
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs.detail = True
    print("\n=== Disassembly context around LDR hits ===")
    for enc, off, reg, target in hits:
        start = max(0, off - 20) & ~1
        end = min(len(pspbl), off + 40)
        code = pspbl[start:end]
        print("\n  --- around +0x{:04X} ---".format(off))
        for insn in cs.disasm(code, start):
            marker = " <<<<" if insn.address == off else ""
            print("    0x{:04X}: {:6s} {}{}".format(
                insn.address, insn.mnemonic, insn.op_str, marker))

# Also search for MOVW/MOVT pairs that construct 0x5D7AC
print("\n=== Searching for MOVW/MOVT constructing 0x5D7AC ===")
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# Search for MOVW with 0xD7AC (lower 16 bits)
# MOVW T3: 1111 0x10 0100 imm4 | 0 imm3 Rd imm8
# imm16 = imm4:i:imm3:imm8 where i is bit 26
for off in range(0, len(pspbl) - 3, 2):
    hw1 = struct.unpack_from("<H", pspbl, off)[0]
    hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]
    # MOVW: hw1 = 1111 0x10 0100 xxxx
    if (hw1 & 0xFBF0) == 0xF240:
        imm4 = hw1 & 0xF
        i = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 7
        imm8 = hw2 & 0xFF
        rd = (hw2 >> 8) & 0xF
        imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
        if imm16 == 0xD7AC:
            print("  +0x{:04X}: MOVW R{}, #0x{:04X}".format(off, rd, imm16))
        elif imm16 == 0xDE0C:
            print("  +0x{:04X}: MOVW R{}, #0x{:04X} (lower 0x5DE0C!)".format(off, rd, imm16))

    # MOVT: hw1 = 1111 0x10 1100 xxxx
    if (hw1 & 0xFBF0) == 0xF2C0:
        imm4 = hw1 & 0xF
        i = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 7
        imm8 = hw2 & 0xFF
        rd = (hw2 >> 8) & 0xF
        imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
        if imm16 == 0x0005:
            print("  +0x{:04X}: MOVT R{}, #0x{:04X} (upper 0x0005xxxx)".format(off, rd, imm16))

print("\nDone.")
