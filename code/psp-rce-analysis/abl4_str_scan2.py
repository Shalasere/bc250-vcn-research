#!/usr/bin/env python3
"""Debug the capstone disassembly and do a proper binary scan for STR instructions."""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

print("ABL4: {} bytes".format(len(abl4)))
print("First 32 bytes: {}".format(abl4[:32].hex()))

# Check first few instructions
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# Try disassembling small chunks to find where it breaks
for start_off in [0, 2, 4, 0x10, 0x100, 0x1000]:
    chunk = abl4[start_off:start_off+32]
    insns = list(cs.disasm(chunk, ABL4_BASE + start_off))
    print("\n  Offset 0x{:X}: {} insns from 32 bytes".format(start_off, len(insns)))
    for insn in insns[:5]:
        print("    0x{:X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# The issue might be that the ENTRY POINT of ABL4 is ARM mode, not Thumb
# PSP_BL launches ABL4 with: FUN_00000328(0, iVar6 + DAT_00003fc8)
# If the address has bit 0 clear, it's ARM mode

# Let me try ARM mode
from capstone import CS_MODE_ARM
cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
cs_arm.detail = True

print("\n\n=== ARM mode disassembly of first 64 bytes ===")
insns = list(cs_arm.disasm(abl4[:64], ABL4_BASE))
for insn in insns:
    print("  0x{:X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# Now try BINARY PATTERN SEARCH instead of disassembly
# Look for Thumb2 STR.W encoding: 1111 1000 1100 Rn | Rt imm12
# STR.W Rt, [Rn, #imm12]
# Encoding T3: 1111 1000 1100 NNNN | TTTT IIII IIIIIIII
# Bytes (little-endian): (0xF8 | (C0 >> 4)) (N0 | (C0 & 0xF)) T0 I_high I_low

print("\n\n" + "=" * 70)
print("BINARY PATTERN SEARCH: Thumb2 STR.W with large imm12 offset")
print("=" * 70)

# STR.W Rt, [Rn, #imm12]
# First halfword: 1111 1000 1100 RRRR = 0xF8C0 | Rn
# So bytes [0] = 0xC0 | (Rn & 0xF), bytes [1] = 0xF8
# Second halfword: RRRR IIII IIIIIIII = Rt<<12 | imm12
# bytes [2] = imm12 low byte, bytes [3] = Rt<<4 | imm12>>8

for off in range(0, len(abl4) - 3, 2):
    # Check for STR.W encoding
    hw1 = struct.unpack_from("<H", abl4, off)[0]
    if (hw1 & 0xFFF0) == 0xF8C0:  # STR.W Rt, [Rn, #imm12]
        rn = hw1 & 0xF
        hw2 = struct.unpack_from("<H", abl4, off + 2)[0]
        rt = (hw2 >> 12) & 0xF
        imm12 = hw2 & 0xFFF

        if imm12 >= 0x100:  # Large offset
            va = ABL4_BASE + off
            print("  VA 0x{:05X}: STR.W r{}, [r{}, #0x{:X}]".format(va, rt, rn, imm12))

# Also look for STR (immediate, T2): encoding 0110 0 iiiii nnn ttt
# STR Rt, [Rn, #imm5*4] — max offset = 31*4 = 124. Too small.

# And STR (immediate, T3): same as above F8C0
# But also STRB.W, STRH.W with similar encodings

# STRB.W: 1111 1000 1000 Rn | Rt imm12 = 0xF880 | Rn
print("\n--- STRB.W with offset >= 0x500 ---")
for off in range(0, len(abl4) - 3, 2):
    hw1 = struct.unpack_from("<H", abl4, off)[0]
    if (hw1 & 0xFFF0) == 0xF880:
        rn = hw1 & 0xF
        hw2 = struct.unpack_from("<H", abl4, off + 2)[0]
        rt = (hw2 >> 12) & 0xF
        imm12 = hw2 & 0xFFF
        if imm12 >= 0x500:
            va = ABL4_BASE + off
            print("  VA 0x{:05X}: STRB.W r{}, [r{}, #0x{:X}]".format(va, rt, rn, imm12))

# STRH.W: 1111 1000 1010 Rn | Rt imm12 = 0xF8A0 | Rn
print("\n--- STRH.W with offset >= 0x500 ---")
for off in range(0, len(abl4) - 3, 2):
    hw1 = struct.unpack_from("<H", abl4, off)[0]
    if (hw1 & 0xFFF0) == 0xF8A0:
        rn = hw1 & 0xF
        hw2 = struct.unpack_from("<H", abl4, off + 2)[0]
        rt = (hw2 >> 12) & 0xF
        imm12 = hw2 & 0xFFF
        if imm12 >= 0x500:
            va = ABL4_BASE + off
            print("  VA 0x{:05X}: STRH.W r{}, [r{}, #0x{:X}]".format(va, rt, rn, imm12))

# Also look for ADD with large immediate that could compute context+0x5xx
# ADD.W Rd, Rn, #imm12 -> could be computing context+offset for a subsequent STR
print("\n--- ADD.W with imm >= 0x500 (context+offset computation) ---")
count = 0
for off in range(0, len(abl4) - 3, 2):
    hw1 = struct.unpack_from("<H", abl4, off)[0]
    # ADD.W: 1111 0x01 0000 Rn | 0 imm3 Rd imm8
    # Encoding T3: 1111 0i01 0000 NNNN | 0iii DDDD iiiiiiii
    if (hw1 & 0xFBE0) == 0xF100:  # ADD.W Rd, Rn, #const
        rn = hw1 & 0xF
        hw2 = struct.unpack_from("<H", abl4, off + 2)[0]
        rd = (hw2 >> 8) & 0xF
        # Decode modified constant (simplified - just check raw imm12)
        i = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 7
        imm8 = hw2 & 0xFF
        imm12 = (i << 11) | (imm3 << 8) | imm8

        if imm12 >= 0x500 and imm12 <= 0x700:
            va = ABL4_BASE + off
            print("  VA 0x{:05X}: ADD.W r{}, r{}, #0x{:X} (raw imm12=0x{:X})".format(
                va, rd, rn, imm12, imm12))
            count += 1
            if count > 30:
                print("  ... (truncated)")
                break

# MOVW/MOVT for constructing large offsets
print("\n--- MOVW with value 0x500..0x700 ---")
for off in range(0, len(abl4) - 3, 2):
    hw1 = struct.unpack_from("<H", abl4, off)[0]
    # MOVW: 1111 0i10 0100 imm4 | 0 imm3 Rd imm8
    if (hw1 & 0xFBF0) == 0xF240:
        hw2 = struct.unpack_from("<H", abl4, off + 2)[0]
        imm4 = hw1 & 0xF
        i = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 7
        rd = (hw2 >> 8) & 0xF
        imm8 = hw2 & 0xFF
        val = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
        if 0x500 <= val <= 0x700:
            va = ABL4_BASE + off
            print("  VA 0x{:05X}: MOVW r{}, #0x{:X}".format(va, rd, val))

print("\nDone.")
