#!/usr/bin/env python3
"""Find code that references the overflow string via ADR/ADR.W/LDR patterns.
AGESA uses ADR Rn, #offset to load string pointers for debug output.
The overflow string VA=0x722F1 can be reached by ADR.W from code in +0x10000-0x11A00 range.

Also: try block-by-block disassembly to find hidden code in the data gaps.
"""
import struct
from capstone import *
from capstone.arm import *

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

OVERFLOW_OFF = 0x11ABD
OVERFLOW_VA = ABL4_BASE + OVERFLOW_OFF  # 0x722F1

# Strategy 1: Block-by-block disassembly through the gap region
# The gap from +0x10C00 to +0x12000 contains interleaved code and data.
# Try disassembly at every 2-byte aligned offset and look for valid code runs.
print("=== Strategy 1: Block disassembly in gap region +0x10C00 to +0x11C00 ===")

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
cs.detail = True

# Try disassembly at each 2-byte aligned position, collect ADR/BL instructions
adr_hits = []
bl_hits = []
svc_hits = []

for start_off in range(0x10C00, 0x11C00, 2):
    # Try to disassemble a small window
    chunk = abl4[start_off:start_off+8]
    insns = list(cs.disasm(chunk, ABL4_BASE + start_off))
    if not insns:
        continue
    insn = insns[0]

    # Check for ADR/ADR.W
    if insn.mnemonic in ("adr", "adr.w", "add", "add.w"):
        # Check if any operand is an immediate that could be the overflow string
        for op in insn.operands:
            if op.type == ARM_OP_IMM:
                target_off = op.imm - ABL4_BASE
                if abs(target_off - OVERFLOW_OFF) < 16:
                    adr_hits.append((start_off, insn.mnemonic, insn.op_str, op.imm))
                    print("  ADR hit at +0x{:05X}: {} {} (target VA 0x{:X})".format(
                        start_off, insn.mnemonic, insn.op_str, op.imm))

    # Check for BL to debug print (0x62908)
    if insn.mnemonic == "bl":
        for op in insn.operands:
            if op.type == ARM_OP_IMM and op.imm == 0x62908:
                bl_hits.append(start_off)

    # Check for SVC
    if insn.mnemonic == "svc":
        svc_hits.append((start_off, insn.op_str))

print("\nBL 0x62908 (debug print) calls found in gap: {}".format(len(bl_hits)))
for off in bl_hits:
    print("  +0x{:05X}".format(off))

print("\nSVC calls in gap: {}".format(len(svc_hits)))
for off, ops in svc_hits:
    print("  +0x{:05X}: SVC {}".format(off, ops))

# Strategy 2: Search for LDR [PC, #offset] that loads from a pool entry containing the overflow VA
print("\n=== Strategy 2: LDR [PC, #n] loading overflow VA ===")
# The overflow VA is 0x722F1. A pool entry would be a u32 at some offset.
# But 0x722F1 is odd (Thumb address?). Let's also check 0x722F0 (aligned).
# And check for pointers to the string start: 0x722F1 without the \n prefix.
# Actually the string has \n prefix at +0x11ABC (0x0A before #)
# So the string pointer might be 0x722F0 (the \n\0\0\0\0\n before the #) or 0x722F1 (#BUFFER...)

# Also: AGESA IDS format strings are often preceded by a 4-byte header
# Let me check what's at +0x11AB7-0x11AC0:
print("Bytes before overflow string:")
for off in range(0x11AB0, 0x11AD0, 4):
    val = struct.unpack_from("<I", abl4, off)[0]
    ascii_str = ''.join(chr(abl4[off+j]) if 0x20 <= abl4[off+j] < 0x7F else '.' for j in range(4))
    print("  +0x{:05X}: 0x{:08X} '{}'".format(off, val, ascii_str))

# Search for u32 values that could be pointers to the overflow string area
print("\nSearching for u32s pointing to overflow string (VA 0x722F0-0x722F4):")
for off in range(0, len(abl4) - 3, 4):
    val = struct.unpack_from("<I", abl4, off)[0]
    if 0x722F0 <= val <= 0x722F4:
        print("  +0x{:05X}: 0x{:08X}".format(off, val))

# Strategy 3: Find code blocks by looking for BX LR / POP PC sequences
print("\n=== Strategy 3: Function boundaries in +0x10C00-0x11C00 ===")
# BX LR = 0x4770 in Thumb
# POP {Rn, PC} = 0xBDxx in Thumb (where xx has bit for PC set)
# POP.W with PC: E8BD xxxx where xxxx has bit 15

returns = []
for off in range(0x10C00, 0x11C00, 2):
    hw = struct.unpack_from("<H", abl4, off)[0]
    if hw == 0x4770:  # BX LR
        returns.append((off, "BX LR"))
    elif (hw & 0xFF00) == 0xBD00:  # POP with PC
        returns.append((off, "POP {..., PC}"))
    # Wide POP.W with PC
    if off + 2 < len(abl4):
        w = struct.unpack_from("<I", abl4, off)[0]
        if (w & 0xFFFF0000) >> 16 in range(0x8000, 0x10000):  # check mask has PC
            if (w & 0xFFFF) == 0xE8BD:
                mask = (w >> 16) & 0xFFFF
                if mask & 0x8000:
                    returns.append((off, "POP.W {..., PC}"))

print("Return instructions found:")
for off, kind in returns:
    print("  +0x{:05X}: {}".format(off, kind))

# Strategy 4: Disassemble from each return instruction backwards/forwards
# to find coherent code blocks
print("\n=== Strategy 4: Code blocks between returns ===")
for ret_off, ret_kind in returns:
    # Try to disassemble a chunk ending at this return
    # Start from the nearest known boundary before it
    search_start = max(0x10C00, ret_off - 0x200)

    # Try disassembly starting from various offsets before the return
    best_run = (0, 0)
    for try_start in range(search_start, ret_off, 2):
        chunk = abl4[try_start:ret_off + 4]
        cs2 = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
        insns = list(cs2.disasm(chunk, ABL4_BASE + try_start))
        if insns and insns[-1].address - ABL4_BASE == ret_off:
            run_len = len(insns)
            if run_len > best_run[0]:
                best_run = (run_len, try_start)

    if best_run[0] > 3:
        start = best_run[1]
        print("\n  Code block ending at +0x{:05X} ({}), {} insns from +0x{:05X}:".format(
            ret_off, ret_kind, best_run[0], start))
        chunk = abl4[start:ret_off + 4]
        cs3 = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
        cs3.detail = True
        for insn in cs3.disasm(chunk, ABL4_BASE + start):
            ins_off = insn.address - ABL4_BASE
            extra = ""
            # Check for ADR targeting overflow string
            for op in insn.operands:
                if op.type == ARM_OP_IMM:
                    imm_off = op.imm - ABL4_BASE
                    if abs(imm_off - OVERFLOW_OFF) < 16:
                        extra = " *** POINTS TO OVERFLOW STRING ***"
                    elif 0x11000 <= imm_off <= 0x12000:
                        # Resolve string
                        s = ""
                        for j in range(min(30, len(abl4) - imm_off)):
                            b = abl4[imm_off + j]
                            if b == 0: break
                            if 0x20 <= b < 0x7F: s += chr(b)
                        if s:
                            extra = " -> \"{}\"".format(s[:30])
                elif op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                    pool_addr = ((insn.address + 4) & ~3) + op.mem.disp
                    pool_off = pool_addr - ABL4_BASE
                    if 0 <= pool_off < len(abl4) - 3:
                        val = struct.unpack_from("<I", abl4, pool_off)[0]
                        if abs(val - OVERFLOW_VA) < 16:
                            extra = " *** POOL -> OVERFLOW VA 0x{:X} ***".format(val)
            print("    0x{:08X} (+{:05X}): {:10s} {} {}".format(
                insn.address, ins_off, insn.mnemonic, insn.op_str, extra))
