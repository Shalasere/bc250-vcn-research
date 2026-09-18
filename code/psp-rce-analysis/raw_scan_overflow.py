#!/usr/bin/env python3
"""Raw byte-pattern scan for PUSH prologues, then disassemble each function individually.
Capstone linear sweep dies on interleaved data - must disassemble per-function.

Thumb PUSH with LR encodings:
  Narrow T1: [reg_list, 0xB5] (2 bytes) — PUSH {regs, LR}
  Wide T2:   [0x2D, 0xE9, mask_lo, mask_hi] (4 bytes) — PUSH.W {regs, LR}
  where mask has bit 14 (LR) set
"""
import struct
from capstone import *
from capstone.arm import *

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

OVERFLOW_OFF = 0x11ABD
OVERFLOW_VA = ABL4_BASE + OVERFLOW_OFF

# Step 1: Find all PUSH prologues by raw byte scan
func_starts = []

for off in range(0x14, len(abl4) - 1, 2):  # Thumb = 2-byte aligned
    # Narrow PUSH with LR: byte[1]=0xB5
    if abl4[off+1] == 0xB5:
        func_starts.append(off)
    # Wide PUSH.W: [0x2D, 0xE9, mask_lo, mask_hi] where mask has bit 14 set (LR)
    elif off + 3 < len(abl4) and abl4[off] == 0x2D and abl4[off+1] == 0xE9:
        mask = struct.unpack_from("<H", abl4, off+2)[0]
        if mask & 0x4000:  # bit 14 = LR
            func_starts.append(off)

func_starts.sort()
print("Found {} PUSH prologues by raw scan".format(len(func_starts)))

# Show functions near the overflow string
print("\nFunctions near overflow string (+0x{:05X}):".format(OVERFLOW_OFF))
for off in func_starts:
    if 0x0E000 <= off <= 0x13000:
        print("  +0x{:05X} (VA 0x{:X})".format(off, ABL4_BASE + off))

# Find the function whose code most likely contains the overflow path
# The overflow string is at +0x11ABD. In AGESA IDS layout, the function
# that USES this string has its code BEFORE the string, and the string
# is in its literal pool/data section that follows the code.
# So we need the LAST function prologue that starts BEFORE +0x11ABD
# whose code extends up to the string region.

nearest_before = None
for off in reversed(func_starts):
    if off < OVERFLOW_OFF:
        nearest_before = off
        break

next_after = None
for off in func_starts:
    if off > OVERFLOW_OFF:
        next_after = off
        break

print("\nNearest function BEFORE overflow: +0x{:05X} (VA 0x{:X})".format(
    nearest_before, ABL4_BASE + nearest_before) if nearest_before else "None")
print("Next function AFTER overflow: +0x{:05X} (VA 0x{:X})".format(
    next_after, ABL4_BASE + next_after) if next_after else "None")

# Step 2: Disassemble the function nearest before the overflow string
if nearest_before:
    # Determine end boundary: either next function or overflow string area
    end = next_after if next_after else min(nearest_before + 0x2000, len(abl4))
    chunk = abl4[nearest_before:end]

    print("\n=== Disassembly of function at +0x{:05X} ===".format(nearest_before))
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
    cs.detail = True

    insn_list = list(cs.disasm(chunk, ABL4_BASE + nearest_before))
    print("Instructions decoded: {}".format(len(insn_list)))

    # Show all instructions
    for insn in insn_list:
        off = insn.address - ABL4_BASE
        marker = ""
        if off == nearest_before:
            marker = " <-- FUNCTION START"
        # Check if this instruction accesses addresses near the overflow string
        for op in insn.operands:
            if op.type == ARM_OP_IMM:
                if abs(op.imm - OVERFLOW_VA) < 0x200:
                    marker = " <-- IMM near overflow!"
            elif op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                pool_addr = ((insn.address + 4) & ~3) + op.mem.disp
                pool_off = pool_addr - ABL4_BASE
                if 0 <= pool_off < len(abl4) - 3:
                    val = struct.unpack_from("<I", abl4, pool_off)[0]
                    val_off = val - ABL4_BASE
                    if abs(val_off - OVERFLOW_OFF) < 0x200:
                        marker = " <-- loads addr near overflow! (pool->0x{:X})".format(val)
        print("  0x{:08X} (+{:05X}): {:10s} {} {}".format(
            insn.address, off, insn.mnemonic, insn.op_str, marker))

# Step 3: Also check a wider set of functions that might reference the overflow
# The AGESA debug system might use an ID-based approach where the function
# calls a debug print routine with an ID that maps to the string.
# Let's look for the function(s) in the +0x10000-0x12000 range

print("\n=== All functions in +0x10000-0x12000 range, disassembled ===")
for fi, fstart in enumerate(func_starts):
    if fstart < 0x10000 or fstart > 0x12000:
        continue

    # Find end: next function start or +0x2000
    fend = fstart + 0x2000
    for fs2 in func_starts:
        if fs2 > fstart:
            fend = fs2
            break

    chunk = abl4[fstart:fend]
    cs_f = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
    cs_f.detail = True
    insns = list(cs_f.disasm(chunk, ABL4_BASE + fstart))

    # Check if this function has interesting string references
    has_overflow_ref = False
    has_apcb_ref = False
    interesting_refs = []

    for insn in insns:
        for op in insn.operands:
            if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                pool_addr = ((insn.address + 4) & ~3) + op.mem.disp
                pool_off = pool_addr - ABL4_BASE
                if 0 <= pool_off < len(abl4) - 3:
                    val = struct.unpack_from("<I", abl4, pool_off)[0]
                    val_off = val - ABL4_BASE
                    if 0x11000 <= val_off <= 0x15000:
                        # Resolve the string
                        s = ""
                        for j in range(min(60, len(abl4) - val_off)):
                            b = abl4[val_off + j]
                            if b == 0: break
                            if 0x20 <= b < 0x7F: s += chr(b)
                            else: s += "."
                        interesting_refs.append((insn.address, val_off, s))
                        if "BUFFER" in s or "OVERFLOW" in s:
                            has_overflow_ref = True
                        if "APCB" in s:
                            has_apcb_ref = True

    if insns or interesting_refs:
        tag = ""
        if has_overflow_ref: tag += " *** OVERFLOW ***"
        if has_apcb_ref: tag += " *** APCB ***"
        print("\n  FUN at +0x{:05X}: {} insns, {} string refs{}".format(
            fstart, len(insns), len(interesting_refs), tag))
        for addr, soff, s in interesting_refs[:5]:
            print("    0x{:08X} -> +0x{:05X}: \"{}\"".format(addr, soff, s[:60]))

# Step 4: Also check: maybe strings are referenced via MOVW/MOVT in function bodies
print("\n=== MOVW/MOVT search across ALL functions ===")
for fstart in func_starts:
    fend = fstart + 0x2000
    for fs2 in func_starts:
        if fs2 > fstart:
            fend = fs2
            break

    chunk = abl4[fstart:fend]
    cs_m = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
    cs_m.detail = True

    movw_vals = {}
    for insn in cs_m.disasm(chunk, ABL4_BASE + fstart):
        if insn.mnemonic in ("movw", "mov.w", "movt", "movt.w"):
            for op in insn.operands:
                if op.type == ARM_OP_IMM:
                    movw_vals[insn.address] = (insn.mnemonic, op.imm)

    # Check for pairs: MOVW Rn,#lo; MOVT Rn,#hi where combined = string VA
    for addr1, (mn1, v1) in movw_vals.items():
        if "movw" in mn1 or (mn1 == "mov.w" and v1 < 0x10000):
            for addr2, (mn2, v2) in movw_vals.items():
                if "movt" in mn2 and abs(addr2 - addr1) < 16:
                    combined = (v2 << 16) | v1
                    combined_off = combined - ABL4_BASE
                    if 0x11000 <= combined_off <= 0x15000:
                        s = ""
                        for j in range(min(40, len(abl4) - combined_off)):
                            b = abl4[combined_off + j]
                            if b == 0: break
                            if 0x20 <= b < 0x7F: s += chr(b)
                        print("  +0x{:05X}: MOVW 0x{:04X} + MOVT 0x{:04X} = VA 0x{:X} -> \"{}\"".format(
                            fstart, v1, v2, combined, s))
