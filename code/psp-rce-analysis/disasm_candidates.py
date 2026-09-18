#!/usr/bin/env python3
"""Disassemble candidate functions near overflow and check EVERY instruction.
Functions at +0x10A34, +0x10AAC, +0x10B88 are within ADR.W range of the overflow string.
Also: try disassembly starting from MORE points in the +0x10000-0x11000 range.
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

# Find all PUSH prologues
func_starts = []
for off in range(0x14, len(abl4) - 1, 2):
    if abl4[off+1] == 0xB5:
        func_starts.append(off)
    elif off + 3 < len(abl4) and abl4[off] == 0x2D and abl4[off+1] == 0xE9:
        mask = struct.unpack_from("<H", abl4, off+2)[0]
        if mask & 0x4000:
            func_starts.append(off)
func_starts.sort()

# Disassemble each candidate function thoroughly
candidates = [off for off in func_starts if 0x0F000 <= off <= 0x11000]
print("Candidate functions (could reach overflow string): {}".format(
    ["0x{:05X}".format(x) for x in candidates]))

def find_strings_in_func(func_off):
    """Disassemble function and find ALL string references via ADR, LDR [PC], etc."""
    # Find end: next PUSH or overflow string area
    func_end = func_off + 0x3000
    for fs in func_starts:
        if fs > func_off:
            func_end = fs
            break

    chunk = abl4[func_off:func_end]
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
    cs.detail = True

    results = {
        'insns': 0,
        'adrs': [],
        'ldr_pc': [],
        'bls': [],
        'svcs': [],
        'all_insns': []
    }

    for insn in cs.disasm(chunk, ABL4_BASE + func_off):
        results['insns'] += 1
        ins_off = insn.address - ABL4_BASE
        results['all_insns'].append((ins_off, insn.mnemonic, insn.op_str))

        # Check for ADR/ADR.W
        if insn.mnemonic in ("adr", "adr.w"):
            for op in insn.operands:
                if op.type == ARM_OP_IMM:
                    target_off = op.imm - ABL4_BASE
                    results['adrs'].append((ins_off, op.imm, target_off))

        # Check for LDR [PC, #offset] — literal pool loads
        if insn.mnemonic in ("ldr", "ldr.w"):
            for op in insn.operands:
                if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                    pool_addr = ((insn.address + 4) & ~3) + op.mem.disp
                    pool_off = pool_addr - ABL4_BASE
                    if 0 <= pool_off < len(abl4) - 3:
                        val = struct.unpack_from("<I", abl4, pool_off)[0]
                        results['ldr_pc'].append((ins_off, pool_off, val))

        # BL calls
        if insn.mnemonic == "bl":
            for op in insn.operands:
                if op.type == ARM_OP_IMM:
                    results['bls'].append((ins_off, op.imm))

        # SVC
        if insn.mnemonic == "svc":
            results['svcs'].append((ins_off, insn.op_str))

    return results

for foff in candidates:
    r = find_strings_in_func(foff)
    print("\n{'=' * 60}")
    print("Function at +0x{:05X} (VA 0x{:X}): {} instructions".format(
        foff, ABL4_BASE + foff, r['insns']))

    if r['adrs']:
        print("  ADR targets:")
        for off, va, tgt_off in r['adrs']:
            s = ""
            if 0 <= tgt_off < len(abl4):
                for j in range(min(40, len(abl4) - tgt_off)):
                    b = abl4[tgt_off + j]
                    if b == 0: break
                    if 0x20 <= b < 0x7F: s += chr(b)
                    else: s += "."
            marker = ""
            if abs(tgt_off - OVERFLOW_OFF) < 16:
                marker = " *** OVERFLOW ***"
            print("    +0x{:05X}: ADR -> VA 0x{:X} (+0x{:05X}) -> \"{}\" {}".format(
                off, va, tgt_off, s[:50], marker))

    if r['ldr_pc']:
        print("  LDR [PC] pool loads:")
        for off, pool_off, val in r['ldr_pc']:
            note = ""
            val_off = val - ABL4_BASE
            if 0 <= val_off < len(abl4):
                s = ""
                for j in range(min(40, len(abl4) - val_off)):
                    b = abl4[val_off + j]
                    if b == 0: break
                    if 0x20 <= b < 0x7F: s += chr(b)
                    else: break
                if s:
                    note = "-> \"{}\"".format(s[:40])
            if abs(val - OVERFLOW_VA) < 16:
                note = "*** OVERFLOW VA ***"
            print("    +0x{:05X}: pool@+0x{:05X} = 0x{:08X} {}".format(
                off, pool_off, val, note))

    if r['bls']:
        print("  BL calls: {}".format(
            ["0x{:X}".format(va) for _, va in r['bls'][:20]]))

    if r['svcs']:
        print("  SVCs: {}".format(r['svcs']))

    # Show full disassembly
    print("  Full disassembly:")
    for off, mn, ops in r['all_insns']:
        marker = ""
        print("    0x{:08X} (+{:05X}): {:10s} {} {}".format(
            ABL4_BASE + off, off, mn, ops, marker))

# ALSO: check the big function at +0x10460 — it had 342 instructions
# It might use ADR.W to reach the overflow string (0x10460 + 4095 = 0x1143F, overflow is at 0x11ABD — OUT OF RANGE)
# Actually 0x10460 + 4095 = 0x1145F — NOT enough to reach 0x11ABD
# But instructions at the END of the function (which has 342 insns) might be at ~0x10460+342*2 = 0x10740+
# From 0x10740: 0x10740 + 4095 = 0x1173F — still not enough
# Let me check where this function actually ends

print("\n\n=== Function at +0x10460 (342 insns, checking last instructions) ===")
r = find_strings_in_func(0x10460)
print("Instructions: {}, last at: +0x{:05X}".format(
    r['insns'],
    r['all_insns'][-1][0] if r['all_insns'] else 0))
if r['adrs']:
    print("ADR targets:")
    for off, va, tgt_off in r['adrs']:
        s = ""
        if 0 <= tgt_off < len(abl4):
            for j in range(min(40, len(abl4) - tgt_off)):
                b = abl4[tgt_off + j]
                if b == 0: break
                if 0x20 <= b < 0x7F: s += chr(b)
                else: s += "."
        marker = ""
        if abs(tgt_off - OVERFLOW_OFF) < 1024:
            marker = " <<< NEAR OVERFLOW >>>"
        print("    +0x{:05X}: ADR -> +0x{:05X} -> \"{}\" {}".format(off, tgt_off, s[:50], marker))
