#!/usr/bin/env python3
"""Disassemble FUN_0006f1d8 and the REAL dispatch target.

FUN_0006f1d8 is 18 bytes. Let's see the actual instruction sequence
and trace where the indirect call goes.

Also disassemble 0x60FE8 with full branch following to understand the
actual function boundaries.
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# 1. Disassemble FUN_0006f1d8 (token write wrapper — 18 bytes)
print("=" * 70)
print("FUN_0006f1d8 — token write wrapper (18 bytes)")
print("=" * 70)
off = 0x6F1D8 - ABL4_BASE
insns = list(cs.disasm(abl4[off:off+18], 0x6F1D8))
for insn in insns:
    print("  0x{:05X}: {:8s} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 2. Disassemble FUN_0006bb9c (token read wrapper — 18 bytes)
print("\n" + "=" * 70)
print("FUN_0006bb9c — token read wrapper (18 bytes)")
print("=" * 70)
off = 0x6BB9C - ABL4_BASE
insns = list(cs.disasm(abl4[off:off+18], 0x6BB9C))
for insn in insns:
    print("  0x{:05X}: {:8s} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 3. Disassemble FUN_0006f1ec (called by FUN_0006f214 at the end)
print("\n" + "=" * 70)
print("FUN_0006f1ec (18 bytes from channel selector)")
print("=" * 70)
off = 0x6F1EC - ABL4_BASE
insns = list(cs.disasm(abl4[off:off+40], 0x6F1EC))
for insn in insns:
    print("  0x{:05X}: {:8s} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 4. Now look at the FULL disassembly from 0x60F00 to 0x61400
# to understand the function structure
print("\n" + "=" * 70)
print("Full disassembly: 0x60F00 - 0x61334 (code gap)")
print("=" * 70)
start = 0x60F00
end = 0x61334
off = start - ABL4_BASE
insns = list(cs.disasm(abl4[off:off+(end-start)], start))
print("  {} instructions in {} bytes".format(len(insns), end - start))

# Find PUSH instructions (function entries)
for insn in insns:
    if insn.mnemonic in ['push', 'push.w']:
        print("  PUSH at 0x{:05X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# Find BX LR / POP PC (function returns)
for insn in insns:
    if (insn.mnemonic == 'bx' and 'lr' in insn.op_str) or \
       (insn.mnemonic in ['pop', 'pop.w'] and 'pc' in insn.op_str):
        print("  RET  at 0x{:05X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# Show context around 0x60FE8
print("\n  Context around 0x60FE8:")
for insn in insns:
    if 0x60FC0 <= insn.address <= 0x61010:
        marker = " >>>" if insn.address == 0x60FE8 else "    "
        print("  {} 0x{:05X}: {:8s} {}".format(marker, insn.address, insn.mnemonic, insn.op_str))

# 5. Now the CRITICAL test: What does FUN_0006f1d8 actually DO?
# Let me read the raw instruction bytes and decode the indirect call
print("\n" + "=" * 70)
print("FUN_0006f1d8 instruction-by-instruction")
print("=" * 70)
off = 0x6F1D8 - ABL4_BASE
# Show raw bytes
raw = abl4[off:off+18]
print("  Raw: {}".format(raw.hex()))

# Decode manually
# Thumb2 LDR.W Rt, [Rn, #imm12]: F8D0 | Rn, then Rt<<12 | imm12
# For loading context+0x660: LDR.W Rn, [R0, #0x660]
for i in range(0, len(raw) - 1, 2):
    hw = struct.unpack_from("<H", raw, i)[0]
    print("  +{}: {:04X}".format(i, hw))

# 6. Look for the ACTUAL token data store function
# The dispatch at +0x660 points to 0x60FE9. But maybe there's a DIFFERENT
# dispatch path. Let me look at FUN_0006804C's token processor for clues
# about where token data is STORED and RETRIEVED.
print("\n" + "=" * 70)
print("Searching for token store/load patterns in ABL4")
print("=" * 70)

# Search for instructions that load from +0x660
# LDR.W Rt, [Rn, #0x660] = F8D0|Rn, Rt<<12|0x660
for off in range(0, len(abl4) - 3, 2):
    hw1 = struct.unpack_from("<H", abl4, off)[0]
    if (hw1 & 0xFFF0) == 0xF8D0:  # LDR.W
        rn = hw1 & 0xF
        hw2 = struct.unpack_from("<H", abl4, off + 2)[0]
        rt = (hw2 >> 12) & 0xF
        imm12 = hw2 & 0xFFF
        if imm12 == 0x660:
            va = ABL4_BASE + off
            print("  VA 0x{:05X}: LDR.W r{}, [r{}, #0x660]".format(va, rt, rn))

# 7. Search for BLX or BX that dereference an address loaded from +0x660 area
# Pattern: LDR Rx, [Ry, #0x660] followed by BLX Rx
print("\n  LDR from +0x660 followed by BLX:")
insns = list(cs.disasm(abl4, ABL4_BASE))
for i, insn in enumerate(insns):
    if insn.mnemonic in ['ldr', 'ldr.w']:
        ops = insn.op_str.lower()
        if '#0x660' in ops:
            # Look ahead for BLX/BX using the loaded register
            dest_reg = ops.split(',')[0].strip()
            for j in range(i+1, min(i+5, len(insns))):
                next_insn = insns[j]
                if next_insn.mnemonic in ['blx', 'bx'] and dest_reg in next_insn.op_str.lower():
                    print("  {} / {} at 0x{:05X}-0x{:05X}".format(
                        insn.op_str, next_insn.op_str,
                        insn.address, next_insn.address))
                    # Show context
                    for k in range(max(0,i-2), min(len(insns),j+2)):
                        ctx = insns[k]
                        print("    0x{:05X}: {:8s} {}".format(ctx.address, ctx.mnemonic, ctx.op_str))

print("\nDone.")
