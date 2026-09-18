#!/usr/bin/env python3
"""Scan ABL4 binary for STR instructions with offsets >= 0x100 that could
overflow into the vtable at context+0x660.

Also scan for:
1. BL to memcpy (FUN_00060870) where length comes from memory (not immediate)
2. Any write loop that uses a variable offset >= 0x100
3. The SPECIFIC functions that write APCB data into context+0x510..0x660
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

print("ABL4: {} bytes, base 0x{:X}".format(len(abl4), ABL4_BASE))

# ============ PART 1: STR with offset >= 0x500 ============
print("\n" + "=" * 70)
print("PART 1: STR instructions with offset >= 0x500")
print("=" * 70)

insns = list(cs.disasm(abl4, ABL4_BASE))
print("  Total instructions: {}".format(len(insns)))

big_stores = []
for insn in insns:
    mn = insn.mnemonic.lower()
    if not mn.startswith('str'):
        continue

    for op in insn.operands:
        if op.type == 4:  # MEM
            disp = op.mem.disp
            if disp >= 0x500:
                base_reg = insn.reg_name(op.mem.base) if op.mem.base != 0 else "?"
                big_stores.append((insn.address, mn, insn.op_str, disp, base_reg))

print("  Found {} STR with offset >= 0x500:".format(len(big_stores)))
for addr, mn, ops, disp, base in big_stores:
    print("  0x{:05X}: {:8s} {} (offset +0x{:X}, base={})".format(addr, mn, ops, disp, base))

# ============ PART 2: STR with offset >= 0x100 (could be overflow start) ============
print("\n" + "=" * 70)
print("PART 2: STR instructions with offset 0x100..0x6A0 (overflow candidates)")
print("=" * 70)

for insn in insns:
    mn = insn.mnemonic.lower()
    if not mn.startswith('str'):
        continue

    for op in insn.operands:
        if op.type == 4:
            disp = op.mem.disp
            if 0x100 <= disp <= 0x6A0:
                base_reg = insn.reg_name(op.mem.base) if op.mem.base != 0 else "?"
                # Only show if base register is likely a parameter (r0-r3) or context pointer
                if base_reg in ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8']:
                    pass  # Show all
                print("  0x{:05X}: {:8s} {} (+0x{:X})".format(insn.address, mn, insn.op_str, disp))

# ============ PART 3: Find memcpy (FUN_00060870) calls with variable length ============
print("\n" + "=" * 70)
print("PART 3: BL to FUN_00060870 (memcpy-like) — check R2 (length) source")
print("=" * 70)

memcpy_addr = 0x60870
for i, insn in enumerate(insns):
    mn = insn.mnemonic.lower()
    if mn != 'bl':
        continue
    if len(insn.operands) == 0:
        continue
    target = insn.operands[0].imm
    if target != memcpy_addr:
        continue

    # Look back for R2 (length argument) setup
    r2_source = "UNKNOWN"
    for j in range(max(0, i-15), i):
        prev = insns[j]
        pmn = prev.mnemonic.lower()
        pops = prev.op_str.lower()

        if (pmn in ['mov', 'mov.w', 'movw', 'movs'] and pops.startswith('r2,')) or \
           (pmn in ['ldr', 'ldr.w'] and pops.startswith('r2,')) or \
           (pmn in ['add', 'add.w'] and pops.startswith('r2,')):
            r2_source = "0x{:05X}: {} {}".format(prev.address, prev.mnemonic, prev.op_str)

    # Also look for R0 (dest) to see if it's context-relative
    r0_source = "UNKNOWN"
    for j in range(max(0, i-15), i):
        prev = insns[j]
        pmn = prev.mnemonic.lower()
        pops = prev.op_str.lower()

        if (pmn.startswith('add') and pops.startswith('r0,')) or \
           (pmn in ['mov', 'movs', 'ldr'] and pops.startswith('r0,')):
            r0_source = "0x{:05X}: {} {}".format(prev.address, prev.mnemonic, prev.op_str)

    print("  BL 0x{:05X} at 0x{:05X}:".format(memcpy_addr, insn.address))
    print("    R0 (dest): {}".format(r0_source))
    print("    R2 (len):  {}".format(r2_source))

# ============ PART 4: Also check FUN_000604E0 (the other memcpy) ============
print("\n" + "=" * 70)
print("PART 4: BL to other copy functions — check R2")
print("=" * 70)

# Search for all BL instructions and identify potential copy functions
bl_targets = {}
for insn in insns:
    if insn.mnemonic.lower() == 'bl' and len(insn.operands) > 0:
        t = insn.operands[0].imm
        bl_targets[t] = bl_targets.get(t, 0) + 1

# Show top-called functions (likely utility functions like memcpy, memset)
top_funcs = sorted(bl_targets.items(), key=lambda x: -x[1])[:20]
print("  Top 20 most-called functions:")
for target, count in top_funcs:
    print("    0x{:05X}: {} calls".format(target, count))

# ============ PART 5: Search for the SPECIFIC write to context+0x510..0x660 ============
print("\n" + "=" * 70)
print("PART 5: All STR with offset in 0x510..0x6A0 range")
print("=" * 70)

for insn in insns:
    mn = insn.mnemonic.lower()
    if not mn.startswith('str'):
        continue
    for op in insn.operands:
        if op.type == 4:
            disp = op.mem.disp
            if 0x510 <= disp <= 0x6A0:
                base_reg = insn.reg_name(op.mem.base) if op.mem.base != 0 else "?"
                # Show surrounding context
                idx = insns.index(insn)
                print("\n  0x{:05X}: {} {} (offset +0x{:X}, base={})".format(
                    insn.address, mn, insn.op_str, disp, base_reg))
                for k in range(max(0, idx-5), min(len(insns), idx+3)):
                    ctx = insns[k]
                    marker = " >>>" if ctx.address == insn.address else "    "
                    print("  {} 0x{:05X}: {:8s} {}".format(marker, ctx.address, ctx.mnemonic, ctx.op_str))

# ============ PART 6: Look for loop writes using variable register offset ============
print("\n" + "=" * 70)
print("PART 6: STR with register offset (STR Rt, [Rn, Rm]) near loops")
print("=" * 70)

# Find STR with register index (variable offset writes)
var_stores = []
for insn in insns:
    mn = insn.mnemonic.lower()
    if not mn.startswith('str'):
        continue
    for op in insn.operands:
        if op.type == 4:  # MEM
            if op.mem.index != 0:  # Has index register (variable offset)
                base = insn.reg_name(op.mem.base) if op.mem.base != 0 else "?"
                idx_reg = insn.reg_name(op.mem.index) if op.mem.index != 0 else "?"
                var_stores.append((insn.address, mn, insn.op_str, base, idx_reg))

print("  Found {} STR with register offset (first 50):".format(len(var_stores)))
for addr, mn, ops, base, idx in var_stores[:50]:
    print("  0x{:05X}: {:8s} {} (base={}, idx={})".format(addr, mn, ops, base, idx))

print("\nDone.")
