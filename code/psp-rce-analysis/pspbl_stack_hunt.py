#!/usr/bin/env python3
"""Find the SVC stack pointer in PSP_BL.

Strategy:
1. Disassemble the vector table/header at 0x0000
2. Search for MSR/CPS instructions and SP initialization
3. Search for literal pool values between context(0x5D7AC) and ABL4(0x60834)
4. Enumerate ALL functions with large stack frames
5. Find cumulative stack depth in worst-case call chains
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

print("PSP_BL binary: {} bytes (0x{:X})".format(len(pspbl), len(pspbl)))

# 1. Header / vector table
print("\n" + "=" * 70)
print("1. First 64 bytes as 32-bit words")
print("=" * 70)
for i in range(0, 64, 4):
    val = struct.unpack_from("<I", pspbl, i)[0]
    print("  +0x{:02X}: 0x{:08X}".format(i, val))

# 2. Disassemble from 0 in both ARM and Thumb
print("\n" + "=" * 70)
print("2a. ARM mode disassembly at offset 0")
print("=" * 70)
cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
for insn in cs_arm.disasm(pspbl[:64], 0):
    print("  0x{:04X}: {:8s} {}".format(insn.address, insn.mnemonic, insn.op_str))

print("\n2b. Thumb mode disassembly at offset 0")
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True
for insn in cs.disasm(pspbl[:64], 0):
    print("  0x{:04X}: {:8s} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 3. ALL SP-setting instructions in PSP_BL
print("\n" + "=" * 70)
print("3. ALL SP-modifying instructions")
print("=" * 70)
all_insns = list(cs.disasm(pspbl[:0x9A00], 0))
for insn in all_insns:
    mn = insn.mnemonic.lower()
    ops = insn.op_str.lower()
    # MOV SP, Rn
    if mn == 'mov' and ops.startswith('sp'):
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))
    # LDR SP, ...
    if mn.startswith('ldr') and ops.startswith('sp'):
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))
    # MSR instructions
    if mn.startswith('msr'):
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))
    # CPS instructions (change processor state)
    if mn.startswith('cps'):
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 4. Literal pool values in 0x50000-0x80000 range
print("\n" + "=" * 70)
print("4. Literal pool values 0x50000-0x80000 (SRAM data/stack region)")
print("=" * 70)
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if 0x50000 <= val <= 0x80000:
        print("  pool[0x{:04X}] = 0x{:08X}  (delta from 0x5D7AC: {:+d}, from 0x5DE0C: {:+d})".format(
            off, val, val - 0x5D7AC, val - 0x5DE0C))

# 5. All functions sorted by stack frame size
print("\n" + "=" * 70)
print("5. Top 30 functions by stack frame size")
print("=" * 70)

frames = []
i = 0
while i < len(all_insns):
    insn = all_insns[i]
    if insn.mnemonic.lower() == 'push':
        func_addr = insn.address
        push_regs = len(insn.operands)
        sub_sp_total = 0
        # Scan next 30 instructions for SUB SP
        for j in range(i+1, min(i+30, len(all_insns))):
            ninsn = all_insns[j]
            nmn = ninsn.mnemonic.lower()
            nops = ninsn.op_str.lower()
            if nmn == 'pop' or (nmn == 'push'):
                break
            if nmn in ['sub', 'sub.w', 'subw'] and nops.startswith('sp'):
                for op in ninsn.operands:
                    if op.type == 2:  # immediate
                        sub_sp_total += op.imm
        total_frame = push_regs * 4 + sub_sp_total
        frames.append((func_addr, total_frame, push_regs, sub_sp_total))
    i += 1

frames.sort(key=lambda x: -x[1])
for addr, total, pregs, sub in frames[:30]:
    print("  0x{:04X}: {} bytes total (push {} regs = {} bytes, sub sp = {} bytes)".format(
        addr, total, pregs, pregs*4, sub))

# 6. Cumulative stack depth calculation
print("\n" + "=" * 70)
print("6. Stack depth calculation")
print("=" * 70)
# The SVC handler stack starts at SP_svc (unknown).
# FUN_000044CC is the SVC dispatcher, called from the PSP ROM's SVC handler.
# Worst-case call chain: 44CC -> 55C0 -> 7014 -> 71AC -> 1C18

chain_addrs = [0x44CC, 0x55C0, 0x7014, 0x71AC, 0x1C18]
frame_map = {}
for a, t, pr, sb in frames:
    frame_map[a] = (t, pr, sb)

total_depth = 0
for addr in chain_addrs:
    if addr in frame_map:
        t, pr, sb = frame_map[addr]
        total_depth += t
        print("  0x{:04X}: {} bytes (cum: {})".format(addr, t, total_depth))
    else:
        print("  0x{:04X}: NOT FOUND in frame scan".format(addr))

print("\n  Worst-case SVC chain depth: {} bytes".format(total_depth))
print("  If SP_svc = 0x5E000: 0x5E000 - {} = 0x{:X} → target 0x5DE0C reached? {}".format(
    total_depth, 0x5E000 - total_depth,
    "YES" if (0x5E000 - total_depth) <= 0x5DE0C else "NO (need {} more)".format(
        (0x5E000 - total_depth) - 0x5DE0C)))

# 7. Check OTHER possible stack start values
print("\n" + "=" * 70)
print("7. Stack reach analysis for different SP_svc values")
print("=" * 70)
for sp_start in [0x5D800, 0x5DA00, 0x5DC00, 0x5DE00, 0x5E000, 0x5E200,
                 0x5E400, 0x5E800, 0x5F000, 0x60000, 0x60834, 0x7F000]:
    dist = sp_start - 0x5DE0C
    if dist >= 0:
        print("  SP_svc = 0x{:05X}: distance to 0x5DE0C = {} bytes → reachable with {} byte frame".format(
            sp_start, dist, dist))
    else:
        print("  SP_svc = 0x{:05X}: BELOW target (stack already past 0x5DE0C)".format(sp_start))

print("\nDone.")
