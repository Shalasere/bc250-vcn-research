#!/usr/bin/env python3
"""Debug capstone disassembly of ABL4."""
import struct
from capstone import *
from capstone.arm import *

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

print("ABL4 size: {} bytes".format(len(abl4)))
print("First 32 bytes: {}".format(abl4[:32].hex()))

# Test 1: Disassemble the ARM trampoline (first 0x14 bytes)
print("\n=== ARM trampoline (first 0x14 bytes) ===")
cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
arm_code = abl4[:0x14]
count = 0
for insn in cs_arm.disasm(arm_code, ABL4_BASE):
    print("  0x{:08X}: {:8s} {}".format(insn.address, insn.mnemonic, insn.op_str))
    count += 1
print("ARM instructions: {}".format(count))

# Test 2: Small Thumb chunk at +0x14
print("\n=== Thumb code at +0x14 (64 bytes) ===")
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
thumb_code = abl4[0x14:0x14+64]
print("Raw hex: {}".format(thumb_code[:32].hex()))
count = 0
for insn in cs_thumb.disasm(thumb_code, ABL4_BASE + 0x14):
    print("  0x{:08X}: {:8s} {}".format(insn.address, insn.mnemonic, insn.op_str))
    count += 1
print("Thumb instructions: {}".format(count))

# Test 3: Check a known code region — the entry at +0x14
# From prior analysis, entry is: PUSH {R4,LR}; LDR R2,[PC,#4]; BLX R2
print("\n=== Bytes at +0x14: {}".format(abl4[0x14:0x24].hex()))

# Test 4: Try Thumb disassembly of a larger chunk
print("\n=== Thumb code at +0x14 (4K), counting PUSHes ===")
cs2 = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
chunk = abl4[0x14:0x1014]
total = 0
pushes = 0
for insn in cs2.disasm(chunk, ABL4_BASE + 0x14):
    total += 1
    if insn.mnemonic in ("push", "push.w") and "lr" in insn.op_str:
        pushes += 1
        if pushes <= 5:
            print("  PUSH at 0x{:08X} (+{:05X}): {} {}".format(
                insn.address, insn.address - ABL4_BASE, insn.mnemonic, insn.op_str))
print("Total instructions in 4K: {}, PUSHes with LR: {}".format(total, pushes))

# Test 5: Full scan for function prologues with fresh Cs instance each time
# Maybe the issue was detail=True interfering
print("\n=== Full scan for function prologues (no detail) ===")
cs3 = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
full_code = abl4[0x14:0x12000]
func_starts = []
total3 = 0
for insn in cs3.disasm(full_code, ABL4_BASE + 0x14):
    total3 += 1
    if insn.mnemonic in ("push", "push.w") and "lr" in insn.op_str:
        func_starts.append(insn.address - ABL4_BASE)
print("Total instructions: {}, Functions: {}".format(total3, len(func_starts)))
if func_starts:
    print("First 10: {}".format(["0x{:05X}".format(x) for x in func_starts[:10]]))
    print("Last 10: {}".format(["0x{:05X}".format(x) for x in func_starts[-10:]]))

    # Find the function nearest before the overflow string
    for off in reversed(func_starts):
        if off < 0x11ABD:
            print("\nNearest function BEFORE overflow: +0x{:05X}".format(off))
            break

# Test 6: Search for SVC instructions
print("\n=== SVC instructions ===")
cs4 = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
for insn in cs4.disasm(full_code, ABL4_BASE + 0x14):
    if insn.mnemonic == "svc":
        print("  SVC at 0x{:08X} (+{:05X}): {} {}".format(
            insn.address, insn.address - ABL4_BASE, insn.mnemonic, insn.op_str))
