#!/usr/bin/env python3
"""Find the vulnerability function by analyzing the code/data interleaving pattern.
AGESA IDS: each function's strings sit RIGHT AFTER it in binary. So the function
using #BUFFER OVERFLOW# is the one whose code ends just before +0x11ABD.

Also: search for MOVW/MOVT pairs that construct 0x722F1 (overflow string VA).
"""
import struct
from capstone import *
from capstone.arm import *

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

OVERFLOW_OFF = 0x11ABD  # "#BUFFER  OVERFLOW#" in binary
OVERFLOW_VA = ABL4_BASE + OVERFLOW_OFF  # = 0x722F1

# 1. Find all function starts (PUSH with LR) in Thumb code
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

print("=== Step 1: Map all function boundaries ===")
func_starts = []
code = abl4[0x14:0x15000]  # All potential code
for insn in cs.disasm(code, ABL4_BASE + 0x14):
    if insn.mnemonic in ("push", "push.w") and "lr" in insn.op_str:
        func_starts.append(insn.address - ABL4_BASE)

print("Found {} function prologues".format(len(func_starts)))
func_starts.sort()

# Find the function that ends just before the overflow string
# The overflow string is at +0x11ABD. Look for functions starting before this
# and the NEXT function starting after this
prev_func = None
next_func = None
for i, off in enumerate(func_starts):
    if off > OVERFLOW_OFF:
        next_func = off
        if i > 0:
            prev_func = func_starts[i-1]
        break

if prev_func:
    print("\nFunction BEFORE overflow string: starts at +0x{:05X} (VA 0x{:X})".format(
        prev_func, ABL4_BASE + prev_func))
if next_func:
    print("Function AFTER overflow string: starts at +0x{:05X} (VA 0x{:X})".format(
        next_func, ABL4_BASE + next_func))

# But the actual function that USES the string may be further back if there's a
# large data section. Let's find ALL functions in the 0x10000-0x12000 range
print("\n=== Step 2: Functions in the overflow neighborhood ===")
for off in func_starts:
    if 0x0F000 <= off <= 0x13000:
        print("  +0x{:05X} (VA 0x{:X})".format(off, ABL4_BASE + off))

# 2. Look at what's immediately BEFORE the overflow string
# Scan backwards from +0x11ABD for the last code instruction
print("\n=== Step 3: Data/code boundary before overflow string ===")
# Check 256 bytes before the string
region_start = OVERFLOW_OFF - 256
region = abl4[region_start:OVERFLOW_OFF + 64]
print("Hex dump +0x{:05X} to +0x{:05X}:".format(region_start, OVERFLOW_OFF + 64))
for i in range(0, len(region), 16):
    off = region_start + i
    hexbytes = ' '.join("{:02X}".format(region[i+j]) for j in range(min(16, len(region)-i)))
    ascii_repr = ''.join(chr(region[i+j]) if 0x20 <= region[i+j] < 0x7F else '.'
                         for j in range(min(16, len(region)-i)))
    marker = ""
    if off <= OVERFLOW_OFF < off + 16:
        marker = " <-- OVERFLOW STRING"
    print("  +{:05X}: {:48s} {:16s} {}".format(off, hexbytes, ascii_repr, marker))

# 3. Disassemble the code chunk before the overflow string
# Find the start of the code section that precedes the string data
print("\n=== Step 4: Disassembly before overflow string ===")
# Search backwards for the function prologue nearest to OVERFLOW_OFF
nearest_func = None
for off in reversed(func_starts):
    if off < OVERFLOW_OFF:
        nearest_func = off
        break

if nearest_func:
    print("Nearest function before overflow: +0x{:05X}".format(nearest_func))
    chunk = abl4[nearest_func:OVERFLOW_OFF + 32]
    last_code_off = nearest_func
    cs2 = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs2.detail = True
    for insn in cs2.disasm(chunk, ABL4_BASE + nearest_func):
        insn_off = insn.address - ABL4_BASE
        if insn_off > OVERFLOW_OFF:
            break
        last_code_off = insn_off
        # Print last 30 instructions before the string
        if insn_off > OVERFLOW_OFF - 200:
            print("  0x{:08X} (+{:05X}): {:8s} {}".format(
                insn.address, insn_off, insn.mnemonic, insn.op_str))
    print("Last disassembled instruction: +0x{:05X}".format(last_code_off))

# 4. Search for MOVW/MOVT pairs constructing the overflow string VA
print("\n=== Step 5: MOVW/MOVT search for VA 0x{:X} ===".format(OVERFLOW_VA))
# OVERFLOW_VA = 0x722F1. MOVW loads low 16 bits (0x22F1), MOVT loads high 16 bits (0x0007)
target_lo = OVERFLOW_VA & 0xFFFF  # 0x22F1
target_hi = (OVERFLOW_VA >> 16) & 0xFFFF  # 0x0007

# Also check nearby strings: "Failed to get internal APCB parameter" at +0x11A76 (VA 0x722AA)
# and "Depth:%d >= MAX_DEPTH(%d)" at +0x113EC (VA 0x71C20)
targets = [
    (OVERFLOW_VA, "BUFFER_OVERFLOW"),
    (ABL4_BASE + 0x11A76, "Failed_APCB"),
    (ABL4_BASE + 0x113EC, "MAX_DEPTH"),
    (ABL4_BASE + 0x11A31, "IDS_INT_PARAM"),
]

cs3 = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs3.detail = True
code_full = abl4[0x14:0x15000]

for target_va, label in targets:
    tgt_lo = target_va & 0xFFFF
    tgt_hi = (target_va >> 16) & 0xFFFF
    print("\n  Target: {} = 0x{:X} (lo=0x{:04X} hi=0x{:04X})".format(
        label, target_va, tgt_lo, tgt_hi))

    # Search for MOVW Rn, #tgt_lo
    movw_hits = []
    for insn in cs3.disasm(code_full, ABL4_BASE + 0x14):
        if insn.mnemonic in ("movw", "mov.w"):
            for op in insn.operands:
                if op.type == ARM_OP_IMM and op.imm == tgt_lo:
                    movw_hits.append(insn.address)
                    print("    MOVW at 0x{:X} (+{:05X}): {} {}".format(
                        insn.address, insn.address - ABL4_BASE,
                        insn.mnemonic, insn.op_str))

    # Also search for MOVT with the high half
    cs4 = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs4.detail = True
    for insn in cs4.disasm(code_full, ABL4_BASE + 0x14):
        if insn.mnemonic in ("movt", "movt.w"):
            for op in insn.operands:
                if op.type == ARM_OP_IMM and op.imm == tgt_hi:
                    # Check if there's a nearby MOVW
                    for mw in movw_hits:
                        if abs(insn.address - mw) < 20:
                            print("    MOVT at 0x{:X} (+{:05X}): {} {} (paired with MOVW at 0x{:X})".format(
                                insn.address, insn.address - ABL4_BASE,
                                insn.mnemonic, insn.op_str, mw))

# 5. Alternative: search for SVC calls near the overflow string area
# ABL4 uses SVC #0xA for debug output. The overflow handler would call SVC with the string
print("\n=== Step 6: SVC calls in the code ===")
cs5 = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
for insn in cs5.disasm(code_full, ABL4_BASE + 0x14):
    if insn.mnemonic == "svc":
        func_off = None
        for f in func_starts:
            if f <= insn.address - ABL4_BASE:
                func_off = f
            else:
                break
        print("  SVC at 0x{:X} (+{:05X}): {} {} (in func +0x{:05X})".format(
            insn.address, insn.address - ABL4_BASE,
            insn.mnemonic, insn.op_str,
            func_off if func_off else 0))

# 6. Check: what strings are near the overflow string in binary layout?
print("\n=== Step 7: Strings near the overflow string ===")
# Search for null-terminated strings around +0x11A00-0x11B00
off = 0x11900
while off < 0x11C00 and off < len(abl4):
    if abl4[off] >= 0x20 and abl4[off] < 0x7F:
        s = ""
        start = off
        while off < len(abl4) and abl4[off] != 0:
            if 0x20 <= abl4[off] < 0x7F:
                s += chr(abl4[off])
            else:
                s += "\\x{:02X}".format(abl4[off])
            off += 1
        if len(s) >= 4:
            print("  +0x{:05X} (VA 0x{:X}): \"{}\"".format(start, ABL4_BASE + start, s))
        off += 1  # skip null
    else:
        off += 1

# 7. Check what's at binary offsets 0x117CC-0x117D8 (where Ghidra found xrefs)
print("\n=== Step 8: Data at Ghidra xref targets (+0x117CC-0x117E0) ===")
for off in range(0x117C0, 0x117F0, 4):
    val = struct.unpack_from("<I", abl4, off)[0]
    note = ""
    val_off = val - ABL4_BASE
    if 0 <= val_off < len(abl4):
        # Check if it points to a string
        b = abl4[val_off]
        if 0x20 <= b < 0x7F:
            s = ""
            for j in range(min(40, len(abl4) - val_off)):
                bb = abl4[val_off + j]
                if bb == 0: break
                if 0x20 <= bb < 0x7F: s += chr(bb)
                else: break
            note = "-> str: \"{}\"".format(s)
        else:
            note = "(in binary +0x{:X})".format(val_off)
    print("  +0x{:05X}: 0x{:08X} {}".format(off, val, note))
