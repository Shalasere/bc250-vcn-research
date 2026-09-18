#!/usr/bin/env python3
"""Use capstone to disassemble ABL4 and find APCB parser / overflow handler.
Strategy:
1. Disassemble the Thumb code section
2. Find all functions (PUSH with LR)
3. For each function, check if it references string addresses
4. Look for the "saved_len" / bounds-check pattern near the overflow string
"""
import struct
from capstone import *
from capstone.arm import *

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

# Find code vs data boundary
# Strings seem to start around 0x11060 based on earlier analysis
# Code is 0x14-0x110xx (Thumb), 0x0-0x13 is ARM trampoline

# First, let's find the APCB-related functions by searching for specific patterns
# The APCB token parser likely:
# 1. Reads from a structure with GroupId/TypeId fields
# 2. Has a loop iterating over tokens
# 3. Has a bounds check (or missing one) that leads to #BUFFER OVERFLOW#

# Let's disassemble the code section in Thumb mode
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs_thumb.detail = True

# Start disassembling from offset 0x14 (after ARM trampoline)
CODE_START = 0x14
CODE_END = 0x11000  # Approximate end of code section

code = abl4[CODE_START:CODE_END]
base_va = ABL4_BASE + CODE_START

# Find all function entries (PUSH with LR)
functions = []
for insn in cs_thumb.disasm(code, base_va):
    mnemonic = insn.mnemonic
    if mnemonic in ("push", "push.w"):
        op_str = insn.op_str
        if "lr" in op_str:
            functions.append((insn.address, insn.address - ABL4_BASE))
    # Stop at code end
    if insn.address - ABL4_BASE >= CODE_END:
        break

print("Found {} functions in Thumb code section".format(len(functions)))

# Now, let's look for the specific overflow-related code patterns
# We need to find:
# 1. A function that references the string table entries for APCB messages
# 2. A function that does APCB token parsing with GroupId/TypeId
# 3. A bounds check (CMP + conditional branch) related to buffer sizes

# Strategy: disassemble every function and look for:
# - References to high addresses (string VAs in 0x72xxx range)
# - CMP instructions with size-like immediates
# - Memory accesses with large offsets (buffer operations)
# - Branch patterns consistent with a parser loop

# First, let's see if there's a different addressing scheme
# Check for ADR (address-relative) instructions
print("\n=== ADR instructions in code ===")
adr_count = 0
for insn in cs_thumb.disasm(code, base_va):
    if insn.mnemonic in ("adr", "adr.w"):
        adr_count += 1
        # The target of ADR might point to string data
        if insn.detail and insn.operands:
            for op in insn.operands:
                if op.type == ARM_OP_IMM:
                    target = op.imm
                    target_off = target - ABL4_BASE
                    if 0x11000 <= target_off <= 0x12000:
                        print("  0x{:08X} (+0x{:05X}): {} {} -> string area +0x{:05X}".format(
                            insn.address, insn.address - ABL4_BASE,
                            insn.mnemonic, insn.op_str, target_off))
    if insn.address - ABL4_BASE >= CODE_END:
        break
print("Total ADR instructions: {}".format(adr_count))

# Also check: does the code use a base register to reference strings?
# Pattern: LDR Rbase, =string_table_base; LDR Rn, [Rbase, #offset]
# Let's look for loads of values in the 0x6xxxx-0x7xxxx range (within ABL4's VA space)
print("\n=== LDR from literal pool loading ABL4 VA-range values ===")
pool_refs = []
for insn in cs_thumb.disasm(code, base_va):
    if insn.mnemonic in ("ldr", "ldr.w") and "[pc" in insn.op_str.lower():
        # PC-relative LDR - check what it loads
        # Extract the target from the instruction encoding
        addr = insn.address
        off_in_bin = addr - ABL4_BASE

        # Try to find the literal pool target
        if insn.detail and insn.operands:
            for op in insn.operands:
                if op.type == ARM_OP_MEM and op.mem.base == ARM_REG_PC:
                    disp = op.mem.disp
                    pool_addr = ((addr + 4) & ~3) + disp if insn.size == 2 else ((addr + 4) & ~3) + disp
                    pool_off = pool_addr - ABL4_BASE
                    if 0 <= pool_off < len(abl4) - 3:
                        val = struct.unpack_from("<I", abl4, pool_off)[0]
                        # Check if it's a VA within ABL4's string section
                        val_off = val - ABL4_BASE
                        if 0x11000 <= val_off <= 0x15000:
                            pool_refs.append((off_in_bin, val, val_off))
    if insn.address - ABL4_BASE >= CODE_END:
        break

print("Found {} literal pool refs to string section:".format(len(pool_refs)))
for code_off, val, str_off in pool_refs[:30]:
    # Show the string at that offset
    s = ""
    for j in range(min(40, len(abl4) - str_off)):
        b = abl4[str_off + j]
        if b == 0:
            break
        if 0x20 <= b < 0x7F:
            s += chr(b)
        else:
            s += "."
    print("  code +0x{:05X} -> VA 0x{:08X} (+0x{:05X}): \"{}\"".format(
        code_off, val, str_off, s))

    # Check if any point to BUFFER OVERFLOW
    if "BUFFER" in s or "OVERFLOW" in s:
        print("    *** OVERFLOW REFERENCE ***")
    if "APCB" in s:
        print("    *** APCB REFERENCE ***")
    if "token" in s.lower() or "Token" in s:
        print("    *** TOKEN REFERENCE ***")
