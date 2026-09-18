#!/usr/bin/env python3
"""Trace PSP_BL's access to ABL4 context at 0x5D7AC.

The literal pool at 0x0BB8 = 0x5D7AC is loaded at offset 0x0958.
Ghidra didn't find a function there. Let me:
1. Disassemble around 0x0958 to see what happens with 0x5D7AC
2. Check if PSP_BL writes to 0x5D7AC+0x660 via a sequence like:
   ldr r0, [pc, #...] -> 0x5D7AC
   add r0, #0x660  (or ldr r1, =offset; add r0, r1)
   str value, [r0]
3. Or uses 0x5D7AC as base and computed offset

Also: search for MOVW/MOVT patterns that could construct 0x5D7AC or 0x5DE0C
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# 1. Disassemble around PSP_BL offset 0x0958 (loads 0x5D7AC)
print("=" * 70)
print("1. PSP_BL code around 0x0958 (loads 0x5D7AC)")
print("=" * 70)
# Find a reasonable start point (scan backwards for PUSH)
start = 0x0900
insns = list(cs.disasm(pspbl[start:0x0A00], start))
for insn in insns:
    marker = " >>>" if insn.address == 0x0958 else "    "
    print("{} 0x{:04X}: {:10s} {}".format(marker, insn.address, insn.mnemonic, insn.op_str))

# 2. What does the code at 0x0958 do with r0=0x5D7AC?
# Let me trace forward from 0x0958
print("\n" + "=" * 70)
print("2. Trace after loading 0x5D7AC at 0x0958")
print("=" * 70)
insns = list(cs.disasm(pspbl[0x0958:0x09C0], 0x0958))
for insn in insns:
    print("  0x{:04X}: {:10s} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 3. Search for ALL MOVW that loads partial 0x5D7AC or 0x5DE0C
# MOVW Rd, #imm16: encoding T3, first halfword = 0xF240 | (i<<10) | (imm4)
# 0x5D7AC -> low 16 bits = 0xD7AC
# 0x5DE0C -> low 16 bits = 0xDE0C
print("\n" + "=" * 70)
print("3. MOVW instructions loading 0xD7AC or 0xDE0C")
print("=" * 70)
insns = list(cs.disasm(pspbl[:len(pspbl)], 0))
for insn in insns:
    if insn.mnemonic == 'movw' and ('#0xd7ac' in insn.op_str.lower() or
                                     '#0xde0c' in insn.op_str.lower()):
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 4. Search for ADD.W that adds 0x660 to any register
# This would be: ADD.W Rd, Rn, #0x660
print("\n" + "=" * 70)
print("4. ADD.W with immediate 0x660 in PSP_BL")
print("=" * 70)
for insn in insns:
    if (insn.mnemonic in ['add', 'add.w', 'adds', 'adds.w'] and
        '#0x660' in insn.op_str):
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# Also check for ADDW
for insn in insns:
    if insn.mnemonic == 'addw' and '#0x660' in insn.op_str:
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 5. What if PSP_BL uses 0x5DE0C directly as an address?
# Search for 0x5DE0C in literal pools
print("\n" + "=" * 70)
print("5. Literal pool search for 0x5DE0C (context+0x660)")
print("=" * 70)
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val == 0x5DE0C:
        print("  Offset 0x{:04X}: 0x5DE0C".format(off))

# 6. What about the OTHER SVC 0x1c paths?
# ABL4 has SVC 0x1c at 0x62848, 0x688A4, 0x6AFB6, 0x6BCCC
# FUN_0006B590 (vtable init) is called ONCE by FUN_0006BC64 (orchestrator)
# Let me check: is the SVC at 0x6BCCC BEFORE or AFTER FUN_0006B590?
# The orchestrator starts at 0x6BC64. Let me check the call order.
print("\n" + "=" * 70)
print("6. ABL4 orchestrator (0x6BC64): BL targets and SVC sequence")
print("=" * 70)

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834
with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

cs2 = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs2.detail = True

# Disassemble orchestrator from 0x6BC64 to ~0x6C100 (first 1700 bytes)
orch_off = 0x6BC64 - ABL4_BASE
orch_insns = list(cs2.disasm(abl4[orch_off:orch_off+1700], 0x6BC64))
print("  BL/SVC sequence in first 1700 bytes of orchestrator:")
for insn in orch_insns:
    if insn.mnemonic in ['bl', 'blx', 'svc']:
        print("  0x{:05X}: {:6s} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 7. Now check: what happens in ABL4 between FUN_0006B590 and first token dispatch
# FUN_0006B590 sets context+0x660 = 0x60FE9
# Search for BL 0x6B590 in ABL4
print("\n" + "=" * 70)
print("7. Calls to FUN_0006B590 (vtable init) in ABL4")
print("=" * 70)
all_abl4_insns = list(cs2.disasm(abl4, ABL4_BASE))
for insn in all_abl4_insns:
    if insn.mnemonic == 'bl' and '0x6b590' in insn.op_str:
        print("  0x{:05X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# And calls to FUN_0006f1d8 (token write via +0x660)
print("\n  Calls to FUN_0006f1d8 (token write dispatch):")
for insn in all_abl4_insns:
    if insn.mnemonic == 'bl' and '0x6f1d8' in insn.op_str:
        print("  0x{:05X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# And FUN_0006bb9c (token read via +0x660)
print("\n  Calls to FUN_0006bb9c (token read dispatch):")
for insn in all_abl4_insns:
    if insn.mnemonic == 'bl' and '0x6bb9c' in insn.op_str:
        print("  0x{:05X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 8. The PSP_BL SVC handler: how does it access caller context?
# When SVC is called, PSP_BL gets the caller's r0-r3 from the exception frame
# For SVC 0x1c, r0 = pointer to ABL4's stack buffer
# But PSP_BL has its OWN address space access — it can read/write SRAM directly
# Can PSP_BL write to 0x5D7AC+0x660 during SVC processing?
print("\n" + "=" * 70)
print("8. PSP_BL: ALL STR instructions in the entire binary")
print("  (looking for any store to 0x5D7AC+N where N >= 0x600)")
print("=" * 70)
# The only way to find stores to 0x5D7AC+0x660 is if the base register
# holds 0x5D7AC (loaded from literal pool at 0x0BB8).
# After loading r0 = 0x5D7AC at offset 0x0958, what stores follow?
# Let me trace ALL instructions that use 0x5D7AC
# Check around 0x0958 more carefully

# Actually, let's search for STR instructions where the base register
# was recently loaded from a literal pool pointing to 0x5D7AC
# This requires a more careful flow analysis.

# Simpler: just search for ANY store with imm offset 0x660 in the ENTIRE PSP_BL
print("  All STR/STR.W with #0x660 offset:")
for insn in list(cs.disasm(pspbl, 0)):
    if insn.mnemonic.startswith('str') and '#0x660' in insn.op_str:
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# Also search via raw halfword pattern for Thumb STR variants
# T1: STR Rt, [Rn, #imm5*4] — max offset 124, too small
# T2: STR Rt, [SP, #imm8*4] — max offset 1020, can do 0x660 but that's 0x198*4=0x660
#     Encoding: 0x9000 | (Rt<<8) | (imm8), where imm8 = 0x660/4 = 0x198
#     But imm8 max is 0xFF, so 0x198 doesn't fit → NOT possible via T2
# T3: STR.W Rt, [Rn, #imm12] — already covered above
# So the only encoding that can reach +0x660 is STR.W, which we've already found

# 9. Check the PSP_BL function that uses 0x4F000 literal at 0x0BDC
print("\n" + "=" * 70)
print("9. Code around PSP_BL literal pool entry 0x0BDC (0x4F000)")
print("=" * 70)
# 0x0BDC contains literal 0x4F000
# Find what loads it
for off in range(0x0B00, 0x0BE0, 2):
    hw = struct.unpack_from("<H", pspbl, off)[0]
    if (hw & 0xF800) == 0x4800:  # Thumb16 LDR Rt, [PC, #imm]
        rt = (hw >> 8) & 7
        imm8 = hw & 0xFF
        pc_val = ((off + 4) & ~3)
        target = pc_val + imm8 * 4
        if target == 0x0BDC:
            print("  Offset 0x{:04X}: LDR r{}, [PC] -> 0x0BDC (0x4F000)".format(off, rt))
            # Show surrounding code
            context_insns = list(cs.disasm(pspbl[max(0,off-20):off+40], max(0,off-20)))
            for ci in context_insns:
                m = " >>>" if ci.address == off else "    "
                print("  {} 0x{:04X}: {:10s} {}".format(m, ci.address, ci.mnemonic, ci.op_str))

print("\nDone.")
