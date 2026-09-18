#!/usr/bin/env python3
"""Two critical questions:
1. What value lives at PSP_BL data offset 0xB814? (This feeds 0x4F000+0x660)
2. Is 0x60FE8 (entered via 0x60FE9) a working dispatch function?

The 0x4F000 buffer is NOT the ABL4 context — it's a separate config structure
that PSP_BL builds and cache-flushes. But +0x660 in that buffer may not mean
"function pointer" — it could be config data with a different semantic.

ABL4 FUN_0006B590 writes context+0x660 = 0x60FE9. If nothing overwrites it,
then 0x60FE8 IS the permanent dispatch. Let me trace if it works.
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()
with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# 1. Read the data at PSP_BL offset 0xB814
print("=" * 70)
print("1. PSP_BL data at 0xB814 (source for 0x4F000+0x660)")
print("=" * 70)
if 0xB814 < len(pspbl):
    for off in range(0xB800, min(0xB830, len(pspbl)), 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        marker = " <<<" if off == 0xB814 else ""
        print("  0x{:04X}: 0x{:08X}{}".format(off, val, marker))
else:
    print("  0xB814 is BEYOND PSP_BL body ({} bytes = 0x{:X})!".format(
        len(pspbl), len(pspbl)))
    print("  PSP_BL body is only {} bytes".format(len(pspbl)))
    print("  0xB814 would be in PSP SRAM DATA AREA (not in the loaded binary)")
    print("  This means the value at 0xB814 is set AT RUNTIME by earlier code")

# 2. Check what's at 0x9A00-0x9A60 in PSP_BL (after code, possible data section)
print("\n" + "=" * 70)
print("2. PSP_BL end-of-binary check")
print("=" * 70)
print("  Total PSP_BL size: {} bytes (0x{:X})".format(len(pspbl), len(pspbl)))
print("  Last 32 bytes: {}".format(pspbl[-32:].hex()))
print("  Data at 0x9A00 (if exists):")
if 0x9A00 < len(pspbl):
    for off in range(0x9A00, min(0x9A40, len(pspbl)), 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        print("    0x{:04X}: 0x{:08X}".format(off, val))

# 3. OK so 0xB814 is RUNTIME DATA. Let's trace who writes to it.
# Search PSP_BL code for stores to 0xB814 or references to it in literal pools
print("\n" + "=" * 70)
print("3. PSP_BL references to 0xB814 and nearby addresses")
print("=" * 70)
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if 0xB800 <= val <= 0xB830:
        print("  Offset 0x{:04X}: literal 0x{:08X}".format(off, val))

# 4. THE BIG QUESTION: trace the actual code path at 0x60FE8
print("\n" + "=" * 70)
print("4. Detailed trace: entry at 0x60FE8 (Thumb)")
print("=" * 70)

# Entry point: 0x60FE8
# Dispatch is called as: dispatch(context, mode, token_id, [value])
# ARM calling convention: r0=context, r1=mode, r2=token_id, r3=value

off = 0x60FE8 - ABL4_BASE
print("  Entry: 0x60FE8")
print("  r0=context, r1=1(write)/0(read), r2=token_id, r3=value")
print()

# Disassemble from 0x60FE8
insns = list(cs.disasm(abl4[off:off+64], 0x60FE8))
for insn in insns:
    print("  0x{:05X}: {:10s} {}".format(insn.address, insn.mnemonic, insn.op_str))
    if insn.mnemonic in ['b', 'bx'] and '#' not in insn.op_str and 'lr' in insn.op_str:
        break

# Follow the branch to 0x60FFC
print("\n  Following branch to 0x60FFC:")
off = 0x60FFC - ABL4_BASE
insns = list(cs.disasm(abl4[off:off+256], 0x60FFC))
for insn in insns[:40]:
    print("  0x{:05X}: {:10s} {}".format(insn.address, insn.mnemonic, insn.op_str))
    if insn.mnemonic in ['pop', 'pop.w'] and 'pc' in insn.op_str:
        print("  [FUNCTION RETURN]")
        break

# 5. Now let's look at the PARENT function starting at 0x60F24
# and find what 0x60FFC-region does in context
print("\n" + "=" * 70)
print("5. Full function 0x60F24 structure: entry points and branches")
print("=" * 70)
off = 0x60F24 - ABL4_BASE
func_insns = list(cs.disasm(abl4[off:off+2112], 0x60F24))
print("  Total instructions: {}".format(len(func_insns)))

# Find all branch targets and conditional branches
# Focus on the path from 0x60FFC
print("\n  Instructions 0x60FF0 - 0x61040:")
for insn in func_insns:
    if 0x60FF0 <= insn.address <= 0x61040:
        print("  0x{:05X}: {:10s} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 6. What about the +0x3B0 dispatch? (channel-select method)
# FUN_0006f214 calls through context+0x3B0
print("\n" + "=" * 70)
print("6. LDR from context+0x3B0 in ABL4 (channel select dispatch)")
print("=" * 70)
for off in range(0, len(abl4) - 3, 2):
    hw1 = struct.unpack_from("<H", abl4, off)[0]
    if (hw1 & 0xFFF0) == 0xF8D0:  # LDR.W
        hw2 = struct.unpack_from("<H", abl4, off + 2)[0]
        imm12 = hw2 & 0xFFF
        if imm12 == 0x3B0:
            rn = hw1 & 0xF
            rt = (hw2 >> 12) & 0xF
            va = ABL4_BASE + off
            print("  VA 0x{:05X}: LDR.W r{}, [r{}, #0x3B0]".format(va, rt, rn))

# 7. Check: does software_interrupt(0x1c) return a value?
# In ABL4's orchestrator, after calling SVC 0x1c, does it read a return
# value and use it to update context+0x660?
print("\n" + "=" * 70)
print("7. SVC 0x1c calls in ABL4 orchestrator")
print("=" * 70)
# Search for SVC 0x1c instruction: DF1C
for off in range(0, len(abl4) - 1, 2):
    hw = struct.unpack_from("<H", abl4, off)[0]
    if hw == 0xDF1C:  # SVC #0x1c
        va = ABL4_BASE + off
        print("  VA 0x{:05X}: SVC #0x1c".format(va))
        # Show context: 10 instructions before and 10 after
        context_off = max(0, off - 30)
        context_insns = list(cs.disasm(abl4[context_off:off+40], ABL4_BASE + context_off))
        print("  Context:")
        for ci in context_insns:
            marker = " >>>" if ci.address == va else "    "
            print("  {} 0x{:05X}: {:10s} {}".format(marker, ci.address, ci.mnemonic, ci.op_str))

# 8. Also search for all SVC instructions in ABL4
print("\n" + "=" * 70)
print("8. ALL SVC instructions in ABL4")
print("=" * 70)
for off in range(0, len(abl4) - 1, 2):
    hw = struct.unpack_from("<H", abl4, off)[0]
    if (hw & 0xFF00) == 0xDF00:  # SVC #imm8
        imm = hw & 0xFF
        va = ABL4_BASE + off
        print("  VA 0x{:05X}: SVC #0x{:02X}".format(va, imm))

# 9. Check: does the orchestrator COPY from a return buffer to context?
# After SVC 0x1c, does ABL4 do something like:
#   result = svc_1c(...)
#   context+0x660 = *(result + offset)
# Search for STR to +0x660 in the orchestrator function range (0x6BC64 - 0x6DE00)
print("\n" + "=" * 70)
print("9. STR.W to +0x660 in ABL4 orchestrator range (0x6BC64-0x6DE00)")
print("=" * 70)
orch_start = 0x6BC64 - ABL4_BASE
orch_end = 0x6DE00 - ABL4_BASE
for off in range(orch_start, min(orch_end, len(abl4) - 3), 2):
    hw1 = struct.unpack_from("<H", abl4, off)[0]
    if (hw1 & 0xFFF0) == 0xF8C0:  # STR.W
        hw2 = struct.unpack_from("<H", abl4, off + 2)[0]
        imm12 = hw2 & 0xFFF
        if imm12 >= 0x500:
            rn = hw1 & 0xF
            rt = (hw2 >> 12) & 0xF
            va = ABL4_BASE + off
            print("  VA 0x{:05X}: STR.W r{}, [r{}, #0x{:X}]".format(va, rt, rn, imm12))

print("\nDone.")
