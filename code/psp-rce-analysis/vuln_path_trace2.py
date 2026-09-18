#!/usr/bin/env python3
"""Trace vulnerability path — continued.

Key findings from first run:
- DAT_0006b5f8 = 0x60FE9 → dispatch ptr = Thumb entry at 0x60FE8
- DAT_000077e8 = 0xB814 → BEYOND PSP_BL binary (39360 bytes = 0x99C0)
  → 0xB814 is in BSS/runtime data, populated from APCB at runtime!
- Config+0x660 source is APCB-derived runtime data at SRAM 0xB814

This script:
1. Check what writes to 0xB814 in PSP_BL (APCB parsing function)
2. Decompile FUN_0006BBC0 (context init before dispatch writes)
3. Decode ABL4 entry to find how local_34 gets set
4. Search for 0x3C4 offset references
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

PSPBL_SIZE = len(pspbl)
print("PSP_BL size: {} bytes (0x{:X})".format(PSPBL_SIZE, PSPBL_SIZE))
print("0xB814 is {} bytes BEYOND PSP_BL → BSS/runtime data".format(0xB814 - PSPBL_SIZE))

# Part 1: What references 0xB814 in PSP_BL?
print("\n" + "=" * 70)
print("PART 1: PSP_BL references to 0xB814 (config+0x660 source)")
print("=" * 70)

# Search for 0xB814 as a 32-bit value in literal pools
needle = struct.pack("<I", 0xB814)
idx = 0
while True:
    idx = pspbl.find(needle, idx)
    if idx < 0:
        break
    print("  [0x{:04X}] = 0x0000B814".format(idx))
    idx += 1

# Also search for nearby BSS addresses that might be part of same structure
for target in [0xB800, 0xB804, 0xB808, 0xB80C, 0xB810, 0xB818, 0xB81C, 0xB820, 0xB82C]:
    needle = struct.pack("<I", target)
    idx = pspbl.find(needle)
    if idx >= 0:
        print("  [0x{:04X}] = 0x{:08X}".format(idx, target))

# Part 2: Check what APCB-related structure is at 0xB814
# From memory: 0x0B82C: APCB header copy / token table 0
# 0xB814 is at 0xB82C - 0x18 = in the APCB header area!
print("\n" + "=" * 70)
print("PART 2: 0xB814 location analysis")
print("=" * 70)
print("  0xB82C = APCB header copy / token table 0 (from SRAM map)")
print("  0xB814 = 0xB82C - 0x18 → 24 bytes BEFORE APCB header copy")
print("  This is likely in the APCB HEADER structure itself!")
print()
print("  APCB header layout (typical AMD):")
print("    +0x00: Signature")
print("    +0x04: Size")
print("    +0x08: Revision")
print("    +0x0C: Checksum")
print("    +0x10: Reserved/Flags")
print("    +0x18: Data offset (points to first group)")
print()
print("  If 0xB82C is the start of APCB data,")
print("  then 0xB814 = header+0x00 to header+0x18 area")
print("  More precisely: 0xB814 - 0xB82C = -0x18 → APCB header field")

# Part 3: DAT_000077e8 context — what function references it?
print("\n" + "=" * 70)
print("PART 3: Literal pool references to 0xB814 in PSP_BL")
print("=" * 70)

# DAT_000077e8 = 0xB814. This literal pool entry is at 0x77E8.
# What function references 0x77E8?
# LDR Rx, [PC, #imm] where PC + 8 + imm = 0x77E8
# For Thumb LDR Rd, [PC, #imm8*4]: PC = (va & ~2), pool = PC + 4 + imm*4
# For Thumb-2 LDR.W Rd, [PC, #imm12]

# Search for PC-relative loads that target 0x77E8
print("  Searching for Thumb LDR Rd, [PC, ...] → 0x77E8:")
for file_off in range(0, PSPBL_SIZE - 1, 2):
    hw = struct.unpack_from("<H", pspbl, file_off)[0]
    va = file_off  # PSP_BL base = 0

    # Thumb-1 LDR Rd, [PC, #imm]: 0x4800-0x4FFF
    if (hw & 0xF800) == 0x4800:
        imm = (hw & 0xFF) * 4
        pool_va = (va & ~3) + 4 + imm
        if pool_va == 0x77E8:
            rd = (hw >> 8) & 7
            print("    0x{:04X}: LDR R{}, [PC, #0x{:X}] → 0x{:04X}".format(
                va, rd, imm, pool_va))

    # Thumb-2 LDR.W Rd, [PC, #imm12]: F8DF xxxx
    if (hw & 0xFFFF) == 0xF8DF and file_off + 2 < PSPBL_SIZE:
        hw2 = struct.unpack_from("<H", pspbl, file_off + 2)[0]
        imm12 = hw2 & 0xFFF
        rd = (hw2 >> 12) & 0xF
        pool_va = (va & ~3) + 4 + imm12
        if pool_va == 0x77E8:
            print("    0x{:04X}: LDR.W R{}, [PC, #0x{:X}] → 0x{:04X}".format(
                va, rd, imm12, pool_va))

# Part 4: The dispatch pointer value 0x60FE9
print("\n" + "=" * 70)
print("PART 4: Dispatch pointer 0x60FE9 — what's at 0x60FE8?")
print("=" * 70)

# 0x60FE9 = Thumb function at 0x60FE8 (VA)
# File offset = 0x60FE8 - 0x60834 = 0x7B4
# Decode first instructions
func_file_off = 0x60FE8 - ABL4_BASE
print("  Entry at VA 0x60FE8 (file offset 0x{:03X}):".format(func_file_off))
for i in range(func_file_off, min(func_file_off + 40, len(abl4)), 2):
    hw = struct.unpack_from("<H", abl4, i)[0]
    va = i + ABL4_BASE
    desc = ""
    if (hw & 0xFE00) == 0xB400:
        regs = [str(b) for b in range(8) if hw & (1 << b)]
        if hw & 0x100: regs.append("LR")
        desc = "PUSH {{R{}}}".format(",R".join(regs))
    elif (hw & 0xFF00) == 0xB000:
        if hw & 0x80:
            desc = "SUB SP, #0x{:X}".format((hw & 0x7F) * 4)
        else:
            desc = "ADD SP, #0x{:X}".format((hw & 0x7F) * 4)
    elif (hw & 0xFE00) == 0x4600:
        hi = ((hw >> 4) & 8) | (hw & 7)
        src = (hw >> 3) & 0xF
        desc = "MOV R{}, R{}".format(hi, src)
    elif hw == 0x4770:
        desc = "BX LR"
    print("    0x{:05X}: 0x{:04X}  {}".format(va, hw, desc))

# Part 5: Ghidra analysis
import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

pyghidra.start(install_dir=GHIDRA_DIR)

with pyghidra.open_program(
    ABL4_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_abl4_v3", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # FUN_0006BBC0 — context initialization
    print("\n" + "=" * 70)
    print("FUN_0006BBC0 — context init before dispatch writes")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6BBC0))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6BBC0))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:6000] if len(c) > 6000 else c)

    # FUN_00060FE8 — the dispatch target function at context+0x660
    print("\n" + "=" * 70)
    print("FUN_00060FE8 — dispatch target (written to context+0x660)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x60FE8))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x60FE8))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:6000] if len(c) > 6000 else c)

    # FUN_00069BE8 — called before condition check
    print("\n" + "=" * 70)
    print("FUN_00069BE8 — called before FUN_0006BC50")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x69BE8))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x69BE8))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # Check what calls context+0x660 (uses it as function pointer)
    print("\n" + "=" * 70)
    print("PART 6: Search for BLX/calls via context+0x660")
    print("=" * 70)

    # In ABL4, whoever reads param_1+0x660 and calls it
    # The offset 0x660 appears at VA 0x6B5BA (from earlier search)
    # Let's check ALL LDR.W Rd, [Rn, #0x660] patterns in ABL4
    for file_off in range(0, len(abl4) - 3, 2):
        hw = struct.unpack_from("<H", abl4, file_off)[0]
        if (hw & 0xFFF0) == 0xF8D0:  # LDR.W prefix
            hw2 = struct.unpack_from("<H", abl4, file_off + 2)[0]
            imm12 = hw2 & 0xFFF
            if imm12 == 0x660:
                rn = hw & 0xF
                rt = (hw2 >> 12) & 0xF
                va = file_off + ABL4_BASE
                func = func_mgr.getFunctionContaining(space.getAddress(va))
                fn = func.getName() if func else "?"
                print("  0x{:05X}: LDR.W R{}, [R{}, #0x660] in {}".format(
                    va, rt, rn, fn))

                # Check if next instruction is BLX Rt
                if file_off + 4 < len(abl4):
                    next_hw = struct.unpack_from("<H", abl4, file_off + 4)[0]
                    if (next_hw & 0xFF87) == 0x4780:  # BLX Rm
                        rm = (next_hw >> 3) & 0xF
                        print("    followed by BLX R{} → DISPATCH CALL!".format(rm))

    # Also search for STR to +0x660 (who else writes it besides FUN_0006B590?)
    print("\n  STR.W Rd, [Rn, #0x660] in ABL4:")
    for file_off in range(0, len(abl4) - 3, 2):
        hw = struct.unpack_from("<H", abl4, file_off)[0]
        if (hw & 0xFFF0) == 0xF8C0:  # STR.W prefix
            hw2 = struct.unpack_from("<H", abl4, file_off + 2)[0]
            imm12 = hw2 & 0xFFF
            if imm12 == 0x660:
                rn = hw & 0xF
                rt = (hw2 >> 12) & 0xF
                va = file_off + ABL4_BASE
                func = func_mgr.getFunctionContaining(space.getAddress(va))
                fn = func.getName() if func else "?"
                print("  0x{:05X}: STR.W R{}, [R{}, #0x660] in {}".format(
                    va, rt, rn, fn))

    decomp.dispose()

print("\nDone.")
