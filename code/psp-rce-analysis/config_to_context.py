#!/usr/bin/env python3
"""Trace the config buffer → context structure connection in ABL4.

RESOLVED: SVCs are NOPs. ABL4 operates independently after launch.
The config buffer at 0x4F000 is the SOLE data channel from PSP_BL.

Key facts:
- PSP_BL FUN_000075A4 writes config+0x660 (0x4F660) from APCB data
- ABL4 context+0x660 (0x5DE0C) = dispatch function pointer
- FUN_0006B590 writes 0x60FE9 to context+0x660, CONDITIONALLY
- ABL4 entry is at 0x60834

Goal: How does config buffer reach ABL4's context structure?

Approach:
1. Check ABL4's entry point — what parameters does it receive?
2. Trace FUN_0006B590's condition (FUN_0006BC50)
3. Find how ABL4 copies config buffer to context
4. Check PSP_BL launch parameters (FUN_00000328)
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

pyghidra.start(install_dir=GHIDRA_DIR)

# =====================================================================
# PART 1: PSP_BL — What does FUN_00000328 pass to ABL4?
# =====================================================================
print("=" * 70)
print("PART 1: PSP_BL launch function — FUN_00000300 (calls FUN_00000328)")
print("=" * 70)

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# First, let's check what DAT_000077e8 points to
dat_77e8 = struct.unpack_from("<I", pspbl, 0x77E8)[0]
dat_77ec = struct.unpack_from("<I", pspbl, 0x77EC)[0]
print("  DAT_000077e8 = 0x{:08X}".format(dat_77e8))
print("  DAT_000077ec = 0x{:08X}".format(dat_77ec))
print("  (config+0x660 = *DAT_000077e8 = value at 0x{:04X})".format(dat_77e8))

# Check what's at the address pointed to
if dat_77e8 < len(pspbl):
    val_at = struct.unpack_from("<I", pspbl, dat_77e8)[0]
    print("  *DAT_000077e8 = [0x{:04X}] = 0x{:08X}".format(dat_77e8, val_at))

# Also check DAT_00003fc8 (from FUN_00000300's launch call)
dat_3fc8 = struct.unpack_from("<I", pspbl, 0x3FC8)[0]
print("  DAT_00003fc8 = 0x{:08X}".format(dat_3fc8))

with pyghidra.open_program(
    PSPBL_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_pspbl_v1", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # Decompile FUN_00000300 to see the launch arguments
    func = func_mgr.getFunctionAt(space.getAddress(0x300))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x300))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("\n  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Show the parts that reference 0x328, 0x4F000, launch
            print(c[:6000] if len(c) > 6000 else c)

    # Decompile FUN_00007BA4 (called from FUN_000082e6 after config buffer)
    print("\n" + "=" * 70)
    print("FUN_00007BA4 — called after config buffer setup")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x7BA4))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x7BA4))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    decomp.dispose()

# =====================================================================
# PART 2: ABL4 — Entry point and context initialization
# =====================================================================
print("\n" + "=" * 70)
print("PART 2: ABL4 entry point and context initialization")
print("=" * 70)

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

    # ABL4 entry point at 0x60834
    func = func_mgr.getFunctionAt(space.getAddress(0x60834))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x60834))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:6000] if len(c) > 6000 else c)
    else:
        print("  No function at ABL4 entry 0x60834")
        # Try nearby
        for addr in [0x60834, 0x60835, 0x60836, 0x60838]:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
            if func:
                entry = func.getEntryPoint().getOffset()
                print("  Found function at 0x{:05X}".format(entry))
                break

    # FUN_0006BC64 — main boot function (8554 bytes)
    print("\n" + "=" * 70)
    print("FUN_0006BC64 — ABL4 main boot function (first 6000 chars)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6BC64))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6BC64))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Show the first part which initializes context and calls FUN_0006b590
            print(c[:6000])

    # FUN_0006B590 — writes dispatch pointer to context+0x660
    print("\n" + "=" * 70)
    print("FUN_0006B590 — dispatch pointer writer (context+0x660)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6B590))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6B590))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:8000] if len(c) > 8000 else c)

    # FUN_0006BC50 — condition gate for dispatch pointer write
    print("\n" + "=" * 70)
    print("FUN_0006BC50 — condition gate for +0x660 write")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6BC50))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6BC50))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:6000] if len(c) > 6000 else c)

    # Check references to 0x4F000 (config buffer) in ABL4
    print("\n" + "=" * 70)
    print("PART 3: ABL4 literal pool references to config buffer area")
    print("=" * 70)

    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()

    # Search for 0x4F000 and nearby addresses in ABL4 literal pools
    targets = [0x4F000, 0x4F660, 0x4F664, 0x5D7AC, 0x5DE0C]
    for target in targets:
        count = 0
        needle = struct.pack("<I", target)
        idx = 0
        while True:
            idx = abl4.find(needle, idx)
            if idx < 0:
                break
            va = idx + ABL4_BASE
            print("  0x{:08X} found at file 0x{:04X} (VA 0x{:05X})".format(target, idx, va))
            count += 1
            idx += 1
        if count == 0:
            print("  0x{:08X} NOT FOUND in ABL4".format(target))

    # Search for values that could be offsets into a config buffer
    # 0x660 as a 32-bit value (offset from buffer base)
    print("\n  32-bit values 0x660 in ABL4:")
    needle = struct.pack("<I", 0x660)
    idx = 0
    while True:
        idx = abl4.find(needle, idx)
        if idx < 0:
            break
        va = idx + ABL4_BASE
        print("    file 0x{:04X} (VA 0x{:05X})".format(idx, va))
        idx += 1

    # 0x660 as a 16-bit Thumb immediate (less likely to be a direct offset)
    print("\n  16-bit values 0x0660 in ABL4:")
    needle16 = struct.pack("<H", 0x660)
    idx = 0
    count = 0
    while True:
        idx = abl4.find(needle16, idx)
        if idx < 0:
            break
        va = idx + ABL4_BASE
        if count < 20:
            print("    file 0x{:04X} (VA 0x{:05X})".format(idx, va))
        count += 1
        idx += 1
    if count >= 20:
        print("    ... and {} more".format(count - 20))

    decomp.dispose()

print("\nDone.")
