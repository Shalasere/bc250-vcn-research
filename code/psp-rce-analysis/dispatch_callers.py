#!/usr/bin/env python3
"""Decompile the functions that CALL through context+0x660.

Two callers found:
- FUN_0006BB9C: LDR.W R4, [R0, #0x660] at 0x6BB9E
- FUN_0006F1D8: LDR.W R4, [R0, #0x660] at 0x6F1DA

Also check: what does PSP_BL's FUN_000075A4 write to BSS 0xB814?
And decompile the APCB header copy function to understand the data source.
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_BASE = 0x60834

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

pyghidra.start(install_dir=GHIDRA_DIR)

# =====================================================================
# Part 1: ABL4 dispatch callers
# =====================================================================
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

    # FUN_0006BB9C — calls through context+0x660
    print("=" * 70)
    print("FUN_0006BB9C — dispatch caller #1")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6BB9C))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6BB9C))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # FUN_0006F1D8 — dispatch caller #2
    print("\n" + "=" * 70)
    print("FUN_0006F1D8 — dispatch caller #2")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6F1D8))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6F1D8))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # FUN_000623A4 — called from token_dispatch (might be interesting)
    print("\n" + "=" * 70)
    print("FUN_000623A4 — called from token_dispatch")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x623A4))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x623A4))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # Now check ALL writes to the context structure in a wider range
    # Specifically look for writes to offsets 0x500-0x700
    print("\n" + "=" * 70)
    print("PART 2: All STR.W to context offsets 0x5B0-0x670")
    print("=" * 70)

    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()

    for target_off in [0x5B8, 0x5C0, 0x614, 0x620, 0x624, 0x628, 0x62C, 0x630, 0x654, 0x660]:
        count = 0
        for file_off in range(0, len(abl4) - 3, 2):
            hw = struct.unpack_from("<H", abl4, file_off)[0]
            if (hw & 0xFFF0) == 0xF8C0:  # STR.W prefix
                hw2 = struct.unpack_from("<H", abl4, file_off + 2)[0]
                imm12 = hw2 & 0xFFF
                if imm12 == target_off:
                    rn = hw & 0xF
                    rt = (hw2 >> 12) & 0xF
                    va = file_off + ABL4_BASE
                    fn = "?"
                    f2 = func_mgr.getFunctionContaining(space.getAddress(va))
                    if f2:
                        fn = f2.getName()
                    if count == 0:
                        print("  +0x{:03X}:".format(target_off))
                    print("    0x{:05X}: STR.W R{}, [R{}, #0x{:03X}] in {}".format(
                        va, rt, rn, target_off, fn))
                    count += 1
        if count == 0:
            print("  +0x{:03X}: (only written by FUN_0006B590)".format(target_off))

    decomp.dispose()

# =====================================================================
# Part 3: PSP_BL — what writes to BSS 0xB814?
# =====================================================================
print("\n" + "=" * 70)
print("PART 3: PSP_BL functions referencing 0xB814")
print("=" * 70)

with pyghidra.open_program(
    PSPBL_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_pspbl_v1", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # Check references to the literal pool at 0x77E8 (contains 0xB814)
    # and to 0x4E4C (also contains 0xB814)
    for pool_addr in [0x77E8, 0x4E4C]:
        refs = ref_mgr.getReferencesTo(space.getAddress(pool_addr))
        ref_list = list(refs)
        if ref_list:
            for ref in ref_list:
                from_addr = ref.getFromAddress().getOffset()
                func = func_mgr.getFunctionContaining(ref.getFromAddress())
                fn = func.getName() if func else "?"
                fe = func.getEntryPoint().getOffset() if func else 0
                print("  [0x{:04X}]=0xB814 referenced from 0x{:04X} in {} (0x{:04X})".format(
                    pool_addr, from_addr, fn, fe))

    # Decompile FUN containing the 0x4E4C reference (likely APCB header copier)
    # 0x4E4C is in the literal pool area, likely referenced by a function near it
    func = func_mgr.getFunctionContaining(space.getAddress(0x4E4C))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("\n  FUN containing 0x4E4C: {} at 0x{:04X} ({} bytes)".format(
            func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Check for writes to 0xB814
            if '0xb814' in c.lower() or 'DAT_0000b814' in c:
                print("  *** Writes to 0xB814! ***")
            print(c[:6000] if len(c) > 6000 else c)

    # Also check who writes to 0xB82C (APCB header copy base)
    print("\n  References to 0xB82C (APCB header copy):")
    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()

    needle = struct.pack("<I", 0xB82C)
    idx = 0
    while True:
        idx = pspbl.find(needle, idx)
        if idx < 0:
            break
        print("    [0x{:04X}] = 0x0000B82C".format(idx))
        idx += 1

    # Check the APCB header structure near 0xB814
    # 0x9B60 = APCB header cache (from SRAM map)
    print("\n  Also checking 0x9B60 (APCB header cache):")
    needle = struct.pack("<I", 0x9B60)
    idx = 0
    while True:
        idx = pspbl.find(needle, idx)
        if idx < 0:
            break
        print("    [0x{:04X}] = 0x00009B60".format(idx))
        idx += 1

    decomp.dispose()

print("\nDone.")
