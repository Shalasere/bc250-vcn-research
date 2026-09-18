#!/usr/bin/env python3
"""Part 2: Get callers of FUN_00068420 and full FUN_0006804C token processor.
Avoiding regex on 'for (' which crashes. Using simple string search instead."""
import os

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
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
    ref_mgr = program.getReferenceManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # 1. Full decompile FUN_0006804C (token processor — 4952 bytes)
    print("=" * 70)
    print("FUN_0006804C — FULL TOKEN PROCESSOR")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6804C))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  Total: {} chars".format(len(c)))
            # Print in 5000-char chunks
            for i in range(0, len(c), 5000):
                print(c[i:i+5000])

    # 2. Callers of FUN_00068420
    print("\n" + "=" * 70)
    print("CALLERS OF FUN_00068420 AND SIZE USAGE")
    print("=" * 70)

    addr = space.getAddress(0x68420)
    refs = list(ref_mgr.getReferencesTo(addr))
    caller_entries = set()
    for r in refs:
        from_func = func_mgr.getFunctionContaining(r.getFromAddress())
        if from_func:
            entry = from_func.getEntryPoint().getOffset()
            caller_entries.add(entry)
            print("  Call at 0x{:X} in {} (0x{:X})".format(
                r.getFromAddress().getOffset(), from_func.getName(), entry))

    for entry in sorted(caller_entries):
        func = func_mgr.getFunctionAt(space.getAddress(entry))
        if not func:
            continue
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        print("\n--- {} (0x{:X}) ---".format(func.getName(), entry))
        # Find FUN_00068420 call and show 800 chars of context
        idx = c.find('FUN_00068420')
        while idx >= 0:
            start = max(0, idx - 200)
            end = min(len(c), idx + 800)
            print(c[start:end])
            print("\n  [...]")
            idx = c.find('FUN_00068420', idx + 1)

    # 3. Full decompile FUN_00060B80 — APCB config parser (has group header parsing)
    print("\n" + "=" * 70)
    print("FUN_00060B80 — APCB CONFIG PARSER")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x60B80))
    if func:
        size = func.getBody().getNumAddresses()
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} bytes code, {} chars decompiled".format(size, len(c)))
            for i in range(0, min(len(c), 12000), 5000):
                print(c[i:i+5000])

    # 4. What allocates the context structure? Search for 0x5D7AC in ABL4
    print("\n" + "=" * 70)
    print("SEARCH: References to 0x5D7AC in ABL4 literal pools")
    print("=" * 70)

    import struct
    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()

    base = 0x60834
    for off in range(0, len(abl4) - 3, 4):
        val = struct.unpack_from("<I", abl4, off)[0]
        if val == 0x5D7AC:
            va = base + off
            containing = func_mgr.getFunctionContaining(space.getAddress(va))
            cname = containing.getName() if containing else "?"
            print("  ABL4 offset 0x{:X} (VA 0x{:X}) in {} = 0x5D7AC".format(off, va, cname))
        if val == 0x5DE0C:
            va = base + off
            containing = func_mgr.getFunctionContaining(space.getAddress(va))
            cname = containing.getName() if containing else "?"
            print("  ABL4 offset 0x{:X} (VA 0x{:X}) in {} = 0x5DE0C (TARGET!)".format(off, va, cname))

    # Also search PSP_BL for 0x5DE0C
    print("\n  PSP_BL search for 0x5DE0C:")
    with open(r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin", "rb") as f:
        pspbl = f.read()
    for off in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        if val == 0x5DE0C:
            print("  PSP_BL offset 0x{:X} = 0x5DE0C".format(off))

    decomp.dispose()
    print("\nDone.")
