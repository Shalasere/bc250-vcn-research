#!/usr/bin/env python3
"""Decompile FUN_000082e6 — the function that:
1. Calls FUN_000035A0 (make all pages R/W with descriptor 0x52)
2. Patches the SVC vector at 0x108
3. Called from FUN_00000300 right before ABL4 launch

Also decompile FUN_00000328 (probable ABL4 launch function).
And check what FUN_000082e6 writes to the vector table area.
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

pyghidra.start(install_dir=GHIDRA_DIR)

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

    # Decompile FUN_000082e6
    print("=" * 70)
    print("FUN_000082e6 — ABL4 launch preparation (calls FUN_000035A0)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x82E6))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x82E6))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            if '0x108' in c:
                print("  *** Contains 0x108 (SVC vector) reference! ***")
            if '0x198' in c:
                print("  *** Contains 0x198 (SVC handler) reference! ***")
            if '0x35a0' in c.lower() or 'FUN_000035a0' in c:
                print("  *** Calls FUN_000035A0 ***")
            if '0xea' in c.lower():
                print("  Contains potential branch instruction construction")
            print(c)

        # Find all functions called by FUN_000082e6
        print("\n  Functions called from within FUN_000082e6:")
        body = func.getBody()
        for addr_range in body:
            start = addr_range.getMinAddress().getOffset()
            end = addr_range.getMaxAddress().getOffset()
            for off in range(start, end + 1, 2):  # Thumb = 2-byte aligned
                a = space.getAddress(off)
                refs_from = ref_mgr.getReferencesFrom(a)
                for ref in refs_from:
                    if ref.getReferenceType().isCall():
                        target = ref.getToAddress().getOffset()
                        tfunc = func_mgr.getFunctionAt(ref.getToAddress())
                        tfn = tfunc.getName() if tfunc else "?"
                        print("    0x{:04X}: calls 0x{:04X} ({})".format(off, target, tfn))

    # Decompile FUN_00000328 (ABL4 launch)
    print("\n" + "=" * 70)
    print("FUN_00000328 — probable ABL4 launch")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x328))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x328))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            if '0x60834' in c or '0x60FE' in c:
                print("  *** Contains ABL4 base address! ***")
            print(c)

    # Decompile FUN_000075A4 (config buffer builder) — called from FUN_000082e6?
    print("\n" + "=" * 70)
    print("FUN_000075A4 — config buffer builder at 0x4F000")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x75A4))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x75A4))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Show key parts: what it writes to config buffer
            print(c[:8000] if len(c) > 8000 else c)

    # Check the SVC handler at 0x198 more carefully
    print("\n" + "=" * 70)
    print("SVC handler at 0x198 — manual disassembly")
    print("=" * 70)

    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()

    # The handler at 0x198 should be a separate function
    func_198 = func_mgr.getFunctionAt(space.getAddress(0x198))
    if not func_198:
        func_198 = func_mgr.getFunctionContaining(space.getAddress(0x198))
    if func_198:
        entry = func_198.getEntryPoint().getOffset()
        fsize = func_198.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func_198.getName(), entry, fsize))

        result = decomp.decompileFunction(func_198, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)
    else:
        print("  No function at 0x198 — checking the containing function")
        func_c = func_mgr.getFunctionContaining(space.getAddress(0x198))
        if func_c:
            print("  0x198 is inside {} (0x{:04X})".format(
                func_c.getName(), func_c.getEntryPoint().getOffset()))

    # Manual check: what ARM instruction at 0x198 decodes to
    print("\n  Disassembly at 0x198:")
    for off in range(0x198, 0x200, 4):
        inst = program.getListing().getInstructionAt(space.getAddress(off))
        if inst:
            print("    0x{:03X}: {} {}".format(off, inst.getMnemonicString(),
                  inst.toString()))
        else:
            val = struct.unpack_from("<I", pspbl, off)[0]
            print("    0x{:03X}: (no inst) raw 0x{:08X}".format(off, val))

    # Decompile FUN_0000120C (cache maintenance called by FUN_000035A0)
    print("\n" + "=" * 70)
    print("FUN_0000120C — cache/TLB maintenance")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x120C))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x120C))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    decomp.dispose()

print("\nDone.")
