#!/usr/bin/env python3
"""Find the PSP_BL stack overflow in APCB processing (CVE-2025-29951).

Attack model: crafted APCB -> PSP_BL stack overflow during SVC 0x1c
-> PSP_BL shellcode execution -> write to SRAM 0x5DE0C (context+0x660)
-> ABL4 dispatches to attacker code.

Focus: FUN_000044CC (2728 bytes, APCB token processor with switch).
"""
import os

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
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

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # 1. Full decompile of FUN_000044CC
    print("=" * 70)
    print("1. FUN_000044CC — FULL DECOMPILE (APCB token processor)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c)
        else:
            print("  FAILED: {}".format(result.getErrorMessage()))

    # 2. FUN_000037FC (APCB group 0x1703)
    print("\n" + "=" * 70)
    print("2. FUN_000037FC (APCB group 0x1703)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x37FC))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:12000])

    # 3. FUN_000082E6 — caller of FUN_000075A4
    print("\n" + "=" * 70)
    print("3. FUN_000082E6 — calls FUN_000075A4")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x82E6))
    if not func:
        for delta in range(-8, 9, 2):
            f = func_mgr.getFunctionAt(space.getAddress(0x82E6 + delta))
            if f:
                func = f
                break
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:10000])
    else:
        print("  No function found near 0x82E6")

    decomp.dispose()
    print("\nDone.")
