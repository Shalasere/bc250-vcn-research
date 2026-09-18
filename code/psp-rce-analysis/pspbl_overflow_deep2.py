#!/usr/bin/env python3
"""Decompile deeper APCB callees and the suspicious memcpy functions.

Key targets:
1. FUN_000071AC — core APCB data installer (called from FUN_00007014)
2. FUN_00000458 — memcpy variant called with 2-3 args (ambiguous)
3. FUN_00001C18 — large copy for APCB data >= 0x400 bytes
4. FUN_000062F8 — type-specific processing
5. FUN_000065B8 — finalization
6. FUN_00008500 — verification
7. FUN_0000237C — decompression/integrity
8. FUN_000074C8 — fills 0x640 buffer
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

    targets = [
        (0x71AC, "FUN_000071AC — core APCB data installer"),
        (0x458, "FUN_00000458 — memcpy variant (ambiguous param count)"),
        (0x4E0, "FUN_000004E0 — memcpy (3+ params)"),
        (0x1C18, "FUN_00001C18 — large APCB copy (>= 0x400)"),
        (0x62F8, "FUN_000062F8 — type-specific APCB processing"),
        (0x65B8, "FUN_000065B8 — APCB finalization"),
        (0x8500, "FUN_00008500 — APCB verification"),
        (0x237C, "FUN_0000237C — decompression/integrity check"),
        (0x74C8, "FUN_000074C8 — buffer fill (called from FUN_000057C4)"),
        (0x22AA, "FUN_000022AA — processing (called from FUN_000068AC)"),
        (0x8064, "FUN_00008064 — called from FUN_00007014 at start"),
    ]

    for addr, desc in targets:
        print("=" * 70)
        print(desc)
        print("=" * 70)
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if func:
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
            timeout = 600 if size > 500 else 300
            result = decomp.decompileFunction(func, timeout, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))
                if len(c) > 6000:
                    print("  [FIRST 6000 CHARS]")
                    print(c[:6000])
                    # Search for copy/overflow patterns
                    for kw in ['FUN_000004e0', 'FUN_00000458', 'memcpy', 'param_',
                               'size', 'len', 'while', 'for (', 'auStack', 'local_']:
                        positions = []
                        idx = 0
                        while True:
                            idx = c.find(kw, idx)
                            if idx < 0:
                                break
                            if idx >= 6000:
                                positions.append(idx)
                            idx += 1
                        if positions:
                            print("\n  [...{} at {}]:".format(kw, positions[:3]))
                            for p in positions[:2]:
                                ctx = c[max(0,p-100):min(len(c),p+400)]
                                print("  " + ctx[:500].replace('\n', '\n  '))
                else:
                    print(c)
            else:
                print("  FAILED: {}".format(result.getErrorMessage()))
        else:
            print("  No function at 0x{:X}".format(addr))
        print()

    decomp.dispose()
    print("Done.")
