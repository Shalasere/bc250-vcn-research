#!/usr/bin/env python3
"""Decompile the APCB data copy functions — where the overflow lives.

Key candidates:
1. FUN_00007014 — called from FUN_000066A0 with APCB data and size
2. FUN_0000823C — APCB header validation/copy
3. FUN_000057C4 — fills 1600-byte stack buffer in FUN_000053C4
4. FUN_000068AC — called from FUN_000073D0
5. FUN_00006984 — called after APCB processing
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
        (0x7014, "FUN_00007014 — APCB data copy/install (called from FUN_000066A0)"),
        (0x823C, "FUN_0000823C — APCB header validation"),
        (0x57C4, "FUN_000057C4 — fills 1600-byte stack buffer"),
        (0x68AC, "FUN_000068AC — called from FUN_000073D0 with stack buffer"),
        (0x6984, "FUN_00006984 — called after APCB processing"),
        (0x2C80, "FUN_00002C80 — called from FUN_000066A0 for APCB group lookup"),
        (0x83C, "FUN_0000083C — called from FUN_000066A0"),
        (0x571A, "FUN_0000571A — called from FUN_000055C0"),
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
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))
                # Show up to 5000 chars, looking for copy patterns
                if len(c) > 5000:
                    print("  [SHOWING FIRST 5000 CHARS]")
                    print(c[:5000])
                    # Also search for overflow patterns
                    for kw in ['memcpy', 'copy', 'FUN_000004e0', 'FUN_00000458',
                               'param_3', 'param_4', 'local_', 'auStack',
                               'while', 'for (']:
                        idx = c.find(kw)
                        if idx >= 0 and idx > 5000:
                            print("\n  [...{}]:".format(kw))
                            print("  " + c[max(0,idx-100):min(len(c),idx+500)].replace('\n', '\n  '))
                else:
                    print(c)
        else:
            print("  No function at 0x{:X}".format(addr))
        print()

    decomp.dispose()
    print("Done.")
