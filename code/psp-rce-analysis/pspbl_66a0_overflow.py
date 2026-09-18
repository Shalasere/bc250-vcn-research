#!/usr/bin/env python3
"""Decompile FUN_000066A0 and its callees — the APCB data processing path.

Called from FUN_000044CC case 2:
  FUN_000066a0(0, group_id, data_ptr, data_size)

Also called from case 0x38/0x3D via the same path.

This is where the actual APCB data gets copied/processed.
The stack overflow is most likely here or in a callee.
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
        (0x66A0, "FUN_000066A0 — APCB data processing (prime overflow candidate)"),
        (0x55C0, "FUN_000055C0 — called from case 0x2d/0x32 (APCB token copy)"),
        (0x73D0, "FUN_000073D0 — called from case 2 for types 0x95/0x42/0x91"),
        (0x7F20, "FUN_00007F20 — called from case 0x63/0xa0"),
        (0x2B1C, "FUN_00002B1C — case 0x1f (0x38-byte buffer)"),
        (0x4388, "FUN_00004388 — case 0x20 (0x38-byte buffer)"),
        (0x53C4, "FUN_000053C4 — case 0xde structure processing"),
        (0x1720, "FUN_00001720 — case 0xf1 (called with APCB derived data)"),
        (0x4480, "FUN_00004480 — validation function (bounds check?)"),
        (0x300, "FUN_00000300 — SVC dispatch handler"),
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
                # For large functions, show key parts
                if len(c) > 8000:
                    # Show stack buffers and copies
                    print("  [LARGE — showing key sections]")
                    for kw in ['local_', 'memcpy', 'copy', 'size', 'len',
                               'param_3', 'param_4', 'while', 'for',
                               'FUN_000004e0', 'FUN_00000458']:
                        idx = c.find(kw)
                        if idx >= 0:
                            print("\n  [{}]:".format(kw))
                            ctx = c[max(0,idx-200):min(len(c),idx+600)]
                            print("  " + ctx[:800].replace('\n', '\n  '))
                    # Also show first 4000 chars
                    print("\n  [First 4000 chars]:")
                    print(c[:4000])
                else:
                    print(c)
            else:
                print("  FAILED: {}".format(result.getErrorMessage()))
        else:
            print("  No function at 0x{:X}".format(addr))
        print()

    decomp.dispose()
    print("Done.")
