#!/usr/bin/env python3
"""Deep decompile the most suspicious functions for CVE-2025-29951.

Priority targets:
1. FUN_00004138 — called by multiple functions with stack buf + variable args
2. FUN_000021a0 — called with tiny (8-byte) stack buffers
3. FUN_000022aa — passes 8-byte stack buf to hash/copy
4. FUN_00008488 — passes 8-byte stack buf to hash/copy
5. FUN_000005f0 — dual stack buffers + variable params
6. FUN_000053c4 — 1600-byte stack buffer
7. FUN_00001720 — stack buf passed to FUN_00004138
8. FUN_000025a4 — called from 0x7B00 with key encryption context
9. FUN_00001eb4 — called from 0x1D30, writes to stack buf
10. FUN_00006992 — called with stack buffers from 0x56C4 and 0x5758
"""
import os

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

OUTPUT = r"C:\Users\WORK~1.DES\AppData\Local\Temp\claude\C--Users-work-DESKTOP-SAM98TB\c5f1fa55-5f57-4770-9f66-592352064239\scratchpad\suspect_decompilations.txt"

TARGETS = [
    0x4138,  # callee: called by 0x5F0, 0x750, 0x1720 with stack bufs
    0x21A0,  # callee: called with tiny stack bufs
    0x22AA,  # caller: 8-byte stack buf -> hash/copy
    0x8488,  # caller: 8-byte stack buf -> hash/copy
    0x05F0,  # caller: dual stack bufs + variable params
    0x53C4,  # caller: 1600-byte stack buf
    0x1720,  # caller: stack buf -> FUN_00004138
    0x0750,  # caller: stack buf -> FUN_00004138
    0x25A4,  # callee: key encryption related
    0x1EB4,  # callee: writes to stack buf from 0x1D30
    0x6992,  # callee: called with stack bufs
    0x8064,  # callee: called from 0x7014 with stack bufs
    0x8500,  # callee: called with stack bufs
    0x56C4,  # caller: small stack bufs
    0x5758,  # caller: small stack bufs
    0x62F8,  # caller: stack buf + variable params
    0x051FC, # callee: called from 0x62F8
    0x6EE0,  # callee: called from 0x56C4
    0x7B00,  # caller: key encryption with 32-byte stack buf
    0x73D0,  # caller: stack bufs passed to 0x5F5C and 0x68AC
    0x68AC,  # callee: called from 0x73D0
    0x1886,  # callee: called from 0x7B00
]

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

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("Deep Decompilation of CVE-2025-29951 Suspects\n")
        out.write("=" * 70 + "\n\n")

        for target in TARGETS:
            func = func_mgr.getFunctionAt(space.getAddress(target))
            if not func:
                func = func_mgr.getFunctionContaining(space.getAddress(target))
            if not func:
                out.write("[0x{:04X}] -- NOT FOUND\n\n".format(target))
                print("  0x{:04X}: NOT FOUND".format(target))
                continue

            entry = func.getEntryPoint().getOffset()
            fsize = func.getBody().getNumAddresses()
            name = func.getName()

            result = decomp.decompileFunction(func, 300, flat.getMonitor())
            if not result or not result.decompileCompleted():
                out.write("[0x{:04X}] {} ({} bytes) -- DECOMPILE FAILED\n\n".format(
                    entry, name, fsize))
                print("  0x{:04X} {}: DECOMPILE FAILED".format(entry, name))
                continue

            c = result.getDecompiledFunction().getC()
            out.write("=" * 70 + "\n")
            out.write("[0x{:04X}] {} ({} bytes)\n".format(entry, name, fsize))
            out.write("=" * 70 + "\n")
            out.write(c)
            out.write("\n\n")

            # Quick summary
            print("  0x{:04X} {} ({} bytes): {} lines".format(
                entry, name, fsize, len(c.split('\n'))))

    decomp.dispose()

print("\nDecompilations written to: {}".format(OUTPUT))
