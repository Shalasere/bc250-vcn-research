#!/usr/bin/env python3
"""Decompile FUN_000057c4 (token reader writing to auStack_664) and
trace the full call chain for the 1600-byte stack buffer overflow.

Also:
- Full 0xDE case from FUN_000044CC
- FUN_00007014 integer overflow check
- FUN_000056c4 (called with auStack_664)
- FUN_000055C0 (another APCB handler with stack buffer)
- FUN_00005F9C (validation function in 053C4)
"""
import os, re
os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

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

    # CRITICAL functions to analyze
    targets = [
        (0x57C4, "FUN_000057C4 — TOKEN READER (writes to auStack_664!)"),
        (0x56C4, "FUN_000056C4 — called with auStack_664 after read"),
        (0x55C0, "FUN_000055C0 — another APCB handler"),
        (0x5F9C, "FUN_00005F9C — validation in FUN_000053C4"),
        (0x7014, "FUN_00007014 — APCB handler with alignment calc"),
        (0x71AC, "FUN_000071AC — APCB copy handler"),
        (0x4480, "FUN_00004480 — validator called from 0xDE case"),
        (0x850, "FUN_00000850 — token read helper"),
    ]

    for addr, desc in targets:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if func:
            entry = func.getEntryPoint().getOffset()
            fsize = func.getBody().getNumAddresses()
            print("=" * 70)
            print("{} at 0x{:04X} ({} bytes)".format(desc, entry, fsize))
            print("=" * 70)
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()

                # Stack buffer analysis
                buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
                if buffers:
                    for name, size in buffers:
                        print("  STACK BUFFER: {} [{}]".format(name, size))

                # Copy operations with sizes
                for copy_fn in ['FUN_0000823c', 'FUN_00008150', 'FUN_000004e0',
                                'FUN_00000458', 'FUN_00001c18']:
                    idx = 0
                    while True:
                        idx = c.find(copy_fn, idx)
                        if idx < 0:
                            break
                        # Extract the full call context (up to closing paren)
                        end = c.find(';', idx)
                        if end > 0:
                            call_text = c[idx:end].strip()
                            print("  COPY CALL: {}".format(call_text))
                        idx += 1

                # Check for param-dependent sizes
                size_refs = re.findall(r'(param_\d+)\s*\+\s*0x([0-9a-f]+)', c, re.I)
                if size_refs:
                    print("  PARAM OFFSETS:")
                    for p, off in size_refs:
                        print("    {} + 0x{}".format(p, off))

                print(c[:6000])
                if len(c) > 6000:
                    print("\n... ({} more chars)".format(len(c) - 6000))
            print()
        else:
            print("  No Ghidra function at/containing 0x{:04X}\n".format(addr))

    # Now get the FULL 0xDE case from FUN_000044CC
    print("=" * 70)
    print("FULL 0xDE CASE from FUN_000044CC")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x44CC))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Extract the full 0xDE case
            idx = c.lower().find('0xde')
            if idx >= 0:
                # Go back to find the if/case start
                start = max(0, idx - 300)
                end = min(len(c), idx + 1500)
                print(c[start:end])

    # Also: extract ALL cases that call FUN_000053C4 or FUN_000055C0
    print("\n" + "=" * 70)
    print("ALL SVC cases calling 053C4 or 055C0")
    print("=" * 70)
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            for fn_name in ['FUN_000053c4', 'FUN_000055c0', 'FUN_000057c4',
                            'FUN_000056c4', 'FUN_000074c8']:
                idx = c.lower().find(fn_name.lower())
                if idx >= 0:
                    start = max(0, idx - 200)
                    end = min(len(c), idx + 200)
                    print("\n  {} context:".format(fn_name))
                    print(c[start:end])

    decomp.dispose()

print("\nDone.")
