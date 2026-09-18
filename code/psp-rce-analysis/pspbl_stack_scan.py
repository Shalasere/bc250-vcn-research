#!/usr/bin/env python3
"""Find ALL large stack allocations in PSP_BL.

Strategy: Instead of tracing call chains, find every function with a
stack frame > 0x80 bytes. The CVE stack overflow must be in one of these.
Then check whether any are reachable from APCB processing.
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

    # Enumerate ALL functions and their stack frame sizes
    print("=" * 70)
    print("ALL PSP_BL functions with stack frame > 0x40 bytes")
    print("=" * 70)

    big_stack_funcs = []
    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        frame = func.getStackFrame()
        if frame:
            frame_size = frame.getFrameSize()
            if frame_size > 0x40:
                entry = func.getEntryPoint().getOffset()
                code_size = func.getBody().getNumAddresses()
                big_stack_funcs.append((frame_size, entry, code_size, func.getName()))

    big_stack_funcs.sort(reverse=True)

    for frame_size, entry, code_size, name in big_stack_funcs:
        print("  Frame 0x{:04X} ({:5d}) | Entry 0x{:04X} | Code {:5d}B | {}".format(
            frame_size, frame_size, entry, code_size, name))

    # Now decompile the TOP 10 by stack frame size
    print("\n" + "=" * 70)
    print("DECOMPILE: Top stack-heavy functions (overflow candidates)")
    print("=" * 70)

    for frame_size, entry, code_size, name in big_stack_funcs[:12]:
        print("\n" + "-" * 60)
        print("{} at 0x{:04X} (stack frame 0x{:X}, code {}B)".format(
            name, entry, frame_size, code_size))
        print("-" * 60)
        func = func_mgr.getFunctionAt(space.getAddress(entry))
        if func:
            result = decomp.decompileFunction(func, 300, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                # Show variable declarations and function calls (overflow indicators)
                lines = c.split('\n')
                # Show first 80 lines (declarations + early logic)
                snippet = '\n'.join(lines[:80])
                print(snippet)
                if len(lines) > 80:
                    print("  ... ({} more lines)".format(len(lines) - 80))
                    # Also extract all function calls
                    calls = set()
                    for line in lines:
                        stripped = line.strip()
                        if 'FUN_' in stripped and '(' in stripped:
                            # Extract function name
                            idx = stripped.find('FUN_')
                            end = stripped.find('(', idx)
                            if end > idx:
                                calls.add(stripped[idx:end])
                    if calls:
                        print("  CALLEES: {}".format(', '.join(sorted(calls))))
            else:
                print("  DECOMPILE FAILED: {}".format(result.getErrorMessage()))

    # Also: search for functions called from FUN_000044CC that we haven't checked
    print("\n" + "=" * 70)
    print("FUN_000044CC callees (SVC dispatcher) — checking for uncovered functions")
    print("=" * 70)

    func_44cc = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if func_44cc:
        result = decomp.decompileFunction(func_44cc, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            calls = set()
            for line in c.split('\n'):
                if 'FUN_' in line and '(' in line:
                    idx = line.find('FUN_')
                    while idx >= 0:
                        end = line.find('(', idx)
                        if end > idx:
                            calls.add(line[idx:end])
                        idx = line.find('FUN_', end if end > 0 else idx + 1)
            print("  Direct callees: {}".format(', '.join(sorted(calls))))

    decomp.dispose()
    print("\nDone.")
