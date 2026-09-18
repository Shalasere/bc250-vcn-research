#!/usr/bin/env python3
"""Deep hunt for CVE-2025-29951 — PSP BL stack buffer overflow.

Strategy: Full decompile of every function that has BOTH:
  1. A stack buffer (auStack_XX or fixed-size local array)
  2. A call to FUN_00000458 (memcpy) or FUN_000004E0 (optimized copy)
     where the size argument could trace back to attacker-controlled data

Also check functions in the APCB processing call chain that we haven't
fully analyzed.
"""
import os, struct, re, sys

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

OUTPUT = r"C:\Users\WORK~1.DES\AppData\Local\Temp\claude\C--Users-work-DESKTOP-SAM98TB\c5f1fa55-5f57-4770-9f66-592352064239\scratchpad\overflow_deep_analysis.txt"

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

    # Enumerate all functions
    all_funcs = []
    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        f = func_iter.next()
        entry = f.getEntryPoint().getOffset()
        size = f.getBody().getNumAddresses()
        name = f.getName()
        all_funcs.append((entry, size, name, f))

    all_funcs.sort(key=lambda x: x[0])
    print("Total functions: {}".format(len(all_funcs)))

    # Phase 1: Decompile ALL functions and find those with stack buffers + copy calls
    # This is the thorough approach - check EVERY function

    hits = []  # (entry, size, name, decompiled_c, reasons)

    for idx, (entry, size, name, func) in enumerate(all_funcs):
        if idx % 30 == 0:
            print("  Phase 1 progress: {}/{} ...".format(idx, len(all_funcs)))

        result = decomp.decompileFunction(func, 120, flat.getMonitor())
        if not result or not result.decompileCompleted():
            continue

        c = result.getDecompiledFunction().getC()
        c_lower = c.lower()

        # Must have BOTH a stack buffer AND a copy function call
        has_stack_buf = bool(re.search(r'auStack_[0-9a-fA-F]{2,}', c))
        has_copy = ('fun_00000458' in c_lower or 'fun_000004e0' in c_lower)

        if not (has_stack_buf and has_copy):
            continue

        # Now analyze: is the copy size param-derived or hardcoded?
        reasons = []

        # Extract stack buffer sizes
        stack_bufs = re.findall(r'auStack_([0-9a-fA-F]+)\s*\[(\d+)\]', c)
        for offset_hex, arr_size in stack_bufs:
            reasons.append("stack buf auStack_{} [{}]".format(offset_hex, arr_size))

        # Find copy calls and check if size is a param or variable vs constant
        # FUN_00000458(dest, src, size) — standard memcpy
        copy_calls_458 = re.findall(r'FUN_00000458\(([^)]+)\)', c)
        for call_args in copy_calls_458:
            args = [a.strip() for a in call_args.split(',')]
            if len(args) >= 3:
                size_arg = args[2]
                # Check if any arg references a stack buffer
                dest_arg = args[0]
                is_stack_dest = 'auStack' in dest_arg or 'local_' in dest_arg
                is_param_size = 'param_' in size_arg
                is_var_size = (not size_arg.startswith('0x') and
                              not size_arg.isdigit() and
                              'param_' not in size_arg and
                              size_arg not in ['0'])

                if is_stack_dest and is_param_size:
                    reasons.append("CRITICAL: memcpy to stack with param size: {}".format(call_args))
                elif is_stack_dest and is_var_size:
                    reasons.append("SUSPICIOUS: memcpy to stack with var size: {}".format(call_args))
                elif is_stack_dest:
                    reasons.append("memcpy to stack (const size): {}".format(call_args))

        # FUN_000004E0(dest, src, size) — optimized copy
        copy_calls_4e0 = re.findall(r'FUN_000004e0\(([^)]+)\)', c, re.IGNORECASE)
        for call_args in copy_calls_4e0:
            args = [a.strip() for a in call_args.split(',')]
            if len(args) >= 3:
                size_arg = args[2]
                dest_arg = args[0]
                is_stack_dest = 'auStack' in dest_arg or 'local_' in dest_arg
                is_param_size = 'param_' in size_arg
                is_var_size = (not size_arg.startswith('0x') and
                              not size_arg.isdigit() and
                              'param_' not in size_arg)

                if is_stack_dest and is_param_size:
                    reasons.append("CRITICAL: opt_copy to stack with param size: {}".format(call_args))
                elif is_stack_dest and is_var_size:
                    reasons.append("SUSPICIOUS: opt_copy to stack with var size: {}".format(call_args))

        if reasons:
            priority = 0
            for r in reasons:
                if 'CRITICAL' in r:
                    priority = 2
                elif 'SUSPICIOUS' in r and priority < 1:
                    priority = 1
            hits.append((entry, size, name, c, reasons, priority))

    # Sort by priority (CRITICAL first)
    hits.sort(key=lambda x: -x[5])

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("CVE-2025-29951 Deep Overflow Analysis\n")
        out.write("=" * 70 + "\n\n")
        out.write("Functions with stack buffer + copy call: {}\n".format(len(hits)))
        out.write("  CRITICAL (param-derived size to stack): {}\n".format(
            sum(1 for h in hits if h[5] == 2)))
        out.write("  SUSPICIOUS (variable size to stack): {}\n".format(
            sum(1 for h in hits if h[5] == 1)))
        out.write("  Low (constant size to stack): {}\n\n".format(
            sum(1 for h in hits if h[5] == 0)))

        for entry, size, name, c, reasons, priority in hits:
            tag = ["LOW", "SUSPICIOUS", "*** CRITICAL ***"][priority]
            out.write("=" * 70 + "\n")
            out.write("[0x{:04X}] {} ({} bytes) — {}\n".format(entry, name, size, tag))
            out.write("Flags:\n")
            for r in reasons:
                out.write("  - {}\n".format(r))
            out.write("\nFull decompilation:\n")
            out.write(c)
            out.write("\n\n")

    decomp.dispose()

print("\nAnalysis written to: {}".format(OUTPUT))
print("\nSummary:")
print("  Total hits: {}".format(len(hits)))
for entry, size, name, _, reasons, priority in hits:
    if priority >= 1:
        tag = ["LOW", "SUSPICIOUS", "*** CRITICAL ***"][priority]
        print("  0x{:04X} {} ({} bytes) — {}".format(entry, name, size, tag))
        for r in reasons:
            if 'CRITICAL' in r or 'SUSPICIOUS' in r:
                print("    {}".format(r))
