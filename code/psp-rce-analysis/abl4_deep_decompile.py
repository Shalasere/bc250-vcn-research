#!/usr/bin/env python3
"""Deep decompile of ABL4 functions with stack buffers.

Key targets:
1. FUN_0006bc64 (8554 bytes): auStack_5b0[1000]
2. FUN_0006242c (192 bytes): auStack_430[1000]
3. All callers of memcpy-like functions
4. All functions referencing APCB data

Also: PSP_BL Ghidra cross-reference analysis for FUN_000004e0 and FUN_00000458.
"""
import os, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"

pyghidra.start(install_dir=GHIDRA_DIR)

# PART 1: ABL4 deep analysis
print("=" * 70)
print("PART 1: ABL4 — Functions with stack buffers")
print("=" * 70)

with pyghidra.open_program(
    ABL4_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_abl4_v3", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # Decompile FUN_0006242c first (smaller, more likely to be the vulnerable one)
    targets = [
        0x6242c,   # 192 bytes, auStack_430[1000]
        0x6bc64,   # 8554 bytes, auStack_5b0[1000]
    ]

    for addr in targets:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if not func:
            print("  No function at 0x{:05X}".format(addr))
            continue

        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("\n" + "=" * 70)
        print("{} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))
        print("=" * 70)

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if not result.decompileCompleted():
            print("  Decompile failed!")
            continue

        c = result.getDecompiledFunction().getC()

        # Stack buffer analysis
        buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
        if buffers:
            for name, size in buffers:
                print("  STACK BUFFER: {} [{}]".format(name, size))

        # Copy operations with variable sizes
        copy_patterns = re.findall(r'(FUN_[0-9a-f]+)\([^)]*param_[^)]*\)', c, re.I)
        if copy_patterns:
            print("  Functions called with params: {}".format(set(copy_patterns)[:10]))

        # Print the decompile
        if len(c) <= 8000:
            print(c)
        else:
            print(c[:8000])
            print("\n... ({} more chars)".format(len(c) - 8000))

    # Also decompile ALL functions that have stack buffers
    print("\n" + "=" * 70)
    print("ALL ABL4 functions with stack buffers >= 64 bytes")
    print("=" * 70)

    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        f = func_iter.next()
        addr = f.getEntryPoint().getOffset()
        fsize = f.getBody().getNumAddresses()

        result = decomp.decompileFunction(f, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
        large_bufs = [(n, int(s)) for n, s in buffers if int(s) >= 64]
        if large_bufs:
            print("\n  {} at 0x{:05X} ({} bytes):".format(f.getName(), addr, fsize))
            for name, size in large_bufs:
                print("    {} [{}]".format(name, size))

            # Check for copy operations TO these buffers
            for bname, bsize in large_bufs:
                # Look for memcpy-like calls with this buffer
                pattern = re.compile(r'FUN_[0-9a-f]+\([^)]*{}[^)]*\)'.format(bname), re.I)
                copies = pattern.findall(c)
                if copies:
                    print("    Copies involving {}:".format(bname))
                    for cp in copies[:5]:
                        print("      {}".format(cp.strip()[:100]))

            # Also check for loops that write to the buffer
            if 'while' in c and any(bname in c[c.find('while'):c.find('while')+500] for bname, _ in large_bufs):
                print("    *** LOOP WRITING TO BUFFER ***")

    decomp.dispose()

# PART 2: PSP_BL cross-reference analysis
print("\n\n" + "=" * 70)
print("PART 2: PSP_BL — Cross-references to copy functions")
print("=" * 70)

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

    # Use Ghidra references to find callers
    ref_mgr = program.getReferenceManager()

    for target_addr in [0x4e0, 0x458, 0x823c, 0x8150]:
        target = space.getAddress(target_addr)
        refs = ref_mgr.getReferencesTo(target)
        callers = []
        for ref in refs:
            if ref.getReferenceType().isCall():
                callers.append(ref.getFromAddress().getOffset())

        print("\n  Callers of FUN_{:04X}: {} refs".format(target_addr, len(callers)))
        for caller_addr in callers:
            func = func_mgr.getFunctionContaining(space.getAddress(caller_addr))
            fname = func.getName() if func else "unknown"
            fentry = func.getEntryPoint().getOffset() if func else 0
            print("    0x{:04X} (in {} @ 0x{:04X})".format(caller_addr, fname, fentry))

    # For each function containing a call to FUN_000004e0 or FUN_00000458,
    # decompile and check for variable-size copies to stack buffers
    print("\n  Checking for variable-size stack buffer copies...")

    seen_funcs = set()
    for target_addr in [0x4e0, 0x458]:
        target = space.getAddress(target_addr)
        refs = ref_mgr.getReferencesTo(target)
        for ref in refs:
            if ref.getReferenceType().isCall():
                func = func_mgr.getFunctionContaining(ref.getFromAddress())
                if func and func.getEntryPoint().getOffset() not in seen_funcs:
                    faddr = func.getEntryPoint().getOffset()
                    seen_funcs.add(faddr)
                    result = decomp.decompileFunction(func, 600, flat.getMonitor())
                    if not result.decompileCompleted():
                        continue
                    c = result.getDecompiledFunction().getC()
                    buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
                    # Check for param-dependent sizes
                    for copy_fn in ['FUN_000004e0', 'FUN_00000458']:
                        idx = 0
                        while True:
                            idx = c.find(copy_fn, idx)
                            if idx < 0:
                                break
                            end = c.find(';', idx)
                            if end > 0:
                                call_text = c[idx:end].strip()
                                has_param = 'param_' in call_text
                                has_stack = any(b[0] in call_text for b in buffers)
                                if has_param or has_stack:
                                    print("\n    {} (0x{:04X}): {}".format(
                                        func.getName(), faddr, call_text))
                                    if has_param:
                                        print("      *** PARAM-DEPENDENT SIZE ***")
                                    if has_stack:
                                        print("      *** WRITES TO STACK BUFFER ***")
                            idx += 1

    decomp.dispose()

print("\nDone.")
