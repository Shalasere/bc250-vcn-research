#!/usr/bin/env python3
"""Trace FUN_0006AEC0 — the typed write function that does param_2[uVar2] = data.

This function writes through a variable offset, potentially into the context
structure. If param_2 is the context base and uVar2 is APCB-derived, this
is the overflow path.

1. Full decompilation of FUN_0006AEC0
2. Find ALL callers (xrefs to 0x6AEC0)
3. Decompile each caller to trace where param_2 and the offset come from
4. Also look at the CBSG (0x1707) sub-cases in FUN_0006804C for different buffer sizes
5. Search for integer overflow patterns in APCB size calculations
"""
import os, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

pyghidra.start(install_dir=GHIDRA_DIR)

with pyghidra.open_program(
    ABL4_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_abl4_v3", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # 1. Full decompilation of FUN_0006AEC0
    print("=" * 70)
    print("FUN_0006AEC0 — typed write function (full)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6AEC0))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)

    # 2. Find ALL callers of FUN_0006AEC0
    print("\n" + "=" * 70)
    print("ALL callers of FUN_0006AEC0")
    print("=" * 70)
    addr = space.getAddress(0x6AEC0)
    refs = list(ref_mgr.getReferencesTo(addr))
    caller_entries = set()
    for r in refs:
        from_addr = r.getFromAddress().getOffset()
        from_func = func_mgr.getFunctionContaining(r.getFromAddress())
        if from_func:
            entry = from_func.getEntryPoint().getOffset()
            caller_entries.add(entry)
            fname = from_func.getName()
            size = from_func.getBody().getNumAddresses()
            print("  0x{:X} in {} (0x{:X}, {} bytes)".format(from_addr, fname, entry, size))

    # 3. Decompile each caller to trace param_2 and offset
    print("\n" + "=" * 70)
    print("DECOMPILE ALL CALLERS")
    print("=" * 70)
    for entry in sorted(caller_entries):
        func = func_mgr.getFunctionAt(space.getAddress(entry))
        if not func:
            continue
        size = func.getBody().getNumAddresses()
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        print("\n" + "-" * 70)
        print("FUN_{:08X} ({} bytes)".format(entry, size))
        print("-" * 70)

        # Show full if small, otherwise just the AEC0 call context
        if len(c) < 3000:
            print(c)
        else:
            print("  [{} chars total]".format(len(c)))
            # Show each call to FUN_0006AEC0 with surrounding context
            for m in re.finditer(r'FUN_0006aec0', c, re.IGNORECASE):
                start = max(0, m.start() - 300)
                end = min(len(c), m.end() + 200)
                print("\n  --- Call site ---")
                print(c[start:end])

    # 4. Find ALL callers of the CALLERS (2 levels up) for context pointer tracing
    print("\n" + "=" * 70)
    print("SECOND-LEVEL CALLERS (who calls the AEC0 callers?)")
    print("=" * 70)
    for entry in sorted(caller_entries):
        addr = space.getAddress(entry)
        refs = list(ref_mgr.getReferencesTo(addr))
        if refs:
            fname = func_mgr.getFunctionAt(addr).getName() if func_mgr.getFunctionAt(addr) else "?"
            callers = []
            for r in refs:
                from_func = func_mgr.getFunctionContaining(r.getFromAddress())
                if from_func:
                    callers.append("{}(0x{:X})".format(
                        from_func.getName(), from_func.getEntryPoint().getOffset()))
            print("  {} <- {}".format(fname, ", ".join(set(callers))))

    # 5. Search for integer overflow patterns in ALL ABL4 functions
    # Pattern: (uint16)(a + b) or (a * b) where result could overflow
    print("\n" + "=" * 70)
    print("APCB size-related integer patterns in ABL4")
    print("=" * 70)

    fi = func_mgr.getFunctions(True)
    all_funcs = []
    while fi.hasNext():
        all_funcs.append(fi.next())

    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Look for: type_size, data_size, group size calculations
        for pat in [r'& 0xffff', r'\(ushort\)', r'\(short\)', r'type_size', r'data_size',
                    r'\+ 0x10\b', r'\+ 0x20\b']:
            for m in re.finditer(pat, c):
                ctx = c[max(0,m.start()-80):min(len(c),m.end()+80)].replace('\n',' ').strip()
                if any(kw in ctx for kw in ['size', 'len', 'count', 'param', 'local', '+']):
                    print("  FUN_{:08X}: ...{}...".format(entry, ctx[:160]))
                    break

    decomp.dispose()
    print("\nDone.")
