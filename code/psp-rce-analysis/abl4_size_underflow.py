#!/usr/bin/env python3
"""Trace the APCB group size through ABL4's parsing chain.

Key finding: FUN_00068420 computes payload_size = *(ushort*)(header+4) - 0x10.
If header size field < 0x10, this underflows. Trace where that size goes.

Also: FUN_0006804C's token loop has NO length check — it reads until sentinel 0x1FFF.
If sentinel is missing (crafted APCB), the loop reads past the buffer, processing
garbage as tokens and writing to the heap buffer until it overflows.

Plan:
1. Full decompile FUN_00068420 (APCB group finder)
2. Full decompile FUN_0006804C (token processor) — focus on how returned size is used
3. Decompile FUN_00069D78 (APCB iterator/walker)
4. Decompile FUN_00069FAC (APCB accessor)
5. Look at APCB main header validation — FUN_0006A52C area
6. Check the CBSG (0x1707) special sub-cases with two different buffer sizes
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

    # 1. FUN_00068420 — APCB group finder (where the size underflow lives)
    targets = [
        (0x68420, "FUN_00068420 — APCB group finder (SIZE UNDERFLOW?)"),
        (0x69D78, "FUN_00069D78 — APCB iterator/walker"),
        (0x69FAC, "FUN_00069FAC — APCB accessor"),
        (0x6804C, "FUN_0006804C — APCB token processor (SENTINEL LOOP)"),
        (0x60B80, "FUN_00060B80 — APCB header/config parser"),
        (0x63284, "FUN_00063284 — reads context+0x516 (APCB-derived config user)"),
    ]

    for va, desc in targets:
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if not func:
            print("\n{}: NOT FOUND".format(desc))
            continue

        size = func.getBody().getNumAddresses()
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if not result.decompileCompleted():
            print("\n{}: DECOMPILE FAILED".format(desc))
            continue

        c = result.getDecompiledFunction().getC()

        print("\n" + "=" * 70)
        print("{} ({} bytes, {} chars decompiled)".format(desc, size, len(c)))
        print("=" * 70)

        if len(c) <= 8000:
            print(c)
        else:
            # Show first 4000 chars
            print(c[:4000])
            print("\n... [{} total] ...".format(len(c)))

            # Show key patterns
            for pat in ['size', 'len', '0x10', 'param_4', 'ushort', 'short',
                        'local_64', 'auStack', '0x1fff', 'sentinel',
                        'while', 'for (', 'FUN_00068420',
                        '0x1707', '0x1705', 'CBSG', 'GNBG',
                        'case 9', 'case 10', 'case 11', 'case 12',
                        'uVar12', 'uVar13', 'uVar14',
                        'buffer', 'alloc', 'heap',
                        'memcpy', 'FUN_000604', 'FUN_00060870']:
                for m in re.finditer(re.escape(pat) if '(' not in pat else pat, c, re.IGNORECASE):
                    start = max(0, m.start() - 100)
                    end = min(len(c), m.end() + 200)
                    ctx = c[start:end].replace('\n', ' ').strip()
                    print("\n  [{}]: ...{}...".format(pat, ctx[:250]))
                    break

    # 2. Callers of FUN_00068420 — who uses the size value?
    print("\n" + "=" * 70)
    print("ALL callers of FUN_00068420")
    print("=" * 70)

    addr = space.getAddress(0x68420)
    refs = list(ref_mgr.getReferencesTo(addr))
    caller_entries = set()
    for r in refs:
        from_func = func_mgr.getFunctionContaining(r.getFromAddress())
        if from_func:
            entry = from_func.getEntryPoint().getOffset()
            caller_entries.add(entry)
            print("  0x{:X} in {} (0x{:X}, {} bytes)".format(
                r.getFromAddress().getOffset(),
                from_func.getName(), entry,
                from_func.getBody().getNumAddresses()))

    # 3. For each caller, show the FUN_00068420 call and how the returned size is used
    print("\n" + "=" * 70)
    print("HOW CALLERS USE THE RETURNED SIZE")
    print("=" * 70)

    for entry in sorted(caller_entries):
        func = func_mgr.getFunctionAt(space.getAddress(entry))
        if not func:
            continue
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        fname = func.getName()
        print("\n  --- {} (0x{:X}) ---".format(fname, entry))

        # Find each call to FUN_00068420 with 500 chars of following context
        for m in re.finditer(r'FUN_00068420', c, re.IGNORECASE):
            start = max(0, m.start() - 100)
            end = min(len(c), m.end() + 600)
            print(c[start:end])
            print()

    # 4. Check ABL4's initial SP / stack setup
    print("\n" + "=" * 70)
    print("ABL4 entry point and stack setup")
    print("=" * 70)

    # ABL4 entry point should be the first function
    first_func = func_mgr.getFunctionAt(space.getAddress(0x60834))
    if first_func:
        size = first_func.getBody().getNumAddresses()
        print("  Entry function at 0x60834: {} ({} bytes)".format(first_func.getName(), size))
        result = decomp.decompileFunction(first_func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:3000])
    else:
        print("  No function at 0x60834!")
        # Check nearby
        for delta in range(-16, 17, 2):
            f = func_mgr.getFunctionAt(space.getAddress(0x60834 + delta))
            if f:
                print("  Found: {} at 0x{:X}".format(f.getName(), 0x60834 + delta))

    # 5. Find the largest ABL4 functions (potential stack buffer overflow candidates)
    print("\n" + "=" * 70)
    print("Largest ABL4 functions (by code size)")
    print("=" * 70)

    fi = func_mgr.getFunctions(True)
    all_funcs = []
    while fi.hasNext():
        f = fi.next()
        all_funcs.append((f.getEntryPoint().getOffset(), f.getBody().getNumAddresses(), f.getName()))

    all_funcs.sort(key=lambda x: -x[1])
    for entry, size, name in all_funcs[:20]:
        print("  {} (0x{:X}): {} bytes".format(name, entry, size))

    # 6. Search for FUN_00060870 (memcpy-like?) callers that use APCB-derived sizes
    print("\n" + "=" * 70)
    print("Functions with APCB group parsing + memcpy")
    print("=" * 70)

    for entry, size, name in all_funcs:
        result = decomp.decompileFunction(
            func_mgr.getFunctionAt(space.getAddress(entry)), 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        has_apcb = 'FUN_00068420' in c or 'FUN_00069d78' in c or 'FUN_00069fac' in c
        has_copy = 'FUN_00060870' in c or 'FUN_000604' in c

        if has_apcb and has_copy:
            print("\n  {} (0x{:X}, {} bytes) — APCB + copy!".format(name, entry, size))
            for pat in ['FUN_00068420', 'FUN_00069d78', 'FUN_00060870', 'FUN_000604']:
                for m in re.finditer(pat, c, re.IGNORECASE):
                    ctx = c[max(0,m.start()-80):min(len(c),m.end()+200)].replace('\n',' ').strip()
                    print("    [{}]: ...{}...".format(pat, ctx[:200]))
                    break

    decomp.dispose()
    print("\nDone.")
