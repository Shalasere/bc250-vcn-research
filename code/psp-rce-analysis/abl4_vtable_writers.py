#!/usr/bin/env python3
"""Investigate ALL writes to vtable zone (+0x5B8..+0x6A0) in ABL4.

Focus on:
1. What function contains VA 0x6A7C4 (STRH to +0x630)?
2. Full decompile of FUN_0006BBC0 (writes to +0x52C, +0x530, +0x620, +0x624)
3. Find the memcpy function address and ALL callers
4. For memcpy callers: trace dest/length to find context-structure copies
"""
import os

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

    # 1. What function contains VA 0x6A7C4?
    print("=" * 70)
    print("1. Function containing VA 0x6A7C4 (STRH to +0x630)")
    print("=" * 70)
    addr = space.getAddress(0x6A7C4)
    func = func_mgr.getFunctionContaining(addr)
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  In {} (0x{:X}, {} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars decompiled".format(len(c)))
            # Show the section around the +0x630 write
            idx = c.find('0x630')
            if idx < 0:
                idx = c.find('630')
            if idx >= 0:
                start = max(0, idx - 400)
                end = min(len(c), idx + 400)
                print(c[start:end])
            else:
                print("  '+0x630' not found in decompile, showing first 3000 chars:")
                print(c[:3000])

    # 2. Full decompile FUN_0006BBC0
    print("\n" + "=" * 70)
    print("2. FUN_0006BBC0 (writes +0x2A4, +0x378, +0x52C, +0x530, +0x620, +0x624)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6BBC0))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)

    # 3. Find the memcpy function — check 0x60834 and 0x60870
    print("\n" + "=" * 70)
    print("3. Memcpy identification")
    print("=" * 70)
    for va in [0x60834, 0x60848, 0x60870, 0x60844]:
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if func:
            size = func.getBody().getNumAddresses()
            print("  0x{:X}: {} ({} bytes)".format(va, func.getName(), size))
        func2 = func_mgr.getFunctionContaining(space.getAddress(va))
        if func2 and (not func or func2.getEntryPoint() != func.getEntryPoint()):
            print("  0x{:X} is inside: {} (entry 0x{:X})".format(
                va, func2.getName(), func2.getEntryPoint().getOffset()))

    # 4. All callers of FUN_00060870 (suspected memcpy)
    print("\n" + "=" * 70)
    print("4. All callers of FUN_00060870")
    print("=" * 70)
    addr = space.getAddress(0x60870)
    refs = list(ref_mgr.getReferencesTo(addr))
    memcpy_callers = set()
    for r in refs:
        from_func = func_mgr.getFunctionContaining(r.getFromAddress())
        if from_func:
            entry = from_func.getEntryPoint().getOffset()
            memcpy_callers.add(entry)
            print("  Call at 0x{:X} in {} (0x{:X})".format(
                r.getFromAddress().getOffset(), from_func.getName(), entry))

    # Also check refs to 0x60834 and 0x60848
    for target in [0x60834, 0x60848]:
        addr = space.getAddress(target)
        refs = list(ref_mgr.getReferencesTo(addr))
        for r in refs:
            from_func = func_mgr.getFunctionContaining(r.getFromAddress())
            if from_func:
                entry = from_func.getEntryPoint().getOffset()
                if entry not in memcpy_callers:
                    memcpy_callers.add(entry)
                    print("  Call at 0x{:X} (to 0x{:X}) in {} (0x{:X})".format(
                        r.getFromAddress().getOffset(), target, from_func.getName(), entry))

    # 5. For EACH memcpy caller: decompile and search for context+offset destinations
    print("\n" + "=" * 70)
    print("5. Memcpy callers with context-relative destinations")
    print("=" * 70)

    for entry in sorted(memcpy_callers):
        func = func_mgr.getFunctionAt(space.getAddress(entry))
        if not func:
            continue
        result = decomp.decompileFunction(func, 120, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Look for memcpy-like calls with large offset destinations
        # Pattern: FUN_00060870(param_N + 0xNNN, ...) or memcpy to context+offset
        for pat in ['0x60870', '0x60834', 'FUN_00060870', 'FUN_00060834']:
            idx = c.find(pat)
            if idx >= 0:
                start = max(0, idx - 200)
                end = min(len(c), idx + 300)
                ctx = c[start:end].strip()
                # Only show if it has large offsets
                has_large_off = any(x in ctx for x in [
                    '+ 0x1', '+ 0x2', '+ 0x3', '+ 0x4', '+ 0x5', '+ 0x6',
                    '0x124', '0x2a4', '0x378', '0x510', '0x5b8', '0x620', '0x660',
                    'param_1', 'param_2', 'context', 'local_'
                ])
                if has_large_off:
                    print("\n  {} (0x{:X}):".format(func.getName(), entry))
                    print(ctx[:500])
                break

    # 6. Who writes to context+0x510..0x5B8 (the data fields)?
    # Look for functions writing to offsets 0x510-0x5B8 through any mechanism
    print("\n" + "=" * 70)
    print("6. Functions writing to context offsets 0x331, 0x516, 0x519, etc.")
    print("=" * 70)

    # These are the offsets FUN_00063284 READS from. Someone must WRITE them.
    target_offsets = ['0x331', '0x516', '0x519', '0x51a', '0x51b', '0x51d', '0x51e', '0x51f',
                      '0x523', '0x146', '0x147', '0x148', '0x149']

    fi = func_mgr.getFunctions(True)
    all_funcs = []
    while fi.hasNext():
        all_funcs.append(fi.next())

    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        if entry == 0x63284:
            continue  # Skip the reader itself
        result = decomp.decompileFunction(func, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        for off in target_offsets:
            if off in c:
                # Check if it's a WRITE (not a read)
                idx = c.find(off)
                while idx >= 0:
                    # Check context: is there a '=' after the offset (within 50 chars)?
                    context_after = c[idx:min(len(c), idx+80)]
                    if '=' in context_after.split('\n')[0]:
                        fname = func.getName()
                        ctx = c[max(0,idx-80):min(len(c),idx+120)].replace('\n',' ').strip()
                        print("  {} (0x{:X}): WRITES offset {}: ...{}...".format(
                            fname, entry, off, ctx[:200]))
                        break
                    idx = c.find(off, idx + 1)

    # 7. The SPECIFIC function that INITIALIZES context+0x331 (this controls the APCB override path)
    print("\n" + "=" * 70)
    print("7. Who initializes context+0x331 (APCB override enable flag)?")
    print("=" * 70)

    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Check for writes to +0x331
        if '0x331' in c and ('param_1' in c or 'param_2' in c):
            idx = c.find('0x331')
            while idx >= 0:
                context = c[max(0,idx-100):min(len(c),idx+100)]
                if '=' in context or 'memset' in context.lower() or 'FUN_000608' in context:
                    print("  {} (0x{:X}):".format(func.getName(), entry))
                    print("  ...{}...".format(context.replace('\n',' ').strip()[:200]))
                    break
                idx = c.find('0x331', idx + 1)

    decomp.dispose()
    print("\nDone.")
