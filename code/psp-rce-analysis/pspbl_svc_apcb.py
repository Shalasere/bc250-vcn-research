#!/usr/bin/env python3
"""Full decompilation of PSP_BL SVC handler FUN_000044CC,
focused on case 0x61 (APCB operations) and case 0x62 (APCB loading).

Also decompile:
- FUN_00003D6C (52 bytes, maps 0x5D004 — writes to context?)
- FUN_00005F1C (maps something, called from boot)
- FUN_000030E0 (mapper + memcpy)
- FUN_000082E6 (called before ABL4 launch)
- ALL functions called from case 0x61/0x62 blocks
"""
import os, struct, re

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

    # 1. FULL decompilation of FUN_000044CC (SVC handler, 2728 bytes)
    print("=" * 70)
    print("FUN_000044CC — SVC HANDLER (FULL, 2728 bytes)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("Total decompiled: {} chars".format(len(c)))

            # Find case 0x61 block
            idx_61 = c.find('0x61')
            if idx_61 >= 0:
                print("\n--- Context around '0x61' in SVC handler ---")
                # Show 2000 chars around it
                start = max(0, idx_61 - 500)
                end = min(len(c), idx_61 + 2000)
                print(c[start:end])
            else:
                print("  '0x61' not found in decompiled output!")

            # Find case 0x62 block
            idx_62 = c.find('0x62')
            if idx_62 >= 0:
                print("\n--- Context around '0x62' in SVC handler ---")
                start = max(0, idx_62 - 200)
                end = min(len(c), idx_62 + 1500)
                print(c[start:end])

            # Find ALL switch cases
            print("\n--- All switch/case values ---")
            for m in re.finditer(r'case\s+(0x[0-9a-fA-F]+|[0-9]+)', c):
                val = m.group(1)
                ctx = c[m.start():min(len(c), m.end()+200)].replace('\n',' ').strip()
                print("  case {}: ...{}...".format(val, ctx[:150]))

            # Search for copy/write patterns
            print("\n--- Copy/write/memcpy patterns in SVC handler ---")
            for pat in ['FUN_000004e0', 'FUN_00000458', '= *', 'while', 'for (',
                        'local_', 'len', 'size', 'saved', '0x5d7', '0x5de',
                        '0x660', 'param_2 +', 'offset', 'group']:
                for m in re.finditer(re.escape(pat) if '(' not in pat and '*' not in pat else pat, c):
                    ctx = c[max(0,m.start()-60):min(len(c),m.end()+100)].replace('\n',' ').strip()
                    print("  [{}]: ...{}...".format(pat, ctx[:180]))
                    break  # Just first match of each

    # 2. Decompile functions that might WRITE to context area
    targets2 = [
        (0x3D6C, "FUN_00003D6C (52 bytes, maps 0x5D004)"),
        (0x5F1C, "FUN_00005F1C (mapper, called from boot)"),
        (0x30E0, "FUN_000030E0 (mapper + memcpy)"),
        (0x82E6, "FUN_000082E6 (called before ABL launch)"),
        (0x6210, "FUN_00006210 (mapper caller)"),
        (0x7868, "FUN_00007868 (2 memcpy calls via mapper)"),
        (0x79D0, "FUN_000079D0 (2 mapper calls)"),
    ]

    for va, desc in targets2:
        print("\n" + "=" * 70)
        print(desc)
        print("=" * 70)
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if func:
            size = func.getBody().getNumAddresses()
            print("  {} bytes".format(size))
            result = decomp.decompileFunction(func, 180, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print(c[:6000] if len(c) > 6000 else c)

    # 3. Search for ALL functions that use FUN_000004E0 or FUN_00000458
    # with the CONTEXT POINTER as the destination
    # The context might be passed as a parameter or through a global
    print("\n" + "=" * 70)
    print("ALL functions with writes through param + large offset (>= 0x500)")
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

        # Look for writes like *(type *)(param + 0x5xx) = ...
        for m in re.finditer(r'\*\s*\([^)]+\)\s*\(\s*\w+\s*\+\s*0x([5-9a-f][0-9a-f]{2,})\s*\)\s*=', c):
            off = int(m.group(1), 16)
            if off >= 0x500:
                ctx = c[max(0,m.start()-30):min(len(c),m.end()+80)].replace('\n',' ').strip()
                print("  FUN_{:08X}: +0x{:X} = ... | ...{}...".format(entry, off, ctx[:150]))

    # 4. Also search for INDIRECT writes: store through dereferenced pointer
    # Pattern: ptr = *(param + N); *(ptr + M) = ...  where N+M could reach 0x660
    print("\n" + "=" * 70)
    print("Functions with DAT_00005028 (APCB buffer in SVC) references")
    print("=" * 70)

    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        if 'DAT_00005028' in c or '0x5028' in c:
            size = func.getBody().getNumAddresses()
            print("\n  FUN_{:08X} ({} bytes):".format(entry, size))
            for m in re.finditer(r'DAT_00005028|0x5028', c):
                ctx = c[max(0,m.start()-60):min(len(c),m.end()+120)].replace('\n',' ').strip()
                print("    ...{}...".format(ctx[:180]))

    decomp.dispose()
    print("\nDone.")
