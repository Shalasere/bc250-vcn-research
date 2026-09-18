#!/usr/bin/env python3
"""Hunt for the APCB overflow function in PSP_BL.

Target: Function that writes APCB-derived data into the context structure
area (0x5D7AC+) using a length variable that may be uninitialized.

Strategy:
1. Decompile FUN_000075A4 (3 memcpy calls — most likely overflow source)
2. Decompile FUN_0000823C (called with 0x4F0 size from boot flow)
3. Decompile FUN_000057C4, FUN_000024FC, FUN_000003BA4, FUN_00000458
4. Search ALL large PSP_BL functions for uninitialized length patterns
5. Find functions that reference BOTH APCB data AND context SRAM addresses
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

print("Starting pyghidra...")
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

    # Key functions to decompile (memcpy callers)
    targets = [
        (0x75A4, "FUN_000075A4 (3 memcpy calls — prime overflow candidate)"),
        (0x823C, "FUN_0000823C (called with size 0x4F0 from boot)"),
        (0x57C4, "FUN_000057C4 (memcpy caller)"),
        (0x24FC, "FUN_000024FC (memcpy caller)"),
        (0x3BA4, "FUN_00003BA4 (memcpy + mapper caller)"),
        (0x458,  "FUN_00000458 (early memcpy caller)"),
    ]

    for va, desc in targets:
        print("\n" + "=" * 70)
        print(desc)
        print("=" * 70)
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if func:
            size = func.getBody().getNumAddresses()
            print("  {} bytes".format(size))
            result = decomp.decompileFunction(func, 300, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                # Full output for all — these are our candidates
                if len(c) > 12000:
                    print(c[:6000])
                    print("\n... [{} total chars, showing key patterns] ...".format(len(c)))
                    # Search for copy/len/size patterns
                    for pat in ['memcpy', 'FUN_000004e0', 'local_', 'param_3', 'len', 'size',
                                'saved', '0x5d', '0x660', 'while', 'for ']:
                        matches = list(re.finditer(pat, c, re.IGNORECASE))
                        if matches:
                            for m in matches[:3]:
                                ctx = c[max(0,m.start()-60):min(len(c),m.end()+120)].replace('\n',' ').strip()
                                print("\n  [{}]: ...{}...".format(pat, ctx[:200]))
                else:
                    print(c)
            else:
                print("  DECOMPILE FAILED: {}".format(result.getErrorMessage()))
        else:
            print("  NOT FOUND")

    # Search ALL functions for the "saved_len" pattern:
    # Look for local variables used as FUN_000004E0 param_3 (length)
    # that are NOT initialized in all code paths
    print("\n" + "=" * 70)
    print("PATTERN SEARCH: Functions with FUN_000004E0 and conditional local init")
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

        # Pattern 1: Has memcpy call
        if 'FUN_000004e0' not in c:
            continue

        # Pattern 2: Has conditional (if/else or switch)
        has_conditional = bool(re.search(r'\bif\b|\bswitch\b|\belse\b', c))

        # Pattern 3: Has local variables used as memcpy length
        # FUN_000004e0(dst, src, len) — look for local in 3rd arg position
        memcpy_calls = re.findall(r'FUN_000004e0\s*\(([^)]+)\)', c)
        has_local_len = False
        for call in memcpy_calls:
            args = [a.strip() for a in call.split(',')]
            if len(args) >= 3:
                len_arg = args[2]
                if 'local_' in len_arg:
                    has_local_len = True

        if has_conditional and has_local_len:
            size = func.getBody().getNumAddresses()
            print("\n  *** FUN_{:08X} ({} bytes) — memcpy with conditional + local len ***".format(
                entry, size))
            for call in memcpy_calls:
                print("    memcpy({})".format(call.strip()[:100]))

        # Pattern 4: Has memcpy AND references SRAM addresses
        has_sram = bool(re.search(r'0x5[cde][0-9a-f]{3}', c, re.IGNORECASE))
        if has_sram:
            size = func.getBody().getNumAddresses()
            print("\n  *** FUN_{:08X} ({} bytes) — memcpy + SRAM reference ***".format(entry, size))
            for m in re.finditer(r'0x5[cde][0-9a-f]{3}', c, re.IGNORECASE):
                ctx = c[max(0,m.start()-40):min(len(c),m.end()+40)].replace('\n',' ').strip()
                print("    SRAM: ...{}...".format(ctx[:120]))

    # Also search for functions that write to specific SRAM offsets
    # through mapped pointers (FUN_00003568 return + offset)
    print("\n" + "=" * 70)
    print("SEARCH: Functions combining FUN_00003568 (mapper) + write + size variable")
    print("=" * 70)

    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        if 'FUN_00003568' in c and ('FUN_000004e0' in c or 'while' in c or 'for (' in c):
            size = func.getBody().getNumAddresses()
            print("\n  FUN_{:08X} ({} bytes) — mapper + copy/loop".format(entry, size))
            # Show the FUN_00003568 calls with args
            for m in re.finditer(r'FUN_00003568\s*\(([^)]+)\)', c):
                print("    map({})".format(m.group(1).strip()))
            for m in re.finditer(r'FUN_000004e0\s*\(([^)]+)\)', c):
                print("    memcpy({})".format(m.group(1).strip()[:100]))

    decomp.dispose()
    print("\nDone.")
