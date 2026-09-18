#!/usr/bin/env python3
"""Trace the APCB token → context structure write path.

Key findings so far:
- Context+0x660 is a vtable function pointer (normally 0x60FE9 -> FUN_00060FE8)
- The vtable is set by FUN_0006B590 with hardcoded literal pool values
- Data fields at +0x510-0x5B8 are between the bulk vtable and specialized vtable
- Token writes into this data region that overflow could reach +0x660
- FUN_00063284 writes to +0x516 (closest write to the vtable from below)

This script:
1. Decompile FUN_00060FE8 (the actual function at vtable+0x660)
2. Decompile FUN_00063284 (writes to +0x516, near the data/vtable boundary)
3. Trace what FUN_0006804C writes into the context (token data buffer)
4. Analyze the complete FUN_0006804C decompilation for write targets
5. Find the "saved_len" candidate variable
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

print("Starting pyghidra...")
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

    # 1. Decompile FUN_00060FE8 — the normal vtable target at +0x660
    print("=" * 70)
    print("=== FUN_00060FE8 — vtable dispatch target (value at context+0x660) ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x60FE8))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x60FE8))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("Entry: 0x{:X}, size: {} bytes".format(entry, size))
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:5000] if len(c) > 5000 else c)
    else:
        print("NOT FOUND — trying nearby addresses")
        for delta in range(-4, 8, 2):
            f = func_mgr.getFunctionAt(space.getAddress(0x60FE8 + delta))
            if f:
                print("  Found at 0x{:X}: {}".format(0x60FE8 + delta, f.getName()))

    # 2. Decompile FUN_00063284 — writes to +0x516 (data region near vtable)
    print("\n" + "=" * 70)
    print("=== FUN_00063284 — writes to context+0x516 (data region) ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x63284))
    if func:
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:6000] if len(c) > 6000 else c)

    # 3. Full decompilation of FUN_0006804C with ALL context writes extracted
    print("\n" + "=" * 70)
    print("=== FUN_0006804C — core APCB handler (full, extracting writes) ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x6804C))
    if func:
        size = func.getBody().getNumAddresses()
        print("Size: {} bytes".format(size))
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("\n--- Full decompilation ({} chars) ---".format(len(c)))
            print(c)

            # Extract all param_1+offset patterns
            print("\n--- All param_1 offset accesses ---")
            for m in re.finditer(r'param_1\s*\+\s*0x([0-9a-fA-F]+)', c):
                off = int(m.group(1), 16)
                start = max(0, m.start() - 50)
                end = min(len(c), m.end() + 50)
                ctx = c[start:end].replace('\n', ' ').strip()
                rw = "WRITE" if re.search(r'\)\s*=', c[m.end():m.end()+20]) else "READ/USE"
                print("  +0x{:04X} {}: ...{}...".format(off, rw, ctx[:100]))

    # 4. Decompile ALL vtable target functions to understand the dispatch table
    print("\n" + "=" * 70)
    print("=== Vtable function pointers (the methods in the dispatch table) ===")
    vtable_entries = [
        (0x60FE8, "+0x660", "main dispatch"),
        (0x64F40, "+0x630", "slot 0x630"),
        (0x60F40, "+0x628", "slot 0x628"),
        (0x60F9C, "+0x62C", "slot 0x62C"),
        (0x6147A, "+0x5C0", "slot 0x5C0"),
        (0x66D9C, "+0x654", "slot 0x654"),
        (0x66D9E, "+0x5B8", "slot 0x5B8"),
        (0x64F24, "+0x614", "slot 0x614"),
    ]

    for va, offset, desc in vtable_entries:
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(va))
        if func:
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            result = decomp.decompileFunction(func, 120, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                # Just show the signature and first few lines
                lines = c.strip().split('\n')
                sig = lines[0] if lines else "?"
                print("\n  {} ({}): 0x{:X}, {} bytes".format(offset, desc, entry, size))
                print("    {}".format(sig))
                # Show first 5 lines of body
                for line in lines[1:6]:
                    print("    {}".format(line))
                if len(lines) > 6:
                    print("    ... [{} more lines]".format(len(lines) - 6))
        else:
            print("\n  {} ({}): 0x{:X} NOT FOUND".format(offset, desc, va))

    # 5. Find what accesses param_2+0x3c4 (the data source in FUN_0006B590)
    # This tells us where the gate condition data comes from
    print("\n" + "=" * 70)
    print("=== Searching for +0x3c4 offset accesses (B590 data source) ===")
    fi = func_mgr.getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        result = decomp.decompileFunction(f, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()
        if '0x3c4' in c:
            entry = f.getEntryPoint().getOffset()
            # Show context around the match
            for m in re.finditer(r'0x3c4', c):
                ctx = c[max(0,m.start()-80):min(len(c),m.end()+80)].replace('\n',' ').strip()
                print("  FUN_{:08X}: ...{}...".format(entry, ctx[:160]))

    # 6. Scan for the "saved_len" pattern — look for uninitialized local variables
    # used as length/count that gate buffer writes
    print("\n" + "=" * 70)
    print("=== Searching for potential 'saved_len' variables ===")
    print("  (uninitialized locals used in buffer size comparisons)")

    # In PSP_BL, search for functions that read from APCB-range addresses
    # and use a length variable
    PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()

    # Find literal pool references to APCB-range addresses (0x7A000 area)
    print("\n  PSP_BL literal pools referencing APCB range:")
    for off in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        if 0x79000 <= val <= 0x7B000:
            print("    +0x{:04X}: 0x{:08X}".format(off, val))

    # Also search for references to the context data region (0x5D7AC + 0x500 area)
    print("\n  PSP_BL literal pools referencing context+0x500 area:")
    context_base = 0x5D7AC
    for off in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        if context_base + 0x400 <= val <= context_base + 0x700:
            diff = val - context_base
            print("    +0x{:04X}: 0x{:08X} (context + 0x{:X})".format(off, val, diff))

    decomp.dispose()
    print("\nDone.")
