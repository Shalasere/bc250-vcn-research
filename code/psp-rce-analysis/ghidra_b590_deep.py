#!/usr/bin/env python3
"""Deep analysis of FUN_0006B590 — the function that WRITES to context+0x660.

This function writes the vtable function pointer. We need to understand:
1. What values does it write? (literal pool DAT_0006b5f8 etc.)
2. Who calls FUN_0006B590? (what triggers the vtable setup)
3. What does FUN_0006BC50 do? (the gate condition)
4. What is at param_2+0x3c4? (the data source)
5. Can the values written to +0x660 be influenced by APCB data?

Also analyze FUN_0006BBC0 which writes to +0x620, +0x624 and zeros
large regions of the context structure — this is the context RESET function.
"""
import os, struct

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

    # Step 1: Read the literal pool values used by FUN_0006B590
    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()

    print("=== FUN_0006B590 literal pool values ===")
    pool_entries = [
        ("DAT_0006b5f8", 0x6b5f8, "written to +0x660 (VTABLE PTR)"),
        ("DAT_0006b5fc", 0x6b5fc, "written to +0x630"),
        ("DAT_0006b600", 0x6b600, "written to +0x628"),
        ("DAT_0006b604", 0x6b604, "written to +0x62c"),
        ("DAT_0006b608", 0x6b608, "written to +0x5c0"),
        ("DAT_0006b60c", 0x6b60c, "written to +0x654"),
        ("DAT_0006b610", 0x6b610, "written to +0x5b8"),
        ("DAT_0006b614", 0x6b614, "written to +0x614"),
    ]

    for name, va, desc in pool_entries:
        off = va - ABL4_BASE
        if 0 <= off < len(abl4) - 3:
            val = struct.unpack_from("<I", abl4, off)[0]
            # Check if the value is a function pointer (within ABL4 code range)
            is_code = ABL4_BASE <= val <= ABL4_BASE + len(abl4)
            is_thumb = val & 1
            code_marker = ""
            if is_code:
                target = val & ~1
                target_func = func_mgr.getFunctionAt(space.getAddress(target))
                if target_func:
                    code_marker = " -> {} (FUNCTION)".format(target_func.getName())
                elif is_thumb:
                    code_marker = " -> 0x{:X} (Thumb code?)".format(target)
                else:
                    code_marker = " -> 0x{:X} (ARM code?)".format(target)
            print("  {} = 0x{:08X}  {}{}".format(name, val, desc, code_marker))
        else:
            print("  {} = OUT OF RANGE  {}".format(name, desc))

    # Step 2: Who calls FUN_0006B590?
    print("\n=== Callers of FUN_0006B590 ===")
    addr_b590 = space.getAddress(0x6B590)
    refs = list(ref_mgr.getReferencesTo(addr_b590))
    callers_b590 = set()
    for r in refs:
        caller = func_mgr.getFunctionContaining(r.getFromAddress())
        if caller:
            entry = caller.getEntryPoint().getOffset()
            callers_b590.add(entry)
            print("  <- 0x{:X} in {} (ref from 0x{:X})".format(
                entry, caller.getName(), r.getFromAddress().getOffset()))

    # Step 3: Decompile FUN_0006BC50 (the gate condition in FUN_0006B590)
    print("\n=== FUN_0006BC50 (gate condition for vtable write) ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x6BC50))
    if func:
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # Step 4: Decompile FUN_00069BE8 (called before the gate check)
    print("\n=== FUN_00069BE8 (pre-gate-check call) ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x69BE8))
    if func:
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # Step 5: Decompile callers of FUN_0006B590 to understand the data flow
    print("\n=== Decompiling callers of FUN_0006B590 ===")
    for caller_entry in sorted(callers_b590):
        func = func_mgr.getFunctionAt(space.getAddress(caller_entry))
        if not func:
            continue
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()
        size = func.getBody().getNumAddresses()
        print("\n" + "=" * 70)
        print("=== {} (0x{:X}, {} bytes) ===".format(func.getName(), caller_entry, size))
        if len(c) < 6000:
            print(c)
        else:
            print(c[:4000])
            print("\n... [truncated, {} total chars]".format(len(c)))

    # Step 6: Decompile FUN_0006F214 (called after vtable setup in B590)
    print("\n=== FUN_0006F214 (post-vtable-setup call) ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x6F214))
    if func:
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # Step 7: Read FUN_0006BBC0 literal pool values
    print("\n=== FUN_0006BBC0 literal pool values ===")
    bbc0_entries = [
        ("DAT_0006bc38", 0x6bc38, "fill value for loop 2 (offsets 0x378+)"),
        ("DAT_0006bc3c", 0x6bc3c, "fill value for loop 3"),
        ("DAT_0006bc40", 0x6bc40, "written to +0x52c"),
        ("DAT_0006bc44", 0x6bc44, "written to +0x530"),
        ("DAT_0006bc48", 0x6bc48, "written to +0x620"),
        ("DAT_0006bc4c", 0x6bc4c, "written to +0x624"),
    ]

    for name, va, desc in bbc0_entries:
        off = va - ABL4_BASE
        if 0 <= off < len(abl4) - 3:
            val = struct.unpack_from("<I", abl4, off)[0]
            is_code = ABL4_BASE <= val <= ABL4_BASE + len(abl4)
            code_marker = ""
            if is_code:
                target = val & ~1
                target_func = func_mgr.getFunctionAt(space.getAddress(target))
                if target_func:
                    code_marker = " -> {} (FUNCTION)".format(target_func.getName())
            print("  {} = 0x{:08X}  {}{}".format(name, val, desc, code_marker))

    # Step 8: Map the FULL context structure layout from all write patterns
    print("\n=== Complete context structure write map (all offsets with WRITEs) ===")
    print("  Showing only offsets with confirmed writes:\n")

    # Re-scan all functions for write patterns
    import re
    write_map = {}  # offset -> [(func, value_source)]

    fi = func_mgr.getFunctions(True)
    all_funcs_list = []
    while fi.hasNext():
        all_funcs_list.append(fi.next())

    offset_write_re = re.compile(
        r'\*\s*\([^)]*param_1\s*\+\s*0x([0-9a-fA-F]+)\)\s*=\s*([^;]+);'
    )

    for func in all_funcs_list:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 120, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        for m in offset_write_re.finditer(c):
            off = int(m.group(1), 16)
            val_src = m.group(2).strip()
            if off not in write_map:
                write_map[off] = []
            write_map[off].append((entry, func.getName(), val_src))

    for off in sorted(write_map.keys()):
        entries = write_map[off]
        for func_entry, fname, val_src in entries:
            critical = " *** VTABLE ***" if off == 0x660 else ""
            val_preview = val_src[:60] if len(val_src) > 60 else val_src
            print("  +0x{:04X}  <- {}  (in {}){}".format(off, val_preview, fname, critical))

    decomp.dispose()
    print("\nDone.")
