#!/usr/bin/env python3
"""Trace ABL4's token → context structure mapping.

FUN_0006804C is the core APCB handler (864 bytes). It processes group data
and maps tokens to offsets in the context structure.

Key questions:
1. How are token IDs mapped to context offsets?
2. Is there a bounds check on token IDs?
3. Can a crafted token ID target offset +0x660?
4. Which APCB group/type contains tokens that map near +0x660?

Also: Decompile FUN_0006F1D8 and FUN_0006BB9C callers to trace how
the dispatch at +0x660 is first USED (which function reads +0x660 first).

And: Check if PSP_BL modifies the L2 page table (0x4DC00) to enable
the SVC vector at runtime.

ABL4 load base: 0x60834
"""
import os, re, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

pyghidra.start(install_dir=GHIDRA_DIR)

# PART 1: ABL4 token processing
print("=" * 70)
print("PART 1: FUN_0006804C — Core APCB group handler (token mapping)")
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

    # Decompile FUN_0006804C (864 bytes)
    func = func_mgr.getFunctionAt(space.getAddress(0x6804C))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6804C))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Look for 0x660 offset
            if '0x660' in c:
                print("  *** Contains 0x660 offset! ***")
            # Look for token ID → offset mapping
            if '* 6' in c or '* 0x6' in c:
                print("  Contains *6 multiplication (6-byte token entries)")
            # Print full
            print(c)
    else:
        print("  No function at 0x6804C!")

    # Decompile FUN_0006F1D8 (token write dispatch)
    print("\n" + "=" * 70)
    print("PART 2: FUN_0006F1D8 — token write dispatch (uses +0x660)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6F1D8))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)

    # Decompile FUN_0006BB9C (token read dispatch)
    print("\n" + "=" * 70)
    print("PART 3: FUN_0006BB9C — token read dispatch (uses +0x660)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6BB9C))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)

    # Decompile FUN_0006BBC0 (called by FUN_0006B590 — vtable bulk init)
    print("\n" + "=" * 70)
    print("PART 4: FUN_0006BBC0 — vtable bulk init (fills +0x378-0x50F)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6BBC0))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6BBC0))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Check what range it fills
            if '0x378' in c or '0x50f' in c or '0x510' in c:
                print("  *** Contains vtable range references ***")
            if '0x660' in c:
                print("  *** Contains 0x660 ***")
            print(c[:4000] if len(c) > 4000 else c)

    # Decompile FUN_0006F364 — first user of +0x660 after SVC
    print("\n" + "=" * 70)
    print("PART 5: FUN_0006F364 — first dispatch user after SVC")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6F364))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6F364))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # Find ALL functions that WRITE to context offsets >= 0x500
    print("\n" + "=" * 70)
    print("PART 6: ALL ABL4 functions writing to context offsets >= 0x500")
    print("=" * 70)

    func_iter = func_mgr.getFunctions(True)
    high_offset_writers = []
    while func_iter.hasNext():
        f = func_iter.next()
        result = decomp.decompileFunction(f, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Look for writes to high offsets from param_1 (context pointer)
        # Pattern: *(param_1 + 0x5xx) or *(param_1 + 0x6xx)
        high_writes = re.findall(r'\*\([^)]*param_1\s*\+\s*(0x[56][0-9a-fA-F]{2})', c)
        if not high_writes:
            # Alternative pattern: *(type *)(param_1 + offset) = ...
            high_writes = re.findall(r'param_1\s*\+\s*(0x[56][0-9a-fA-F]{2})\)', c)
        if high_writes:
            faddr = f.getEntryPoint().getOffset()
            offsets = sorted(set(high_writes))
            has_660 = '0x660' in offsets or '0x660' in c
            high_offset_writers.append((faddr, f.getName(), offsets, has_660))

    if high_offset_writers:
        print("  Functions with high-offset context writes:")
        for faddr, fname, offsets, has_660 in high_offset_writers:
            marker = " ***0x660***" if has_660 else ""
            print("    0x{:05X} {}: {}{}".format(faddr, fname, offsets, marker))
    else:
        print("  No functions write to param_1 + 0x5xx/0x6xx")

    # Part 7: Find functions writing to +0x660 via ANY pattern
    print("\n" + "=" * 70)
    print("PART 7: ALL ABL4 functions referencing offset 0x660")
    print("=" * 70)

    func_iter = func_mgr.getFunctions(True)
    refs_660 = []
    while func_iter.hasNext():
        f = func_iter.next()
        result = decomp.decompileFunction(f, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()
        if '0x660' in c:
            faddr = f.getEntryPoint().getOffset()
            # Count reads vs writes
            writes = c.count('+ 0x660)') + c.count('+0x660)')
            reads = c.count('0x660')
            refs_660.append((faddr, f.getName(), reads, writes))

    if refs_660:
        print("  Functions referencing 0x660:")
        for faddr, fname, reads, writes in refs_660:
            print("    0x{:05X} {}: {} total refs".format(faddr, fname, reads))
    else:
        print("  No functions reference 0x660!")

    decomp.dispose()

# PART 8: PSP_BL — check if any function writes to L2 page table (0x4DC00)
print("\n" + "=" * 70)
print("PART 8: PSP_BL — writes to L2 page table at 0x4DC00")
print("=" * 70)

with pyghidra.open_program(
    PSPBL_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_pspbl_v1", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()

    # Search for literal pool entries containing 0x4DC00 or nearby
    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()

    print("  Literal pool entries for L2 page table (0x4DC00):")
    for i in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, i)[0]
        if 0x4DB00 <= val <= 0x4DD00:
            refs = ref_mgr.getReferencesTo(space.getAddress(i))
            ref_list = list(refs)
            if ref_list:
                for ref in ref_list:
                    func = func_mgr.getFunctionContaining(ref.getFromAddress())
                    fn = func.getName() if func else "?"
                    print("    [0x{:04X}] = 0x{:05X} → ref from 0x{:04X} in {}".format(
                        i, val, ref.getFromAddress().getOffset(), fn))
            else:
                func = func_mgr.getFunctionContaining(space.getAddress(i))
                fn = func.getName() if func else "no_func"
                print("    [0x{:04X}] = 0x{:05X} (in {}, no ref)".format(i, val, fn))

    # Also check for 0x4E000 (L1 table / TTBR0)
    print("\n  Literal pool entries for L1 page table (0x4E000):")
    for i in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, i)[0]
        if val == 0x4E000:
            refs = ref_mgr.getReferencesTo(space.getAddress(i))
            ref_list = list(refs)
            if ref_list:
                for ref in ref_list:
                    func = func_mgr.getFunctionContaining(ref.getFromAddress())
                    fn = func.getName() if func else "?"
                    print("    [0x{:04X}] = 0x{:05X} → ref from 0x{:04X} in {}".format(
                        i, val, ref.getFromAddress().getOffset(), fn))

    # Check for writes to address 0x108 (SVC vector)
    print("\n  References to 0x108 (SVC vector address):")
    refs = ref_mgr.getReferencesTo(space.getAddress(0x108))
    for ref in refs:
        func = func_mgr.getFunctionContaining(ref.getFromAddress())
        fn = func.getName() if func else "?"
        print("    0x{:04X} ({}) in {}".format(
            ref.getFromAddress().getOffset(), ref.getReferenceType().toString(), fn))

print("\nDone.")
