#!/usr/bin/env python3
"""Phase 2.5: Trace exact overflow path.

1. Decompile FUN_00003214 in PSP_BL (312 bytes, APCB loader, called from main boot + SVC 0x62)
2. Search ALL ABL4 functions for writes to context offsets +0x500..+0x5B8 (data region)
3. Look for memcpy/loop patterns that could overflow from data region into vtable
4. Find functions that write through a base pointer to sequential offsets (copy operations)
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

print("Starting pyghidra...")
pyghidra.start(install_dir=GHIDRA_DIR)

# ===================== PART 1: PSP_BL FUN_00003214 =====================
print("=" * 70)
print("PART 1: PSP_BL FUN_00003214 (312 bytes, APCB loader)")
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

    # Decompile FUN_00000944 — THE function that loads context base 0x5D7AC
    print("\n--- FUN_00000944 (loads context base, calls FUN_00006B76) ---")
    func_0944 = func_mgr.getFunctionAt(space.getAddress(0x0944))
    if func_0944:
        size = func_0944.getBody().getNumAddresses()
        print("Entry: 0x{:X}, size: {} bytes".format(func_0944.getEntryPoint().getOffset(), size))
        result = decomp.decompileFunction(func_0944, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)
        else:
            print("DECOMPILE FAILED")
    else:
        print("FUN_00000944 not found!")

    # Decompile FUN_00006B76 — called with (context_base, 0x3C00)
    print("\n--- FUN_00006B76 (context init with size 0x3C00) ---")
    func_6b76 = func_mgr.getFunctionAt(space.getAddress(0x6B76))
    if func_6b76:
        size = func_6b76.getBody().getNumAddresses()
        print("Entry: 0x{:X}, size: {} bytes".format(func_6b76.getEntryPoint().getOffset(), size))
        result = decomp.decompileFunction(func_6b76, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:8000] if len(c) > 8000 else c)
    else:
        print("FUN_00006B76 not found! Searching nearby...")
        for delta in range(-16, 17, 2):
            f = func_mgr.getFunctionAt(space.getAddress(0x6B76 + delta))
            if f:
                print("  Found: {} at 0x{:X}, {} bytes".format(
                    f.getName(), 0x6B76 + delta, f.getBody().getNumAddresses()))

    # Decompile FUN_00006364 — called just before context init
    print("\n--- FUN_00006364 (called before context init) ---")
    func_6364 = func_mgr.getFunctionAt(space.getAddress(0x6364))
    if func_6364:
        size = func_6364.getBody().getNumAddresses()
        print("Entry: 0x{:X}, size: {} bytes".format(func_6364.getEntryPoint().getOffset(), size))
        result = decomp.decompileFunction(func_6364, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:5000] if len(c) > 5000 else c)

    # Decompile FUN_00003214
    print("\n--- FUN_00003214 (312 bytes, APCB loader) ---")
    func = func_mgr.getFunctionAt(space.getAddress(0x3214))
    if func:
        size = func.getBody().getNumAddresses()
        print("Entry: 0x{:X}, size: {} bytes".format(func.getEntryPoint().getOffset(), size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("\n--- Full decompilation ---")
            print(c)
        else:
            print("DECOMPILE FAILED: {}".format(result.getErrorMessage()))
    else:
        print("FUN_00003214 not found! Searching nearby...")
        for delta in range(-16, 17, 2):
            f = func_mgr.getFunctionAt(space.getAddress(0x3214 + delta))
            if f:
                print("  Found: {} at 0x{:X}".format(f.getName(), 0x3214 + delta))

    # Also decompile FUN_00003CB4 (only function that references SRAM 0x5D000)
    print("\n" + "=" * 70)
    print("FUN_00003CB4 (references SRAM 0x5D000)")
    func = func_mgr.getFunctionAt(space.getAddress(0x3CB4))
    if func:
        size = func.getBody().getNumAddresses()
        print("Entry: 0x{:X}, size: {} bytes".format(func.getEntryPoint().getOffset(), size))
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)
    else:
        print("NOT FOUND")

    # Decompile FUN_000026F8 (called from main boot with DAT_00000bb4 + 0x10)
    print("\n" + "=" * 70)
    print("FUN_000026F8 (called from boot flow with literal pool param)")
    func = func_mgr.getFunctionAt(space.getAddress(0x26F8))
    if func:
        size = func.getBody().getNumAddresses()
        print("Entry: 0x{:X}, size: {} bytes".format(func.getEntryPoint().getOffset(), size))
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:5000] if len(c) > 5000 else c)

    # Decompile FUN_00005028 (DAT_00005028 is APCB buffer pointer in SVC case 0x61)
    # Actually DAT_00005028 is a DATA reference, not a function.
    # Check what's there.
    print("\n" + "=" * 70)
    print("DAT_00005028 (APCB buffer pointer from SVC case 0x61)")
    addr = space.getAddress(0x5028)
    func = func_mgr.getFunctionContaining(addr)
    if func:
        print("  Inside function: {} at 0x{:X}".format(func.getName(), func.getEntryPoint().getOffset()))
    else:
        # It's a data address - read the value
        raw_val = struct.unpack_from("<I", open(PSPBL_PATH, "rb").read(), 0x5028)[0]
        print("  Data value: 0x{:08X}".format(raw_val))

    decomp.dispose()

# ===================== PART 2: ABL4 context data region writers =====================
print("\n" + "=" * 70)
print("PART 2: ABL4 functions that WRITE to context offsets +0x500..+0x6A0")
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

    # Collect ALL functions
    fi = func_mgr.getFunctions(True)
    all_funcs = []
    while fi.hasNext():
        all_funcs.append(fi.next())
    print("Total functions: {}".format(len(all_funcs)))

    # Scan for writes in the +0x500..+0x6A0 range
    # Pattern: *(type *)(param_N + 0xNNN) = ...
    # where 0xNNN is in [0x500, 0x6A0]
    write_pattern = re.compile(
        r'\*\s*\([^)]+\)\s*\(\s*(\w+)\s*\+\s*0x([0-9a-fA-F]+)\s*\)\s*='
    )
    # Also catch array-style: param[offset] = ...
    array_pattern = re.compile(
        r'(\w+)\s*\[\s*0x([0-9a-fA-F]+)\s*\]\s*='
    )

    writers = []
    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        func_writes = []
        for pat in [write_pattern, array_pattern]:
            for m in pat.finditer(c):
                try:
                    off = int(m.group(2), 16)
                except ValueError:
                    continue
                if 0x4F0 <= off <= 0x6A0:
                    ctx_start = max(0, m.start() - 30)
                    ctx_end = min(len(c), m.end() + 80)
                    line = c[ctx_start:ctx_end].replace('\n', ' ').strip()
                    func_writes.append((off, line))

        if func_writes:
            writers.append((entry, func.getName(), func_writes))

    print("\nFunctions with writes to context +0x4F0..+0x6A0:")
    for entry, name, writes in sorted(writers, key=lambda x: x[0]):
        print("\n  {} (0x{:X}):".format(name, entry))
        for off, line in sorted(writes, key=lambda x: x[0]):
            print("    +0x{:03X}: ...{}...".format(off, line[:140]))

    # Decompile the MOST IMPORTANT writers
    # Focus on functions that write to offsets near +0x5B8 (boundary between data and vtable)
    print("\n" + "=" * 70)
    print("DETAILED DECOMPILATION: Functions writing near vtable boundary (+0x580..+0x6A0)")
    print("=" * 70)

    critical_entries = set()
    for entry, name, writes in writers:
        for off, _ in writes:
            if 0x580 <= off <= 0x6A0:
                critical_entries.add(entry)

    for entry in sorted(critical_entries):
        func = func_mgr.getFunctionAt(space.getAddress(entry))
        if not func:
            continue
        size = func.getBody().getNumAddresses()
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        print("\n" + "-" * 70)
        print("FUN_{:08X} ({} bytes)".format(entry, size))
        print("-" * 70)
        if len(c) < 8000:
            print(c)
        else:
            print(c[:4000])
            print("\n... [{} total chars]".format(len(c)))
            # Show all writes in the critical range
            for m in write_pattern.finditer(c):
                try:
                    off = int(m.group(2), 16)
                except ValueError:
                    continue
                if 0x580 <= off <= 0x6A0:
                    ctx_start = max(0, m.start() - 60)
                    ctx_end = min(len(c), m.end() + 120)
                    print("\n  WRITE +0x{:X}:".format(off))
                    print("  {}".format(c[ctx_start:ctx_end].replace('\n', ' ').strip()[:200]))

    # ===================== PART 3: Search for memcpy/loop overflow patterns =====================
    print("\n" + "=" * 70)
    print("PART 3: Functions with loops writing through context pointer")
    print("=" * 70)

    # Look for patterns like:
    # for/while loop with param_1 + variable_offset = ...
    # These are the overflow candidates
    loop_write_pattern = re.compile(
        r'while|for\s*\('
    )
    var_offset_write = re.compile(
        r'\*\s*\([^)]+\)\s*\(\s*(\w+)\s*\+\s*(\w+)\s*\)\s*='
    )

    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        has_loop = bool(loop_write_pattern.search(c))
        has_var_write = bool(var_offset_write.search(c))

        if has_loop and has_var_write:
            # Check if the variable offset could reach the critical zone
            var_writes = list(var_offset_write.finditer(c))
            if not var_writes:
                continue

            # Check if any param is used with variable offsets
            for m in var_writes:
                base_var = m.group(1)
                offset_var = m.group(2)
                # Skip constant offsets
                try:
                    int(offset_var, 16)
                    continue
                except ValueError:
                    pass
                try:
                    int(offset_var)
                    continue
                except ValueError:
                    pass

                ctx = c[max(0, m.start()-60):min(len(c), m.end()+120)].replace('\n', ' ').strip()
                print("  FUN_{:08X}: {}[{}] = ... | ...{}...".format(
                    entry, base_var, offset_var, ctx[:150]))

    decomp.dispose()
    print("\nDone.")
