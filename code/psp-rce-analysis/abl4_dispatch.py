#!/usr/bin/env python3
"""Decompile the token dispatch function at 0x60FE8/0x60FE9 (Thumb).

This is THE CRITICAL FUNCTION:
- Called via vtable at context+0x660
- Maps token IDs to context offsets
- Called by FUN_0006f1d8 (write) and FUN_0006bb9c (read)
- If it writes to offsets up to +0x660 without bounds checking, that's the overflow

Also decompile ALL 8 vtable functions to understand the attack surface:
  +0x660: 0x60FE9 (THE target)
  +0x630: 0x64F41
  +0x628: 0x60F41
  +0x62C: 0x60F9D
  +0x5C0: 0x6147B
  +0x654: 0x66D9D
  +0x5B8: 0x66D9F
  +0x614: 0x64F25
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

    # The vtable function pointers (stored as Thumb addresses with bit 0 set)
    vtable_entries = {
        '+0x660': 0x60FE8,  # 0x60FE9 with Thumb bit cleared
        '+0x630': 0x64F40,  # 0x64F41
        '+0x628': 0x60F40,  # 0x60F41
        '+0x62C': 0x60F9C,  # 0x60F9D
        '+0x5C0': 0x6147A,  # 0x6147B
        '+0x654': 0x66D9C,  # 0x66D9D
        '+0x5B8': 0x66D9E,  # 0x66D9F
        '+0x614': 0x64F24,  # 0x64F25
    }

    # Also the bulk vtable and per-channel function pointers
    other_vtable = {
        'bulk (+0x378-0x50F)': 0x61464,  # 0x61465
        '+0x52C': 0x64AE0,  # 0x64AE1
        '+0x530': 0x64AB8,  # 0x64AB9
        '+0x620': 0x61468,  # 0x61469
        '+0x624': 0x64AA4,  # 0x64AA5
        'channel': 0x66D9E,  # 0x66D9F
    }

    # 1. Decompile THE dispatch function at +0x660
    print("=" * 70)
    print("THE DISPATCH FUNCTION: +0x660 = 0x60FE8/0x60FE9")
    print("Called as: dispatch(context, mode, token_id, [value])")
    print("=" * 70)

    # Try both even and odd addresses, and nearby
    for va in [0x60FE8, 0x60FE9, 0x60FEA, 0x60FE6]:
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if func:
            size = func.getBody().getNumAddresses()
            print("\n  Found at 0x{:X}: {} ({} bytes)".format(va, func.getName(), size))
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))
                print(c[:15000])
            break
    else:
        # Check containing function
        for va in [0x60FE8, 0x60FE9]:
            func = func_mgr.getFunctionContaining(space.getAddress(va))
            if func:
                entry = func.getEntryPoint().getOffset()
                size = func.getBody().getNumAddresses()
                print("  0x{:X} is inside {} (0x{:X}, {} bytes)".format(va, func.getName(), entry, size))
                result = decomp.decompileFunction(func, 600, flat.getMonitor())
                if result.decompileCompleted():
                    c = result.getDecompiledFunction().getC()
                    print("  {} chars".format(len(c)))
                    print(c[:15000])
                break

    # 2. Decompile all 8 specialized vtable functions
    print("\n" + "=" * 70)
    print("ALL VTABLE FUNCTIONS (specialized)")
    print("=" * 70)

    for name, va in sorted(vtable_entries.items(), key=lambda x: x[1]):
        if va == 0x60FE8:
            continue  # Already done above
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(va))
        if func:
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            result = decomp.decompileFunction(func, 300, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("\n--- {} (0x{:X}, {} at 0x{:X}, {} bytes) ---".format(
                    name, va, func.getName(), entry, size))
                # Show first 2000 chars
                print(c[:2000])

    # 3. Decompile the bulk vtable function
    print("\n" + "=" * 70)
    print("BULK VTABLE FUNCTION (0x61464/0x61465)")
    print("=" * 70)
    for va in [0x61464, 0x61465]:
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if func:
            size = func.getBody().getNumAddresses()
            result = decomp.decompileFunction(func, 300, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} at 0x{:X} ({} bytes, {} chars)".format(func.getName(), va, size, len(c)))
                print(c[:5000])
            break
        func = func_mgr.getFunctionContaining(space.getAddress(va))
        if func:
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            print("  0x{:X} inside {} (0x{:X}, {} bytes)".format(va, func.getName(), entry, size))
            result = decomp.decompileFunction(func, 300, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print(c[:5000])
            break

    # 4. List all functions in the 0x60F00-0x61500 range
    # (near the vtable function addresses)
    print("\n" + "=" * 70)
    print("FUNCTIONS IN 0x60F00-0x61500 RANGE")
    print("=" * 70)
    fi = func_mgr.getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        entry = f.getEntryPoint().getOffset()
        if 0x60F00 <= entry <= 0x61500:
            size = f.getBody().getNumAddresses()
            print("  {} at 0x{:X} ({} bytes)".format(f.getName(), entry, size))

    decomp.dispose()
    print("\nDone.")
