#!/usr/bin/env python3
"""Full decompile of FUN_0006BC64 (the orchestrator) and its callees.

FUN_0006BC64 calls:
  - FUN_00060870 (memcpy)
  - FUN_00069FAC (APCB accessor)
  - FUN_0006B590 (vtable init with +0x660 write)

Also decompile:
  - thunk_FUN_0006a47e and thunk_FUN_0006a48a (memcpy/memset wrappers)
  - ALL functions that reference FUN_0006b590 (who calls the vtable init?)
  - The function at VA 0x6A7C4 — check nearby functions
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

    # 1. Full decompile FUN_0006BC64 (THE ORCHESTRATOR)
    print("=" * 70)
    print("1. FUN_0006BC64 — THE ORCHESTRATOR (full decompile)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6BC64))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c)
    else:
        print("  NOT FOUND - checking nearby")
        for delta in range(-8, 9, 2):
            f = func_mgr.getFunctionAt(space.getAddress(0x6BC64 + delta))
            if f:
                print("  Found {} at 0x{:X}".format(f.getName(), 0x6BC64 + delta))

    # 2. Who calls FUN_0006B590 (vtable init)?
    print("\n" + "=" * 70)
    print("2. ALL callers of FUN_0006B590 (vtable init)")
    print("=" * 70)
    addr = space.getAddress(0x6B590)
    refs = list(ref_mgr.getReferencesTo(addr))
    b590_callers = set()
    for r in refs:
        from_func = func_mgr.getFunctionContaining(r.getFromAddress())
        if from_func:
            entry = from_func.getEntryPoint().getOffset()
            b590_callers.add(entry)
            print("  Call at 0x{:X} in {} (0x{:X})".format(
                r.getFromAddress().getOffset(), from_func.getName(), entry))

    # 3. Who calls FUN_0006BBC0 (context init)?
    print("\n" + "=" * 70)
    print("3. ALL callers of FUN_0006BBC0 (context init)")
    print("=" * 70)
    addr = space.getAddress(0x6BBC0)
    refs = list(ref_mgr.getReferencesTo(addr))
    for r in refs:
        from_func = func_mgr.getFunctionContaining(r.getFromAddress())
        if from_func:
            print("  Call at 0x{:X} in {} (0x{:X})".format(
                r.getFromAddress().getOffset(), from_func.getName(),
                from_func.getEntryPoint().getOffset()))

    # 4. Decompile thunk functions (memcpy/memset wrappers)
    print("\n" + "=" * 70)
    print("4. thunk_FUN_0006a47e and thunk_FUN_0006a48a")
    print("=" * 70)
    for va in [0x6a47e, 0x6a48a]:
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if func:
            size = func.getBody().getNumAddresses()
            result = decomp.decompileFunction(func, 120, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("\n  {} (0x{:X}, {} bytes):".format(func.getName(), va, size))
                print(c)
        else:
            # Check if it's inside another function
            func2 = func_mgr.getFunctionContaining(space.getAddress(va))
            if func2:
                print("  0x{:X} inside {} (0x{:X})".format(
                    va, func2.getName(), func2.getEntryPoint().getOffset()))

    # 5. ALL callers of thunk_FUN_0006a47e (memcpy wrapper)
    print("\n" + "=" * 70)
    print("5. ALL callers of thunk_FUN_0006a47e (memcpy wrapper)")
    print("=" * 70)
    for target_va in [0x6a47e, 0x6a48a]:
        addr = space.getAddress(target_va)
        func = func_mgr.getFunctionAt(addr)
        if not func:
            print("  No function at 0x{:X}".format(target_va))
            continue
        refs = list(ref_mgr.getReferencesTo(addr))
        print("  0x{:X} ({}): {} callers".format(target_va, func.getName(), len(refs)))
        callers = set()
        for r in refs:
            from_func = func_mgr.getFunctionContaining(r.getFromAddress())
            if from_func:
                entry = from_func.getEntryPoint().getOffset()
                callers.add(entry)
                print("    Call at 0x{:X} in {} (0x{:X})".format(
                    r.getFromAddress().getOffset(), from_func.getName(), entry))

    # 6. What's at VA 0x6A7C4? Check nearby function boundaries
    print("\n" + "=" * 70)
    print("6. What's near VA 0x6A7C4?")
    print("=" * 70)
    # Search for nearest function
    target = 0x6A7C4
    for check in range(target, target - 2000, -2):
        func = func_mgr.getFunctionAt(space.getAddress(check))
        if func:
            end = func.getEntryPoint().getOffset() + func.getBody().getNumAddresses()
            in_func = target < end
            print("  Nearest function before 0x{:X}: {} at 0x{:X} ({} bytes, ends ~0x{:X})".format(
                target, func.getName(), check, func.getBody().getNumAddresses(), end))
            print("  0x{:X} {} in this function".format(target, "IS" if in_func else "is NOT"))
            if in_func:
                result = decomp.decompileFunction(func, 300, flat.getMonitor())
                if result.decompileCompleted():
                    c = result.getDecompiledFunction().getC()
                    # Find the 0x630 write
                    idx = c.find('0x630')
                    if idx >= 0:
                        print("  +0x630 context:")
                        print(c[max(0,idx-300):min(len(c),idx+300)])
                    else:
                        print("  No '0x630' in decompile ({} chars)".format(len(c)))
                        print(c[:2000])
            break

    # 7. Check if there's a function list gap — maybe the STRH at 0x6A7C4 is in a data table
    print("\n" + "=" * 70)
    print("7. Functions near 0x6A7xx range")
    print("=" * 70)
    fi = func_mgr.getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        entry = f.getEntryPoint().getOffset()
        size = f.getBody().getNumAddresses()
        if 0x6A600 <= entry <= 0x6A900:
            print("  {} at 0x{:X} ({} bytes, ends ~0x{:X})".format(
                f.getName(), entry, size, entry + size))

    # 8. Full decompile of FUN_0006B590 (vtable init - we know it but need param types)
    print("\n" + "=" * 70)
    print("8. FUN_0006B590 — vtable init (param propagation)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6B590))
    if func:
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)

    # 9. What DAT values are in the literal pools near FUN_0006BBC0?
    print("\n" + "=" * 70)
    print("9. Literal pool values for FUN_0006BBC0")
    print("=" * 70)
    import struct
    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()
    base = 0x60834
    for dat_va in [0x6BC38, 0x6BC3C, 0x6BC40, 0x6BC44, 0x6BC48, 0x6BC4C]:
        off = dat_va - base
        if 0 <= off < len(abl4) - 3:
            val = struct.unpack_from("<I", abl4, off)[0]
            print("  DAT_0x{:X} = 0x{:08X}".format(dat_va, val))

    # 10. Also check DAT_0006c070 and DAT_0006c074 used by orchestrator
    print("\n" + "=" * 70)
    print("10. Literal pool values for FUN_0006BC64 (orchestrator)")
    print("=" * 70)
    for dat_va in [0x6C070, 0x6C074]:
        off = dat_va - base
        if 0 <= off < len(abl4) - 3:
            val = struct.unpack_from("<I", abl4, off)[0]
            print("  DAT_0x{:X} = 0x{:08X}".format(dat_va, val))

    decomp.dispose()
    print("\nDone.")
