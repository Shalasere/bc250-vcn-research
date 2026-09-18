#!/usr/bin/env python3
"""Trace token write/read mechanism.

Key question: how does FUN_0006f1d8(context, token_id, value) map token_id to a context offset?
If the mapping allows APCB-controlled token IDs to reach vtable offsets, that's the overflow.

Also: find ALL callers of thunk_FUN_0006a47e (0x6A474) and thunk_FUN_0006a48a (0x6A484).
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

    # 1. FUN_0006f1d8 — token write function
    print("=" * 70)
    print("1. FUN_0006f1d8 — token write (FULL)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6f1d8))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:10000])

    # 2. FUN_0006bb9c — token read function
    print("\n" + "=" * 70)
    print("2. FUN_0006bb9c — token read")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6bb9c))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:5000])

    # 3. FUN_0006f214 — called by orchestrator and vtable init
    print("\n" + "=" * 70)
    print("3. FUN_0006f214 — channel selector?")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6f214))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:3000])

    # 4. ALL callers of thunk wrappers (0x6A474, 0x6A484)
    print("\n" + "=" * 70)
    print("4. ALL callers of thunk_FUN_0006a47e (0x6A474) — memcpy")
    print("=" * 70)
    addr = space.getAddress(0x6A474)
    refs = list(ref_mgr.getReferencesTo(addr))
    thunk_memcpy_callers = set()
    for r in refs:
        from_func = func_mgr.getFunctionContaining(r.getFromAddress())
        if from_func:
            entry = from_func.getEntryPoint().getOffset()
            thunk_memcpy_callers.add(entry)
            print("  Call at 0x{:X} in {} (0x{:X})".format(
                r.getFromAddress().getOffset(), from_func.getName(), entry))
    if not refs:
        print("  No callers found!")

    print("\n" + "=" * 70)
    print("5. ALL callers of thunk_FUN_0006a48a (0x6A484) — memset")
    print("=" * 70)
    addr = space.getAddress(0x6A484)
    refs = list(ref_mgr.getReferencesTo(addr))
    thunk_memset_callers = set()
    for r in refs:
        from_func = func_mgr.getFunctionContaining(r.getFromAddress())
        if from_func:
            entry = from_func.getEntryPoint().getOffset()
            thunk_memset_callers.add(entry)
            print("  Call at 0x{:X} in {} (0x{:X})".format(
                r.getFromAddress().getOffset(), from_func.getName(), entry))
    if not refs:
        print("  No callers found!")

    # 6. What does FUN_0006804C store to? Focus on the buffer allocation and writes
    # Looking for the heap buffer address that token data goes into
    print("\n" + "=" * 70)
    print("6. FUN_0006804C — focus on buffer allocation + writes (first 6000 chars)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6804C))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Show the parts with buffer allocation and memcpy
            for keyword in ['alloc', 'FUN_00069d78', 'FUN_0006a47', 'FUN_0006a48',
                            'FUN_00060870', 'thunk', 'memcpy', 'param_1 +',
                            'switch', 'case 0:', 'case 1:', 'case 2:',
                            'case 3:', 'case 4:', 'case 5:', 'case 6:',
                            'case 7:', 'case 8:', 'case 9:', 'case 10:',
                            'case 11:', 'case 12:']:
                idx = c.find(keyword)
                if idx >= 0:
                    ctx = c[max(0,idx-50):min(len(c),idx+300)]
                    print("\n  [{}]:".format(keyword))
                    print("  " + ctx.replace('\n', '\n  ')[:350])

    # 7. FUN_00069fac — the APCB accessor called by orchestrator
    print("\n" + "=" * 70)
    print("7. FUN_00069fac — APCB accessor")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x69fac))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:5000])

    # 8. FUN_0006bc50 — called by vtable init to check something
    print("\n" + "=" * 70)
    print("8. FUN_0006bc50 — vtable init guard check")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6bc50))
    if func:
        size = func.getBody().getNumAddresses()
        result = decomp.decompileFunction(func, 120, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} bytes, {} chars".format(size, len(c)))
            print(c[:2000])

    # 9. FUN_00069be8 — also called by vtable init
    print("\n" + "=" * 70)
    print("9. FUN_00069be8 — called by vtable init")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x69be8))
    if func:
        size = func.getBody().getNumAddresses()
        result = decomp.decompileFunction(func, 120, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} bytes, {} chars".format(size, len(c)))
            print(c[:3000])

    decomp.dispose()
    print("\nDone.")
