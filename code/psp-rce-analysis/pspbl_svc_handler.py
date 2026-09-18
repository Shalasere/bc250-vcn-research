#!/usr/bin/env python3
"""Analyze PSP_BL's SVC handler, specifically SVC 0x1c and APCB processing.

PSP_BL: 39,360 bytes, ARM/Thumb mixed
SVC handler at 0x298
Context base: pool[0x0BB8] = 0x5D7AC

The hypothesis: SVC 0x1c from ABL4 triggers APCB processing in PSP_BL
that overwrites the vtable at context+0x660. A buffer overflow here
(CVE-2025-29951) could corrupt +0x660.
"""
import os

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
    ref_mgr = program.getReferenceManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # 1. SVC handler at 0x298
    print("=" * 70)
    print("1. SVC handler at 0x298")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x298))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:10000])
    else:
        print("  No function at 0x298")
        # Check nearby
        for delta in range(-16, 17, 2):
            f = func_mgr.getFunctionAt(space.getAddress(0x298 + delta))
            if f:
                print("  Found {} at 0x{:X}".format(f.getName(), 0x298 + delta))

    # 2. Find function containing SVC dispatch table
    # SVC 0x1c would be dispatched somewhere
    print("\n" + "=" * 70)
    print("2. Functions with 0x1c switch cases or SVC dispatch")
    print("=" * 70)

    fi = func_mgr.getFunctions(True)
    all_funcs = []
    while fi.hasNext():
        all_funcs.append(fi.next())

    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        if size < 50:
            continue
        result = decomp.decompileFunction(func, 120, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Look for SVC dispatch patterns
        if 'switch' in c and ('0x1c' in c or '0x1C' in c or 'case 0x1c' in c.lower()):
            print("\n  {} (0x{:X}, {} bytes) has switch with 0x1c:".format(
                func.getName(), entry, size))
            idx = c.lower().find('0x1c')
            if idx >= 0:
                print(c[max(0,idx-300):min(len(c),idx+500)])

    # 3. What writes to context+0x660? Search PSP_BL for stores to +0x660
    print("\n" + "=" * 70)
    print("3. PSP_BL references to offset 0x660")
    print("=" * 70)

    import struct
    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()

    # Search for LDR/STR with #0x660 offset in Thumb2
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs.detail = True

    # Binary pattern search for STR.W with imm12=0x660
    for off in range(0, len(pspbl) - 3, 2):
        hw1 = struct.unpack_from("<H", pspbl, off)[0]
        if (hw1 & 0xFFF0) == 0xF8C0:  # STR.W
            hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]
            imm12 = hw2 & 0xFFF
            if imm12 == 0x660:
                rn = hw1 & 0xF
                rt = (hw2 >> 12) & 0xF
                print("  Offset 0x{:X}: STR.W r{}, [r{}, #0x660]".format(off, rt, rn))

    # Also search for 0x5DE0C in literal pools
    for off in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        if val == 0x5DE0C:
            func = func_mgr.getFunctionContaining(space.getAddress(off))
            fname = func.getName() if func else "?"
            print("  Offset 0x{:X}: literal 0x5DE0C in {}".format(off, fname))

    # 4. Find ALL functions that reference 0x5D7AC (context base)
    print("\n" + "=" * 70)
    print("4. PSP_BL functions referencing context base 0x5D7AC")
    print("=" * 70)

    for off in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        if val == 0x5D7AC:
            func = func_mgr.getFunctionContaining(space.getAddress(off))
            fname = func.getName() if func else "?"
            print("  Offset 0x{:X}: literal 0x5D7AC in {}".format(off, fname))

    # 5. Look for APCB-related functions in PSP_BL
    # APCB magic: 0x41504342 = "APCB", or header signature
    print("\n" + "=" * 70)
    print("5. APCB-related patterns in PSP_BL")
    print("=" * 70)

    # Search for APCB magic in literal pools
    for off in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        if val == 0x42435041:  # "APCB" little-endian
            func = func_mgr.getFunctionContaining(space.getAddress(off))
            fname = func.getName() if func else "?"
            print("  Offset 0x{:X}: APCB magic in {}".format(off, fname))

    # Search for APCB group IDs (0x1701-0x1707) in literal pools
    for group_id in [0x1701, 0x1702, 0x1703, 0x1704, 0x1705, 0x1706, 0x1707]:
        for off in range(0, len(pspbl) - 3, 2):
            hw = struct.unpack_from("<H", pspbl, off)[0]
            if hw == group_id:
                func = func_mgr.getFunctionContaining(space.getAddress(off))
                fname = func.getName() if func else "?"
                if fname != "?":
                    print("  Offset 0x{:X}: group ID 0x{:X} in {}".format(off, group_id, fname))

    # 6. Functions that allocate or copy large amounts of data (potential overflow sites)
    print("\n" + "=" * 70)
    print("6. Large PSP_BL functions (potential overflow sites)")
    print("=" * 70)

    sized_funcs = []
    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        sized_funcs.append((entry, size, func.getName()))

    sized_funcs.sort(key=lambda x: -x[1])
    for entry, size, name in sized_funcs[:20]:
        print("  {} (0x{:X}): {} bytes".format(name, entry, size))

    # 7. Decompile the function containing the 0x5D7AC reference at 0x0BB8
    print("\n" + "=" * 70)
    print("7. Function at/near 0x0BB8 (context base literal pool)")
    print("=" * 70)
    func = func_mgr.getFunctionContaining(space.getAddress(0x0BB8))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} (0x{:X}, {} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            # Show parts with context access
            for keyword in ['0x5d7ac', '0x660', 'param_1', 'context', '+']:
                idx = c.lower().find(keyword)
                if idx >= 0:
                    print("\n  [{}]:".format(keyword))
                    print(c[max(0,idx-200):min(len(c),idx+400)])
                    break
            else:
                print(c[:3000])

    decomp.dispose()
    print("\nDone.")
