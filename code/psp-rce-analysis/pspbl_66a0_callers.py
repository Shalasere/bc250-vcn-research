#!/usr/bin/env python3
"""Find callers of FUN_000066A0 (APCB group installer) and trace
what destination addresses they pass.

Also:
1. Read PSP_BL[0x67BC] to resolve DAT_000067bc (default dest pointer)
2. Find which function contains literal pool at 0x0BB8 (0x5D7AC)
3. Check FUN_00006B76 — the function that READS from context structure
4. Decompile FUN_00002C80 (APCB DMA processing) — called by FUN_000066A0
5. Decompile FUN_00003D6C (references 0x5D004)
"""
import os, re, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

# Read raw literal pool values first
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

print("=" * 70)
print("PART 0: Key literal pool values")
print("=" * 70)

pool_addrs = [
    0x0BB8, 0x0BC8,  # Context structure pointers
    0x67BC,           # DAT_000067bc (FUN_000066A0 default dest)
    0x3DA0,           # Points to 0x5D004
    0x0958,           # Previously identified context ref
    0x08B0, 0x08B4, 0x08B8,  # Token table pointers
]

for addr in pool_addrs:
    if addr + 3 < len(pspbl):
        val = struct.unpack_from("<I", pspbl, addr)[0]
        print("  [0x{:04X}] = 0x{:08X}".format(addr, val))

# Also check what function body contains offset 0x0BB8
print("\n  Functions near 0x0BB8:")

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

    # Find function containing 0x0BB8
    func = func_mgr.getFunctionContaining(space.getAddress(0x0BB8))
    if func:
        print("  0x0BB8 is in {} (0x{:04X}, {} bytes)".format(
            func.getName(), func.getEntryPoint().getOffset(),
            func.getBody().getNumAddresses()))
    else:
        print("  0x0BB8 is NOT in any function body")
        # Check instructions nearby
        for off in [0x0BB0, 0x0BB4, 0x0BB8, 0x0BBC, 0x0BC0]:
            inst = program.getListing().getInstructionAt(space.getAddress(off))
            if inst:
                print("    0x{:04X}: {}".format(off, inst.toString()))

    # Find what references 0x0BB8 (instructions that LDR from this pool)
    refs = ref_mgr.getReferencesTo(space.getAddress(0x0BB8))
    for ref in refs:
        func = func_mgr.getFunctionContaining(ref.getFromAddress())
        fn = func.getName() if func else "?"
        print("  0x0BB8 ref from 0x{:04X} in {} ({})".format(
            ref.getFromAddress().getOffset(), fn, ref.getReferenceType().toString()))

    # Same for 0x0BC8
    refs = ref_mgr.getReferencesTo(space.getAddress(0x0BC8))
    for ref in refs:
        func = func_mgr.getFunctionContaining(ref.getFromAddress())
        fn = func.getName() if func else "?"
        print("  0x0BC8 ref from 0x{:04X} in {} ({})".format(
            ref.getFromAddress().getOffset(), fn, ref.getReferenceType().toString()))

    # Part 1: Callers of FUN_000066A0
    print("\n" + "=" * 70)
    print("PART 1: Callers of FUN_000066A0 (APCB group installer)")
    print("=" * 70)

    target = space.getAddress(0x66A0)
    refs = ref_mgr.getReferencesTo(target)
    callers = []
    for ref in refs:
        if ref.getReferenceType().isCall():
            ca = ref.getFromAddress().getOffset()
            func = func_mgr.getFunctionContaining(ref.getFromAddress())
            if func:
                callers.append((ca, func.getEntryPoint().getOffset(), func.getName()))

    print("  FUN_000066A0 callers: {} refs".format(len(callers)))
    for call_addr, func_addr, fname in callers:
        print("    Call at 0x{:04X} in {} (0x{:04X})".format(call_addr, fname, func_addr))

    # Decompile each caller to see what param_3 (destination) is
    seen = set()
    for call_addr, func_addr, fname in callers:
        if func_addr in seen:
            continue
        seen.add(func_addr)

        func = func_mgr.getFunctionAt(space.getAddress(func_addr))
        if not func:
            continue

        print("\n  --- {} (0x{:04X}) ---".format(fname, func_addr))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if not result.decompileCompleted():
            print("    Decompile failed!")
            continue

        c = result.getDecompiledFunction().getC()

        # Find calls to FUN_000066A0 and extract arguments
        idx = 0
        while True:
            idx = c.find('FUN_000066a0', idx)
            if idx < 0:
                break
            # Get the full call
            end = c.find(';', idx)
            if end > 0:
                call = c[idx:end].strip()
                print("    CALL: {}".format(call[:200]))
            idx += 1

        # Show the function if it's not too large
        fsize = func.getBody().getNumAddresses()
        if fsize < 1500:
            print(c[:4000] if len(c) > 4000 else c)
        else:
            # Just show the context around FUN_000066A0 calls
            idx = 0
            while True:
                idx = c.find('FUN_000066a0', idx)
                if idx < 0:
                    break
                start = max(0, c.rfind('\n', 0, max(0, idx - 300)))
                end = min(len(c), c.find('\n', idx + 300) if c.find('\n', idx + 300) > 0 else idx + 300)
                print("    Context:\n" + c[start:end])
                idx += 1

    # Part 2: Decompile FUN_00002C80 (APCB DMA processing)
    print("\n" + "=" * 70)
    print("PART 2: FUN_00002C80 — APCB DMA group processing")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x2C80))
    if func:
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), 0x2C80, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Look for address computations, group ID handling
            if '0x1702' in c or '0x1705' in c:
                print("  *** Contains group IDs 0x1702/0x1705 ***")

            print(c[:6000] if len(c) > 6000 else c)

    # Part 3: Decompile FUN_00003D6C (references 0x5D004)
    print("\n" + "=" * 70)
    print("PART 3: FUN_00003D6C — references 0x5D004 (context-adjacent)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x3D6C))
    if func:
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), 0x3D6C, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # Part 4: Decompile FUN_00006B76 (reads context structure via 0x5D7AC)
    print("\n" + "=" * 70)
    print("PART 4: FUN_00006B76 — context structure reader")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6B76))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6B76))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # Part 5: Find the function that references 0x0BB8 / 0x0958
    # 0x0958 was identified as the "read from context" reference
    print("\n" + "=" * 70)
    print("PART 5: Functions referencing context structure (0x5D7AC)")
    print("=" * 70)

    for pool_addr in [0x0BB8, 0x0BC8, 0x0958]:
        val = struct.unpack_from("<I", pspbl, pool_addr)[0]
        refs = ref_mgr.getReferencesTo(space.getAddress(pool_addr))
        ref_list = list(refs)
        if ref_list:
            for ref in ref_list:
                func = func_mgr.getFunctionContaining(ref.getFromAddress())
                fn = func.getName() if func else "?"
                fe = func.getEntryPoint().getOffset() if func else 0
                print("  [0x{:04X}] = 0x{:05X}: ref from 0x{:04X} in {} (0x{:04X})".format(
                    pool_addr, val, ref.getFromAddress().getOffset(), fn, fe))
        else:
            # Search by scanning for LDR instructions that reference this offset
            # LDR Rn, [PC, #offset] — encoded with PC-relative offset
            print("  [0x{:04X}] = 0x{:05X}: NO Ghidra refs (may be unreferenced literal)".format(
                pool_addr, val))

            # Manual search: find 32-bit words in PSP_BL that could be
            # PC-relative loads targeting this address
            # In ARM mode: LDR Rd, [PC, #imm] where PC = current + 8
            # The literal pool entry at 0xBB8 would be loaded by an instruction
            # at approximately 0xBB8 - imm - 8

    # Check: is there a function starting near 0x0958?
    func = func_mgr.getFunctionContaining(space.getAddress(0x0958))
    if func:
        print("\n  0x0958 is in {} (0x{:04X})".format(
            func.getName(), func.getEntryPoint().getOffset()))

        # Decompile it
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Look for context structure references
            if '0x5d7ac' in c.lower() or '5D7AC' in c:
                print("  *** Contains 0x5D7AC reference ***")
            if '0x660' in c:
                print("  *** Contains 0x660 offset ***")

            print(c[:4000] if len(c) > 4000 else c)

    decomp.dispose()

print("\nDone.")
