#!/usr/bin/env python3
"""Decompile FUN_000008bc — the CORE token lookup function.

FUN_00000850 dispatches to FUN_000008bc, which returns:
- token source address
- token size
- token flags

These returned values control ALL downstream copy operations.
If FUN_000008bc computes sizes incorrectly from APCB data,
the integer overflow bypasses bounds checks.

Also decompile:
- FUN_0000084A (alternate token entry, called by FUN_000055C0)
- FUN_00003568 (called in FUN_00003BA4 loop)
- FUN_00008064 (called by FUN_00007014 for signature setup)
- FUN_00006992 (called by FUN_000056C4)
- FUN_00006EE0 (called by FUN_000056C4 when param_5=0)
- FUN_00008488 (called by FUN_000056C4 for actual processing)
- FUN_000062F8 (called by FUN_00007014 for compressed APCB)
- FUN_000062BE (alternative copy path in FUN_000071AC)
- FUN_00001F40 (signature verify + copy in FUN_000071AC)
"""
import os, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

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

    targets = [
        (0x08BC, "*** FUN_000008BC — CORE TOKEN LOOKUP (sizes returned to all callers) ***"),
        (0x084A, "FUN_0000084A — alternate token entry point"),
        (0x083C, "FUN_0000083C — token wrapper (calls FUN_00000850)"),
        (0x062BE, "FUN_000062BE — alternative copy path from FUN_000071AC"),
        (0x01F40, "FUN_00001F40 — signature + copy path from FUN_000071AC"),
        (0x08488, "FUN_00008488 — processing function from FUN_000056C4"),
        (0x06992, "FUN_00006992 — called by FUN_000056C4"),
        (0x06EE0, "FUN_00006EE0 — called by FUN_000056C4 (no-sig path)"),
        (0x062F8, "FUN_000062F8 — compressed APCB from FUN_00007014"),
        (0x08064, "FUN_00008064 — signature setup from FUN_00007014"),
    ]

    for addr, desc in targets:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if not func:
            print("\n  No function at 0x{:05X}".format(addr))
            continue

        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("\n" + "=" * 70)
        print("{} at 0x{:04X} ({} bytes)".format(desc, entry, fsize))
        print("=" * 70)

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if not result.decompileCompleted():
            print("  Decompile failed!")
            continue

        c = result.getDecompiledFunction().getC()

        # Check for size computations
        # Subtraction patterns
        subs = re.findall(r'(\w+)\s*-\s*(0x[0-9a-fA-F]+)', c)
        for var, val in subs:
            if any(kw in var for kw in ['local_', 'param_', 'uVar', 'iVar', '*']):
                print("  SUBTRACT: {} - {}".format(var, val))

        # Stack buffers
        buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
        for name, size in buffers:
            print("  STACK BUFFER: {} [{}]".format(name, size))

        # Casts
        casts = re.findall(r'\((ushort|short|uint|int|byte|char)\)\s*\*?\(?\w+', c)
        if casts:
            unique_casts = set(casts)
            for cast in unique_casts:
                print("  CAST to: {}".format(cast))

        # Print full decompile
        print("\n--- FULL DECOMPILE ---")
        if len(c) <= 6000:
            print(c)
        else:
            print(c[:6000])
            print("\n... ({} more chars)".format(len(c) - 6000))

    # PART 2: Trace what *DAT_00003848 points to and how it's initialized
    print("\n\n" + "=" * 70)
    print("PART 2: DAT_00003848 initialization (APCB metadata table)")
    print("=" * 70)

    # Find all references to 0x3848 (literal pool entry for the APCB metadata pointer)
    ref_mgr = program.getReferenceManager()
    for target_addr in [0x3848, 0x08B0, 0x08B4, 0x08B8]:
        target = space.getAddress(target_addr)
        refs = ref_mgr.getReferencesTo(target)
        ref_list = []
        for ref in refs:
            ref_list.append((ref.getFromAddress().getOffset(), ref.getReferenceType().toString()))
        if ref_list:
            print("  References to 0x{:04X}:".format(target_addr))
            for from_addr, ref_type in ref_list:
                func = func_mgr.getFunctionContaining(space.getAddress(from_addr))
                fname = func.getName() if func else "unknown"
                print("    0x{:04X} ({}) in {}".format(from_addr, ref_type, fname))

    # Read the raw bytes at these literal pool addresses
    import struct
    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()

    for addr in [0x3848, 0x08B0, 0x08B4, 0x08B8, 0x549C, 0x54A0]:
        if addr + 3 < len(pspbl):
            val = struct.unpack_from("<I", pspbl, addr)[0]
            print("  [{:04X}] = 0x{:08X}".format(addr, val))

    # PART 3: Check callers of FUN_000008bc
    print("\n\n" + "=" * 70)
    print("PART 3: Callers of FUN_000008BC")
    print("=" * 70)

    target = space.getAddress(0x8BC)
    refs = ref_mgr.getReferencesTo(target)
    for ref in refs:
        if ref.getReferenceType().isCall():
            from_addr = ref.getFromAddress().getOffset()
            func = func_mgr.getFunctionContaining(ref.getFromAddress())
            fname = func.getName() if func else "unknown"
            print("    Call at 0x{:04X} in {} (0x{:04X})".format(
                from_addr, fname, func.getEntryPoint().getOffset() if func else 0))

    decomp.dispose()

print("\nDone.")
