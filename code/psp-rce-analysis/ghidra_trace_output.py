#!/usr/bin/env python3
"""Decompile FUN_00062950 (actual debug output implementation) and FUN_0006A140 (post-assert).
Also: scan for all literal pool values that might be IDS buffer base pointers near 0x5DE0C.
And: decompile functions that reference the SRAM pointer table at 0x753A4.
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

    targets = [
        (0x62950, "debug_output_impl_FUN_00062950"),
        (0x6A140, "post_assert_FUN_0006A140"),
        (0x61334, "get_something_FUN_00061334"),
        (0x61400, "report_FUN_00061400"),
    ]

    for va, label in targets:
        addr = space.getAddress(va)
        func = func_mgr.getFunctionAt(addr)
        if not func:
            func = func_mgr.getFunctionContaining(addr)

        if func:
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            print("\n" + "=" * 70)
            print("=== {} (entry 0x{:X}, {} bytes) ===".format(label, entry, size))
            result = decomp.decompileFunction(func, 180, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                if len(c) < 8000:
                    print(c)
                else:
                    print(c[:4000])
                    print("\n... [truncated, {} total]".format(len(c)))
            else:
                print("  DECOMPILE FAILED: {}".format(result.getErrorMessage()))
        else:
            print("\n=== {} (VA 0x{:X}): NOT FOUND ===".format(label, va))

    # Find what references the SRAM pointer table
    print("\n" + "=" * 70)
    print("=== References to SRAM pointer table base (VA 0x753A4) ===")
    for delta in range(-8, 8, 4):
        addr = space.getAddress(0x753A4 + delta)
        refs = list(ref_mgr.getReferencesTo(addr))
        if refs:
            for r in refs:
                func = func_mgr.getFunctionContaining(r.getFromAddress())
                fname = func.getName() if func else "?"
                print("  0x{:X} <- 0x{:X} in {}".format(
                    0x753A4 + delta, r.getFromAddress().getOffset(), fname))

    # Look at what VA 0x7A000 contains — that's the APCB group base
    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()

    print("\n" + "=" * 70)
    print("=== APCB group base at VA 0x7A000 (offset 0x{:X}) ===".format(0x7A000 - ABL4_BASE))
    off = 0x7A000 - ABL4_BASE
    if off >= 0 and off < len(abl4):
        print("  NOTE: Offset 0x{:X} is BEYOND binary size (0x{:X})!".format(off, len(abl4)))
    else:
        print("  Offset 0x{:X} vs binary size 0x{:X}".format(off, len(abl4)))

    # The APCB base at 0x7A000 is BEYOND the 88K binary (binary ends at 0x75FB4)
    # This means it's a RUNTIME address - populated by earlier boot stages
    print("  0x7A000 is {} bytes past ABL4 end (0x{:X})".format(
        0x7A000 - (ABL4_BASE + len(abl4)), ABL4_BASE + len(abl4)))

    # Check what the assert error codes mean
    print("\n" + "=" * 70)
    print("=== Assert error code analysis ===")
    # DAT_000683bc = 0xF7000369 = file 0xF700, line 0x0369 = 873
    # DAT_000683c0 = 0xF7000515 = file 0xF700, line 0x0515 = 1301
    print("  FUN_0006804c assert 1: file=0xF700 line=873 (0x369)")
    print("  FUN_0006804c assert 2: file=0xF700 line=1301 (0x515)")
    print("  Allocator assert: file=0xF702 line=1091 (0x443)")

    # Now scan for any address EXACTLY 0x5DE0C in the binary
    print("\n" + "=" * 70)
    print("=== Exhaustive scan for 0x5DE0C-related values ===")
    target = 0x5DE0C

    # As u32 LE
    needle = struct.pack("<I", target)
    for off in range(len(abl4) - 3):
        if abl4[off:off+4] == needle:
            va = ABL4_BASE + off
            print("  FOUND u32 0x{:08X} at offset +0x{:04X} (VA 0x{:X})".format(target, off, va))

    # As u16 LE for lower half
    needle16 = struct.pack("<H", target & 0xFFFF)
    count16 = 0
    for off in range(len(abl4) - 1):
        if abl4[off:off+2] == needle16:
            count16 += 1
            if count16 <= 10:
                va = ABL4_BASE + off
                print("  u16 lower 0x{:04X} at +0x{:04X} (VA 0x{:X})".format(
                    target & 0xFFFF, off, va))
    if count16 > 10:
        print("  ... {} total u16 matches for 0x{:04X}".format(count16, target & 0xFFFF))

    # Check for values that could be base+offset to reach 0x5DE0C
    # Common bases in literal pools: find all u32 values that when added to
    # a reasonable offset (< 0x1000) give 0x5DE0C
    print("\n  Searching for base+offset decompositions of 0x5DE0C:")
    for off in range(0, len(abl4) - 3, 4):
        val = struct.unpack_from("<I", abl4, off)[0]
        if val == 0:
            continue
        diff = target - val
        if 0 < diff < 0x1000:
            va = ABL4_BASE + off
            # Check if any instruction references this literal pool location
            addr = space.getAddress(va)
            refs = list(ref_mgr.getReferencesTo(addr))
            if refs:
                for r in refs:
                    func = func_mgr.getFunctionContaining(r.getFromAddress())
                    fname = func.getName() if func else "?"
                    print("    base=0x{:X} + 0x{:X} = 0x5DE0C  at VA 0x{:X} <- {} in {}".format(
                        val, diff, va, r.getFromAddress().getOffset(), fname))

    decomp.dispose()
    print("\nDone.")
