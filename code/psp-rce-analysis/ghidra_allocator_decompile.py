#!/usr/bin/env python3
"""Decompile the APCB allocator (FUN_00069D78) and search for what sets
DAT_0006a020 (the global APCB blob pointer) to understand how the APCB
gets loaded to SRAM. Also decompile FUN_0006f8a4 (called when APCB type
not found — might be the SPI flash loader).
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

    # 1. Decompile the allocator and related functions
    targets = [
        (0x69D78, "allocator_FUN_00069D78"),
        (0x6F8A4, "flash_loader_FUN_0006F8A4"),
        (0x69238, "init_check_FUN_00069238"),
        (0x6AAAC, "init_FUN_0006AAAC"),
        (0x6AAE4, "init_FUN_0006AAE4"),
        (0x68420, "type_lookup_FUN_00068420"),
        (0x68540, "core_state_FUN_00068540"),
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
                    for kw in ["APCB", "buffer", "alloc", "size", "copy", "memcpy",
                               "sram", "flash", "spi", "load", "0x5d", "0x5e"]:
                        for idx in range(len(c)):
                            pos = c.lower().find(kw, idx)
                            if pos >= 0 and pos > idx:
                                print("\n  '{}' at {}:".format(kw, pos))
                                print("  ...{}...".format(c[max(0,pos-60):pos+200]))
                                break
            else:
                print("  DECOMPILE FAILED: {}".format(result.getErrorMessage()))
        else:
            print("\n=== {} (VA 0x{:X}): NOT FOUND ===".format(label, va))

    # 2. Find ALL references to DAT_0006a020 and DAT_0006a024
    # These are the global APCB blob pointer and magic value
    print("\n" + "=" * 70)
    print("=== References to DAT_0006a020 (APCB blob pointer) ===")
    for offset in range(0x6a020, 0x6a030, 4):
        addr = space.getAddress(offset)
        refs_to = list(ref_mgr.getReferencesTo(addr))
        if refs_to:
            for ref in refs_to:
                from_addr = ref.getFromAddress().getOffset()
                func = func_mgr.getFunctionContaining(ref.getFromAddress())
                fname = func.getName() if func else "?"
                print("  DAT_{:08X} <- 0x{:X} in {} (type: {})".format(
                    offset, from_addr, fname, ref.getReferenceType()))

    # 3. Read the binary to check the literal pool values at 0x6a020-0x6a02c
    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()

    print("\n" + "=" * 70)
    print("=== Literal pool values at VA 0x6a020-0x6a030 ===")
    for va in range(0x6a020, 0x6a030, 4):
        off = va - ABL4_BASE
        if 0 <= off < len(abl4) - 3:
            val = struct.unpack_from("<I", abl4, off)[0]
            print("  VA 0x{:05X} (+0x{:04X}): 0x{:08X}".format(va, off, val))

    # 4. Find ALL functions that reference addresses in the 0x5D000-0x5F000 range
    # through literal pool loads
    print("\n" + "=" * 70)
    print("=== Scanning ALL literal pools for SRAM addresses 0x5D000-0x60000 ===")
    for off in range(0, len(abl4) - 3, 4):
        val = struct.unpack_from("<I", abl4, off)[0]
        if 0x5D000 <= val <= 0x60000:
            va = ABL4_BASE + off
            # Check if any instruction loads from this literal pool location
            addr = space.getAddress(va)
            refs = list(ref_mgr.getReferencesTo(addr))
            ref_str = ""
            if refs:
                for r in refs:
                    func = func_mgr.getFunctionContaining(r.getFromAddress())
                    fname = func.getName() if func else "?"
                    ref_str += " <- 0x{:X} in {}".format(r.getFromAddress().getOffset(), fname)
            print("  VA 0x{:05X}: 0x{:08X}{}".format(va, val, ref_str))

    # 5. Search for SVC calls (software_interrupt) that might load APCB from flash
    print("\n" + "=" * 70)
    print("=== SVC (software_interrupt) instructions ===")
    listing = program.getListing()
    fi = func_mgr.getFunctions(True)
    svc_funcs = {}
    while fi.hasNext():
        f = fi.next()
        body = f.getBody()
        insn_iter = listing.getInstructions(body, True)
        while insn_iter.hasNext():
            insn = insn_iter.next()
            mn = insn.getMnemonicString()
            if mn and mn.lower().startswith("svc"):
                fname = f.getName()
                if fname not in svc_funcs:
                    svc_funcs[fname] = []
                svc_funcs[fname].append("0x{:X}: {}".format(
                    insn.getAddress().getOffset(), str(insn)))

    for fname, svcs in sorted(svc_funcs.items()):
        print("  {} ({} SVCs):".format(fname, len(svcs)))
        for s in svcs[:5]:
            print("    {}".format(s))
        if len(svcs) > 5:
            print("    ... ({} more)".format(len(svcs) - 5))

    decomp.dispose()
    print("\nDone.")
