#!/usr/bin/env python3
"""Decompile the APCB vulnerability-relevant functions.
Target: FUN_0006804C (core APCB handler with token lookup) and
FUN_00069FAC (APCB blob loader) plus surrounding functions.
"""
import os, sys

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

print("Starting pyghidra...")
pyghidra.start(install_dir=GHIDRA_DIR)
print("OK")

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

    # Functions to decompile FULLY (no truncation)
    targets = [
        (0x6804C, "APCB_core_handler"),     # Core switch + token lookup
        (0x69FAC, "APCB_blob_loader"),       # Loads APCB into SRAM
        (0x67E80, "APCB_param_getter"),      # Wrapper that calls core handler
        (0x67EB0, "APCB_config_handler"),    # References "APCB Config parameter"
        (0x713BC, "overflow_check_func"),    # Contains/near #BUFFER OVERFLOW# string
        (0x6F1D8, "most_called_func"),       # 316 calls, LDR r4,[r0,#0x660]
        (0x6BB9C, "second_most_called"),     # 140 calls, context structure access
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
            print("=== {} (VA 0x{:X}, entry 0x{:X}, {} bytes) ===".format(
                label, va, entry, size))

            result = decomp.decompileFunction(func, 180, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                # Print FULL decompilation — these functions are critical
                print(c)
                print("--- END {} ({} chars) ---".format(label, len(c)))
            else:
                print("  DECOMPILE FAILED: {}".format(result.getErrorMessage()))
        else:
            print("\n=== {} (VA 0x{:X}): NOT FOUND ===".format(label, va))
            # Try to create function here
            print("  Attempting to create function...")
            txid = program.startTransaction("CreateFunc")
            try:
                flat.createFunction(addr, "FUN_{:08X}".format(va))
                flat.disassemble(addr)
                program.endTransaction(txid, True)
                func = func_mgr.getFunctionAt(addr)
                if func:
                    result = decomp.decompileFunction(func, 180, flat.getMonitor())
                    if result.decompileCompleted():
                        c = result.getDecompiledFunction().getC()
                        print(c)
                    else:
                        print("  DECOMPILE FAILED: {}".format(result.getErrorMessage()))
            except Exception as e:
                program.endTransaction(txid, False)
                print("  CREATE FAILED: {}".format(e))

    # Also: list functions around the vulnerability region
    print("\n" + "=" * 70)
    print("=== Functions near SRAM 0x5DE0C (in context structure access pattern) ===")

    # Find all functions that reference literal pool values near 0x5DE0C
    listing = program.getListing()
    fi = func_mgr.getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        body = f.getBody()
        insn_iter = listing.getInstructions(body, True)
        found_refs = []
        while insn_iter.hasNext():
            insn = insn_iter.next()
            refs = insn.getReferencesFrom()
            for ref in refs:
                target = ref.getToAddress().getOffset()
                # Check if this references a data location that might contain 0x5DE0C
                if 0x5D000 <= target <= 0x5F000:
                    found_refs.append((insn.getAddress().getOffset(), str(insn), target))
        if found_refs:
            print("\n  {} (entry 0x{:X}):".format(f.getName(), f.getEntryPoint().getOffset()))
            for iaddr, istr, target in found_refs:
                print("    0x{:X}: {} -> 0x{:X}".format(iaddr, istr, target))

    # Check the SRAM pointer table at the end of the binary
    print("\n" + "=" * 70)
    print("=== SRAM pointer table analysis (binary tail) ===")
    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()

    import struct
    # Scan last 2K for SRAM pointers (0x50000-0x60000)
    for off in range(len(abl4) - 200, len(abl4) - 4, 4):
        val = struct.unpack_from("<I", abl4, off)[0]
        if 0x50000 <= val <= 0x60000:
            va = ABL4_BASE + off
            print("  +0x{:04X} (VA 0x{:05X}): 0x{:08X}".format(off, va, val))

    decomp.dispose()
    print("\nDone.")
