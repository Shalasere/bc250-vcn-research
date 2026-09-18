#!/usr/bin/env python3
"""Decompile the APCB parsing chain deeper — FUN_00067E80 and its callees.
Also: list ALL Ghidra functions to find coverage gaps.
"""
import os

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

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # 1. List ALL Ghidra functions to see coverage
    print("\n=== ALL functions in Ghidra project ===")
    all_funcs = []
    fi = func_mgr.getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        entry = f.getEntryPoint().getOffset()
        size = f.getBody().getNumAddresses()
        all_funcs.append((entry, f.getName(), size))
    all_funcs.sort()

    print("Total: {} functions".format(len(all_funcs)))
    # Show functions near the overflow area (+0x10000-0x12000 = VA 0x70834-0x72834)
    print("\nFunctions in overflow neighborhood (VA 0x70000-0x73000):")
    for entry, name, size in all_funcs:
        if 0x70000 <= entry <= 0x73000:
            print("  0x{:08X}: {} ({} bytes, end ~0x{:X})".format(
                entry, name, size, entry + size))

    # Show the gap analysis
    print("\nGaps > 1000 bytes between functions:")
    for i in range(len(all_funcs) - 1):
        end_prev = all_funcs[i][0] + all_funcs[i][2]
        start_next = all_funcs[i+1][0]
        gap = start_next - end_prev
        if gap > 1000:
            print("  Gap: 0x{:X} to 0x{:X} ({} bytes) between {} and {}".format(
                end_prev, start_next, gap, all_funcs[i][1], all_funcs[i+1][1]))

    # 2. Decompile the core APCB functions
    key_funcs = [
        0x67e80,   # Core APCB parameter getter (called by FUN_0006308c)
        0x67e50,   # Called by FUN_00067eb0 for CBS token lookup
        0x6804c,   # Called by FUN_00067eb0 for non-CBS config
        0x6a0d0,   # Assert/halt function (called on errors)
        0x62908,   # Debug print function
        0x69238,   # Check function called at start of many funcs
    ]

    for va in key_funcs:
        addr = space.getAddress(va)
        func = func_mgr.getFunctionAt(addr)
        if not func:
            func = func_mgr.getFunctionContaining(addr)

        if func:
            print("\n{'='*60}")
            print("=== FUN_{:08X} (size: {}) ===".format(
                func.getEntryPoint().getOffset(), func.getBody().getNumAddresses()))
            result = decomp.decompileFunction(func, 120, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                # Print full if < 4000, otherwise truncate with keyword search
                if len(c) < 4000:
                    print(c)
                else:
                    print(c[:3000])
                    print("\n... [{} chars total]".format(len(c)))
                    for kw in ["buffer", "overflow", "depth", "size", "length", "APCB", "group", "type"]:
                        idx = c.lower().find(kw.lower())
                        if idx >= 0:
                            print("\n  '{}' at {}:".format(kw, idx))
                            print("  ...{}...".format(c[max(0,idx-80):idx+200]))
            else:
                print("  FAILED: {}".format(result.getErrorMessage()))
        else:
            print("\nFUN_{:08X}: NOT FOUND".format(va))

    # 3. Try to create functions in the gap region and analyze them
    # The gap between FUN_713BC+176 = 0x7146C and FUN_7373C
    # might contain code that wasn't found by auto-analysis
    print("\n\n{'='*60}")
    print("=== Attempting to find hidden functions in gap 0x7146C-0x7373C ===")

    # Read the binary to find PUSH prologues in this range
    mem = program.getMemory()
    gap_start = 0x7146C
    gap_end = 0x7373C

    import struct
    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()

    hidden_funcs = []
    for off in range(gap_start - ABL4_BASE, gap_end - ABL4_BASE, 2):
        if off + 1 < len(abl4):
            if abl4[off+1] == 0xB5:  # Narrow PUSH with LR
                va = ABL4_BASE + off
                hidden_funcs.append(va)
            elif off + 3 < len(abl4) and abl4[off] == 0x2D and abl4[off+1] == 0xE9:
                mask = struct.unpack_from("<H", abl4, off+2)[0]
                if mask & 0x4000:
                    va = ABL4_BASE + off
                    hidden_funcs.append(va)

    print("PUSH prologues in gap: {}".format(len(hidden_funcs)))
    for va in hidden_funcs:
        print("  VA 0x{:X} (binary +0x{:X})".format(va, va - ABL4_BASE))
        # Try to create function and decompile
        txid = program.startTransaction("CreateFunc")
        try:
            addr = space.getAddress(va)
            existing = func_mgr.getFunctionAt(addr)
            if not existing:
                flat.createFunction(addr, "HIDDEN_{:08X}".format(va))
                flat.disassemble(addr)
        except Exception as e:
            print("    Create failed: {}".format(e))
        program.endTransaction(txid, True)

    # Re-run analysis on the new functions
    if hidden_funcs:
        from ghidra.app.plugin.core.analysis import AutoAnalysisManager
        mgr = AutoAnalysisManager.getAnalysisManager(program)
        txid = program.startTransaction("ReAnalyze")
        mgr.reAnalyzeAll(None)
        mgr.startAnalysis(flat.getMonitor())
        program.endTransaction(txid, True)

        # Now decompile the hidden functions
        for va in hidden_funcs:
            func = func_mgr.getFunctionAt(space.getAddress(va))
            if func:
                result = decomp.decompileFunction(func, 60, flat.getMonitor())
                if result.decompileCompleted():
                    c = result.getDecompiledFunction().getC()
                    print("\n--- HIDDEN_{:08X} ({} bytes) ---".format(va, func.getBody().getNumAddresses()))
                    print(c[:2000])

    # 4. Now check references to the overflow string again
    ref_mgr = program.getReferenceManager()
    print("\n=== Post-analysis: refs near overflow string ===")
    for delta in range(-16, 24):
        addr = space.getAddress(0x722F1 + delta)
        refs = list(ref_mgr.getReferencesTo(addr))
        if refs:
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = func_mgr.getFunctionContaining(from_addr)
                fname = func.getName() if func else "?"
                print("  VA 0x{:X} <- 0x{:X} in {}".format(
                    0x722F1 + delta, from_addr.getOffset(), fname))

    program.save("Decompiled", flat.getMonitor())
    decomp.dispose()
    print("\nDone.")
