#!/usr/bin/env python3
"""Load ABL4 into Ghidra, rebase, analyze, find BUFFER OVERFLOW xrefs."""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"
os.makedirs(PROJECT_DIR, exist_ok=True)

print("Starting pyghidra...")
pyghidra.start(install_dir=GHIDRA_DIR)
print("OK")

with pyghidra.open_program(
    ABL4_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_abl4_v3", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    mem = program.getMemory()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()

    # Rebase
    txid = program.startTransaction("Rebase")
    block = list(mem.getBlocks())[0]
    mem.moveBlock(block, space.getAddress(ABL4_BASE), flat.getMonitor())
    program.endTransaction(txid, True)
    print("Rebased to 0x{:X}".format(ABL4_BASE))

    # Set TMode for Thumb region
    from java.math import BigInteger
    txid = program.startTransaction("TMode")
    ctx_reg = program.getRegister("TMode")
    program.getProgramContext().setValue(ctx_reg,
        space.getAddress(ABL4_BASE + 0x14),
        space.getAddress(ABL4_BASE + 0x157BF),
        BigInteger.ONE)
    program.endTransaction(txid, True)
    print("TMode set")

    # Create ARM entry + disassemble Thumb
    txid = program.startTransaction("Disasm")
    try:
        flat.createFunction(space.getAddress(ABL4_BASE), "ABL4_entry_ARM")
    except: pass
    flat.disassemble(space.getAddress(ABL4_BASE + 0x14))
    program.endTransaction(txid, True)

    # Auto-analysis
    print("Running analysis...")
    from ghidra.app.plugin.core.analysis import AutoAnalysisManager
    mgr = AutoAnalysisManager.getAnalysisManager(program)
    txid = program.startTransaction("Analysis")
    mgr.reAnalyzeAll(None)
    mgr.startAnalysis(flat.getMonitor())
    program.endTransaction(txid, True)
    print("Analysis done.")

    # Count functions
    all_funcs = []
    fi = func_mgr.getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        all_funcs.append((f.getEntryPoint().getOffset(), f.getName(), f.getBody().getNumAddresses()))
    all_funcs.sort()
    print("Functions: {}".format(len(all_funcs)))

    # Key string addresses to check for xrefs
    key_strings = [
        (0x11ABD, "BUFFER_OVERFLOW", "#BUFFER  OVERFLOW#"),
        (0x11A76, "Failed_APCB", "Failed to get internal APCB parameter"),
        (0x11A31, "IDS_INT", "IDS OPTIONS GET INTERNAL PARAMETER"),
        (0x07769, "APCB_Config", "APCB Config parameter"),
        (0x07C96, "GroupId", "GroupId : 0x%04X"),
        (0x07B93, "Init_APCB", "Initializing APCB parameters"),
        (0x0294A, "Parent_APCB", "Parent APCB parameter disabled"),
        (0x0298E, "Get_APCB", "Get internal APCB parameter"),
        (0x0AA01, "AGESA4_BL", "Starting AGESA 4 BL"),
        (0x113EC, "MAX_DEPTH", "Depth >= MAX_DEPTH"),
    ]

    print("\n=== String cross-references ===")
    overflow_func = None

    for str_off, tag, label in key_strings:
        str_va = ABL4_BASE + str_off
        str_addr = space.getAddress(str_va)
        refs = list(ref_mgr.getReferencesTo(str_addr))
        if refs:
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = func_mgr.getFunctionContaining(from_addr)
                fname = func.getName() if func else "?"
                entry = func.getEntryPoint().getOffset() if func else 0
                print("  [{}] 0x{:X} -> from 0x{:X} in {} (entry 0x{:X})".format(
                    tag, str_va, from_addr.getOffset(), fname, entry))
                if tag == "BUFFER_OVERFLOW" and func:
                    overflow_func = func
        else:
            # Try +/- 1 byte in case of alignment
            for delta in [-1, 0, 1, 2]:
                alt_addr = space.getAddress(str_va + delta)
                alt_refs = list(ref_mgr.getReferencesTo(alt_addr))
                if alt_refs:
                    for ref in alt_refs:
                        from_addr = ref.getFromAddress()
                        func = func_mgr.getFunctionContaining(from_addr)
                        fname = func.getName() if func else "?"
                        print("  [{}] 0x{:X}+{} -> from 0x{:X} in {}".format(
                            tag, str_va, delta, from_addr.getOffset(), fname))
                        if "BUFFER" in tag and func:
                            overflow_func = func
                    break
            else:
                print("  [{}] 0x{:X}: no xrefs found".format(tag, str_va))

    # Also search ALL references in the string data area (0x71834+0x11000 to +0x12000)
    print("\n=== Scanning ALL xrefs into string region 0x{:X}-0x{:X} ===".format(
        ABL4_BASE + 0x11000, ABL4_BASE + 0x12000))
    xref_to_strings = []
    for off in range(0x11000, 0x12000, 4):
        addr = space.getAddress(ABL4_BASE + off)
        refs = list(ref_mgr.getReferencesTo(addr))
        for ref in refs:
            from_addr = ref.getFromAddress()
            func = func_mgr.getFunctionContaining(from_addr)
            fname = func.getName() if func else "?"
            xref_to_strings.append((off, from_addr.getOffset(), fname))

    print("Found {} xrefs into string region".format(len(xref_to_strings)))
    for str_off, from_va, fname in xref_to_strings[:30]:
        print("  +0x{:05X} <- 0x{:08X} in {}".format(str_off, from_va, fname))

    # Also scan the APCB code region (0x60834+0x2000 to +0x8000)
    print("\n=== Scanning xrefs into APCB code region ===")
    for off in range(0x02000, 0x03000, 4):
        addr = space.getAddress(ABL4_BASE + off)
        refs = list(ref_mgr.getReferencesTo(addr))
        for ref in refs:
            from_addr = ref.getFromAddress()
            func = func_mgr.getFunctionContaining(from_addr)
            fname = func.getName() if func else "?"
            if "APCB" in fname or True:  # show all
                xref_to_strings.append((off, from_addr.getOffset(), fname))
                print("  +0x{:05X} <- 0x{:08X} in {}".format(off, from_addr.getOffset(), fname))

    # Decompile the overflow function if found
    if overflow_func:
        print("\n=== Decompiling {} (overflow function) ===".format(overflow_func.getName()))
        from ghidra.app.decompiler import DecompInterface
        decomp = DecompInterface()
        decomp.openProgram(program)
        result = decomp.decompileFunction(overflow_func, 60, flat.getMonitor())
        if result.decompileCompleted():
            c_code = result.getDecompiledFunction().getC()
            print(c_code[:5000])
        else:
            print("Decompile failed: {}".format(result.getErrorMessage()))
        decomp.dispose()
    else:
        print("\nOverflow function not found via xrefs. Trying decompile of all functions near string area...")
        # Find functions closest to the string area
        for addr, name, size in all_funcs:
            func_end = addr + size
            # Functions whose code is near the overflow string
            if addr > ABL4_BASE + 0x10000 and addr < ABL4_BASE + 0x12000:
                print("  Near-string func: {} at 0x{:X} ({} bytes)".format(name, addr, size))

    program.save("Done", flat.getMonitor())
    print("\nSaved.")
