#!/usr/bin/env python3
"""Reopen the Ghidra ABL4 project and decompile key APCB functions.
Key targets:
- FUN_00067eb0: references "APCB Config parameter" string (confirmed xref)
- FUN_000713bc (+0x10B88): nearest function before overflow string
- FUN_00071268 (+0x10A34): function near overflow area
- FUN_000712e0 (+0x10AAC): function near overflow area
- FUN_0006308c: references Parent/Get APCB parameter strings area
- FUN_000631fc: references APCB strings
- FUN_000664d4: huge function, many refs to APCB data
- FUN_0006bc64: also references APCB data area

Also: do a proper string search by scanning the binary for all known APCB strings
and finding what references them through Ghidra's analysis.
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
print("OK")

# Open the existing project
with pyghidra.open_program(
    ABL4_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_abl4_v3", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()

    # Import decompiler
    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # Key functions to decompile
    targets = [
        (0x67eb0, "APCB_Config_handler"),
        (0x713bc, "nearest_before_overflow"),
        (0x71268, "near_overflow_1"),
        (0x712e0, "near_overflow_2"),
        (0x6308c, "APCB_parent_get"),
        (0x631fc, "APCB_strings_1"),
        (0x664d4, "big_APCB_handler"),
    ]

    for va, label in targets:
        addr = space.getAddress(va)
        func = func_mgr.getFunctionContaining(addr)
        if not func:
            # Try exact entry
            func = func_mgr.getFunctionAt(addr)

        if func:
            print("\n{'='*70}")
            print("=== {} @ VA 0x{:X} (entry: 0x{:X}, size: {}) ===".format(
                label, va, func.getEntryPoint().getOffset(),
                func.getBody().getNumAddresses()))

            # Decompile
            result = decomp.decompileFunction(func, 120, flat.getMonitor())
            if result.decompileCompleted():
                c_code = result.getDecompiledFunction().getC()
                # Print first 3000 chars
                print(c_code[:3000])
                if len(c_code) > 3000:
                    print("\n... [truncated, {} total chars]".format(len(c_code)))
                    # Search for BUFFER, OVERFLOW, APCB in the rest
                    for keyword in ["BUFFER", "OVERFLOW", "APCB", "depth", "MAX_DEPTH", "overflow"]:
                        idx = c_code.lower().find(keyword.lower())
                        if idx >= 0:
                            start = max(0, idx - 100)
                            end = min(len(c_code), idx + 200)
                            print("\n  Found '{}' at char {}:".format(keyword, idx))
                            print("  ...{}...".format(c_code[start:end]))
            else:
                print("  Decompile FAILED: {}".format(result.getErrorMessage()))
        else:
            print("\n=== {} @ VA 0x{:X}: NO FUNCTION FOUND ===".format(label, va))

    # Also: find ALL references in the program to any address in the range
    # where the overflow string lives (VA 0x722F0-0x722F8)
    print("\n\n{'='*70}")
    print("=== Searching for ALL references near overflow string VA 0x722F0-0x722F8 ===")
    for delta in range(-8, 16):
        addr = space.getAddress(0x722F1 + delta)
        refs = list(ref_mgr.getReferencesTo(addr))
        if refs:
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = func_mgr.getFunctionContaining(from_addr)
                fname = func.getName() if func else "?"
                print("  VA 0x{:X} <- 0x{:X} in {} (type: {})".format(
                    0x722F1 + delta, from_addr.getOffset(), fname, ref.getReferenceType()))

    # Also search for references to the FAILED string VA 0x722AA
    print("\n=== Searching refs to 'Failed' string VA 0x722A0-0x722B0 ===")
    for delta in range(-4, 16):
        addr = space.getAddress(0x722AA + delta)
        refs = list(ref_mgr.getReferencesTo(addr))
        if refs:
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = func_mgr.getFunctionContaining(from_addr)
                fname = func.getName() if func else "?"
                print("  VA 0x{:X} <- 0x{:X} in {} (type: {})".format(
                    0x722AA + delta, from_addr.getOffset(), fname, ref.getReferenceType()))

    # And the IDS INTERNAL string VA 0x72265
    print("\n=== Searching refs to IDS INTERNAL string VA 0x72260-0x72270 ===")
    for delta in range(-4, 16):
        addr = space.getAddress(0x72265 + delta)
        refs = list(ref_mgr.getReferencesTo(addr))
        if refs:
            for ref in refs:
                from_addr = ref.getFromAddress()
                func = func_mgr.getFunctionContaining(from_addr)
                fname = func.getName() if func else "?"
                print("  VA 0x{:X} <- 0x{:X} in {} (type: {})".format(
                    0x72265 + delta, from_addr.getOffset(), fname, ref.getReferenceType()))

    # Key insight: maybe the function at +0x10B88 uses ADR.W to reach the strings
    # but Ghidra didn't create references for it. Let me check what Ghidra says
    # the instructions ARE at that function.
    print("\n\n{'='*70}")
    print("=== Listing of function at 0x713BC (raw Ghidra instructions) ===")
    listing = program.getListing()
    func = func_mgr.getFunctionAt(space.getAddress(0x713bc))
    if func:
        body = func.getBody()
        addr_set = body
        insn_iter = listing.getInstructions(addr_set, True)
        count = 0
        while insn_iter.hasNext() and count < 200:
            insn = insn_iter.next()
            refs = insn.getReferencesFrom()
            ref_str = ""
            if refs:
                ref_str = " -> " + ", ".join("0x{:X}".format(r.getToAddress().getOffset()) for r in refs)
            mn = insn.getMnemonicString()
            if mn.lower().startswith("adr") or "buffer" in str(insn).lower():
                ref_str += " <<< ADR/BUFFER"
            print("  0x{:08X}: {:30s} {}".format(
                insn.getAddress().getOffset(),
                str(insn),
                ref_str))
            count += 1

    decomp.dispose()
    print("\nDone.")
