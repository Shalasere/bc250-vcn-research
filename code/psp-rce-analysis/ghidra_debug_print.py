#!/usr/bin/env python3
"""Decompile FUN_00062908 (debug print) and related IDS buffer management
to find where debug output goes (likely 0x5DE0C).
Also: decompile FUN_00069A14 (referenced from flash_loader) and
check what DAT_000684f0 points to (APCB base ptr used in type lookup).
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

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    targets = [
        (0x62908, "debug_print_FUN_00062908"),
        (0x69A14, "event_log_FUN_00069A14"),
        (0x60870, "memcpy_FUN_00060870"),       # Called by config_handler for table copy
        (0x68B88, "heap_mark_FUN_00068B88"),     # Called by allocator
        (0x6A14C, "heap_mgmt_FUN_0006A14C"),     # Called by allocator
        (0x6A0D0, "assert_FUN_0006A0D0"),        # Assert/abort handler
        (0x6A48A, "memset_thunk"),               # Called by allocator to zero buffer
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
                if len(c) < 6000:
                    print(c)
                else:
                    print(c[:3000])
                    print("\n... [truncated, {} total]".format(len(c)))
                    # Search for key patterns
                    for kw in ["0x5d", "0x5e", "buffer", "overflow", "write", "ptr", "base"]:
                        idx = c.lower().find(kw)
                        if idx >= 0:
                            print("\n  '{}' at {}:".format(kw, idx))
                            print("  ...{}...".format(c[max(0,idx-60):idx+200]))
            else:
                print("  DECOMPILE FAILED: {}".format(result.getErrorMessage()))
        else:
            print("\n=== {} (VA 0x{:X}): NOT FOUND ===".format(label, va))

    # Check literal pool values for key data pointers
    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()

    print("\n" + "=" * 70)
    print("=== Key data pointers from literal pools ===")
    for name, va in [
        ("DAT_000683bc (FUN_0006804c err1)", 0x683bc),
        ("DAT_000683c0 (FUN_0006804c err2)", 0x683c0),
        ("DAT_000684f0 (APCB base in type_lookup)", 0x684f0),
        ("DAT_00069ea0 (allocator heap ptr)", 0x69ea0),
        ("DAT_00069ea4 (allocator magic)", 0x69ea4),
        ("DAT_00069ea8 (allocator err)", 0x69ea8),
        ("DAT_00069eac (allocator err2)", 0x69eac),
        ("DAT_00069eb0 (allocator err3)", 0x69eb0),
    ]:
        off = va - ABL4_BASE
        if 0 <= off < len(abl4) - 3:
            val = struct.unpack_from("<I", abl4, off)[0]
            print("  {} (VA 0x{:05X}): 0x{:08X}".format(name, va, val))

    # Look for FUN_00062908 callee — does it call a lower-level output function?
    print("\n" + "=" * 70)
    print("=== Callees of FUN_00062908 (debug print) ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x62908))
    if func:
        body = func.getBody()
        listing = program.getListing()
        insn_iter = listing.getInstructions(body, True)
        while insn_iter.hasNext():
            insn = insn_iter.next()
            mn = insn.getMnemonicString()
            if mn and (mn.lower().startswith("bl") or mn.lower().startswith("b.")):
                refs = insn.getReferencesFrom()
                for r in refs:
                    target = r.getToAddress().getOffset()
                    tfunc = func_mgr.getFunctionAt(r.getToAddress())
                    tname = tfunc.getName() if tfunc else "?"
                    print("  0x{:X}: {} {} -> 0x{:X} ({})".format(
                        insn.getAddress().getOffset(), mn, str(insn)[:40], target, tname))

    decomp.dispose()
    print("\nDone.")
