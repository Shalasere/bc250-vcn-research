#!/usr/bin/env python3
"""Find ALL PSP_BL functions that write to the context region (0x5D7AC-0x5E400).

Key targets:
1. FUN_000044CC — writes to 0xB814 (source for config+0x660)
2. FUN_000075A4 — builds config buffer at 0x4F000 (writes to 0x4F660)
3. Any function that writes to 0x5D000-0x5E000 region
4. FUN_000066A0 — APCB group dispatcher (handles group IDs 0x1701-0x1707)
5. FUN_00000300 — SVC dispatcher (main entry for APCB processing)

Also: Check if 0x60FE8 (dispatch default) IS a real function in ABL4.
And: Find what reads the config buffer (0x4F000) after PSP_BL populates it.
"""
import os, re, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"

# First: check what's at ABL4 offset 0x7B4 (= VA 0x60FE8)
print("=" * 70)
print("PART 0: ABL4 function at 0x60FE8 (dispatch default target)")
print("=" * 70)

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

# 0x60FE8 - 0x60834 = 0x7B4
offset = 0x7B4
# Read 32 bytes of code at this offset
code_bytes = abl4[offset:offset+32]
print("  ABL4 file offset 0x{:04X} (VA 0x{:05X}):".format(offset, 0x60834 + offset))
print("  Raw bytes: {}".format(code_bytes.hex()))

# Check if this looks like a Thumb function prologue
# PUSH {r4-r7, lr} = B5F0 or similar
if len(code_bytes) >= 2:
    hw = struct.unpack_from("<H", code_bytes, 0)[0]
    print("  First halfword: 0x{:04X}".format(hw))
    if (hw & 0xFF00) == 0xB500:
        print("  *** PUSH instruction — valid Thumb function prologue ***")
    elif (hw & 0xFF00) == 0xB400:
        print("  *** PUSH (low regs) instruction ***")

# Now PSP_BL Ghidra analysis
print("\n" + "=" * 70)
print("PART 1: PSP_BL — ALL references to context region (0x5D000-0x5E400)")
print("=" * 70)

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

    # Scan ALL literal pool entries for addresses in 0x5D000-0x5E400
    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()

    print("\n  Literal pool entries pointing to context region:")
    for i in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, i)[0]
        if 0x5D000 <= val <= 0x5E400:
            # Check if this offset is referenced (i.e., is a literal pool)
            refs = ref_mgr.getReferencesTo(space.getAddress(i))
            ref_list = list(refs)
            if ref_list:
                for ref in ref_list:
                    func = func_mgr.getFunctionContaining(ref.getFromAddress())
                    fname = func.getName() if func else "unknown"
                    print("    [0x{:04X}] = 0x{:05X} → ref from 0x{:04X} in {} ({})".format(
                        i, val, ref.getFromAddress().getOffset(), fname,
                        ref.getReferenceType().toString()))
            else:
                # Check if it's within a function's body
                func = func_mgr.getFunctionContaining(space.getAddress(i))
                if func:
                    fname = func.getName()
                else:
                    fname = "no_func"
                print("    [0x{:04X}] = 0x{:05X} (in {}, no direct ref)".format(
                    i, val, fname))

    # Part 2: Decompile FUN_000044CC (writes to 0xB814)
    print("\n" + "=" * 70)
    print("PART 2: FUN_000044CC — writes to 0xB814 (config value source)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x44CC))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:6000] if len(c) > 6000 else c)

        # Find callers
        refs = ref_mgr.getReferencesTo(space.getAddress(entry))
        callers = [(r.getFromAddress().getOffset(), r.getReferenceType().toString())
                   for r in refs if r.getReferenceType().isCall()]
        if callers:
            print("\n  Callers of FUN_{:04X}:".format(entry))
            for ca, ct in callers:
                cf = func_mgr.getFunctionContaining(space.getAddress(ca))
                cfn = cf.getName() if cf else "unknown"
                print("    0x{:04X} in {} ({})".format(ca, cfn, ct))

    # Part 3: Decompile FUN_000066A0 (APCB group dispatcher)
    print("\n" + "=" * 70)
    print("PART 3: FUN_000066A0 — APCB group dispatcher")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x66A0))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x66A0))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Look for group ID handling (0x1702, 0x1705)
            if '0x1702' in c or '0x1705' in c:
                print("  *** Contains group IDs 0x1702 or 0x1705 ***")
            if '0x1701' in c:
                print("  Contains group ID 0x1701")
            print(c[:8000] if len(c) > 8000 else c)

    # Part 4: Trace FUN_00000300 (SVC main dispatcher)
    print("\n" + "=" * 70)
    print("PART 4: FUN_00000300 — SVC dispatcher (abbreviated)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x300))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x300))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Look for context structure references
            context_refs = re.findall(r'0x5[dD][0-9a-fA-F]{3}', c)
            if context_refs:
                print("  Context refs in SVC handler: {}".format(set(context_refs)))

            # Look for 0x1C case (the SVC that ABL4 calls)
            idx = c.find('0x1c')
            if idx >= 0:
                start = max(0, c.rfind('\n', 0, idx) - 100)
                end = min(len(c), idx + 500)
                print("  Around 0x1C case:")
                print(c[start:end])

    # Part 5: Find ALL functions that reference SRAM addresses near context
    print("\n" + "=" * 70)
    print("PART 5: PSP_BL functions with writes to 0x5D000-0x5F000 region")
    print("=" * 70)

    func_iter = func_mgr.getFunctions(True)
    context_writers = []
    while func_iter.hasNext():
        f = func_iter.next()
        result = decomp.decompileFunction(f, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Look for writes to 0x5Dxxx or 0x5Exxx
        writes = re.findall(r'_DAT_0005[dDeE][0-9a-fA-F]{3}', c)
        if writes:
            faddr = f.getEntryPoint().getOffset()
            context_writers.append((faddr, f.getName(), list(set(writes))))

        # Also look for pointer arithmetic leading to context writes
        # Pattern: *(param + 0x660) or *(base + large_offset)
        if '+\s*0x660' in c or '+ 0x660' in c:
            faddr = f.getEntryPoint().getOffset()
            context_writers.append((faddr, f.getName(), ["+0x660 OFFSET"]))

    if context_writers:
        print("  Functions writing to context region:")
        for faddr, fname, writes in context_writers:
            print("    0x{:04X} {}: {}".format(faddr, fname, writes))
    else:
        print("  NO functions write directly to 0x5D000-0x5F000 region!")

    # Part 6: Check what function contains address 0x4D0C (the other ref to 0xB814)
    # 0x4D0C is a WRITE to 0xB814 in FUN_000044CC
    print("\n" + "=" * 70)
    print("PART 6: Trace 0xB814 write chain")
    print("=" * 70)

    # Check all writes to SRAM addresses referenced by FUN_000075A4's literal pools
    # These are the addresses that feed into the config buffer
    source_addrs = [0xB808, 0xB814, 0xB82C, 0x9B60, 0x9A28, 0x93EC]
    for sa in source_addrs:
        target = space.getAddress(sa)
        refs = ref_mgr.getReferencesTo(target)
        writes = []
        reads = []
        for ref in refs:
            rt = ref.getReferenceType().toString()
            fa = ref.getFromAddress().getOffset()
            func = func_mgr.getFunctionContaining(ref.getFromAddress())
            fn = func.getName() if func else "?"
            if 'WRITE' in rt:
                writes.append((fa, fn))
            elif 'READ' in rt:
                reads.append((fa, fn))
        if writes or reads:
            print("  0x{:04X}: {} writes, {} reads".format(sa, len(writes), len(reads)))
            for wa, wn in writes:
                print("    WRITE from 0x{:04X} in {}".format(wa, wn))
            for ra, rn in reads:
                print("    READ  from 0x{:04X} in {}".format(ra, rn))

    decomp.dispose()

# Part 7: Check ABL4 — what function is at 0x60FE8?
print("\n" + "=" * 70)
print("PART 7: ABL4 — function at 0x60FE8 (dispatch default)")
print("=" * 70)

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

    func = func_mgr.getFunctionAt(space.getAddress(0x60FE8))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x60FE8))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)
    else:
        print("  No function at 0x60FE8!")
        # Check what instruction is there
        inst = program.getListing().getInstructionAt(space.getAddress(0x60FE8))
        if inst:
            print("  Instruction: {} {}".format(inst.getMnemonicString(), inst.toString()))
        else:
            print("  No instruction at 0x60FE8")
            # Try 0x60FE9 (Thumb entry)
            inst = program.getListing().getInstructionAt(space.getAddress(0x60FE9))
            if inst:
                print("  Instruction at 0x60FE9: {} {}".format(inst.getMnemonicString(), inst.toString()))

    decomp.dispose()

print("\nDone.")
