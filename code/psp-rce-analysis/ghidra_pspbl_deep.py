#!/usr/bin/env python3
"""Deep PSP_BL analysis:
1. What's at file offset +0x0BB8? Code or data?
2. Decompile FUN_000044CC (2728 bytes, largest) and FUN_00000300 (1000 bytes)
3. Find ALL functions between offsets 0x0900-0x0C00 (near the literal pools)
4. Search for STR instructions that could write to context+0x660
5. Decompile FUN_00000850 (called with arg 0x62 from FUN_00005850 — SVC-like?)
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

print("Starting pyghidra...")
pyghidra.start(install_dir=GHIDRA_DIR)

with pyghidra.open_program(
    PSPBL_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_pspbl_v1", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()
    listing = program.getListing()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # Step 1: What does Ghidra think is at 0x0BB8?
    print("=== Ghidra view at offset 0x0B00 - 0x0C00 ===")
    for va in range(0x0B00, 0x0C10, 4):
        addr = space.getAddress(va)
        func = func_mgr.getFunctionAt(addr)
        func_containing = func_mgr.getFunctionContaining(addr)
        insn = listing.getInstructionAt(addr)
        data = listing.getDataAt(addr)

        with open(PSPBL_PATH, "rb") as f:
            f.seek(va)
            raw = struct.unpack("<I", f.read(4))[0]

        label = ""
        if func:
            label = "FUNC_ENTRY: {}".format(func.getName())
        elif func_containing:
            label = "in {}".format(func_containing.getName())
        elif insn:
            label = "INSN: {} {}".format(insn.getMnemonicString(), str(insn))
        elif data:
            label = "DATA: {}".format(str(data))
        else:
            label = "UNDEFINED"

        marker = ""
        if va == 0x0BB8:
            marker = " <<<< 0x5D7AC (context base)"
        elif va == 0x0BC8:
            marker = " <<<< 0x5D5A4"

        print("  0x{:04X}: 0x{:08X}  {}{}".format(va, raw, label, marker))

    # Step 2: List ALL functions between 0x0800 and 0x0D00
    print("\n=== Functions in range 0x0800-0x0D00 ===")
    fi = func_mgr.getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        entry = f.getEntryPoint().getOffset()
        if 0x0800 <= entry <= 0x0D00:
            size = f.getBody().getNumAddresses()
            print("  0x{:04X}: {} bytes  {}".format(entry, size, f.getName()))

    # Step 3: Decompile the function that CONTAINS 0x0BB8 (if any)
    print("\n=== Function containing 0x0BB8 ===")
    addr = space.getAddress(0x0BB8)
    func = func_mgr.getFunctionContaining(addr)
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} (0x{:X}, {} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:6000] if len(c) > 6000 else c)
    else:
        print("  NO FUNCTION contains 0x0BB8 — it's in a data/undefined region")
        # Check if there's ARM-mode code here (not Thumb)
        with open(PSPBL_PATH, "rb") as f:
            f.seek(0x0B90)
            chunk = f.read(0x50)
        print("  Raw bytes at 0x0B90-0x0BE0:")
        for i in range(0, len(chunk), 4):
            val = struct.unpack_from("<I", chunk, i)[0]
            print("    +0x{:04X}: 0x{:08X}".format(0x0B90 + i, val))

    # Step 4: Decompile FUN_000044CC (largest, 2728 bytes)
    print("\n" + "=" * 70)
    print("=== FUN_000044CC (2728 bytes, largest function) ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if func:
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:8000] if len(c) > 8000 else c)
            if len(c) > 8000:
                print("\n... [truncated, {} total]".format(len(c)))
                # Search for key patterns
                for pat in ['0x5d', '0x660', '0x5de', 'context', 'apcb', 'type_size',
                            'saved', 'len', 'overflow', 'copy', 'param_1 + 0x']:
                    for m in re.finditer(pat, c, re.IGNORECASE):
                        ctx = c[max(0,m.start()-80):min(len(c),m.end()+120)].replace('\n', ' ')
                        print("\n  [{}]:".format(pat))
                        print("  ...{}...".format(ctx[:200]))
                        break  # just first match
    else:
        print("  NOT FOUND")

    # Step 5: Decompile FUN_00000300 (1000 bytes, second largest)
    print("\n" + "=" * 70)
    print("=== FUN_00000300 (1000 bytes) ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x0300))
    if func:
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:8000] if len(c) > 8000 else c)

    # Step 6: Decompile FUN_00000850 (SVC-like function called from boot flow)
    print("\n" + "=" * 70)
    print("=== FUN_00000850 ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x0850))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # Step 7: Search ALL decompiled functions for context-related patterns
    # looking for any function that computes 0x5D7AC or accesses offsets
    # that would map to the 0x5D000 SRAM range
    print("\n" + "=" * 70)
    print("=== Searching ALL PSP_BL functions for SRAM range patterns ===")

    fi = func_mgr.getFunctions(True)
    all_funcs = []
    while fi.hasNext():
        all_funcs.append(fi.next())

    sram_hits = {}
    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Search for SRAM addresses
        for m in re.finditer(r'0x0{0,2}5[cde][0-9a-fA-F]{3}', c):
            val = int(m.group(), 16)
            if 0x5C000 <= val <= 0x5F000:
                if entry not in sram_hits:
                    sram_hits[entry] = []
                ctx = c[max(0,m.start()-40):min(len(c),m.end()+40)].replace('\n',' ')
                sram_hits[entry].append((val, ctx.strip()))

    for entry in sorted(sram_hits.keys()):
        fname = func_mgr.getFunctionAt(space.getAddress(entry))
        name = fname.getName() if fname else "?"
        hits = sram_hits[entry]
        print("\n  FUN_{:08X} ({}):".format(entry, name))
        for val, ctx in hits[:5]:
            print("    0x{:X}: ...{}...".format(val, ctx[:120]))

    # Step 8: Check the function at 0x0944 (Gate 3, hardware fingerprint)
    # This function is known to be important for PSP_BL boot
    print("\n" + "=" * 70)
    print("=== FUN_00000944 (Gate 3, hardware fingerprint) ===")
    func = func_mgr.getFunctionAt(space.getAddress(0x0944))
    if func:
        size = func.getBody().getNumAddresses()
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:3000] if len(c) > 3000 else c)

    decomp.dispose()
    print("\nDone.")
