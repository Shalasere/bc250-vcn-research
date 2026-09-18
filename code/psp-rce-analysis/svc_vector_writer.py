#!/usr/bin/env python3
"""Find WHO writes the SVC vector branch to 0x108.

Known facts:
- Literal pool [0x0384] = 0x100, [0x9280] = 0x100
- FUN_000035A0 makes pages 0x0000-0x80000 R/W before ABL4 launch
- ABL4 has 96 SVCs — they MUST work
- SVC handler at 0x198 exists but Ghidra didn't disassemble it

Strategy:
1. Find what references [0x0384] (literal pool containing VBAR=0x100)
2. Decompile FUN_0000022C and FUN_00000244 (early init, before MMU)
3. Search for the exact code pattern that writes to 0x108
4. Check if the real SVC handler at 0x198 is the same as FUN_000044CC
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

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

    # Part 1: What references literal pool at 0x0384 (= 0x100)?
    print("=" * 70)
    print("PART 1: References to literal pool entries containing 0x100")
    print("=" * 70)

    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()

    for pool_off in [0x0384, 0x9280]:
        val = struct.unpack_from("<I", pspbl, pool_off)[0]
        print("  [0x{:04X}] = 0x{:08X}".format(pool_off, val))

        refs = ref_mgr.getReferencesTo(space.getAddress(pool_off))
        ref_list = list(refs)
        if ref_list:
            for ref in ref_list:
                func = func_mgr.getFunctionContaining(ref.getFromAddress())
                fn = func.getName() if func else "?"
                fe = func.getEntryPoint().getOffset() if func else 0
                print("    ref from 0x{:04X} in {} (0x{:04X})".format(
                    ref.getFromAddress().getOffset(), fn, fe))
        else:
            print("    NO refs — checking nearby instructions")
            for check_off in range(max(0, pool_off - 0x400), pool_off, 4):
                inst = program.getListing().getInstructionAt(space.getAddress(check_off))
                if inst:
                    istr = inst.toString()
                    if '0x{:04x}'.format(pool_off) in istr.lower() or \
                       '0x{:03x}'.format(pool_off) in istr.lower():
                        print("    Possible ref at 0x{:04X}: {}".format(check_off, istr))

    # Part 2: Decompile FUN_0000022C (early init #1, before MMU)
    print("\n" + "=" * 70)
    print("PART 2: FUN_0000022C — early init #1 (called at 0x050, before MMU)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x022C))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x022C))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            if '0x108' in c or '0x198' in c:
                print("  *** Contains vector table references! ***")
            print(c)

    # Part 3: Decompile FUN_00000244 (early init #2)
    print("\n" + "=" * 70)
    print("PART 3: FUN_00000244 — early init #2 (called at 0x054)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x0244))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x0244))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            if '0x108' in c or '0x198' in c:
                print("  *** Contains vector table references! ***")
            print(c)

    # Part 4: Decompile the function that contains [0x0384]
    print("\n" + "=" * 70)
    print("PART 4: Function containing literal pool at 0x0384")
    print("=" * 70)

    func = func_mgr.getFunctionContaining(space.getAddress(0x0384))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)
    else:
        print("  No function contains 0x0384 — it's in data/pool area")

    # Part 5: Check what function 0x0384 is near — decode instructions around it
    print("\n" + "=" * 70)
    print("PART 5: Instructions near 0x0384")
    print("=" * 70)
    for off in range(0x360, 0x3A0, 4):
        inst = program.getListing().getInstructionAt(space.getAddress(off))
        if inst:
            print("    0x{:03X}: {} {}".format(off, inst.getMnemonicString(), inst.toString()))
        else:
            val = struct.unpack_from("<I", pspbl, off)[0]
            print("    0x{:03X}: (data) 0x{:08X}".format(off, val))

    # Part 6: Manual search — find STR to 0x108 by searching for LDR+STR patterns
    # that use 0x100 as base and 8 as offset
    print("\n" + "=" * 70)
    print("PART 6: Search for ALL functions writing to VBAR area (0x100-0x120)")
    print("=" * 70)

    func_iter = func_mgr.getFunctions(True)
    vbar_writers = []
    while func_iter.hasNext():
        f = func_iter.next()
        result = decomp.decompileFunction(f, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Look for writes to VBAR area addresses
        for target in ['0x100', '0x104', '0x108', '0x10c', '0x110',
                       '0x114', '0x118', '0x11c', '0x120',
                       'DAT_00000108', 'DAT_00000100']:
            if target in c.lower():
                faddr = f.getEntryPoint().getOffset()
                vbar_writers.append((faddr, f.getName(), target))
                break

    if vbar_writers:
        print("  Functions referencing VBAR area:")
        for faddr, fname, target in vbar_writers:
            print("    0x{:04X} {}: {}".format(faddr, fname, target))
            # Decompile and show context around the reference
            func = func_mgr.getFunctionAt(space.getAddress(faddr))
            if func:
                result = decomp.decompileFunction(func, 600, flat.getMonitor())
                if result.decompileCompleted():
                    c = result.getDecompiledFunction().getC()
                    idx = c.lower().find(target.lower())
                    if idx >= 0:
                        start = max(0, c.rfind('\n', 0, max(0, idx - 200)))
                        end = min(len(c), c.find('\n', min(len(c), idx + 200)))
                        print("      Context: " + c[start:end].strip()[:300])
    else:
        print("  NO functions reference VBAR area (0x100-0x120)!")

    # Part 7: Check what's at 0x9280 — the other literal pool with 0x100
    print("\n" + "=" * 70)
    print("PART 7: Literal pool at 0x9280 context")
    print("=" * 70)

    func = func_mgr.getFunctionContaining(space.getAddress(0x9280))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  0x9280 is in {} (0x{:04X}, {} bytes)".format(
            func.getName(), entry, fsize))
    else:
        print("  0x9280 is NOT in a function body")

    # Part 8: Check the entry point flow (0x0000-0x0050) through Ghidra
    print("\n" + "=" * 70)
    print("PART 8: Entry point disassembly (0x0000-0x0100)")
    print("=" * 70)

    for off in range(0x0000, 0x0100, 4):
        inst = program.getListing().getInstructionAt(space.getAddress(off))
        if inst:
            print("    0x{:03X}: {} {}".format(off, inst.getMnemonicString(),
                  inst.toString()))
        else:
            val = struct.unpack_from("<I", pspbl, off)[0]
            # Only show if it doesn't look like code
            if off >= 0x100:
                print("    0x{:03X}: (vector) 0x{:08X}".format(off, val))

    # Part 9: Search for 0xE92D5FFF pattern (PUSH {R0-R12,LR}) which is at 0x198
    # If this same pattern is used elsewhere as a DATA value (to be copied to 0x198)
    print("\n" + "=" * 70)
    print("PART 9: Search for runtime-constructed SVC handler")
    print("=" * 70)

    # The SVC handler at 0x198 starts with PUSH {R0-R12,LR} = 0xE92D5FFF
    # Check if 0x198 is inside any function's body
    func_198 = func_mgr.getFunctionContaining(space.getAddress(0x198))
    if func_198:
        print("  0x198 is in {} (0x{:04X})".format(
            func_198.getName(), func_198.getEntryPoint().getOffset()))
    else:
        print("  0x198 is NOT in any function body")

    # Check if 0x134 contains the SVC dispatch (the decompiler said FUN_00000134)
    func_134 = func_mgr.getFunctionAt(space.getAddress(0x134))
    if func_134:
        entry = func_134.getEntryPoint().getOffset()
        fsize = func_134.getBody().getNumAddresses()
        print("  FUN_00000134 at 0x{:04X} ({} bytes)".format(entry, fsize))

        result = decomp.decompileFunction(func_134, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)

    # Final check: find the SVC #0 literal pool (from earlier: [0x1CC] has 0x5279)
    print("\n  Decode potential SVC dispatch literals:")
    for off in [0x1B8, 0x1BC, 0x1C8, 0x1CC, 0x1D0, 0x1D4, 0x1E0, 0x1E4]:
        if off + 3 < len(pspbl):
            val = struct.unpack_from("<I", pspbl, off)[0]
            # Check if this might be an LDR PC literal load
            if (val & 0x0FFF0000) == 0x059F0000:
                imm = val & 0xFFF
                pool_addr = off + 8 + imm
                if pool_addr + 3 < len(pspbl):
                    pool_val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                    print("    [0x{:03X}] LDR R{}, [PC, #0x{:X}] → [0x{:03X}] = 0x{:08X}".format(
                        off, (val >> 12) & 0xF, imm, pool_addr, pool_val))

    decomp.dispose()

print("\nDone.")
