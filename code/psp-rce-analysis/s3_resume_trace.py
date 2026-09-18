#!/usr/bin/env python3
"""Trace the S3 resume path — CVE-2023-31316's original vector.

FUN_00000300 case 2 (S3 resume):
  FUN_000082e6(2)
  FUN_00000328(1, uVar4)

Key questions:
1. What is uVar4? Where does the resume context come from?
2. Does FUN_000018E4 handle saved context restoration?
3. If the S3 save buffer contains crafted data (e.g., from a previous
   controlled boot), does the resume path load it into the context
   structure without revalidation?
4. Could a corrupted S3 save buffer put an attacker-chosen value at
   context+0x660?

Also: trace the alternative copy paths (FUN_000062BE, FUN_00001F40)
that were never investigated.
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

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # =====================================================================
    # PART 1: FUN_000018E4 — S3 resume handler
    # =====================================================================
    print("=" * 70)
    print("PART 1: FUN_000018E4 (S3 resume handler)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x18E4))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x18E4))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:8000] if len(c) > 8000 else c)

            # Check for references to context-related addresses
            for keyword in ['0x5d7ac', '0x5de0c', '0x660', '0x4f000', 'memcpy',
                           'FUN_00000458', '0x40100', '3fc8']:
                if keyword.lower() in c.lower():
                    print("  ** Contains reference to '{}' **".format(keyword))
    else:
        print("  Function not found at 0x18E4")

    # =====================================================================
    # PART 2: FUN_000062BE — alternative copy path
    # =====================================================================
    print("\n" + "=" * 70)
    print("PART 2: FUN_000062BE (alternative copy path)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x62BE))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x62BE))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:8000] if len(c) > 8000 else c)
    else:
        print("  Function not found at 0x62BE")

    # =====================================================================
    # PART 3: FUN_00001F40 — alternative copy
    # =====================================================================
    print("\n" + "=" * 70)
    print("PART 3: FUN_00001F40 (alternative copy)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x1F40))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x1F40))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:8000] if len(c) > 8000 else c)
    else:
        print("  Function not found at 0x1F40")

    # =====================================================================
    # PART 4: FUN_00000328 — the ABL4 launch function
    # =====================================================================
    print("\n" + "=" * 70)
    print("PART 4: FUN_00000328 (ABL4 launch function)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x328))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x328))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:6000] if len(c) > 6000 else c)
    else:
        print("  Function not found at 0x328")

    # =====================================================================
    # PART 5: Where does the S3 resume context come from?
    # Check the complete FUN_00000300 decompilation for the S3 path
    # =====================================================================
    print("\n" + "=" * 70)
    print("PART 5: FUN_00000300 — S3 resume path (case 2)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x300))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x300))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            lines = c.split('\n')

            # Find the S3 resume section (case 2)
            # Look for FUN_000018E4 call or the case 2 branch
            for i, line in enumerate(lines):
                if '18e4' in line.lower() or '0x328' in line.lower() or 'uVar4' in line.lower():
                    start_ctx = max(0, i - 3)
                    end_ctx = min(len(lines), i + 3)
                    for j in range(start_ctx, end_ctx):
                        marker = " <<<" if j == i else ""
                        print("  {:4d}: {}{}".format(j, lines[j], marker))
                    print()

    # =====================================================================
    # PART 6: Check what functions reference the context base 0x5D7AC
    # and what functions reference DAT_00003fc0 (base pointer)
    # =====================================================================
    print("\n" + "=" * 70)
    print("PART 6: Who references DAT_00003fc0/DAT_00003fc8?")
    print("=" * 70)

    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()

    # DAT_00003fc0 = base pointer used to compute context address
    # DAT_00003fc8 = 0x40100
    val_3fc0 = struct.unpack_from("<I", pspbl, 0x3FC0)[0]
    val_3fc4 = struct.unpack_from("<I", pspbl, 0x3FC4)[0]
    val_3fc8 = struct.unpack_from("<I", pspbl, 0x3FC8)[0]
    val_3fcc = struct.unpack_from("<I", pspbl, 0x3FCC)[0]
    print("  [0x3FC0] = 0x{:08X}".format(val_3fc0))
    print("  [0x3FC4] = 0x{:08X}".format(val_3fc4))
    print("  [0x3FC8] = 0x{:08X}".format(val_3fc8))
    print("  [0x3FCC] = 0x{:08X}".format(val_3fcc))

    # Find Thumb LDR instructions that target 0x3FC0-0x3FCC
    print("\n  Instructions loading from 0x3FC0-0x3FCC:")
    for pool_addr in range(0x3FC0, 0x3FD0, 4):
        for off in range(0, len(pspbl) - 1, 2):
            hw = struct.unpack_from("<H", pspbl, off)[0]
            if (hw & 0xF800) == 0x4800:
                imm = (hw & 0xFF) * 4
                pool = (off & ~3) + 4 + imm
                if pool == pool_addr:
                    rd = (hw >> 8) & 7
                    fn = func_mgr.getFunctionContaining(space.getAddress(off))
                    fn_name = fn.getName() if fn else "?"
                    print("    0x{:04X} in {}: LDR R{}, [PC, #0x{:X}] -> [0x{:04X}]".format(
                        off, fn_name, rd, imm, pool_addr))

    # =====================================================================
    # PART 7: Check FUN_0000151C — called in boot with error checking
    # (from FUN_00000300's callee list, might be APCB-related)
    # =====================================================================
    print("\n" + "=" * 70)
    print("PART 7: FUN_0000151C (called during boot)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x151C))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x151C))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:6000] if len(c) > 6000 else c)

    decomp.dispose()

print("\nDone.")
