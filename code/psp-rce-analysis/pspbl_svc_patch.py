#!/usr/bin/env python3
"""Check if PSP_BL patches the SVC vector at runtime by modifying the
L2 page table at 0x4DC00.

Three functions reference 0x4DC00:
- FUN_000035A0 (from 0x35A4)
- FUN_0000373C (from 0x3746)
- FUN_00005A00 (from 0x5A02)

If any of these temporarily makes the code region writable, writes a
branch instruction to 0x108 (SVC vector), and restores R/O... then
SVCs DO work at runtime.

Also: Decompile FUN_00005278 (SVC #0 handler) to understand what
SVC 0 does vs higher-numbered SVCs.
"""
import os, re, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

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

    targets = [
        (0x35A0, "FUN_000035A0 — L2 page table modifier #1"),
        (0x373C, "FUN_0000373C — L2 page table modifier #2"),
        (0x5A00, "FUN_00005A00 — L2 page table modifier #3"),
        (0x5278, "FUN_00005278 — SVC #0 handler"),
        (0x0134, "FUN_00000134 — Contains SVC dispatch at 0x198"),
        (0x30C4, "FUN_000030C4 — write_page_entry (per MMU agent)"),
    ]

    for addr, desc in targets:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if not func:
            print("\n  No function at 0x{:04X}".format(addr))
            continue

        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("\n" + "=" * 70)
        print("{} at 0x{:04X} ({} bytes)".format(desc, entry, fsize))
        print("=" * 70)

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if not result.decompileCompleted():
            print("  Decompile failed!")
            continue

        c = result.getDecompiledFunction().getC()

        # Check for page table modifications
        if '0x4dc00' in c.lower() or '4DC00' in c:
            print("  *** Contains L2 page table reference ***")
        if '0x108' in c:
            print("  *** Contains SVC vector address 0x108 ***")
        if '0x252' in c or '0x52' in c:
            print("  Contains page descriptor value")
        if 'TLBI' in c.upper() or 'tlb' in c.lower() or 'mcr' in c.lower():
            print("  Contains TLB/MCR operation")

        # Print decompilation
        print(c[:5000] if len(c) > 5000 else c)

    # Also: Check what's at the SVC dispatch location 0x198
    print("\n" + "=" * 70)
    print("RAW BYTES at 0x198-0x200 (SVC handler area)")
    print("=" * 70)

    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()

    for off in range(0x198, 0x200, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        # Decode as ARM instruction
        print("  [0x{:03X}] 0x{:08X}".format(off, val))

    # Check literal pool entries used by the SVC handler
    print("\n  Literal pool values for SVC handler:")
    for off in [0x1E8, 0x1EC, 0x1F0, 0x1F4, 0x1F8, 0x1FC]:
        if off < len(pspbl) - 3:
            val = struct.unpack_from("<I", pspbl, off)[0]
            print("  [0x{:03X}] = 0x{:08X}".format(off, val))

    # Decode the real SVC vector — what SHOULD be at 0x108
    # If PSP_BL patches it, it would write a branch instruction
    # LDR PC, [PC, #offset] to jump to 0x198
    # Let's compute: from 0x108, LDR PC, [PC, #X] where PC = 0x110
    # To load from pool at 0x1F0: offset = 0x1F0 - 0x110 = 0xE0
    # E59FF0E0 = LDR PC, [PC, #0xE0]
    print("\n  Expected SVC vector instruction: LDR PC, [PC, #0xE0] = 0xE59FF0E0")
    print("  Alternatively: B 0x198 from 0x108 = offset 0x90 - 8 = 0x88")
    print("  0xEA000022 = B +0x90 (from 0x108 to 0x198)")

    # Compute: ARM branch encoding: 0xEA000000 + (offset/4 - 2)
    # From 0x108 to 0x198: delta = 0x90 bytes = 0x24 words
    # Branch: 0xEA000000 + (0x24 - 2) = 0xEA000022
    branch_val = 0xEA000022
    print("  Branch encoding check: 0x{:08X}".format(branch_val))

    # Check if 0xEA000022 appears anywhere in PSP_BL (as a data value to write)
    needle = struct.pack("<I", branch_val)
    idx = 0
    while True:
        idx = pspbl.find(needle, idx)
        if idx < 0:
            break
        print("  Found 0xEA000022 at offset 0x{:04X}".format(idx))
        idx += 1

    # Also check for 0xE59FF0E0 (LDR PC, [PC, #0xE0])
    needle2 = struct.pack("<I", 0xE59FF0E0)
    idx = 0
    while True:
        idx = pspbl.find(needle2, idx)
        if idx < 0:
            break
        print("  Found 0xE59FF0E0 at offset 0x{:04X}".format(idx))
        idx += 1

    decomp.dispose()

print("\nDone.")
