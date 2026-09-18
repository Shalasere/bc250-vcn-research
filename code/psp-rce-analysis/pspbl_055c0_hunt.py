#!/usr/bin/env python3
"""Decompile the remaining APCB handler functions called from FUN_000044CC.

Critical targets:
1. FUN_000055C0 — general APCB token handler (case 0x2D/0x32 for non-0x60/0x63/0x68)
2. FUN_00004400 — APCB handler for types 0x60/0x63/0x68 (probably wraps FUN_00004412)
3. FUN_00005510 — case 0x34 handler
4. FUN_00005F9C — case 0x43 handler
5. FUN_00005030 — case 0xC handler
6. FUN_00007F20 — case 0x63/0xA0 handler (receives &local_40 stack pointer)
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

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

    targets = [
        (0x55C0, "FUN_000055C0 — general APCB token handler (CRITICAL)"),
        (0x4400, "FUN_00004400 — APCB 0x60/0x63/0x68 handler"),
        (0x5510, "FUN_00005510 — case 0x34 handler"),
        (0x5F9C, "FUN_00005F9C — case 0x43 handler"),
        (0x5030, "FUN_00005030 — case 0xC handler"),
        (0x7F20, "FUN_00007F20 — case 0x63/0xA0 handler"),
        (0x5AB4, "FUN_00005AB4 — case 0x27 handler"),
        (0x2DA4, "FUN_00002DA4 — case 0x33 handler"),
    ]

    for addr, desc in targets:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if func:
            entry = func.getEntryPoint().getOffset()
            fsize = func.getBody().getNumAddresses()
            print("\n" + "=" * 70)
            print("{} at 0x{:04X} ({} bytes)".format(desc, entry, fsize))
            print("=" * 70)
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))

                # Check for stack buffers
                buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
                if buffers:
                    print("  !!! STACK BUFFERS:")
                    for name, size in buffers:
                        print("    {} [{}]".format(name, size))

                # Check for copy calls
                for kw in ['FUN_0000823c', 'FUN_00008150', 'FUN_000004e0',
                           'FUN_00000458', 'FUN_00001c18', 'FUN_000057c4',
                           'FUN_000074c8', 'FUN_00004412', 'FUN_000082b0']:
                    matches = re.findall(kw + r'\([^)]+\)', c, re.I)
                    if matches:
                        print("  CALLS {}:".format(kw))
                        for m in matches:
                            print("    {}".format(m))

                if len(c) <= 5000:
                    print(c)
                else:
                    print(c[:5000])
                    print("\n  ... ({} more chars)".format(len(c) - 5000))
        else:
            print("\n  No function at 0x{:04X}".format(addr))

    decomp.dispose()

print("\nDone.")
