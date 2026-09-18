#!/usr/bin/env python3
"""Enumerate ALL functions in PSP_BL with stack frames > 0x40 bytes.
Decompile each and check for buffer+copy patterns.

Also: read DAT_00000BEC to find context/APCB addresses.
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# Read key literal pool values
print("=" * 70)
print("KEY LITERAL POOL VALUES (SRAM addresses used by PSP_BL)")
print("=" * 70)
for lp_off in [0x0BB8, 0x0BBC, 0x0BC0, 0x0BC4, 0x0BC8, 0x0BCC, 0x0BD0,
               0x0BD4, 0x0BD8, 0x0BDC, 0x0BE0, 0x0BE4, 0x0BE8, 0x0BEC,
               0x0BF0, 0x0BF4, 0x0BF8, 0x0BFC, 0x0C00]:
    if lp_off < len(pspbl) - 3:
        val = struct.unpack_from("<I", pspbl, lp_off)[0]
        print("  0x{:04X}: 0x{:08X}".format(lp_off, val))

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

    # Enumerate ALL functions
    print("\n" + "=" * 70)
    print("ALL FUNCTIONS IN PSP_BL")
    print("=" * 70)
    all_funcs = []
    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        func = func_iter.next()
        entry = func.getEntryPoint().getOffset()
        if entry < 0x9A00:  # PSP_BL code region
            fsize = func.getBody().getNumAddresses()
            all_funcs.append((entry, fsize, func))

    all_funcs.sort(key=lambda x: x[0])
    print("  Total functions: {}".format(len(all_funcs)))
    for entry, fsize, func in all_funcs:
        print("  0x{:04X}: {} ({} bytes)".format(entry, func.getName(), fsize))

    # Decompile ALL functions and search for stack buffers + copy operations
    print("\n" + "=" * 70)
    print("FUNCTIONS WITH STACK BUFFERS (searching all)")
    print("=" * 70)

    copy_funcs_re = re.compile(
        r'FUN_0000(?:823c|8150|04e0|0458|1c18|071ac|74c8|57c4|8488)\(', re.I)

    vuln_funcs = []
    for entry, fsize, func in all_funcs:
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Search for stack buffers
        buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
        if not buffers:
            continue

        # This function has stack buffers!
        max_buf = max(int(s) for _, s in buffers)

        # Check for copy operations
        has_copy = bool(copy_funcs_re.search(c))

        # Check for any function call with variable args
        # (calls that might write to the stack buffer)
        all_calls = re.findall(r'(FUN_[0-9a-f]+)\([^)]*\)', c, re.I)

        status = ""
        if has_copy:
            status = "*** HAS COPY ***"
            vuln_funcs.append((entry, func.getName(), buffers, c))

        print("\n  0x{:04X}: {} ({} bytes) {}".format(
            entry, func.getName(), fsize, status))
        for name, size in buffers:
            print("    STACK BUFFER: {} [{}]".format(name, size))
        if has_copy:
            # Show the copy calls
            for m in copy_funcs_re.finditer(c):
                start = max(0, m.start() - 100)
                end = min(len(c), m.end() + 200)
                print("    COPY CONTEXT: ...{}...".format(c[start:end]))

    print("\n" + "=" * 70)
    print("SUMMARY: {} functions with BOTH stack buffers AND copy operations".format(
        len(vuln_funcs)))
    print("=" * 70)
    for entry, fname, buffers, c in vuln_funcs:
        print("\n  0x{:04X}: {}".format(entry, fname))
        for name, size in buffers:
            print("    BUFFER: {} [{}]".format(name, size))
        # Full decompile for each
        print("    FULL DECOMPILE ({} chars):".format(len(c)))
        if len(c) <= 3000:
            print(c)
        else:
            print(c[:3000])
            print("    ... ({} more)".format(len(c) - 3000))

    decomp.dispose()

print("\nDone.")
