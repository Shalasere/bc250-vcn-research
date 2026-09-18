#!/usr/bin/env python3
"""Extract the full SVC handler decompilation and find LAB_00004afc
(the APCB operation handler for SVC case 0x61)."""
import os, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
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

    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    result = decomp.decompileFunction(func, 600, flat.getMonitor())
    c = result.getDecompiledFunction().getC()

    # Find LAB_00004afc and surrounding context
    idx = c.find('LAB_00004afc')
    if idx >= 0:
        print("=== LAB_00004afc (APCB operation handler) ===")
        # Show 3000 chars starting from the label
        end = min(len(c), idx + 3000)
        print(c[idx:end])
    else:
        print("LAB_00004afc not found! Searching for '4afc'...")
        for m in re.finditer(r'4af', c):
            print("  Found at char {}: ...{}...".format(m.start(), c[m.start():m.start()+100]))

    # Also find all LAB_ labels to understand control flow
    print("\n=== ALL labels in SVC handler ===")
    labels = set(re.findall(r'LAB_0000[0-9a-f]+', c))
    for label in sorted(labels):
        count = c.count(label)
        idx = c.find(label)
        # Get 100 chars of context at label definition (preceded by newline)
        def_idx = c.find(label + ':')
        if def_idx >= 0:
            ctx = c[def_idx:min(len(c), def_idx + 200)].replace('\n', ' ').strip()
            print("  {} (refs: {}, def): {}".format(label, count, ctx[:150]))

    # Show the section from LAB_00004afc to the next major label
    print("\n=== FULL APCB handler block ===")
    def_idx = c.find('LAB_00004afc:')
    if def_idx >= 0:
        # Find the next LAB_ after this block
        next_labels = list(re.finditer(r'\nLAB_0000[0-9a-f]+:', c[def_idx+13:]))
        if next_labels:
            end = def_idx + 13 + next_labels[0].start()
        else:
            end = min(len(c), def_idx + 5000)
        print(c[def_idx:end])

    # Also decompile secondary targets
    targets = [
        (0x3D6C, "FUN_00003D6C (maps 0x5D004)"),
        (0x5F1C, "FUN_00005F1C (mapper from boot)"),
        (0x82E6, "FUN_000082E6 (pre-ABL launch)"),
    ]
    for va, desc in targets:
        print("\n" + "=" * 70)
        print(desc)
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if func:
            size = func.getBody().getNumAddresses()
            result = decomp.decompileFunction(func, 180, flat.getMonitor())
            if result.decompileCompleted():
                c2 = result.getDecompiledFunction().getC()
                print(c2[:4000] if len(c2) > 4000 else c2)

    decomp.dispose()
    print("\nDone.")
