#!/usr/bin/env python3
"""Deep overflow hunt — decompile remaining candidate functions and
search FUN_000044CC for hidden patterns.

FUN_00004412: bl 0x823C at 0x445E — param_1 could be stack from caller
FUN_000082B0: bl 0x823C at 0x82E0 — param_2 could be stack from caller
FUN_00005850: bl 0x823C at 0x5932/0x5956 — iVar3 could be stack
FUN_000044CC: 2728 bytes — search for stack overflow patterns

Also: FUN_00007160, FUN_000062BE (has 1C18 call)
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)

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
        (0x5279, "FUN_00005279 — ACTUAL SVC handler dispatch (from ARM exception LP@0x3BC)"),
        (0x4412, "FUN_00004412 — near SVC dispatcher, variable copy to param_1"),
        (0x82B0, "FUN_000082B0 — variable copy to param_2"),
        (0x5850, "FUN_00005850 — variable copy to iVar3"),
        (0x7160, "FUN_00007160 — variable copy to *DAT"),
        (0x62F8, "FUN_000062F8 — called from FUN_00007014"),
    ]

    for addr, desc in targets:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if func:
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            print("\n" + "=" * 70)
            print("{} at 0x{:04X} ({} bytes)".format(desc, entry, size))
            print("=" * 70)
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))
                if len(c) <= 4000:
                    print(c)
                else:
                    print(c[:4000])
                    print("\n  ... ({} more chars)".format(len(c) - 4000))

    # Now: callers of FUN_00004412 and FUN_000082B0
    print("\n" + "=" * 70)
    print("Callers of FUN_00004412")
    print("=" * 70)
    for off in range(0, len(pspbl) - 3, 2):
        insns = list(cs.disasm(pspbl[off:off+4], off))
        for insn in insns:
            if insn.mnemonic == 'bl' and '0x4412' in insn.op_str:
                func = func_mgr.getFunctionContaining(space.getAddress(off))
                fname = func.getName() if func else "???"
                faddr = func.getEntryPoint().getOffset() if func else 0
                print("  0x{:04X}: bl 0x4412 (in {} @ 0x{:04X})".format(off, fname, faddr))

    print("\nCallers of FUN_000082B0:")
    for off in range(0, len(pspbl) - 3, 2):
        insns = list(cs.disasm(pspbl[off:off+4], off))
        for insn in insns:
            if insn.mnemonic == 'bl' and '0x82b0' in insn.op_str:
                func = func_mgr.getFunctionContaining(space.getAddress(off))
                fname = func.getName() if func else "???"
                faddr = func.getEntryPoint().getOffset() if func else 0
                print("  0x{:04X}: bl 0x82B0 (in {} @ 0x{:04X})".format(off, fname, faddr))

    # FUN_000044CC: search the full decompile for buffer-copy patterns
    print("\n" + "=" * 70)
    print("FUN_000044CC — searching 24K decompile for overflow patterns")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x44CC))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars total".format(len(c)))
            import re
            # Find all local/stack buffer declarations
            buffers = re.findall(r'(undefined\d|char|int|byte|short)\s+(auStack_[0-9a-f]+|local_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
            if buffers:
                print("\n  Stack buffers in FUN_000044CC:")
                for btype, name, size in buffers:
                    print("    {} {} [{}]".format(btype, name, size))
            # Find all FUN_000004E0/FUN_00000458 calls (memcpy)
            copies = re.findall(r'FUN_0000(?:04e0|0458)\([^)]+\)', c, re.I)
            if copies:
                print("\n  Memcpy calls in FUN_000044CC:")
                for cp in copies:
                    print("    {}".format(cp))
            # Find all FUN_0000823C/FUN_00008150 calls
            copies2 = re.findall(r'FUN_0000(?:823c|8150)\([^)]+\)', c, re.I)
            if copies2:
                print("\n  Bounded copy calls in FUN_000044CC:")
                for cp in copies2:
                    print("    {}".format(cp))
            # Find all FUN_00001C18 calls (DMA)
            dmas = re.findall(r'FUN_00001c18\([^)]+\)', c, re.I)
            if dmas:
                print("\n  DMA calls in FUN_000044CC:")
                for d in dmas:
                    print("    {}".format(d))

            # Show the parts with copy operations
            for kw in ['FUN_000004e0', 'FUN_00000458', 'FUN_0000823c',
                       'FUN_00008150', 'FUN_00001c18']:
                for match in re.finditer(kw, c, re.I):
                    start = max(0, match.start() - 300)
                    end = min(len(c), match.end() + 200)
                    print("\n  CONTEXT around {} at char {}:".format(kw, match.start()))
                    print("  {}".format(c[start:end]))

    # Also: decompile FUN_000030C4 — called by FUN_000035A0 (cache management)
    # This is in the APCB processing chain and might have copy operations
    print("\n" + "=" * 70)
    print("FUN_000030C4 — called in cache management loop")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x30C4))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x30C4))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 4000:
                print(c)
            else:
                print(c[:4000])

    decomp.dispose()

print("\nDone.")
