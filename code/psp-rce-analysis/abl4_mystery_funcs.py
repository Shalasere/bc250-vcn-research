#!/usr/bin/env python3
"""Decompile the two mystery functions between SVC 0x1c and first token dispatch.

Orchestrator sequence:
  0x6BCA4: bl 0x6b590   ; vtable init (+0x660 = 0x60FE9)
  0x6BCCC: svc #0x1c    ; PSP_BL processes APCB
  ...logging...
  0x6BD5C: bl 0x6f364   ; ??? MYSTERY 1
  0x6BD74: bl 0x6f290   ; ??? MYSTERY 2
  0x6BDA4: bl 0x6f214   ; channel select (calls through +0x3B0)
  0x6BDB4: bl 0x6bb9c   ; FIRST TOKEN READ via +0x660 ← must work by now!

One of FUN_0006f364 or FUN_0006f290 must overwrite context+0x660
with the REAL dispatch function.
"""
import os

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

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

    # 1. FUN_0006f364 (mystery function 1)
    print("=" * 70)
    print("MYSTERY 1: FUN_0006f364")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6f364))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6f364))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:8000])
    else:
        print("  No function at/containing 0x6f364")

    # 2. FUN_0006f290 (mystery function 2)
    print("\n" + "=" * 70)
    print("MYSTERY 2: FUN_0006f290")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6f290))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6f290))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:8000])
    else:
        print("  No function at/containing 0x6f290")

    # 3. Also check: does the orchestrator itself do a STR between SVC and dispatch?
    # Search for STR in the 0x6BCD6-0x6BDB4 range
    print("\n" + "=" * 70)
    print("3. Orchestrator code between SVC return (0x6BCCE) and first dispatch (0x6BDB4)")
    print("=" * 70)

    import struct
    with open(ABL4_PATH, "rb") as f:
        abl4 = f.read()

    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs.detail = True
    ABL4_BASE = 0x60834

    start = 0x6BCCE
    end = 0x6BDB6
    off = start - ABL4_BASE
    insns = list(cs.disasm(abl4[off:off+(end-start)], start))
    print("  Full disassembly:")
    for insn in insns:
        # Highlight stores and function calls
        if insn.mnemonic.startswith('str') or insn.mnemonic in ['bl', 'blx', 'svc']:
            marker = " ***"
        else:
            marker = "    "
        print("  {} 0x{:05X}: {:10s} {}".format(marker, insn.address, insn.mnemonic, insn.op_str))

    # 4. Decompile the full orchestrator around this area
    print("\n" + "=" * 70)
    print("4. Orchestrator decompile around SVC 0x1c (searching for +0x660 write)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x6BC64))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6BC64))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars total".format(len(c)))
            # Search for 0x660 in the decompile
            idx = c.find('0x660')
            if idx >= 0:
                print("  FOUND 0x660 reference at char {}:".format(idx))
                print(c[max(0,idx-500):min(len(c),idx+1000)])
            else:
                print("  0x660 NOT found in decompile!")
                # Search for the area after SVC
                for kw in ['software_interrupt', 'svc', '0x1c', 'FUN_0006f364', 'FUN_0006f290']:
                    idx = c.find(kw)
                    if idx >= 0:
                        print("\n  [{}] at char {}:".format(kw, idx))
                        print(c[max(0,idx-200):min(len(c),idx+800)])
                        break
    else:
        print("  No orchestrator function found")

    # 5. Also check FUN_0006f290 for references to the 0x4F000 buffer
    # PSP_BL caches the config at 0x4F000. Maybe ABL4 reads from there
    print("\n" + "=" * 70)
    print("5. References to 0x4F000 in ABL4")
    print("=" * 70)
    for off in range(0, len(abl4) - 3, 4):
        val = struct.unpack_from("<I", abl4, off)[0]
        if val == 0x4F000:
            va = ABL4_BASE + off
            func = func_mgr.getFunctionContaining(space.getAddress(va))
            fname = func.getName() if func else "?"
            print("  VA 0x{:05X}: literal 0x4F000 in {}".format(va, fname))

    decomp.dispose()
    print("\nDone.")
