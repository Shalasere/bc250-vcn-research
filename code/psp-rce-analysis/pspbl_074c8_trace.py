#!/usr/bin/env python3
"""Decompile FUN_000074C8 — the function that writes to FUN_000053C4's stack buffer.

Call chain: FUN_000053C4 → FUN_000057C4 → FUN_000074C8(buffer, 0x640, token_type, 0)

If FUN_000074C8 writes > 0x640 bytes to param_1, it overflows the 1600-byte
stack buffer in FUN_000053C4, overwriting saved registers and the return address.

Also decompile:
- FUN_00005278 — the actual SVC handler dispatch (at 0x5278, called from ARM handler)
- FUN_000056C4 — called by FUN_000053C4 with the stack buffer
- Search for ALL callers of FUN_000074C8 to see other buffer sizes
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# First: find ALL call sites of FUN_000074C8
print("=" * 70)
print("0. ALL callers of FUN_000074C8")
print("=" * 70)
callers = []
for off in range(0, len(pspbl) - 3, 2):
    insns = list(cs.disasm(pspbl[off:off+4], off))
    for insn in insns:
        if insn.mnemonic == 'bl' and '0x74c8' in insn.op_str:
            callers.append(off)
            # Show context: what R1 (buffer size) is set to before the call
            ctx_start = max(0, off - 30)
            ctx_insns = list(cs.disasm(pspbl[ctx_start:off+4], ctx_start))
            print("  Call at 0x{:04X}:".format(off))
            for ci in ctx_insns[-10:]:
                ann = ""
                if 'r1' in ci.op_str.split(',')[0]:
                    ann = "  *** R1 (size param)"
                if ci.address == off:
                    ann = "  <<<< CALL"
                print("    0x{:04X}: {:10s} {}{}".format(ci.address, ci.mnemonic, ci.op_str, ann))
            print()

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

    # 1. FUN_000074C8 — THE critical write function
    print("\n" + "=" * 70)
    print("1. FUN_000074C8 — token buffer writer")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x74C8))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x74C8))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c)
    else:
        print("  No function at 0x74C8")

    # 2. FUN_000056C4 — processes the filled buffer in FUN_000053C4
    print("\n" + "=" * 70)
    print("2. FUN_000056C4 — processes filled buffer")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x56C4))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x56C4))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 5000:
                print(c)
            else:
                print(c[:5000])

    # 3. FUN_00005278 — the SVC handler dispatch (Thumb entry)
    print("\n" + "=" * 70)
    print("3. FUN_00005278 — SVC handler dispatch (Thumb)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x5278))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x5278))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 5000:
                print(c)
            else:
                print(c[:5000])
    else:
        print("  No function at 0x5278")
        # Try nearby
        for delta in range(-8, 9, 2):
            f = func_mgr.getFunctionAt(space.getAddress(0x5278 + delta))
            if f:
                print("  Found {} at 0x{:04X}".format(f.getName(), f.getEntryPoint().getOffset()))

    # 4. Functions that FUN_000074C8 calls — trace the copy mechanism
    # We need to know: does 074C8 use FUN_00000458 (memcpy), FUN_0000823C (bounded),
    # or FUN_00001C18 (DMA)?
    print("\n" + "=" * 70)
    print("4. FUN_000074C8 call targets (from disassembly)")
    print("=" * 70)
    # Disassemble FUN_000074C8
    func = func_mgr.getFunctionAt(space.getAddress(0x74C8))
    if func:
        fsize = func.getBody().getNumAddresses()
        code = pspbl[0x74C8:0x74C8 + fsize]
        insns = list(cs.disasm(code, 0x74C8))
        for insn in insns:
            if insn.mnemonic in ('bl', 'blx'):
                print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

    # 5. Decompile callers' functions to see what buffer sizes they use
    print("\n" + "=" * 70)
    print("5. Callers of FUN_000074C8 — decompiled with buffer sizes")
    print("=" * 70)
    seen = set()
    for call_off in callers:
        func = func_mgr.getFunctionContaining(space.getAddress(call_off))
        if func:
            addr = func.getEntryPoint().getOffset()
            if addr not in seen:
                seen.add(addr)
                size = func.getBody().getNumAddresses()
                print("\n" + "-" * 60)
                print("{} at 0x{:04X} ({} bytes) — calls 074C8 from 0x{:04X}".format(
                    func.getName(), addr, size, call_off))
                print("-" * 60)
                result = decomp.decompileFunction(func, 600, flat.getMonitor())
                if result.decompileCompleted():
                    c = result.getDecompiledFunction().getC()
                    # Search for buffer size in calls to FUN_000074c8
                    import re
                    matches = re.findall(r'FUN_000074c8\([^)]+\)', c, re.I)
                    for m in matches:
                        print("  CALL: {}".format(m))
                    # Show locals for stack buffer sizing
                    locals_found = re.findall(r'(auStack_[0-9a-f]+|local_[0-9a-f]+)\s+\[(\d+)\]', c, re.I)
                    for name, sz in locals_found:
                        print("  STACK BUFFER: {} [{}]".format(name, sz))
                    if len(c) <= 3000:
                        print(c)
                    else:
                        # Show just the FUN_000074c8 call context
                        for match in re.finditer(r'FUN_000074c8', c, re.I):
                            start = max(0, match.start() - 200)
                            end = min(len(c), match.end() + 200)
                            print("  ...{}\n".format(c[start:end]))

    # 6. Also look at FUN_00008150 (wrapper around FUN_0000823C)
    # FUN_000053C4 calls it: FUN_00008150(DAT_0000549c, local_24, auStack_20[0], 0x200, 0)
    print("\n" + "=" * 70)
    print("6. FUN_00008150 — bounded copy wrapper")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x8150))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x8150))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)

    decomp.dispose()

print("\nDone.")
