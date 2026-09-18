#!/usr/bin/env python3
"""Verify the stack overflow candidates:

1. FUN_0000083C — provides offset/size for token types 5/6 in FUN_000074C8
   Q: Does it return attacker-controlled sizes?

2. FUN_00008488 — called by FUN_00005758 with buffer+0x440 destination
   Q: Does it write to its 6th param? How many bytes?

3. ALL callers of FUN_000057C4 — find paths with token type 5/6/10
   Q: Which callers provide a stack buffer?

4. FUN_00007568 — calls FUN_000066A0 with group 0x24, uses 0x9B60
   Q: Different processing path we haven't explored?

5. ALL callers of FUN_000074C8 with token types 5/6/10 (not just via FUN_000057C4)
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

# Find ALL callers of FUN_000057C4
print("=" * 70)
print("0. ALL callers of FUN_000057C4")
print("=" * 70)
callers_57c4 = []
for off in range(0, len(pspbl) - 3, 2):
    insns = list(cs.disasm(pspbl[off:off+4], off))
    for insn in insns:
        if insn.mnemonic == 'bl' and '0x57c4' in insn.op_str:
            callers_57c4.append(off)
            # Show R0 (token type param) setup
            ctx_start = max(0, off - 20)
            ctx_insns = list(cs.disasm(pspbl[ctx_start:off+4], ctx_start))
            print("  Call at 0x{:04X}:".format(off))
            for ci in ctx_insns[-8:]:
                ann = ""
                if ci.op_str.startswith('r0,') or ci.op_str == 'r0':
                    ann = "  *** R0 (token type)"
                print("    0x{:04X}: {:10s} {}{}".format(ci.address, ci.mnemonic, ci.op_str, ann))
            print()

# Find ALL callers of FUN_00005758
print("=" * 70)
print("0b. ALL callers of FUN_00005758")
print("=" * 70)
callers_5758 = []
for off in range(0, len(pspbl) - 3, 2):
    insns = list(cs.disasm(pspbl[off:off+4], off))
    for insn in insns:
        if insn.mnemonic == 'bl' and '0x5758' in insn.op_str:
            callers_5758.append(off)
            print("  Call at 0x{:04X}".format(off))

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

    # 1. FUN_0000083C — size provider for token types 5/6
    print("\n" + "=" * 70)
    print("1. FUN_0000083C — size/offset provider for types 5/6")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x83C))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x83C))
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
        print("  No function at 0x83C")

    # 2. FUN_00008488 — may write to buffer+0x440
    print("\n" + "=" * 70)
    print("2. FUN_00008488 — signature/verification function")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x8488))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x8488))
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
        print("  No function at 0x8488")

    # 3. Decompile ALL callers of FUN_000057C4
    print("\n" + "=" * 70)
    print("3. ALL callers of FUN_000057C4 — find token type 5/6/10 paths")
    print("=" * 70)
    seen = set()
    for call_off in callers_57c4:
        func = func_mgr.getFunctionContaining(space.getAddress(call_off))
        if func:
            addr = func.getEntryPoint().getOffset()
            if addr not in seen:
                seen.add(addr)
                size = func.getBody().getNumAddresses()
                print("\n" + "-" * 60)
                print("{} at 0x{:04X} ({} bytes)".format(func.getName(), addr, size))
                result = decomp.decompileFunction(func, 600, flat.getMonitor())
                if result.decompileCompleted():
                    c = result.getDecompiledFunction().getC()
                    import re
                    calls = re.findall(r'FUN_000057c4\([^)]+\)', c, re.I)
                    for m in calls:
                        print("  CALL: {}".format(m))
                    # Show the full decompile for context
                    if len(c) <= 3000:
                        print(c)
                    else:
                        for match in re.finditer(r'FUN_000057c4', c, re.I):
                            start = max(0, match.start() - 300)
                            end = min(len(c), match.end() + 300)
                            print("  CONTEXT: ...{}...\n".format(c[start:end]))

    # 4. Decompile ALL callers of FUN_00005758
    print("\n" + "=" * 70)
    print("4. ALL callers of FUN_00005758")
    print("=" * 70)
    seen = set()
    for call_off in callers_5758:
        func = func_mgr.getFunctionContaining(space.getAddress(call_off))
        if func:
            addr = func.getEntryPoint().getOffset()
            if addr not in seen:
                seen.add(addr)
                print("  {} at 0x{:04X}".format(func.getName(), addr))

    # 5. FUN_00003BB0 — the OTHER function with a large stack frame (260 bytes)
    print("\n" + "=" * 70)
    print("5. Function at 0x3BB0 — large stack frame")
    print("=" * 70)
    for delta in range(-16, 1, 2):
        func = func_mgr.getFunctionAt(space.getAddress(0x3BB2 + delta))
        if func:
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))
                # Check for copy functions and stack buffers
                for kw in ['FUN_00000458', 'FUN_0000823c', 'FUN_00008150',
                           'FUN_00001c18', 'FUN_00008488']:
                    if kw in c:
                        print("  *** CALLS {} ***".format(kw))
                locals_found = re.findall(r'(auStack_[0-9a-f]+)\s+\[(\d+)\]', c, re.I)
                for name, sz in locals_found:
                    print("  STACK BUFFER: {} [{}]".format(name, sz))
                if len(c) <= 5000:
                    print(c)
                else:
                    print(c[:5000])
            break

    # 6. Check FUN_000065B8 — called at end of FUN_00007014
    print("\n" + "=" * 70)
    print("6. FUN_000065B8 — post-copy token processor")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x65B8))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x65B8))
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

    decomp.dispose()

print("\nDone.")
