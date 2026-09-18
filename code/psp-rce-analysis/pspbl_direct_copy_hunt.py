#!/usr/bin/env python3
"""Find ALL direct copy calls (FUN_000004e0, FUN_00000458) in PSP_BL
that bypass FUN_0000823c's bounds checking.

Also: Use Ghidra to analyze ABL4 for stack buffers and APCB parsing.
"""
import os, struct, re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# Part 1: Find all BL/BLX calls to FUN_000004e0 and FUN_00000458 in PSP_BL
print("=" * 70)
print("PART 1: ALL calls to FUN_000004e0 / FUN_00000458 in PSP_BL")
print("=" * 70)

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# Scan Thumb code for BL/BLX targets
callers_04e0 = []
callers_0458 = []
callers_823c = []
callers_8150 = []

all_insns = list(cs.disasm(pspbl[0x400:0x9A00], 0x400))
for i, insn in enumerate(all_insns):
    if insn.mnemonic.lower() in ['bl', 'blx']:
        target = None
        for op in insn.operands:
            if op.type == 2:
                target = op.imm & 0xFFFFFFFF
        if target == 0x4E0:
            callers_04e0.append((insn.address, i))
        elif target == 0x458:
            callers_0458.append((insn.address, i))
        elif target == 0x823C:
            callers_823c.append((insn.address, i))
        elif target == 0x8150:
            callers_8150.append((insn.address, i))

print("  FUN_000004e0 callers: {}".format(len(callers_04e0)))
for addr, idx in callers_04e0:
    # Get context: 5 instructions before and the call
    context = []
    for j in range(max(0, idx-8), idx+1):
        insn = all_insns[j]
        context.append("    0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))
    # Find containing function (scan back for PUSH)
    func_start = "?"
    for j in range(idx, max(0, idx-200), -1):
        if all_insns[j].mnemonic.lower() in ['push', 'push.w']:
            func_start = "0x{:04X}".format(all_insns[j].address)
            break
    print("  Call at 0x{:04X} (in func starting ~{}):\n{}".format(
        addr, func_start, "\n".join(context)))

print("\n  FUN_00000458 callers: {}".format(len(callers_0458)))
for addr, idx in callers_0458:
    context = []
    for j in range(max(0, idx-8), idx+1):
        insn = all_insns[j]
        context.append("    0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))
    func_start = "?"
    for j in range(idx, max(0, idx-200), -1):
        if all_insns[j].mnemonic.lower() in ['push', 'push.w']:
            func_start = "0x{:04X}".format(all_insns[j].address)
            break
    print("  Call at 0x{:04X} (in func starting ~{}):\n{}".format(
        addr, func_start, "\n".join(context)))

print("\n  FUN_0000823c callers: {}".format(len(callers_823c)))
for addr, idx in callers_823c:
    print("    0x{:04X}".format(addr))

print("  FUN_00008150 callers: {}".format(len(callers_8150)))
for addr, idx in callers_8150:
    print("    0x{:04X}".format(addr))

# Part 2: Use Ghidra to decompile ALL functions that call FUN_000004e0 or FUN_00000458
# to find APCB-controlled copy sizes
print("\n" + "=" * 70)
print("PART 2: Ghidra decompile of functions calling direct copy")
print("=" * 70)

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

pyghidra.start(install_dir=GHIDRA_DIR)

# Analyze PSP_BL functions with direct copies
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

    # Find all unique containing functions for 04e0 and 0458 calls
    call_addrs = set()
    for addr, _ in callers_04e0 + callers_0458:
        func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if func:
            call_addrs.add(func.getEntryPoint().getOffset())

    print("  Functions containing direct copy calls: {}".format(len(call_addrs)))

    for func_addr in sorted(call_addrs):
        func = func_mgr.getFunctionAt(space.getAddress(func_addr))
        if not func:
            continue
        fsize = func.getBody().getNumAddresses()
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Check for stack buffers
        buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
        has_04e0 = 'FUN_000004e0' in c
        has_0458 = 'FUN_00000458' in c or 'FUN_00000458' in c.lower()

        # Also check for param-dependent sizes in copy calls
        param_sizes = False
        for copy_fn in ['FUN_000004e0', 'FUN_00000458']:
            idx = 0
            while True:
                idx = c.find(copy_fn, idx)
                if idx < 0:
                    break
                # Extract call context
                paren_start = c.find('(', idx)
                paren_end = c.find(')', paren_start) if paren_start >= 0 else -1
                if paren_end >= 0:
                    args = c[paren_start:paren_end+1]
                    if 'param_' in args:
                        # Could have variable size!
                        param_sizes = True
                idx += 1

        # Print interesting functions
        if buffers or param_sizes:
            print("\n  0x{:04X} ({} bytes):".format(func_addr, fsize))
            if buffers:
                for name, size in buffers:
                    print("    STACK BUFFER: {} [{}]".format(name, size))
            if param_sizes:
                print("    *** HAS PARAM-DEPENDENT COPY SIZE ***")

            # Extract copy call details
            for copy_fn in ['FUN_000004e0', 'FUN_00000458']:
                idx = 0
                while True:
                    idx = c.find(copy_fn, idx)
                    if idx < 0:
                        break
                    end = c.find(';', idx)
                    if end > 0:
                        print("    COPY: {}".format(c[idx:end].strip()))
                    idx += 1

            # Print abbreviated decompile
            if len(c) <= 3000:
                print(c)
            else:
                print(c[:3000])
                print("    ... ({} more)".format(len(c) - 3000))

    # Part 3: ABL4 analysis with Ghidra
    decomp.dispose()

print("\n" + "=" * 70)
print("PART 3: ABL4 Ghidra analysis")
print("=" * 70)

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

    # List all functions
    func_iter = func_mgr.getFunctions(True)
    funcs = []
    while func_iter.hasNext():
        f = func_iter.next()
        funcs.append((f.getEntryPoint().getOffset(), f.getBody().getNumAddresses(), f.getName()))

    print("  Total functions in ABL4: {}".format(len(funcs)))
    print("  Top 20 by size:")
    funcs.sort(key=lambda x: -x[1])
    for addr, size, name in funcs[:20]:
        print("    0x{:05X}: {} ({} bytes)".format(addr, name, size))

    # Decompile the largest functions and look for stack buffers + copy operations
    print("\n  Decompiling largest functions for stack buffers...")
    for addr, size, name in funcs[:30]:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            continue
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Check for stack buffers
        buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
        if buffers:
            large_bufs = [(n, int(s)) for n, s in buffers if int(s) >= 64]
            if large_bufs:
                print("\n  {} at 0x{:05X} ({} bytes):".format(name, addr, size))
                for bname, bsize in large_bufs:
                    print("    STACK BUFFER: {} [{}]".format(bname, bsize))
                # Check for copy operations
                for kw in ['memcpy', 'FUN_', 'copy', 'svc', 'SVC']:
                    if kw.lower() in c.lower():
                        # Find first occurrence
                        idx = c.lower().find(kw.lower())
                        context = c[max(0,idx-20):min(len(c),idx+100)]
                        print("    Contains '{}': ...{}...".format(kw, context.strip()[:80]))
                        break

    decomp.dispose()

print("\nDone.")
