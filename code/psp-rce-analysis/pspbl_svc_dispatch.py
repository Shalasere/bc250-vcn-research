#!/usr/bin/env python3
"""Focused analysis of the SVC dispatch path.

1. Disassemble code at 0x5279 (actual SVC entry from ARM exception)
2. Dump full FUN_000044CC decompile + search for function pointer tables
3. Find all computed branch targets in FUN_000044CC (BLX reg, etc)
4. Decompile FUN_00002E3C (caller of FUN_000082B0) + FUN_00005238/FUN_000014B0
5. Look for the SVC handler table used by the dispatcher
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# 1. Disassemble from 0x5279 to see the actual code
print("=" * 70)
print("1. Disassembly at 0x5279 (SVC dispatch entry, Thumb)")
print("=" * 70)
# 0x5279 is Thumb (bit 0 set → 0x5278)
thumb_addr = 0x5278
code = pspbl[thumb_addr:thumb_addr+200]
insns = list(cs.disasm(code, thumb_addr))
for insn in insns[:50]:
    ann = ""
    if insn.mnemonic in ('bl', 'blx', 'bx'):
        ann = "  <<<< CALL/BRANCH"
    if 'sp' in insn.op_str.lower().split(',')[0]:
        ann = "  *** SP WRITE"
    print("  0x{:04X}: {:10s} {}{}".format(insn.address, insn.mnemonic, insn.op_str, ann))

# 2. Search for function pointer tables near FUN_000044CC
# Look for sequences of Thumb addresses (odd values in 0x0000-0x9A00 range)
print("\n" + "=" * 70)
print("2. Search for function pointer tables in PSP_BL data regions")
print("=" * 70)
# Tables often reside after code, in literal pool areas
# Look for runs of 4+ consecutive 32-bit values that look like Thumb addresses
for base in range(0, len(pspbl) - 31, 4):
    vals = [struct.unpack_from("<I", pspbl, base + i*4)[0] for i in range(8)]
    # Check if they're all valid Thumb addresses in PSP_BL range
    thumb_count = sum(1 for v in vals if 0x100 < v < 0x9A00 and (v & 1) == 1)
    if thumb_count >= 6:
        # Potential dispatch table
        print("  Table at 0x{:04X}:".format(base))
        for i, v in enumerate(vals):
            marker = "THUMB" if (v & 1) == 1 and 0x100 < v < 0x9A00 else ""
            print("    [{}] 0x{:08X} {}".format(i, v, marker))
        # Extend to see the full table
        idx = 8
        while base + idx*4 < len(pspbl) - 3:
            v = struct.unpack_from("<I", pspbl, base + idx*4)[0]
            if 0x100 < v < 0x9A00 and (v & 1) == 1:
                print("    [{}] 0x{:08X} THUMB".format(idx, v))
                idx += 1
            else:
                break
        print()

# 3. Find computed branches (BLX reg) in FUN_000044CC (0x44CC-0x4F74)
print("=" * 70)
print("3. Computed branches in FUN_000044CC range (0x44CC-0x4F74)")
print("=" * 70)
code44 = pspbl[0x44CC:0x4F74]
insns44 = list(cs.disasm(code44, 0x44CC))
for insn in insns44:
    if insn.mnemonic in ('blx', 'bx') and not insn.op_str.startswith('#'):
        # register-indirect call/branch
        # Show context
        ctx_start = max(0x44CC, insn.address - 20)
        ctx = list(cs.disasm(pspbl[ctx_start:insn.address+4], ctx_start))
        print("  Computed branch at 0x{:04X}: {} {}".format(
            insn.address, insn.mnemonic, insn.op_str))
        for c in ctx[-8:]:
            marker = " <<<<" if c.address == insn.address else ""
            print("    0x{:04X}: {:10s} {}{}".format(c.address, c.mnemonic, c.op_str, marker))
        print()

# Also check for TBB/TBH (table branch byte/halfword) in the range
for insn in insns44:
    if insn.mnemonic in ('tbb', 'tbh'):
        print("  TABLE BRANCH at 0x{:04X}: {} {}".format(
            insn.address, insn.mnemonic, insn.op_str))

# 4. Direct BL targets in FUN_000044CC
print("=" * 70)
print("4. ALL direct BL targets in FUN_000044CC")
print("=" * 70)
bl_targets = {}
for insn in insns44:
    if insn.mnemonic == 'bl':
        target = int(insn.op_str.replace('#', ''), 16)
        if target not in bl_targets:
            bl_targets[target] = 0
        bl_targets[target] += 1
for target in sorted(bl_targets.keys()):
    print("  bl 0x{:04X} (×{})".format(target, bl_targets[target]))

# 5. Now Ghidra for deeper analysis
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

    # 5a. Full FUN_000044CC decompile — save to file for analysis
    print("\n" + "=" * 70)
    print("5a. FUN_000044CC full decompile — saved to file")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x44CC))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            with open("fun_044cc_full.c", "w") as f:
                f.write(c)
            print("  {} chars saved to fun_044cc_full.c".format(len(c)))

            # Search for ALL function calls in the decompile
            all_calls = re.findall(r'FUN_[0-9a-f]+', c, re.I)
            call_counts = {}
            for call in all_calls:
                if call not in call_counts:
                    call_counts[call] = 0
                call_counts[call] += 1
            print("\n  Functions referenced in FUN_000044CC:")
            for name in sorted(call_counts.keys()):
                print("    {} (×{})".format(name, call_counts[name]))

            # Search for param_1 being passed to function calls
            # (param_1 might be a buffer passed in from the SVC dispatcher)
            param1_uses = [m.start() for m in re.finditer(r'param_1', c)]
            print("\n  param_1 used {} times".format(len(param1_uses)))

            # Look for stack buffer declarations
            buffers = re.findall(r'(undefined\d?|char|int|byte|uint)\s+(auStack_[0-9a-f]+|local_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
            if buffers:
                print("\n  Stack buffers in FUN_000044CC:")
                for btype, name, size in buffers:
                    print("    {} {} [{}]".format(btype, name, size))
            else:
                print("\n  NO stack array buffers found in decompile")
                # Maybe the decompiler represents them differently?
                # Search for large stack-relative loads/stores
                subs = re.findall(r'auStack[_0-9a-fA-F]+', c)
                if subs:
                    print("  But found auStack references: {}".format(set(subs)))

            # Find lines containing FUN_00004412 or FUN_000082B0
            for target_fn in ['FUN_00004412', 'FUN_000082b0', 'FUN_00002e3c',
                              'FUN_0000823c', 'FUN_00008150', 'FUN_000004e0']:
                for m in re.finditer(target_fn, c, re.I):
                    start = max(0, m.start() - 200)
                    end = min(len(c), m.end() + 200)
                    print("\n  {} in FUN_000044CC (at char {}):".format(target_fn, m.start()))
                    print("  {}".format(c[start:end]))

    # 5b. FUN_00002E3C (calls FUN_000082B0)
    print("\n" + "=" * 70)
    print("5b. FUN_00002E3C — caller of FUN_000082B0")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x2E3C))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x2E3C))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 6000:
                print(c)
            else:
                # Show the FUN_000082B0 call context
                for m in re.finditer('FUN_000082b0', c, re.I):
                    start = max(0, m.start() - 400)
                    end = min(len(c), m.end() + 400)
                    print("  CONTEXT: {}".format(c[start:end]))

    # 5c. FUN_00005238 — called from FUN_00002358 (the SVC handler)
    print("\n" + "=" * 70)
    print("5c. FUN_00005238 — called from SVC handler")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x5238))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x5238))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 6000:
                print(c)
            else:
                print(c[:6000])
                print("  ... ({} more chars)".format(len(c) - 6000))

    # 5d. FUN_000014B0 — called from SVC handler
    print("\n" + "=" * 70)
    print("5d. FUN_000014B0 — called from SVC handler")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x14B0))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x14B0))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 6000:
                print(c)
            else:
                print(c[:6000])

    # 5e. FUN_00005A28 — called from SVC handler
    print("\n" + "=" * 70)
    print("5e. FUN_00005A28 — called from SVC handler on success")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x5A28))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x5A28))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 6000:
                print(c)
            else:
                print(c[:6000])
                print("  ... ({} more)".format(len(c) - 6000))

    decomp.dispose()

print("\nDone.")
