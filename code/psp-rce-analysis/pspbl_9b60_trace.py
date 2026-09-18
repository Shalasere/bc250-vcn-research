#!/usr/bin/env python3
"""Trace *(0x9B60) — the uninitialized pointer vulnerability candidate.

Hypothesis: When CCXG group (0x28) is missing from APCB:
1. First FUN_000066A0 call (group 0x28, param_7=1) fails to find group
2. *(0x9B60) is never set
3. Second FUN_000066A0 call (group 0x02, param_7=0) uses *(0x9B60) as buffer dest
4. APCB data copied to wherever *(0x9B60) points → write-what-where

Need to verify:
- ALL writes to *(0x9B60) in PSP_BL
- Whether FUN_000066A0 writes to *(0x9B60) on success (param_7=1 path)
- The full FUN_000066A0 decompile (need the WRITE-BACK code)
- What *(0x9B60) contains in SRAM at boot (zeroed? garbage?)
- If *(0x9B60) = 0, what happens? (FUN_0000823C checks for null)
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

# 1. Find ALL literal pool entries pointing to 0x9B60
print("=" * 70)
print("1. ALL literal pool references to 0x9B60")
print("=" * 70)
refs = []
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val == 0x9B60:
        refs.append(off)
        print("  +0x{:04X}: 0x00009B60".format(off))

# 2. For each ref, find code that loads it and check for WRITE vs READ
print("\n" + "=" * 70)
print("2. Code using 0x9B60 — WRITE vs READ analysis")
print("=" * 70)

write_sites = []
read_sites = []

for lp_off in refs:
    print("\n  --- LP at +0x{:04X} ---".format(lp_off))
    for code_off in range(max(0, lp_off - 1024), lp_off, 2):
        hw = struct.unpack_from("<H", pspbl, code_off)[0]
        if (hw & 0xF800) == 0x4800:
            rt = (hw >> 8) & 7
            imm8 = hw & 0xFF
            pc_val = ((code_off + 4) & ~3)
            target = pc_val + imm8 * 4
            if target == lp_off:
                # Found load of 0x9B60 into register rt
                # Check next 40 instructions
                ctx_end = min(len(pspbl), code_off + 100)
                insns = list(cs.disasm(pspbl[code_off:ctx_end], code_off))
                for insn in insns:
                    m = " >>>" if insn.address == code_off else "    "
                    ann = ""
                    if insn.mnemonic.startswith('str'):
                        # Check if storing TO [rt] (write to *(0x9B60))
                        if '[r{}'.format(rt) in insn.op_str:
                            ann = " <<< WRITE to *(0x9B60)!"
                            write_sites.append(insn.address)
                        # Also check if storing rt itself to [something] (saving ptr)
                        elif 'r{},'.format(rt) == insn.op_str[:3]:
                            ann = " (storing ptr value, not write through)"
                    elif insn.mnemonic.startswith('ldr'):
                        if '[r{}'.format(rt) in insn.op_str:
                            ann = " <<< READ from *(0x9B60)"
                            read_sites.append(insn.address)
                    elif insn.mnemonic == 'mov' and 'r{}'.format(rt) in insn.op_str:
                        # Register copy — lose tracking
                        ann = " (reg copy)"
                    print("  {} 0x{:04X}: {:10s} {}{}".format(
                        m, insn.address, insn.mnemonic, insn.op_str, ann))
                    if insn.mnemonic in ['bl', 'blx', 'bx', 'pop', 'b.w']:
                        break
                print()

print("\n  Summary:")
print("  WRITE sites: {}".format(write_sites if write_sites else "NONE!"))
print("  READ sites: {}".format(read_sites if read_sites else "NONE!"))

# 3. Ghidra: decompile ALL functions referencing 0x9B60
print("\n" + "=" * 70)
print("3. Ghidra decompile — all functions referencing 0x9B60")
print("=" * 70)

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

    # Find unique functions containing 0x9B60 references
    ref_funcs = set()
    for lp_off in refs:
        for code_off in range(max(0, lp_off - 1024), lp_off, 2):
            hw = struct.unpack_from("<H", pspbl, code_off)[0]
            if (hw & 0xF800) == 0x4800:
                imm8 = hw & 0xFF
                pc_val = ((code_off + 4) & ~3)
                target = pc_val + imm8 * 4
                if target == lp_off:
                    func = func_mgr.getFunctionContaining(space.getAddress(code_off))
                    if func:
                        ref_funcs.add(func.getEntryPoint().getOffset())

    for addr in sorted(ref_funcs):
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if func:
            print("\n" + "-" * 60)
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            print("{} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
            print("-" * 60)
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))
                # Search for patterns involving 0x9B60 / DAT_000067bc / DAT_00009b60
                for kw in ['DAT_000067bc', 'DAT_00009b60', '0x9b60', '*DAT']:
                    idx = c.lower().find(kw.lower())
                    if idx >= 0:
                        print("\n  [{}] found at char {}:".format(kw, idx))
                        # Show context around the match
                        start = max(0, idx - 200)
                        end = min(len(c), idx + 500)
                        print("  ..." + c[start:end] + "...")
                # Always show full for small functions
                if len(c) <= 3000:
                    print("\n  FULL DECOMPILE:")
                    print(c)
                else:
                    # Show function signature and first few lines
                    lines = c.split('\n')
                    print("\n  FIRST 40 LINES:")
                    print('\n'.join(lines[:40]))
                    if len(lines) > 40:
                        print("  ... ({} more lines)".format(len(lines) - 40))

    # 4. Also check FUN_000035A0 — mystery function between APCB and config buffer
    print("\n" + "=" * 70)
    print("4. FUN_000035A0 — between APCB processing and config buffer")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x35A0))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x35A0))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("{} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 4000:
                print(c)
            else:
                print(c[:4000])
                print("  ... ({} more)".format(len(c) - 4000))

    # 5. Check the Cortex-A5 reset handler for stack setup
    print("\n" + "=" * 70)
    print("5. Reset handler at 0x13C — stack initialization")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x13C))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x13C))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("{} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:5000])
    else:
        # The binary starts with ARM exception vectors, not Thumb
        # Ghidra may need ARM mode analysis
        print("  No function found at 0x13C")
        print("  Note: PSP_BL starts with ARM exception vectors")
        print("  The reset handler might not be analyzed as Thumb")
        # Try nearby
        for delta in range(-16, 17, 2):
            func = func_mgr.getFunctionAt(space.getAddress(0x13C + delta))
            if func:
                print("  Found {} at 0x{:04X}".format(
                    func.getName(), func.getEntryPoint().getOffset()))
                break

    # 6. Also check the initial code at PSP_BL — what happens right after vectors?
    print("\n  Disassembly at 0x13C (ARM mode):")
    from capstone import CS_MODE_ARM
    cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    arm_insns = list(cs_arm.disasm(pspbl[0x13C:0x200], 0x13C))
    for insn in arm_insns[:30]:
        print("    0x{:04X}: {:10s} {}".format(insn.address, insn.mnemonic, insn.op_str))

    # Also check the SVC handler at 0x298
    print("\n  SVC handler at 0x298 (ARM mode):")
    svc_insns = list(cs_arm.disasm(pspbl[0x298:0x310], 0x298))
    for insn in svc_insns[:20]:
        print("    0x{:04X}: {:10s} {}".format(insn.address, insn.mnemonic, insn.op_str))

    decomp.dispose()

print("\nDone.")
