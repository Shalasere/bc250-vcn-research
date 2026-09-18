#!/usr/bin/env python3
"""Disassemble PSP_BL initialization code (ARM mode) to find SP_abt.

The SVC handler at 0x150 switches to ABT mode (0xD7 = mode 0x17 with I+F).
FUN_000044CC runs on SP_abt. If SP_abt is close to 0x5DE0C, a large stack
frame can overwrite the dispatch pointer.

Need to find:
1. Where mode stacks are initialized (CPS + MOV SP patterns)
2. The specific SP_abt value
3. Also check the code at 0x338+ which appears to be init code
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
cs_arm.detail = True
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs_thumb.detail = True

def disasm_arm(start, end, label=""):
    print("\n" + "=" * 70)
    print("{} (ARM 0x{:04X}-0x{:04X})".format(label, start, end))
    print("=" * 70)
    data = pspbl[start:end]
    for insn in cs_arm.disasm(data, start):
        ops = insn.op_str
        ann = ""
        mn = insn.mnemonic.lower()
        if 'sp' in ops.lower() and mn not in ['push', 'pop']:
            ann += " *** SP ***"
        if mn.startswith('msr'):
            ann += " *** STATUS ***"
            # Check for CPSR_c mode switches
            if 'cpsr' in ops.lower():
                # Try to extract the immediate
                parts = ops.split('#')
                if len(parts) >= 2:
                    try:
                        imm = int(parts[1].strip(), 0)
                        mode = imm & 0x1F
                        modes = {0x10:'USR', 0x11:'FIQ', 0x12:'IRQ', 0x13:'SVC',
                                 0x17:'ABT', 0x1B:'UND', 0x1F:'SYS'}
                        ann += " → {} mode".format(modes.get(mode, "0x{:02X}".format(mode)))
                    except:
                        pass
        if mn.startswith('cps'):
            ann += " *** MODE SWITCH ***"
        if mn in ['bx', 'blx']:
            ann += " *** BRANCH ***"
        if mn == 'ldr' and '[pc' in ops:
            try:
                for op in insn.operands:
                    if hasattr(op, 'mem') and op.mem.base == 15:
                        pc = insn.address + 8
                        pool_addr = pc + op.mem.disp
                        if 0 <= pool_addr < len(pspbl):
                            val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                            ann += " ; [0x{:X}]=0x{:08X}".format(pool_addr, val)
            except:
                pass
        # Immediate values that look like SRAM addresses
        if '#' in ops:
            parts = ops.split('#')
            for p in parts[1:]:
                try:
                    v = int(p.strip().split(',')[0].split(']')[0].split('}')[0], 0)
                    if 0x40000 <= v <= 0x80000:
                        ann += " *** SRAM ADDR ***"
                except:
                    pass
        print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))

# 1. Initialization code at 0x338+ (ARM mode)
disasm_arm(0x338, 0x3D0, "PSP_BL init code (0x338)")

# 2. Code at 0x944+ — this was identified in the Ghidra analysis as "main_boot" area
# Let me check if it's ARM or Thumb
print("\n" + "=" * 70)
print("Checking 0x944 as ARM vs Thumb")
print("=" * 70)
arm_insns = list(cs_arm.disasm(pspbl[0x944:0x960], 0x944))
thumb_insns = list(cs_thumb.disasm(pspbl[0x944:0x960], 0x944))
print("  ARM: {} instructions decoded".format(len(arm_insns)))
for insn in arm_insns[:3]:
    print("    0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))
print("  Thumb: {} instructions decoded".format(len(thumb_insns)))
for insn in thumb_insns[:3]:
    print("    0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 3. Disassemble the Thumb code at 0x944 (likely where Ghidra has FUN_00000944)
# This is FUN_00000944 = main boot entry point in Thumb mode
# Check if it sets up mode stacks
print("\n" + "=" * 70)
print("FUN_00000944 first 128 bytes (Thumb)")
print("=" * 70)
for insn in cs_thumb.disasm(pspbl[0x944:0x9C4], 0x944):
    ops = insn.op_str
    ann = ""
    mn = insn.mnemonic.lower()
    if 'sp' in ops.lower() and mn not in ['push', 'pop', 'str', 'stm']:
        ann += " *** SP ***"
    if mn.startswith('msr'):
        ann += " *** STATUS ***"
    if mn.startswith('cps'):
        ann += " *** MODE ***"
    if mn == 'ldr' and '[pc' in ops:
        try:
            pc = (insn.address + 4) & ~3
            parts = ops.split('#')
            if len(parts) >= 2:
                imm = int(parts[1].rstrip(']').strip(), 0)
                pool_addr = pc + imm
                if 0 <= pool_addr < len(pspbl):
                    val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                    ann += " ; [0x{:X}]=0x{:08X}".format(pool_addr, val)
        except:
            pass
    print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))

# 4. Look for ALL MSR CPSR instructions in the entire binary (ARM + Thumb)
print("\n" + "=" * 70)
print("ALL MSR/CPS instructions (ARM mode, 0x0-0x400)")
print("=" * 70)
for insn in cs_arm.disasm(pspbl[:0x400], 0):
    mn = insn.mnemonic.lower()
    if mn.startswith('msr') or mn.startswith('cps'):
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

print("\n" + "=" * 70)
print("ALL MSR/CPS instructions (Thumb mode, 0x400-0x9A00)")
print("=" * 70)
for insn in cs_thumb.disasm(pspbl[0x400:0x9A00], 0x400):
    mn = insn.mnemonic.lower()
    if mn.startswith('msr') or mn.startswith('cps'):
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 5. Specific: Look for the MSR CPSR_c, #0xD7 pattern (ABT mode switch)
# and check what MOV SP instructions follow
print("\n" + "=" * 70)
print("ABT mode switch (0xD7/0x17) + SP setup patterns")
print("=" * 70)
arm_insns = list(cs_arm.disasm(pspbl[:0x400], 0))
for i, insn in enumerate(arm_insns):
    if insn.mnemonic.lower() == 'msr' and '0xd7' in insn.op_str.lower():
        print("  0x{:04X}: {} {} ← ABT MODE!".format(insn.address, insn.mnemonic, insn.op_str))
        # Show next 5 instructions
        for j in range(i+1, min(i+6, len(arm_insns))):
            ninsn = arm_insns[j]
            print("    0x{:04X}: {} {}".format(ninsn.address, ninsn.mnemonic, ninsn.op_str))

# Also check if there are any MOVW/MOVT SP patterns (32-bit immediate to SP)
print("\n" + "=" * 70)
print("MOVW/MOVT + SP patterns (Thumb mode)")
print("=" * 70)
thumb_insns = list(cs_thumb.disasm(pspbl[:0x9A00], 0))
for i, insn in enumerate(thumb_insns):
    mn = insn.mnemonic.lower()
    ops = insn.op_str.lower()
    if mn in ['movw', 'movt'] and 'sp' in ops:
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 6. Check what FUN_00006CF0 does (called from SVC handler before FUN_000044CC)
print("\n" + "=" * 70)
print("FUN_00006CF0 first 64 bytes (Thumb) — called from SVC handler")
print("=" * 70)
for insn in cs_thumb.disasm(pspbl[0x6CF0:0x6D30], 0x6CF0):
    ops = insn.op_str
    ann = ""
    mn = insn.mnemonic.lower()
    if 'sp' in ops.lower():
        ann += " *** SP ***"
    if mn.startswith('msr'):
        ann += " *** STATUS ***"
    if mn == 'ldr' and '[pc' in ops:
        try:
            pc = (insn.address + 4) & ~3
            parts = ops.split('#')
            if len(parts) >= 2:
                imm = int(parts[1].rstrip(']').strip(), 0)
                pool_addr = pc + imm
                if 0 <= pool_addr < len(pspbl):
                    val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                    ann += " ; [0x{:X}]=0x{:08X}".format(pool_addr, val)
        except:
            pass
    print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))

# 7. GHIDRA decompile of the init function that contains 0x338 and FUN_00006CF0
import os
os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

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

    # Decompile FUN_00006CF0 (called from SVC handler before FUN_000044CC)
    for addr in [0x6CF0, 0x338, 0x394C, 0x944, 0x9F8, 0x0A44, 0x0B00]:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if func:
            entry = func.getEntryPoint().getOffset()
            fsize = func.getBody().getNumAddresses()
            print("\n" + "=" * 70)
            print("GHIDRA: {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
            print("=" * 70)
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                if len(c) <= 3000:
                    print(c)
                else:
                    print(c[:3000])
                    print("\n... ({} more)".format(len(c) - 3000))
        else:
            print("\n  No Ghidra function at/containing 0x{:04X}".format(addr))

    decomp.dispose()

print("\nDone.")
