#!/usr/bin/env python3
"""Resolve the actual runtime value of *(0x9A10) by tracing FUN_00003650's inputs.

*(0x9A10) = FUN_00003650(*(0x9A18), 0, 6, DAT_0000822c)

Need to determine:
1. DAT_0000822c literal value (static, from literal pool in FUN_00008168)
2. What sets *(0x9A18) — trace all writes to 0x9A18
3. FUN_00003650 internal logic with these specific params
4. What the slot allocation actually returns (SRAM address? CCP window?)

Then: compute *(0x9A10) + max_offset + 0x100 to see if it can reach 0x5D7AC.
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

# 1. Read static values from FUN_00008168's literal pool
print("=" * 70)
print("1. FUN_00008168 literal pool values")
print("=" * 70)

# These are the literal pool entries in FUN_00008168
# From the summary: DAT_00008230 points to 0x9A18, DAT_0000822c is a parameter
lp_entries = {
    0x8224: "DAT_00008224 (stored to 0x9A14)",
    0x8228: "DAT_00008228 (ptr to 0x9A14?)",
    0x822C: "DAT_0000822C (param_4 to FUN_00003650)",
    0x8230: "DAT_00008230 (ptr to 0x9A18, used as *ptr = param_1 to FUN_00003650)",
    0x8234: "DAT_00008234 (ptr to 0x9A10, result of FUN_00003650 stored here)",
}

for off, desc in lp_entries.items():
    val = struct.unpack_from("<I", pspbl, off)[0]
    print("  +0x{:04X} = 0x{:08X}  ({})".format(off, val, desc))
    if val < len(pspbl):
        inner = struct.unpack_from("<I", pspbl, val)[0]
        print("    -> within binary, *ptr = 0x{:08X}".format(inner))
    elif val < 0x100000:
        print("    -> SRAM runtime address")
    else:
        print("    -> literal constant (not a pointer)")

# 2. Find ALL writes to 0x9A18 (what sets the input to FUN_00003650)
print("\n" + "=" * 70)
print("2. ALL literal pool entries pointing to 0x9A18")
print("=" * 70)
refs_9a18 = []
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val == 0x9A18:
        refs_9a18.append(off)
        print("  +0x{:04X}: 0x00009A18".format(off))

# For each ref, find loading code and check for STR (write)
print("\n  Code that loads 0x9A18 pointer:")
for lp_off in refs_9a18:
    for code_off in range(max(0, lp_off - 1024), lp_off, 2):
        hw = struct.unpack_from("<H", pspbl, code_off)[0]
        if (hw & 0xF800) == 0x4800:
            rt = (hw >> 8) & 7
            imm8 = hw & 0xFF
            pc_val = ((code_off + 4) & ~3)
            target = pc_val + imm8 * 4
            if target == lp_off:
                # Check next ~20 instructions for STR and LDR patterns
                ctx_end = min(len(pspbl), code_off + 60)
                insns = list(cs.disasm(pspbl[code_off:ctx_end], code_off))
                for insn in insns:
                    m = " >>>" if insn.address == code_off else "    "
                    ann = ""
                    if insn.mnemonic.startswith('str'):
                        if '[r{}' .format(rt) in insn.op_str:
                            ann = " <<< WRITE to *(0x9A18)"
                    elif insn.mnemonic.startswith('ldr'):
                        if '[r{}' .format(rt) in insn.op_str:
                            ann = " <<< READ from *(0x9A18)"
                    print("  {} 0x{:04X}: {:10s} {}{}".format(
                        m, insn.address, insn.mnemonic, insn.op_str, ann))
                    if insn.mnemonic in ['bl', 'blx', 'bx', 'b.w', 'pop']:
                        break
                print()

# 3. FUN_00003650 detailed analysis with slot 6 params
print("=" * 70)
print("3. FUN_00003650 detailed trace with (*(0x9A18), 0, 6, DAT_0000822c)")
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

    # Full decompile of FUN_00003650
    print("\n  FUN_00003650 full decompile:")
    func = func_mgr.getFunctionAt(space.getAddress(0x3650))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x3650))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c)

    # Also decompile FUN_00007FA4 (called by FUN_00008168 before FUN_00003650)
    print("\n" + "-" * 60)
    print("  FUN_00007FA4 — called before FUN_00003650 in init path:")
    func = func_mgr.getFunctionAt(space.getAddress(0x7FA4))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x7FA4))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 4000:
                print(c)
            else:
                print(c[:4000])
                print("  ... ({} more chars)".format(len(c) - 4000))

    # 4. What functions write to 0x9A18?
    # Find functions containing the code offsets that write to *(0x9A18)
    print("\n" + "-" * 60)
    print("4. Functions that write to *(0x9A18)")
    print("-" * 60)
    writer_funcs = set()
    for lp_off in refs_9a18:
        for code_off in range(max(0, lp_off - 1024), lp_off, 2):
            hw = struct.unpack_from("<H", pspbl, code_off)[0]
            if (hw & 0xF800) == 0x4800:
                rt = (hw >> 8) & 7
                imm8 = hw & 0xFF
                pc_val = ((code_off + 4) & ~3)
                target = pc_val + imm8 * 4
                if target == lp_off:
                    # Check for STR in next instructions
                    ctx_end = min(len(pspbl), code_off + 60)
                    insns = list(cs.disasm(pspbl[code_off:ctx_end], code_off))
                    for insn in insns:
                        if insn.mnemonic.startswith('str') and '[r{}'.format(rt) in insn.op_str:
                            func = func_mgr.getFunctionContaining(space.getAddress(code_off))
                            if func:
                                writer_funcs.add(func.getEntryPoint().getOffset())
                                print("  WRITE at 0x{:04X} in {} (0x{:04X})".format(
                                    insn.address, func.getName(),
                                    func.getEntryPoint().getOffset()))

    for addr in sorted(writer_funcs):
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if func:
            print("\n  Decompile {} at 0x{:04X}:".format(func.getName(), addr))
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                if len(c) <= 3000:
                    print(c)
                else:
                    print(c[:3000])
                    print("  ... ({} more chars)".format(len(c) - 3000))

    # 5. Also trace what *(0x9A18) typically holds
    # It's read by FUN_000008BC: *param_3 = *(iVar2 + 0x18) - *DAT_00000940
    # DAT_00000940 = 0x9A18, so *(0x9A18) is an SRAM base address used for
    # offset calculations
    print("\n" + "-" * 60)
    print("5. FUN_000008BC — reads *(0x9A18) for address computation")
    print("-" * 60)
    func = func_mgr.getFunctionAt(space.getAddress(0x8BC))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x8BC))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:3000])

    # 6. The KEY question: what are the CCP/SMN slots?
    # FUN_00003650 returns (base & 0x3FFFFFF) + slot*0x4000000 + 0x4000000
    # With param_3 = 6 (slot type), let's trace what slot index is used
    print("\n" + "-" * 60)
    print("6. FUN_00003650 slot analysis with param_3=6")
    print("-" * 60)
    # Read the function's disassembly for precise register tracking
    func_start = 0x3650
    func_data = pspbl[func_start:func_start+256]
    insns = list(cs.disasm(func_data, func_start))
    print("  Disassembly of FUN_00003650:")
    for insn in insns:
        print("    0x{:04X}: {:10s} {}".format(insn.address, insn.mnemonic, insn.op_str))
        if insn.mnemonic in ['pop', 'bx']:
            break

    # Read literal pool entries within FUN_00003650's range
    print("\n  Literal pool entries in FUN_00003650 range (0x3650-0x3740):")
    for off in range(0x3650, 0x3740, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        if val > 0x1000 or val == 0:
            # Skip obvious code
            if val < 0x100000 and val > 0:
                print("    +0x{:04X}: 0x{:08X}".format(off, val))

    decomp.dispose()

# 7. Compute possible DMA destination range
print("\n" + "=" * 70)
print("7. DMA destination range analysis")
print("=" * 70)

# DAT_0000822c value (param_4 to FUN_00003650)
val_822c = struct.unpack_from("<I", pspbl, 0x822C)[0]
print("  DAT_0000822C (param_4) = 0x{:08X}".format(val_822c))

# DAT_00009A24 value (mask) — this is runtime, but from literal pool ref
val_2ccc = struct.unpack_from("<I", pspbl, 0x2CCC)[0]
print("  DAT_00002CCC (ptr to mask @ 0x9A24) = 0x{:08X}".format(val_2ccc))

# FUN_00003650 returns: (param_1 & 0x3FFFFFF) + slot*0x4000000 + 0x4000000
# With param_3=6, slot comes from slot counter at 8+slot_idx
# Minimum return (if base=0, slot=0): 0x4000000
# The APCB region starts at *(0x9A10) + 0x100

print("\n  FUN_00003650 return value analysis:")
print("  Return = (*(0x9A18) & 0x3FFFFFF) + slot*0x4000000 + 0x4000000")
print("  With param_3=6: slots 8-14 are used (modes 5/6)")
print("  If *(0x9A18) = 0: return = 0x4000000 * (slot+1) = 0x{:X} to 0x{:X}".format(
    9*0x4000000, 15*0x4000000))
print("  If *(0x9A18) = 0x3C000 (PSP SRAM typical): return = 0x{:X}+".format(
    0x3C000 + 9*0x4000000))
print()
print("  Context structure at: 0x5D7AC")
print("  Target (context+0x660): 0x5DE0C")
print()
print("  For DMA to reach 0x5DE0C:")
print("  Need *(0x9A10) + offset + 0x100 + size > 0x5DE0C")
print("  With *(0x9A10) near 0x4000000: 0x4000000 + offset + 0x100 + 0x40000 = 0x4040100 + offset")
print("  That's 0x4040100 which is WAY above 0x5DE0C — wait, that's in PSP virtual space")
print()
print("  KEY INSIGHT: The DMA operates on PHYSICAL addresses via FUN_00005A00")
print("  FUN_00005A00: if addr < 0x100000, translate via page table; else passthrough")
print("  PSP SRAM is typically 0x0-0x100000 (1MB)")
print("  The DMA slot allocator maps PHYSICAL memory into a CCP window")
print("  The DMA destination is NOT in SRAM but in the CCP's DMA window")
print("  Unless... the page table re-maps it back to SRAM")
print()
print("  ALTERNATIVE: *(0x9A10) may be a SRAM address if FUN_00003650")
print("  configures the CCP to map SRAM at a low address")
print("  AND the subsequent DMA operations use physical SRAM addresses")

print("\nDone.")
