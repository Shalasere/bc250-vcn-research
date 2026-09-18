#!/usr/bin/env python3
"""Resolve DMA destination base and decompile alternative copy paths.

Key targets:
1. DAT_0000729c — literal pool value that provides the DMA destination base
   in FUN_000071AC: dest = *DAT_0000729c + param_4 + 0x100
2. FUN_000062BE — alternative copy path (called when param_5 != 0)
3. FUN_00001F40 — called from FUN_000071AC for decompression path
4. FUN_000018E4 — S3 resume path (called from FUN_00000300)
5. FUN_00006B76 — the function that READS context 0x5D7AC (at PSP_BL 0x0958)

Also: trace ALL literal pool entries near 0x729c to understand the
surrounding data structures.
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# 1. Read DAT_0000729c value
print("=" * 70)
print("1. DAT_0000729c — DMA destination base pointer")
print("=" * 70)
val_729c = struct.unpack_from("<I", pspbl, 0x729c)[0]
print("  DAT_0000729c = 0x{:08X}".format(val_729c))
print("  This is a POINTER — dest = *DAT_0000729c + param_4 + 0x100")
print("  If *DAT_0000729c is a runtime value, this is an indirect pointer")
print()

# Check if it's within binary (data) or beyond (runtime)
if val_729c < len(pspbl):
    inner = struct.unpack_from("<I", pspbl, val_729c)[0]
    print("  Value AT 0x{:04X} in binary: 0x{:08X}".format(val_729c, inner))
else:
    print("  0x{:08X} is BEYOND binary (runtime SRAM address)".format(val_729c))

# Also read surrounding literal pool entries for context
print("\n  Literal pool around 0x729c:")
for off in range(0x7280, 0x72C0, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    marker = " <<<" if off == 0x729c else ""
    print("    +0x{:04X}: 0x{:08X}{}".format(off, val, marker))

# 2. Read DAT_00007154, DAT_00007158 (used in FUN_00007014)
print("\n" + "=" * 70)
print("2. Other critical literal pool entries from FUN_00007014/FUN_000071AC")
print("=" * 70)
for off, name in [(0x7154, "DAT_00007154"), (0x7158, "DAT_00007158"),
                   (0x715c, "DAT_0000715c"), (0x729c, "DAT_0000729c")]:
    val = struct.unpack_from("<I", pspbl, off)[0]
    print("  {} (+0x{:04X}) = 0x{:08X}".format(name, off, val))
    if val < len(pspbl):
        inner = struct.unpack_from("<I", pspbl, val)[0]
        print("    -> points within binary, *ptr = 0x{:08X}".format(inner))
    else:
        print("    -> SRAM/runtime address")

# 3. What code loads DAT_0000729c? Search for LDR Rx, [PC, #...] -> 0x729c
print("\n" + "=" * 70)
print("3. Code that loads DAT_0000729c")
print("=" * 70)
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

for off in range(0x7000, 0x72A0, 2):
    hw = struct.unpack_from("<H", pspbl, off)[0]
    if (hw & 0xF800) == 0x4800:  # Thumb16 LDR Rt, [PC, #imm]
        rt = (hw >> 8) & 7
        imm8 = hw & 0xFF
        pc_val = ((off + 4) & ~3)
        target = pc_val + imm8 * 4
        if target == 0x729c:
            print("  Offset 0x{:04X}: LDR r{}, [PC] -> 0x729c".format(off, rt))
            # Show context
            ctx_start = max(0, off - 16)
            insns = list(cs.disasm(pspbl[ctx_start:off+32], ctx_start))
            for insn in insns:
                m = " >>>" if insn.address == off else "    "
                print("  {} 0x{:04X}: {:10s} {}".format(m, insn.address, insn.mnemonic, insn.op_str))

# Also check Thumb32 LDR.W patterns
print("\n  (Also checking Thumb32 LDR.W patterns...)")
all_insns = list(cs.disasm(pspbl[:len(pspbl)], 0))
for insn in all_insns:
    if insn.mnemonic.startswith('ldr') and '0x729c' in insn.op_str.lower():
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 4. Now Ghidra analysis
print("\n" + "=" * 70)
print("4. Ghidra decompilation of key functions")
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

    targets = [
        (0x62BE, "FUN_000062BE — alternative copy path (param_5 != 0)"),
        (0x1F40, "FUN_00001F40 — decompression alternative"),
        (0x18E4, "FUN_000018E4 — S3 resume APCB path"),
        (0x6B76, "FUN_00006B76 — reads context 0x5D7AC"),
        (0x8150, "FUN_00008150 — APCB data validation/load"),
        (0x5758, "FUN_00005758 — APCB token processing"),
        (0x56C4, "FUN_000056C4 — uses 1600-byte buffer"),
        (0x850, "FUN_00000850 — called from FUN_000066A0 (param_1!=0 path)"),
    ]

    for addr, desc in targets:
        print("\n" + "-" * 60)
        print(desc)
        print("-" * 60)
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if func:
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))
                if len(c) > 4000:
                    print(c[:4000])
                    print("  ... ({} more chars)".format(len(c) - 4000))
                    # Search for key patterns
                    for kw in ['0x5d7ac', '0x5de0c', '0x660', 'param_4', 'param_5',
                               'FUN_000004e0', 'FUN_00000458', 'FUN_00001c18', 'size']:
                        idx = c.lower().find(kw.lower())
                        if idx >= 0 and idx >= 4000:
                            print("\n  [{}] at {}:".format(kw, idx))
                            print("  " + c[max(0,idx-100):min(len(c),idx+400)])
                else:
                    print(c)
        else:
            print("  No function at 0x{:X}".format(addr))

    # 5. Also: what does the code around PSP_BL offset 0x0958 do?
    # This is where 0x5D7AC is loaded — trace what happens to it
    print("\n" + "-" * 60)
    print("FUN containing 0x0958 (loads 0x5D7AC)")
    print("-" * 60)
    func = func_mgr.getFunctionContaining(space.getAddress(0x0958))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            # Search for 0x5d7ac
            idx = c.lower().find('0x5d7ac')
            if idx < 0:
                idx = c.lower().find('dat_00000bb8')
            if idx >= 0:
                print(c[max(0,idx-300):min(len(c),idx+800)])
            else:
                print(c[:3000])
    else:
        print("  No function")

    decomp.dispose()
    print("\nDone.")
