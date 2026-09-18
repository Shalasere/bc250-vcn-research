#!/usr/bin/env python3
"""Trace writes to SRAM 0x9A10 and re-decompile FUN_000066A0.

The DMA destination in FUN_000071AC is: *(0x9A10) + param_4 + 0x100
If *(0x9A10) points near 0x5D7AC and param_4 is large enough, the DMA
could reach context+0x660 (= 0x5DE0C).

Also need to understand FUN_000066A0's local_2c computation, since that
becomes FUN_000071AC's param_4 (the offset added to the DMA base).
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

# 1. Find ALL code that references 0x9A10 (writes or reads)
print("=" * 70)
print("1. ALL references to 0x9A10 in PSP_BL")
print("=" * 70)

# Search literal pools for 0x9A10
print("  Literal pool entries pointing to 0x9A10:")
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val == 0x9A10:
        print("    +0x{:04X}: 0x00009A10".format(off))

# Find code that loads addresses pointing to those literal pool entries
# Thumb16 LDR Rt, [PC, #imm8*4]
print("\n  Code loading literal pool entries that contain 0x9A10:")
lp_offsets = []
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val == 0x9A10:
        lp_offsets.append(off)

for lp_off in lp_offsets:
    # Search backwards from lp_off for LDR instructions targeting it
    for code_off in range(max(0, lp_off - 1024), lp_off, 2):
        hw = struct.unpack_from("<H", pspbl, code_off)[0]
        if (hw & 0xF800) == 0x4800:
            rt = (hw >> 8) & 7
            imm8 = hw & 0xFF
            pc_val = ((code_off + 4) & ~3)
            target = pc_val + imm8 * 4
            if target == lp_off:
                print("    0x{:04X}: LDR r{}, [PC] -> 0x{:04X} (=0x9A10)".format(code_off, rt, lp_off))
                # Show surrounding context to understand if it's a read or write
                ctx_start = max(0, code_off - 8)
                ctx_end = min(len(pspbl), code_off + 24)
                insns = list(cs.disasm(pspbl[ctx_start:ctx_end], ctx_start))
                for insn in insns:
                    m = " >>>" if insn.address == code_off else "    "
                    is_str = " STR!" if insn.mnemonic.startswith('str') else ""
                    print("      {} 0x{:04X}: {:10s} {}{}".format(m, insn.address, insn.mnemonic, insn.op_str, is_str))

# 2. Also search for STR to [r_n] where r_n was loaded with 0x9A10
# This requires tracing — let me just look for STR patterns after each LDR
print("\n" + "=" * 70)
print("2. STR instructions near 0x9A10 loads (write patterns)")
print("=" * 70)
for lp_off in lp_offsets:
    for code_off in range(max(0, lp_off - 1024), lp_off, 2):
        hw = struct.unpack_from("<H", pspbl, code_off)[0]
        if (hw & 0xF800) == 0x4800:
            rt = (hw >> 8) & 7
            imm8 = hw & 0xFF
            pc_val = ((code_off + 4) & ~3)
            target = pc_val + imm8 * 4
            if target == lp_off:
                # Found a load of 0x9A10 into register rt
                # Look for STR instructions in the next 40 bytes that use rt as base
                print("  At 0x{:04X}: r{} = 0x9A10, looking for STR [r{},...]:".format(code_off, rt, rt))
                search_insns = list(cs.disasm(pspbl[code_off:code_off+60], code_off))
                for si in search_insns:
                    if si.mnemonic.startswith('str') and 'r{}'.format(rt) in si.op_str:
                        print("    >>> 0x{:04X}: {} {}".format(si.address, si.mnemonic, si.op_str))
                    elif si.mnemonic in ['bl', 'blx', 'bx', 'b', 'pop']:
                        break  # Stop at branch/return

# 3. Now re-decompile FUN_000066A0 to trace local_2c
print("\n" + "=" * 70)
print("3. FUN_000066A0 — full decompile to trace local_2c")
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
        (0x66A0, "FUN_000066A0 — APCB data processing (full decompile)"),
        (0x8BC, "FUN_000008BC — called from FUN_00000850 (APCB entry setup)"),
        (0x37FC, "FUN_000037FC — APCB group lookup (re-check for local_2c)"),
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
                print(c[:8000])
                if len(c) > 8000:
                    print("  ... ({} more chars)".format(len(c) - 8000))
        else:
            print("  No function at 0x{:X}".format(addr))

    # 4. Find the function that INITIALIZES 0x9A10
    # It's in PSP_BL's runtime data area. Who writes to it?
    # Search for FUN_000075A4 (config builder) and FUN_00000300 (SVC handler)
    # to see if they write to 0x9A10
    print("\n" + "-" * 60)
    print("4. FUN_000075A4 — check for writes to 0x9A10 region")
    print("-" * 60)
    func = func_mgr.getFunctionAt(space.getAddress(0x75A4))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Search for 0x9a10 or DAT_00009a
            for kw in ['0x9a10', '0x9a', 'DAT_00009a']:
                idx = c.lower().find(kw.lower())
                if idx >= 0:
                    print("  FOUND '{}' at {}:".format(kw, idx))
                    print("  " + c[max(0,idx-200):min(len(c),idx+400)])
            # Also check if it writes to *(any_ptr) = computed_value
            # where any_ptr is in the 0x9xxx range
            print("\n  First 3000 chars:")
            print(c[:3000])

    # 5. Check FUN_00005F9C — called from FUN_000053C4
    print("\n" + "-" * 60)
    print("5. FUN_00005F9C — APCB entry setup (called from FUN_000053C4)")
    print("-" * 60)
    func = func_mgr.getFunctionAt(space.getAddress(0x5F9C))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:4000])

    decomp.dispose()
    print("\nDone.")
