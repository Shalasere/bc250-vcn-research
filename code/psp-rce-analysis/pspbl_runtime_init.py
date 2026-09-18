#!/usr/bin/env python3
"""Trace initialization of runtime values at 0x9A20 (bounds) and 0x9A24 (mask).

These are THE critical values for the DMA overshoot:
- *(0x9A20) = upper bound in FUN_0000823C's check
- *(0x9A24) = mask in FUN_00002C80's offset computation

If either is uninitialized (e.g., missing APCB group skips the init path),
the DMA destination is unconstrained.

Approach:
1. Find ALL literal pool refs to 0x9A20 and 0x9A24
2. For each ref, find the code that loads it
3. Check if the code WRITES to *(0x9A20) or *(0x9A24) (STR pattern)
4. Decompile the containing function to understand conditions
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

# 1. Find ALL literal pool entries pointing to 0x9A20 and 0x9A24
print("=" * 70)
print("1. Literal pool entries for 0x9A20 (bounds) and 0x9A24 (mask)")
print("=" * 70)

targets = {0x9A20: [], 0x9A24: []}
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val in targets:
        targets[val].append(off)
        print("  +0x{:04X}: 0x{:08X}".format(off, val))

# 2. For each literal pool entry, find code that loads it
print("\n" + "=" * 70)
print("2. Code that loads these literal pool entries")
print("=" * 70)

load_sites = {}  # (target_addr, lp_off) -> code_off

for target_addr, lp_offsets in targets.items():
    for lp_off in lp_offsets:
        print("\n  --- 0x{:04X} via literal pool at +0x{:04X} ---".format(target_addr, lp_off))
        # Search backwards from lp_off for Thumb16 LDR Rt, [PC, #imm8*4]
        found = False
        for code_off in range(max(0, lp_off - 1024), lp_off, 2):
            hw = struct.unpack_from("<H", pspbl, code_off)[0]
            if (hw & 0xF800) == 0x4800:  # LDR Rt, [PC, #imm]
                rt = (hw >> 8) & 7
                imm8 = hw & 0xFF
                pc_val = ((code_off + 4) & ~3)
                target = pc_val + imm8 * 4
                if target == lp_off:
                    found = True
                    load_sites[(target_addr, lp_off)] = (code_off, rt)
                    # Show surrounding context (before and after)
                    ctx_start = max(0, code_off - 8)
                    ctx_end = min(len(pspbl), code_off + 40)
                    insns = list(cs.disasm(pspbl[ctx_start:ctx_end], ctx_start))
                    has_str = False
                    for insn in insns:
                        m = " >>>" if insn.address == code_off else "    "
                        is_str = ""
                        if insn.mnemonic.startswith('str') and 'r{}'.format(rt) in insn.op_str:
                            is_str = " <<< WRITE to *0x{:04X}!".format(target_addr)
                            has_str = True
                        elif insn.mnemonic.startswith('ldr') and '[r{}' .format(rt) in insn.op_str:
                            is_str = " <<< READ from *0x{:04X}".format(target_addr)
                        print("  {} 0x{:04X}: {:10s} {}{}".format(
                            m, insn.address, insn.mnemonic, insn.op_str, is_str))
                    if has_str:
                        print("  *** WRITE FOUND at this site ***")
        if not found:
            print("  (no Thumb16 LDR found — may be Thumb32)")
            # Check Thumb32 LDR.W patterns
            all_insns = list(cs.disasm(pspbl[max(0,lp_off-1024):lp_off], max(0,lp_off-1024)))
            for insn in all_insns:
                if insn.mnemonic.startswith('ldr') and '0x{:x}'.format(lp_off) in insn.op_str.lower():
                    print("  T32: 0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# 3. Also scan for STR.W with [Rn] where Rn loaded 0x9A20 or 0x9A24
# This catches indirect patterns where the LDR and STR are further apart
print("\n" + "=" * 70)
print("3. Extended STR scan — looking for writes to *(0x9A20) and *(0x9A24)")
print("=" * 70)

# For each function that references 0x9A20 or 0x9A24, decompile it
# to find writes
write_functions = set()
for (target_addr, lp_off), (code_off, rt) in load_sites.items():
    # Check more context for STR
    ctx_start = code_off
    ctx_end = min(len(pspbl), code_off + 100)
    insns = list(cs.disasm(pspbl[ctx_start:ctx_end], ctx_start))
    for insn in insns:
        if insn.mnemonic.startswith('str'):
            if 'r{}'.format(rt) in insn.op_str:
                print("  WRITE: 0x{:04X}: {} {} (target=0x{:04X}, loaded at 0x{:04X})".format(
                    insn.address, insn.mnemonic, insn.op_str, target_addr, code_off))
                write_functions.add((insn.address, target_addr))
            # Also check if the register was moved to another register first
        elif insn.mnemonic == 'mov' and 'r{}'.format(rt) in insn.op_str:
            # Track register rename
            pass
        elif insn.mnemonic in ['bl', 'blx', 'bx', 'b.w', 'pop']:
            break  # Stop at branches

# 4. Ghidra: decompile functions that WRITE to 0x9A20 and 0x9A24
print("\n" + "=" * 70)
print("4. Ghidra decompilation — functions that reference 0x9A20/0x9A24")
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

    # Find all functions containing references to 0x9A20 or 0x9A24
    ref_functions = set()
    for (target_addr, lp_off), (code_off, rt) in load_sites.items():
        func = func_mgr.getFunctionContaining(space.getAddress(code_off))
        if func:
            ref_functions.add((func.getEntryPoint().getOffset(), target_addr))

    for func_addr, target_addr in sorted(ref_functions):
        func = func_mgr.getFunctionAt(space.getAddress(func_addr))
        if func:
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            print("\n" + "-" * 60)
            print("{} at 0x{:04X} ({} bytes) — refs 0x{:04X}".format(
                func.getName(), entry, size, target_addr))
            print("-" * 60)
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))
                # Show full decomp for smaller functions, abbreviated for large ones
                if len(c) <= 5000:
                    print(c)
                else:
                    print(c[:3000])
                    print("  ... ({} more chars)".format(len(c) - 3000))
                    # Search for key patterns
                    for kw in ['0x9a20', '0x9a24', 'DAT_', '*DAT', 'param_', 'mask',
                               'bound', 'size', 'len']:
                        for idx in range(len(c)):
                            if c[idx:idx+len(kw)].lower() == kw.lower():
                                if idx >= 3000:
                                    print("\n  [{}] at {}:".format(kw, idx))
                                    print("  " + c[max(0,idx-100):min(len(c),idx+300)])
                                break

    # 5. Also decompile FUN_00008168 more thoroughly — it initializes 0x9A10
    # and likely other runtime values in the same flow
    print("\n" + "-" * 60)
    print("5. FUN_00008168 — full decompile (init path)")
    print("-" * 60)
    func = func_mgr.getFunctionAt(space.getAddress(0x8168))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c)

    # 6. Who CALLS FUN_00008168? That's the init sequence
    print("\n" + "-" * 60)
    print("6. Who calls FUN_00008168?")
    print("-" * 60)
    # Search for BL 0x8168 in the binary
    for off in range(0, len(pspbl) - 3, 2):
        insns = list(cs.disasm(pspbl[off:off+4], off))
        for insn in insns:
            if insn.mnemonic == 'bl' and '0x8168' in insn.op_str:
                func = func_mgr.getFunctionContaining(space.getAddress(off))
                fname = func.getName() if func else "???"
                faddr = func.getEntryPoint().getOffset() if func else 0
                print("  0x{:04X}: bl 0x8168 (in {} @ 0x{:04X})".format(off, fname, faddr))

    # 7. Decompile the CALLERS of FUN_00008168 to see the full init chain
    print("\n" + "-" * 60)
    print("7. Decompiling callers of FUN_00008168")
    print("-" * 60)
    # We already found them above, let's just decompile any unique callers
    caller_addrs = set()
    for off in range(0, len(pspbl) - 3, 2):
        insns = list(cs.disasm(pspbl[off:off+4], off))
        for insn in insns:
            if insn.mnemonic == 'bl' and '0x8168' in insn.op_str:
                func = func_mgr.getFunctionContaining(space.getAddress(off))
                if func:
                    caller_addrs.add(func.getEntryPoint().getOffset())

    for addr in sorted(caller_addrs):
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if func:
            print("\n  Caller: {} at 0x{:04X}".format(func.getName(), addr))
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))
                if len(c) <= 4000:
                    print(c)
                else:
                    print(c[:4000])
                    print("  ... ({} more chars)".format(len(c) - 4000))

    decomp.dispose()

print("\nDone.")
