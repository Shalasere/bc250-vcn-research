#!/usr/bin/env python3
"""Deep analysis of the PSP_BL function at +0x0944 that loads the context base.

Also:
1. Full disassembly of 0x0944 to POP PC (capstone)
2. Identify ALL literal pool references in this function
3. Decompile FUN_00001C18 (APCB copy from SPI to SRAM)
4. Decompile FUN_00007DB8 (the actual SVC instruction)
5. Determine the SVC number used to call context init
6. Find ALL callers of FUN_000004E0 (memcpy) in PSP_BL
7. Decompile FUN_00003568 (memory mapper)
"""
import os, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# ===================== PART 1: Full disassembly of function at +0x0944 =====================
print("=" * 70)
print("PART 1: Full disassembly of function at +0x0944")
print("=" * 70)

code = pspbl[0x0944:0x0C00]  # Generous range
insns = list(cs.disasm(code, 0x0944))

pool_refs = {}
reg_vals = {}

for insn in insns:
    mn = insn.mnemonic.lower()
    ops = insn.op_str

    # Track literal pool loads
    pool_info = ""
    if mn == 'ldr' and 'pc' in ops.lower():
        for op in insn.operands:
            if op.type == 4 and op.mem.base == 15:
                pc = (insn.address + 4) & ~3
                pool_addr = pc + op.mem.disp
                if 0 <= pool_addr < len(pspbl):
                    pool_val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                    pool_info = "  ; pool[0x{:04X}] = 0x{:08X}".format(pool_addr, pool_val)
                    pool_refs[insn.address] = (pool_addr, pool_val)
                    rd = insn.reg_name(insn.operands[0].reg)
                    reg_vals[rd] = pool_val

    # Track MOVW
    if mn == 'movw':
        for op in insn.operands:
            if op.type == 2:  # IMM
                rd = insn.reg_name(insn.operands[0].reg)
                reg_vals[rd] = op.imm
                pool_info = "  ; {} = 0x{:X}".format(rd, op.imm)

    # Track MOVT
    if mn == 'movt':
        for op in insn.operands:
            if op.type == 2:
                rd = insn.reg_name(insn.operands[0].reg)
                if rd in reg_vals:
                    reg_vals[rd] = (reg_vals[rd] & 0xFFFF) | (op.imm << 16)
                    pool_info = "  ; {} = 0x{:08X}".format(rd, reg_vals[rd])

    # Annotate BL calls with known register values
    if mn == 'bl':
        args = []
        for r in ['r0', 'r1', 'r2', 'r3']:
            if r in reg_vals:
                args.append("{}=0x{:X}".format(r, reg_vals[r]))
        if args:
            pool_info = "  ; ({})".format(", ".join(args))

    print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, pool_info))

    # Stop at POP {PC}
    if mn == 'pop' and 'pc' in ops.lower():
        break

# ===================== PART 2: Decode all literal pool values =====================
print("\n" + "=" * 70)
print("PART 2: All literal pool references from function 0x0944")
print("=" * 70)
for addr, (pool_addr, pool_val) in sorted(pool_refs.items()):
    label = ""
    if pool_val == 0x5D7AC:
        label = "CONTEXT_BASE"
    elif pool_val == 0x5D5A4:
        label = "CONTEXT-0x208"
    elif pool_val == 0x03200048:
        label = "MP0_HW_ID_REG"
    elif pool_val == 0xBC0B02A0:
        label = "BC250_FINGERPRINT"
    elif pool_val == 0x5B13C:
        label = "SRAM_ADDR"
    elif pool_val == 0x3FFFC0:
        label = "SRAM_MASK"
    elif pool_val == 0x7F000:
        label = "SRAM_ADDR2"
    elif 0x100 <= pool_val <= 0x9FFF:
        label = "CODE_ADDR?"
    print("  0x{:04X}: LDR from pool[0x{:04X}] = 0x{:08X}  {}".format(
        addr, pool_addr, pool_val, label))

# ===================== PART 3: Ghidra analysis =====================
print("\n" + "=" * 70)
print("PART 3: Ghidra decompilation of key functions")
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

    # What function CONTAINS 0x0944?
    addr = space.getAddress(0x0944)
    containing = func_mgr.getFunctionContaining(addr)
    if containing:
        print("\n  0x0944 is INSIDE: {} (entry 0x{:X}, {} bytes)".format(
            containing.getName(), containing.getEntryPoint().getOffset(),
            containing.getBody().getNumAddresses()))
    else:
        print("\n  0x0944 is NOT inside any function!")
        # Try to create function at 0x0944
        from ghidra.program.model.symbol import SourceType
        txn = program.startTransaction("create_func_0944")
        try:
            from ghidra.app.cmd.function import CreateFunctionCmd
            cmd = CreateFunctionCmd(space.getAddress(0x0944))
            cmd.applyTo(program)
            new_func = func_mgr.getFunctionAt(space.getAddress(0x0944))
            if new_func:
                print("  Created function at 0x0944!")
                size = new_func.getBody().getNumAddresses()
                print("  Size: {} bytes".format(size))
                result = decomp.decompileFunction(new_func, 300, flat.getMonitor())
                if result.decompileCompleted():
                    c = result.getDecompiledFunction().getC()
                    print("\n--- Decompilation of FUN_00000944 ---")
                    print(c)
        finally:
            program.endTransaction(txn, True)

    # Decompile FUN_00001C18 (APCB copy from SPI)
    targets = [
        (0x1C18, "FUN_00001C18 (APCB copy from SPI to buffer)"),
        (0x7DB8, "FUN_00007DB8 (SVC instruction wrapper)"),
        (0x3568, "FUN_00003568 (memory mapper/allocator)"),
        (0x4E0,  "FUN_000004E0 (memcpy)"),
        (0x5094, "FUN_00005094 (release/unmap)"),
        (0x511C, "FUN_0000511C (release/unmap 2)"),
        (0x66A0, "FUN_000066A0 (memory mapping)"),
        (0x281C, "FUN_0000281C (called first from 0x0944)"),
    ]

    for va, desc in targets:
        print("\n" + "-" * 70)
        print(desc)
        print("-" * 70)
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if func:
            size = func.getBody().getNumAddresses()
            print("  {} bytes".format(size))
            result = decomp.decompileFunction(func, 300, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print(c[:6000] if len(c) > 6000 else c)
            else:
                print("  DECOMPILE FAILED")
        else:
            print("  NOT FOUND")
            # Search nearby
            for delta in range(-8, 9, 2):
                f = func_mgr.getFunctionAt(space.getAddress(va + delta))
                if f:
                    print("  Found nearby: {} at 0x{:X}".format(f.getName(), va + delta))

    # Find ALL callers of FUN_000004E0 (memcpy) via references
    print("\n" + "=" * 70)
    print("ALL callers of FUN_000004E0 (memcpy)")
    print("=" * 70)
    ref_mgr = program.getReferenceManager()
    memcpy_addr = space.getAddress(0x4E0)
    refs = list(ref_mgr.getReferencesTo(memcpy_addr))
    for r in refs:
        from_addr = r.getFromAddress().getOffset()
        from_func = func_mgr.getFunctionContaining(r.getFromAddress())
        fname = from_func.getName() if from_func else "?"
        entry = from_func.getEntryPoint().getOffset() if from_func else 0
        print("  0x{:04X} in {} (entry 0x{:04X})".format(from_addr, fname, entry))

    # Find ALL callers of FUN_00003568 (memory mapper)
    print("\n" + "=" * 70)
    print("ALL callers of FUN_00003568 (memory mapper)")
    print("=" * 70)
    mapper_addr = space.getAddress(0x3568)
    refs = list(ref_mgr.getReferencesTo(mapper_addr))
    for r in refs:
        from_addr = r.getFromAddress().getOffset()
        from_func = func_mgr.getFunctionContaining(r.getFromAddress())
        fname = from_func.getName() if from_func else "?"
        entry = from_func.getEntryPoint().getOffset() if from_func else 0
        print("  0x{:04X} in {} (entry 0x{:04X})".format(from_addr, fname, entry))

    decomp.dispose()
    print("\nDone.")
