#!/usr/bin/env python3
"""Resolve: is 0x4F000 the context, or does it feed into 0x5D7AC?

FUN_000075A4 writes to 0x4F000+0x660, but ABL4 context is at 0x5D7AC.
0x4F000 + 0x660 = 0x4F660
0x5D7AC + 0x660 = 0x5DE0C

These are 0xE7AC bytes apart. Need to understand the relationship.

Questions:
1. What literal pool values feed the +0x660 store? (DAT_000077e8)
2. Does any PSP_BL function load 0x5D7AC and write to +0x660 via it?
3. Does FUN_0000120c (called at end of FUN_000075A4) copy from 0x4F000 to 0x5D7AC?
4. Does the SVC return mechanism copy the buffer?
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# 1. Read ALL literal pool entries in FUN_000075A4 (offsets 0x77B8 - 0x7868)
print("=" * 70)
print("1. Literal pool for FUN_000075A4 (0x77B8 - 0x7868)")
print("=" * 70)
for off in range(0x77B8, min(0x7870, len(pspbl)), 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    # Check if it's a pointer to SRAM (0x3xxxx - 0x6xxxx range)
    region = ""
    if 0x30000 <= val <= 0x70000:
        region = " [PSP SRAM]"
    elif 0x1000000 <= val <= 0x2000000:
        region = " [SMN/MMIO]"
    elif val < 0x10000:
        region = " [PSP_BL code/data]"
    print("  0x{:04X}: 0x{:08X}{}".format(off, val, region))

# 2. The critical literal pool: DAT_000077E8 (source of +0x660 value)
print("\n" + "=" * 70)
print("2. DAT_000077E8 and DAT_000077EC (sources for +0x660 and +0x66C)")
print("=" * 70)
# From capstone:
# 0x7624: ldr r0, [pc, #0x1c0] → literal at 0x77E8
# 0x7628: ldr r1, [r0]         → dereference
# 0x762A: str.w r1, [r4, #0x660]
val_77e8 = struct.unpack_from("<I", pspbl, 0x77E8)[0]
val_77ec = struct.unpack_from("<I", pspbl, 0x77EC)[0]
print("  DAT_000077E8 = 0x{:08X} (source pointer for +0x660/+0x664)".format(val_77e8))
print("  DAT_000077EC = 0x{:08X} (source pointer for +0x66C/+0x670)".format(val_77ec))
# These point to memory locations that contain the actual values
# The values at those addresses are what end up at +0x660

# 3. Check: does 0x5D7AC appear anywhere in the literal pool?
print("\n" + "=" * 70)
print("3. All references to 0x5D7AC in PSP_BL")
print("=" * 70)
count = 0
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val == 0x5D7AC:
        count += 1
        print("  Offset 0x{:04X}: literal 0x5D7AC".format(off))
# Also check for 0x5DE0C (context + 0x660)
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val == 0x5DE0C:
        print("  Offset 0x{:04X}: literal 0x5DE0C (context+0x660!)".format(off))
# Check for 0x4F000
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val == 0x4F000:
        print("  Offset 0x{:04X}: literal 0x4F000".format(off))
print("  Total 0x5D7AC refs: {}".format(count))

# 4. FUN_0000120c — called at end of FUN_000075A4 with args (0, 1, 0x4F000, 0x1000)
# This could be the function that copies the buffer to ABL4-visible memory
print("\n" + "=" * 70)
print("4. FUN_0000120c (called with 0x4F000, 0x1000 at end of FUN_000075A4)")
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

    # 4a. Decompile FUN_0000120c
    func = func_mgr.getFunctionAt(space.getAddress(0x120C))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:5000])
    else:
        print("  No function at 0x120C")
        # Check if it's a data address being called
        for delta in range(-8, 9, 2):
            f = func_mgr.getFunctionAt(space.getAddress(0x120C + delta))
            if f:
                print("  Found {} at 0x{:X}".format(f.getName(), 0x120C + delta))

    # 4b. Decompile FUN_00000598 (called at start with 0x4F000, 0x1000)
    print("\n  FUN_00000598 (buffer init):")
    func = func_mgr.getFunctionAt(space.getAddress(0x598))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:3000])

    # 5. Check FUN_00004150 (called mid-function with crypto-like args)
    print("\n  FUN_00004150 (called mid-function):")
    func = func_mgr.getFunctionAt(space.getAddress(0x4150))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 300, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:3000])

    # 6. Who CALLS FUN_000075A4? Trace back to SVC dispatch
    print("\n" + "=" * 70)
    print("6. Callers of FUN_000075A4")
    print("=" * 70)
    addr_75a4 = space.getAddress(0x75A4)
    refs = list(program.getReferenceManager().getReferencesTo(addr_75a4))
    for r in refs:
        src = r.getFromAddress().getOffset()
        func = func_mgr.getFunctionContaining(r.getFromAddress())
        fname = func.getName() if func else "?"
        print("  Called from 0x{:04X} in {}".format(src, fname))

    # 7. Decompile ALL functions that reference 0x5D7AC
    # This might reveal which function actually writes to the REAL context+0x660
    print("\n" + "=" * 70)
    print("7. Functions using context pointer 0x5D7AC")
    print("=" * 70)
    # From step 3, we know 0x5D7AC appears at offset 0x0BB8
    # Who loads from that literal pool entry?
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    cs.detail = True

    # Find LDR PC-relative that would load from 0x0BB8
    # Thumb LDR Rt, [PC, #imm8*4]: opcode 0x4800 | (Rt<<8) | (imm8)
    # PC-relative load: effective = (PC & ~3) + 4 + imm8*4
    # Also Thumb2 LDR.W Rt, [PC, #imm12]
    print("  Looking for PC-relative loads that target literal pool at 0x0BB8...")
    for off in range(0, min(0x0BB8, len(pspbl)), 2):
        hw = struct.unpack_from("<H", pspbl, off)[0]
        # Thumb16 LDR Rt, [PC, #imm]
        if (hw & 0xF800) == 0x4800:
            rt = (hw >> 8) & 7
            imm8 = hw & 0xFF
            pc_val = ((off + 4) & ~3)  # Thumb PC = current + 4, aligned
            target = pc_val + imm8 * 4
            if target == 0x0BB8:
                func = func_mgr.getFunctionContaining(space.getAddress(off))
                fname = func.getName() if func else "?"
                print("  Offset 0x{:04X}: LDR r{}, [PC, #0x{:X}] → 0x{:04X} (0x5D7AC) in {}".format(
                    off, rt, imm8*4, target, fname))

    # Also check Thumb2 LDR.W Rt, [PC, #imm12]
    for off in range(0, min(0x0BB8, len(pspbl) - 3), 2):
        hw1 = struct.unpack_from("<H", pspbl, off)[0]
        if (hw1 & 0xFF7F) == 0xF85F:  # LDR.W Rt, [PC, ±imm12]
            hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]
            imm12 = hw2 & 0xFFF
            u = (hw1 >> 7) & 1  # add/sub
            rt = (hw2 >> 12) & 0xF
            pc_val = ((off + 4) & ~3)
            if u:
                target = pc_val + imm12
            else:
                target = pc_val - imm12
            if target == 0x0BB8:
                func = func_mgr.getFunctionContaining(space.getAddress(off))
                fname = func.getName() if func else "?"
                print("  Offset 0x{:04X}: LDR.W r{}, [PC, #0x{:X}] → 0x{:04X} (0x5D7AC) in {}".format(
                    off, rt, imm12, target, fname))

    # 8. What about STR via computed address?
    # If PSP_BL loads 0x5D7AC into a register, then ADDs offset, then STRs
    # Let me find all loads of 0x5D7AC
    print("\n" + "=" * 70)
    print("8. STR instructions near 0x5D7AC loads")
    print("=" * 70)
    # Disassemble full PSP_BL and find patterns
    insns = list(cs.disasm(pspbl[:0x9A00], 0))
    # Build instruction index
    insn_map = {i.address: i for i in insns}
    # Find all LDR that produce 0x5D7AC
    for i, insn in enumerate(insns):
        if insn.mnemonic.startswith('ldr') and 'pc' in insn.op_str:
            # PC-relative load — check if it loads 0x5D7AC
            # We know the literal is at 0x0BB8
            op_str = insn.op_str
            # The loaded value is from the literal pool
            # Check a few instructions ahead for STR with offset 0x660 or large offsets
            for j in range(i+1, min(i+20, len(insns))):
                next_insn = insns[j]
                if next_insn.mnemonic.startswith('str') and '#0x660' in next_insn.op_str:
                    print("  0x{:04X}: {} {} → 0x{:04X}: {} {}".format(
                        insn.address, insn.mnemonic, insn.op_str,
                        next_insn.address, next_insn.mnemonic, next_insn.op_str))

    # 9. Final check: maybe the 0x4F000 buffer IS mapped to where ABL4 sees context
    # PSP virtual memory: 0x4F000 in PSP might map to 0x5D7AC in the physical view?
    # Or: maybe ABL4's context pointer is loaded from a PSP-controlled location
    print("\n" + "=" * 70)
    print("9. PSP memory layout hypothesis")
    print("=" * 70)
    print("  PSP_BL code: 0x0000 - 0x9A00")
    print("  0x4F000 buffer: 0x4F000 - 0x50000 (initialized by FUN_000075A4)")
    print("  ABL4 context: 0x5D7AC (literal pool at 0x0BB8)")
    print("  ABL4 code: 0x60834 - 0x75FB4")
    print()
    print("  These are all in the PSP SRAM (256KB: 0x00000-0x3FFFF)")
    print("  Wait: 0x4F000 and 0x5D7AC are BOTH above 0x3FFFF!")
    print("  0x4F000 = 0x4F000 (317 KB — might be in a different region)")
    print("  0x5D7AC = 0x5D7AC (374 KB)")
    print("  0x60834 = 0x60834 (386 KB)")
    print()
    print("  Could be a flat physical map where:")
    print("  - Boot ROM / PSP_BL: 0x00000-0x09A00")
    print("  - General SRAM: 0x4F000 area")
    print("  - Context struct: 0x5D7AC")
    print("  - ABL4 loaded code: 0x60834+")

    # 10. Check: maybe FUN_0000120c does memory mapping / cache flush
    # Args: (0, 1, 0x4F000, 0x1000) — this could be:
    #   - SVC return (return data to caller)
    #   - Memory region permission update
    #   - Cache/TLB operation
    print("\n" + "=" * 70)
    print("10. FUN_0000120c callers (how is it used elsewhere?)")
    print("=" * 70)
    addr_120c = space.getAddress(0x120C)
    refs = list(program.getReferenceManager().getReferencesTo(addr_120c))
    for r in refs:
        src = r.getFromAddress().getOffset()
        func = func_mgr.getFunctionContaining(r.getFromAddress())
        fname = func.getName() if func else "?"
        # Get context: show a few instructions before the call
        off = src
        context_start = max(0, off - 20)
        context_insns = list(cs.disasm(pspbl[context_start:off+4], context_start))
        args = ""
        for ci in context_insns[-6:]:
            args += "  {} {} | ".format(ci.mnemonic, ci.op_str)
        print("  0x{:04X} in {}: {}".format(src, fname, args))

    decomp.dispose()
    print("\nDone.")
