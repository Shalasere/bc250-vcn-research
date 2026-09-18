#!/usr/bin/env python3
"""Decompile FUN_000057C4 — the function that writes to FUN_000053C4's 1600-byte stack buffer.

FUN_000053C4 calls:
    FUN_000057c4(0x73, auStack_664, 0, 0, 1, 0, 0)
where auStack_664 is a 1600-byte stack buffer.

If FUN_000057C4 can write MORE than 1600 bytes to param_2, we have the overflow.

Also decompile the full call chain:
  FUN_000057C4 → what does it call? How is the size determined?

And trace the APCB data flow: where does the size come from in the APCB?
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

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

    # 1. FUN_000057C4 — THE critical function
    print("=" * 70)
    print("1. FUN_000057C4 — writes to 1600-byte stack buffer")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x57C4))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x57C4))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c)  # Print ALL — this is the key function
    else:
        print("  No function at 0x57C4")

    # 2. FUN_00005758 — related APCB token function (from prior analysis)
    print("\n" + "=" * 70)
    print("2. FUN_00005758 — APCB token processing")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x5758))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x5758))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c)
    else:
        print("  No function at 0x5758")

    # 3. FUN_0000571A — APCB token extractor
    print("\n" + "=" * 70)
    print("3. FUN_0000571A — APCB token extractor")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x571A))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x571A))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c)
    else:
        print("  No function at 0x571A")

    # 4. Look for OTHER functions called by FUN_000057C4
    # (identified from its decompile above)
    # We need to check: does 057C4 call 00000458 (memcpy) or FUN_0000823C (bounded copy)?

    # 5. FUN_00008064 — called by FUN_00007014 before FUN_000071AC
    # and FUN_00008150 — called by FUN_000053C4
    print("\n" + "=" * 70)
    print("5. FUN_00008064 — APCB validation (called from FUN_00007014)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x8064))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x8064))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 5000:
                print(c)
            else:
                print(c[:5000])
                print("  ... ({} more)".format(len(c) - 5000))

    # 6. FUN_00000850 — called by FUN_000053C4 before FUN_000057C4
    # This allocates something that might determine the copy size
    print("\n" + "=" * 70)
    print("6. FUN_00000850 — resource allocator")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x850))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x850))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 5000:
                print(c)
            else:
                print(c[:5000])

    # 7. The SVC stack: check the literal pool around the SVC vector for SP values
    # and check FUN_000044CC's entry for SP manipulation
    print("\n" + "=" * 70)
    print("7. SVC vector table entries (addresses)")
    print("=" * 70)
    # ARM exception vectors: each is LDR PC, [PC, #0x18]
    # The handler addresses are at 0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x3C
    for i, name in enumerate(["Reset", "Undef", "SVC", "Prefetch", "Data", "Reserved", "IRQ", "FIQ"]):
        addr = 0x20 + i * 4
        val = struct.unpack_from("<I", pspbl, addr)[0]
        print("  0x{:04X}: 0x{:08X} ({})".format(addr, val, name))

    # 8. Check what's at the LP referenced by the reset handler at 0x148
    # LDR LR, [PC, #0x264] → PC = 0x148+8 = 0x150, #0x264 → 0x3B4
    print("\n  Reset handler jumps to:")
    lp_addr = 0x3B4
    if lp_addr < len(pspbl) - 3:
        val = struct.unpack_from("<I", pspbl, lp_addr)[0]
        print("  LP at 0x{:04X}: 0x{:08X}".format(lp_addr, val))
        if val & 1:
            print("  -> Thumb entry at 0x{:04X}".format(val & ~1))
        else:
            print("  -> ARM entry at 0x{:04X}".format(val))

    # Also check the BLX target at 0x194: LDR r12, [PC, #0x220] → 0x194+8+0x220 = 0x3BC
    lp_addr2 = 0x3BC
    if lp_addr2 < len(pspbl) - 3:
        val = struct.unpack_from("<I", pspbl, lp_addr2)[0]
        print("  Handler dispatch: LP at 0x{:04X}: 0x{:08X}".format(lp_addr2, val))

    # 9. Check the Thumb code at the reset handler target for SP initialization
    print("\n" + "=" * 70)
    print("9. Thumb entry point — SP initialization search")
    print("=" * 70)
    # The reset handler jumps to a Thumb address. Find it.
    target_addr = struct.unpack_from("<I", pspbl, 0x3B4)[0]
    thumb_addr = target_addr & ~1
    if thumb_addr < len(pspbl):
        print("  Entry at 0x{:04X}:".format(thumb_addr))
        from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
        cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
        code = pspbl[thumb_addr:min(len(pspbl), thumb_addr+200)]
        insns = list(cs.disasm(code, thumb_addr))
        for insn in insns[:60]:
            ann = ""
            if 'sp' in insn.op_str.lower():
                ann = "  *** SP"
            print("  0x{:04X}: {:10s} {}{}".format(insn.address, insn.mnemonic, insn.op_str, ann))

    # 10. Search ENTIRE PSP_BL for MSR/MOV that sets SP directly
    print("\n" + "=" * 70)
    print("10. ALL instructions that write to SP in PSP_BL (via disassembly)")
    print("=" * 70)
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
    cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    all_insns = list(cs.disasm(pspbl, 0))
    sp_writes = []
    for insn in all_insns:
        # Look for MOV SP, LDR SP, or MSR with sp
        if insn.mnemonic in ('mov', 'mov.w', 'ldr', 'ldr.w'):
            parts = insn.op_str.split(',')
            if len(parts) >= 1 and parts[0].strip() == 'sp':
                sp_writes.append(insn)
                print("  0x{:04X}: {:10s} {}".format(insn.address, insn.mnemonic, insn.op_str))

    decomp.dispose()

print("\nDone.")
