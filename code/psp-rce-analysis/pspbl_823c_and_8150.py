#!/usr/bin/env python3
"""Critical analysis: FUN_0000823c (the bounded copy) and FUN_00008150.

The call chain for the 1600-byte stack buffer:
  FUN_000053c4: auStack_664[1600], calls FUN_000057c4(0x73, auStack_664, ...)
  FUN_000057c4: calls FUN_000074c8(auStack_664, 0x640, 0x73, 0)
  FUN_000074c8: calls FUN_00008150(auStack_664, src_addr, src_size, 0x640, 0)
  FUN_00008150: calls FUN_0000823c(...) — passes through r0-r3 + stack arg

Question: Does FUN_0000823c check that src_size <= 0x640?

Also:
1. Raw disassembly of FUN_00008150 (22 bytes)
2. Full decompile of FUN_0000823c
3. Decompile FUN_0000083c (APCB token lookup — returns size)
4. Decompile FUN_00001C18 (DMA copy in FUN_000071AC)
5. Check if there's a path where the APCB token size exceeds the buffer
"""
import os, struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# 1. Raw disassembly of FUN_00008150 (22 bytes)
print("=" * 70)
print("1. FUN_00008150 raw disassembly (22 bytes at 0x8150)")
print("=" * 70)
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True
for insn in cs.disasm(pspbl[0x8150:0x8166], 0x8150):
    ops = insn.op_str
    ann = ""
    if insn.mnemonic == 'ldr' and '[pc' in ops:
        try:
            pc = (insn.address + 4) & ~3
            parts = ops.split('#')
            if len(parts) >= 2:
                imm = int(parts[1].rstrip(']').strip(), 0)
                pool_addr = pc + imm
                if 0 <= pool_addr < len(pspbl):
                    val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                    ann = "  ; [0x{:X}]=0x{:08X}".format(pool_addr, val)
        except:
            pass
    print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))

# Also get the raw bytes
print("  Raw: {}".format(pspbl[0x8150:0x8166].hex()))

# 2. Disassemble FUN_0000823c (used in many places)
print("\n" + "=" * 70)
print("2. FUN_0000823c raw disassembly")
print("=" * 70)
# Get the function size — scan until we hit a POP or BX LR
end = 0x823c + 200
for insn in cs.disasm(pspbl[0x823c:end], 0x823c):
    ops = insn.op_str
    ann = ""
    if insn.mnemonic == 'ldr' and '[pc' in ops:
        try:
            pc = (insn.address + 4) & ~3
            parts = ops.split('#')
            if len(parts) >= 2:
                imm = int(parts[1].rstrip(']').strip(), 0)
                pool_addr = pc + imm
                if 0 <= pool_addr < len(pspbl):
                    val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                    ann = "  ; [0x{:X}]=0x{:08X}".format(pool_addr, val)
        except:
            pass
    print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))
    # Stop at return
    if insn.mnemonic.lower() in ['pop', 'bx'] and 'pc' in ops.lower():
        break
    if insn.mnemonic.lower() == 'bx' and 'lr' in ops.lower():
        break

# 3. Ghidra decompilation
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
        (0x823C, "FUN_0000823C — THE BOUNDED COPY FUNCTION"),
        (0x083C, "FUN_0000083C — APCB token lookup (returns token addr+size)"),
        (0x1C18, "FUN_00001C18 — DMA copy function"),
        (0x237C, "FUN_0000237C — copy/verify in FUN_00007014"),
        (0x62BE, "FUN_000062BE — alt copy in FUN_000071AC"),
        (0x571A, "FUN_0000571A — called from FUN_000055C0"),
        (0x5758, "FUN_00005758 — called from FUN_000074c8"),
        (0x8488, "FUN_00008488 — called from FUN_000056C4"),
        (0x8500, "FUN_00008500 — cert verify in FUN_00007014"),
    ]

    for addr, desc in targets:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if func:
            entry = func.getEntryPoint().getOffset()
            fsize = func.getBody().getNumAddresses()
            print("\n" + "=" * 70)
            print("{} at 0x{:04X} ({} bytes)".format(desc, entry, fsize))
            print("=" * 70)
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                if len(c) <= 4000:
                    print(c)
                else:
                    print(c[:4000])
                    print("\n... ({} more chars)".format(len(c) - 4000))
        else:
            print("\n  No Ghidra function at 0x{:04X}".format(addr))

    # 4. Specific: How does FUN_000074c8 pass args to FUN_00008150?
    # The decompile showed: FUN_00008150(param_1, local_28[0], local_2c, param_2, 0)
    # But Ghidra shows FUN_00008150 with 3 params. Let's check the CALL SITE
    # in FUN_000074c8 at the assembly level
    print("\n" + "=" * 70)
    print("4. FUN_000074c8 calling FUN_00008150 — instruction-level")
    print("=" * 70)
    # Disassemble FUN_000074c8 (146 bytes at 0x74C8)
    for insn in cs.disasm(pspbl[0x74C8:0x74C8+146], 0x74C8):
        ops = insn.op_str
        ann = ""
        mn = insn.mnemonic.lower()
        if 'r0' in ops or 'r1' in ops or 'r2' in ops or 'r3' in ops:
            ann = " ** ARGS **"
        if mn in ['bl', 'blx']:
            ann = " *** CALL ***"
            # Try to resolve target
            if insn.mnemonic == 'bl':
                try:
                    for op in insn.operands:
                        if op.type == 2:  # immediate
                            ann += " → 0x{:04X}".format(op.imm & 0xFFFFFFFF)
                except:
                    pass
        if insn.mnemonic == 'ldr' and '[pc' in ops:
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
        # Also show PUSH for args on stack
        if mn == 'push' or (mn.startswith('str') and 'sp' in ops):
            ann = " ** STACK ARG? **"
        print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))

    decomp.dispose()

print("\nDone.")
