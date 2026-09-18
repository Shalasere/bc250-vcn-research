#!/usr/bin/env python3
"""Deep analysis of FUN_000053C4 (1600-byte stack buffer) and VBAR changes.

1. Full decompile of FUN_000053C4 — every path through auStack_664
2. Search Thumb code for MCR p15 c12 (VBAR writes)
3. Decompile FUN_000074C8 (the token validator that "rejects 0x73")
4. Decompile FUN_00008150 (copy function used in FUN_000053C4)
5. Check how SVC 0xDE reaches FUN_000053C4
6. Also: decompile FUN_00006992 (hash output to 16-byte buffer)
"""
import os, struct, re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# 1. Search for VBAR writes (MCR p15, 0, Rn, c12, c0, 0) in Thumb code
# MCR encoding in Thumb2: 0xEE0C_0F10 for MCR p15,0,R0,c12,c0,0
# Generic: 0xEE0C_nF10 where n = register number
print("=" * 70)
print("1. Search for MCR p15 c12 (VBAR writes) in Thumb code")
print("=" * 70)
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True
for insn in cs.disasm(pspbl[0x400:0x9A00], 0x400):
    mn = insn.mnemonic.lower()
    ops = insn.op_str.lower()
    if mn == 'mcr' and 'c12' in ops:
        print("  0x{:04X}: {} {} *** VBAR WRITE ***".format(
            insn.address, insn.mnemonic, insn.op_str))
    # Also catch MCR2 or any coprocessor writes to c12
    if mn.startswith('mcr') and 'c12' in ops:
        print("  0x{:04X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))

# Also search the ARM code region (0x0-0x400)
from capstone import CS_MODE_ARM
cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
cs_arm.detail = True
for insn in cs_arm.disasm(pspbl[:0x400], 0):
    mn = insn.mnemonic.lower()
    ops = insn.op_str.lower()
    if mn == 'mcr' and 'c12' in ops:
        print("  0x{:04X}: {} {} (ARM)".format(insn.address, insn.mnemonic, insn.op_str))

# 2. Ghidra decompilation
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
        (0x53C4, "FUN_000053C4 — 1600-byte stack buffer (FULL)"),
        (0x74C8, "FUN_000074C8 — token validator"),
        (0x8150, "FUN_00008150 — copy function"),
        (0x6992, "FUN_00006992 — hash output function"),
        (0x6EE0, "FUN_00006EE0 — hash function"),
        (0x37FC, "FUN_000037FC — APCB search/lookup"),
        (0x84A, "FUN_0000084A — token read helper"),
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
                print("  {} chars".format(len(c)))

                # Check for stack buffers
                buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
                if buffers:
                    print("  STACK BUFFERS:")
                    for name, size in buffers:
                        print("    {} [{}]".format(name, size))

                # Check for copy operations
                for kw in ['FUN_0000823c', 'FUN_00008150', 'FUN_000004e0',
                           'FUN_00000458', 'FUN_00001c18', 'FUN_000074c8',
                           'FUN_00006992', 'FUN_00006ee0', 'FUN_00008064']:
                    if kw in c:
                        print("  CALLS {}".format(kw))

                # Check for variable-size operations
                param_refs = re.findall(r'param_\d+', c)
                if param_refs:
                    unique = sorted(set(param_refs))
                    print("  PARAMS: {}".format(unique))

                if len(c) <= 5000:
                    print(c)
                else:
                    print(c[:5000])
                    print("\n... ({} more)".format(len(c) - 5000))
        else:
            print("\n  No Ghidra function at/containing 0x{:04X}".format(addr))

    # 3. Also check the SVC dispatch for case 0xDE
    print("\n" + "=" * 70)
    print("CASE 0xDE in FUN_000044CC (extract from full decompile)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x44CC))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Find the 0xDE case
            idx = c.find('0xde')
            if idx < 0:
                idx = c.find('0xDE')
            if idx < 0:
                idx = c.find('222')  # decimal 0xDE = 222
            if idx >= 0:
                start = max(0, idx - 200)
                end = min(len(c), idx + 600)
                print("  Found 0xDE reference at char {}:".format(idx))
                print(c[start:end])
            else:
                print("  0xDE not found directly, checking for FUN_000053C4 calls:")
                idx = c.find('FUN_000053c4')
                if idx < 0:
                    idx = c.find('FUN_000053C4')
                if idx >= 0:
                    start = max(0, idx - 300)
                    end = min(len(c), idx + 300)
                    print(c[start:end])
                else:
                    print("  FUN_000053C4 not found in FUN_000044CC decompile!")
                    # Search for 53c4
                    for pattern in ['53c4', '53C4', '0x53c4', 'case 0xde', 'case 222']:
                        idx = c.lower().find(pattern.lower())
                        if idx >= 0:
                            start = max(0, idx - 100)
                            end = min(len(c), idx + 500)
                            print("  Found '{}' at {}:".format(pattern, idx))
                            print(c[start:end])
                            break

    decomp.dispose()

print("\nDone.")
