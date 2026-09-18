#!/usr/bin/env python3
"""Decompile the finalization chain and remaining uninspected functions.

1. FUN_000082E6 — finalization, called at end of boot
2. FUN_000035A0 — called by FUN_000082E6 (from prior session summary)
3. FUN_000075A4 — called by FUN_000035A0
4. FUN_00002C80 — boot-time APCB group finder (param_1==0 path in FUN_000066A0)
5. FUN_00006650 — called after APCB group processing in FUN_00000300

Also: Read the value at key LP addresses to understand SRAM layout.
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# Read DAT values that are SRAM pointers used during context setup
print("=" * 70)
print("KEY DAT values for context setup")
print("=" * 70)
# The context is at 0x5D7AC. Who writes to it?
# LP at 0x0BB8 = 0x5D7AC = DAT_00000BB8
# Which functions reference LP at 0x0BB8?
# In Thumb, literal pool loads use PC-relative: LDR Rn, [PC, #offset]
# The instruction that loads from 0x0BB8 is at PC where PC+4+offset = 0x0BB8

# Search for ALL Thumb LDR instructions that reference the 0x0BB8-0x0C00 range
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

print("\nInstructions that load from LP 0x0BB8-0x0BF0:")
for off in range(0, min(len(pspbl), 0x9A00) - 3, 2):
    insns = list(cs.disasm(pspbl[off:off+4], off))
    for insn in insns:
        if insn.mnemonic.startswith('ldr') and '[pc' in insn.op_str:
            # Extract the target LP address
            # LDR Rn, [PC, #imm] → target = (PC + 4) & ~3 + imm
            # For Thumb: PC = instruction address
            pc_aligned = (insn.address + 4) & ~3
            try:
                # Parse immediate from op_str
                parts = insn.op_str.split('#')
                if len(parts) >= 2:
                    imm_str = parts[1].rstrip(']').strip()
                    imm = int(imm_str, 0)
                    target = pc_aligned + imm
                    if 0x0BB8 <= target <= 0x0BF0:
                        val = struct.unpack_from("<I", pspbl, target)[0]
                        print("  0x{:04X}: {} {} → LP 0x{:04X} = 0x{:08X}".format(
                            insn.address, insn.mnemonic, insn.op_str, target, val))
            except (ValueError, struct.error):
                pass

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
        (0x82E6, "FUN_000082E6 — finalization (end of boot)"),
        (0x35A0, "FUN_000035A0 — called by finalization"),
        (0x75A4, "FUN_000075A4 — called by FUN_000035A0"),
        (0x2C80, "FUN_00002C80 — boot-time APCB group finder"),
        (0x6650, "FUN_00006650 — post-group-processing"),
        (0x72A0, "FUN_000072A0 — called before group processing"),
        (0x7A20, "FUN_00007A20 — called in boot sequence"),
        (0x7C08, "FUN_00007C08 — called in boot sequence"),
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

                # Check for references to context region (0x5D000-0x5E000)
                context_refs = re.findall(r'0x0*5[dD][0-9a-fA-F]{3}', c)
                if context_refs:
                    print("  !!! CONTEXT REGION REFERENCES: {}".format(context_refs))

                # Check for DAT references
                dat_refs = re.findall(r'DAT_0000[0-9a-f]+', c, re.I)
                if dat_refs:
                    unique_dats = sorted(set(dat_refs))
                    print("  DAT references: {}".format(unique_dats))

                # Check for copy operations
                for kw in ['FUN_0000823c', 'FUN_00008150', 'FUN_000004e0',
                           'FUN_00000458', 'FUN_00001c18']:
                    if kw in c:
                        print("  *** CALLS {} ***".format(kw))

                # Check for stack buffers
                buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
                if buffers:
                    print("  !!! STACK BUFFERS:")
                    for name, size in buffers:
                        print("    {} [{}]".format(name, size))

                if len(c) <= 4000:
                    print(c)
                else:
                    print(c[:4000])
                    print("\n  ... ({} more chars)".format(len(c) - 4000))
        else:
            print("\n  No function at 0x{:04X}".format(addr))

    decomp.dispose()

print("\nDone.")
