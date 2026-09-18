#!/usr/bin/env python3
"""Deep analysis of APCB parsing functions in PSP_BL.

Focus on:
1. FUN_000075A4 — config buffer builder (full decompile)
2. All functions referencing APCB-related addresses
3. Functions with inline loops that copy to stack buffers
4. The APCB checksum verification code

APCB addresses:
  0xB82C — APCB header copy / token table 0
  0x7A000 — APCB group data (runtime)
  0x4F000 — config buffer (output of APCB processing)
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

OUTPUT = r"C:\Users\WORK~1.DES\AppData\Local\Temp\claude\C--Users-work-DESKTOP-SAM98TB\c5f1fa55-5f57-4770-9f66-592352064239\scratchpad\apcb_parsing_analysis.txt"

# APCB-related literal values to search for in the binary
APCB_LITERALS = [0xB82C, 0xB814, 0x7A000, 0x4F000, 0x4F200]

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# Find all literal pool entries containing APCB addresses
print("Searching for APCB literal references...")
apcb_refs = {}  # addr -> value
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val in APCB_LITERALS:
        apcb_refs[off] = val

print("Found {} literal pool entries with APCB addresses:".format(len(apcb_refs)))
for addr, val in sorted(apcb_refs.items()):
    print("  [0x{:04X}] = 0x{:05X}".format(addr, val))

# Find Thumb LDR instructions that load from these literal pool entries
print("\nInstructions loading APCB addresses:")
apcb_users = []  # (instr_addr, pool_addr, apcb_val)
for pool_addr, apcb_val in apcb_refs.items():
    for off in range(0, len(pspbl) - 1, 2):
        hw = struct.unpack_from("<H", pspbl, off)[0]
        if (hw & 0xF800) == 0x4800:
            imm = (hw & 0xFF) * 4
            pool = (off & ~3) + 4 + imm
            if pool == pool_addr:
                rd = (hw >> 8) & 7
                apcb_users.append((off, pool_addr, apcb_val, rd))
                print("  0x{:04X}: LDR R{}, [PC, #0x{:X}] -> 0x{:05X}".format(
                    off, rd, imm, apcb_val))

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

    # Find functions containing APCB references
    apcb_funcs = set()
    for instr_addr, _, apcb_val, _ in apcb_users:
        func = func_mgr.getFunctionContaining(space.getAddress(instr_addr))
        if func:
            apcb_funcs.add(func.getEntryPoint().getOffset())

    print("\nFunctions with APCB references: {}".format(len(apcb_funcs)))

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("APCB Parsing Deep Analysis\n")
        out.write("=" * 70 + "\n\n")

        # Part 1: Decompile ALL functions with APCB references
        out.write("PART 1: Functions referencing APCB addresses\n")
        out.write("-" * 70 + "\n\n")

        for addr in sorted(apcb_funcs):
            func = func_mgr.getFunctionAt(space.getAddress(addr))
            if not func:
                continue

            name = func.getName()
            fsize = func.getBody().getNumAddresses()

            result = decomp.decompileFunction(func, 300, flat.getMonitor())
            if not result or not result.decompileCompleted():
                out.write("[0x{:04X}] {} ({} bytes) -- DECOMPILE FAILED\n\n".format(
                    addr, name, fsize))
                continue

            c = result.getDecompiledFunction().getC()

            # Check for overflow indicators
            indicators = []
            has_stack = bool(re.search(r'auStack_[0-9a-fA-F]{2,}', c))
            has_loop = bool(re.search(r'while|for\s*\(|do\s*\{', c))
            has_param_write = bool(re.search(r'param_\d+\[', c))
            has_size_field = bool(re.search(r'\*\(.*\+\s*0x[0-9a-f]+\)', c))

            if has_stack:
                indicators.append("HAS_STACK_VARS")
            if has_loop:
                indicators.append("HAS_LOOPS")
            if has_param_write:
                indicators.append("WRITES_TO_PARAM")

            out.write("=" * 70 + "\n")
            out.write("[0x{:04X}] {} ({} bytes) {}\n".format(
                addr, name, fsize, " ".join(indicators)))
            out.write("=" * 70 + "\n")
            out.write(c)
            out.write("\n\n")

            print("  0x{:04X} {} ({} bytes, {} lines) {}".format(
                addr, name, fsize, len(c.split('\n')), " ".join(indicators)))

        # Part 2: Specifically look at FUN_000075A4 and its callees
        out.write("\n" + "=" * 70 + "\n")
        out.write("PART 2: FUN_000075A4 callee chain\n")
        out.write("-" * 70 + "\n\n")

        # Get callees of FUN_000075A4
        func_75a4 = func_mgr.getFunctionAt(space.getAddress(0x75A4))
        if func_75a4:
            callees = set()
            called = func_75a4.getCalledFunctions(flat.getMonitor())
            for callee in called:
                callees.add(callee.getEntryPoint().getOffset())

            out.write("FUN_000075A4 calls: {}\n\n".format(
                ", ".join("0x{:04X}".format(a) for a in sorted(callees))))

            # Decompile each callee not already shown
            for callee_addr in sorted(callees):
                if callee_addr in apcb_funcs:
                    continue  # Already decompiled above

                func = func_mgr.getFunctionAt(space.getAddress(callee_addr))
                if not func:
                    continue

                name = func.getName()
                fsize = func.getBody().getNumAddresses()

                result = decomp.decompileFunction(func, 300, flat.getMonitor())
                if not result or not result.decompileCompleted():
                    continue

                c = result.getDecompiledFunction().getC()

                has_stack = bool(re.search(r'auStack_[0-9a-fA-F]{2,}', c))
                has_loop = bool(re.search(r'while|for\s*\(|do\s*\{', c))

                out.write("[0x{:04X}] {} ({} bytes) {}{}\n".format(
                    callee_addr, name, fsize,
                    "HAS_STACK " if has_stack else "",
                    "HAS_LOOPS " if has_loop else ""))
                out.write(c)
                out.write("\n\n")

                print("  callee 0x{:04X} {} ({} bytes)".format(callee_addr, name, fsize))

        # Part 3: ARM-level search for inline copy loops targeting stack
        # Look for: STRB Rt, [SP, Rm] or STR Rt, [SP, Rm] in loops
        out.write("\n" + "=" * 70 + "\n")
        out.write("PART 3: Inline loop analysis (ARM-level)\n")
        out.write("-" * 70 + "\n\n")

        # Find backward branches (loops) and check for stack writes inside
        for off in range(0, len(pspbl) - 3, 2):
            hw = struct.unpack_from("<H", pspbl, off)[0]
            # Conditional backward branch (loop back edge)
            if (hw & 0xF000) == 0xD000:
                cond = (hw >> 8) & 0xF
                if cond < 0xE:  # Conditional
                    offset8 = hw & 0xFF
                    if offset8 & 0x80:  # Negative offset = backward branch
                        offset8 = offset8 - 256
                    target = off + 4 + offset8 * 2
                    if target < off:  # Backward branch = loop
                        # Check instructions in the loop body for stack writes
                        for body_off in range(target, off, 2):
                            body_hw = struct.unpack_from("<H", pspbl, body_off)[0]
                            # STR Rt, [SP, #imm]
                            if (body_hw & 0xF800) == 0x9000:
                                rt = (body_hw >> 8) & 7
                                imm = (body_hw & 0xFF) * 4
                                # Check if this is inside a loop with variable bounds
                                func = func_mgr.getFunctionContaining(space.getAddress(body_off))
                                if func:
                                    fn = func.getName()
                                    entry = func.getEntryPoint().getOffset()
                                    out.write("  Loop 0x{:04X}->0x{:04X} in {}: STR R{}, [SP, #0x{:X}]\n".format(
                                        target, off, fn, rt, imm))

    decomp.dispose()

print("\nResults written to: {}".format(OUTPUT))
