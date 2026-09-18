#!/usr/bin/env python3
"""Decode PSP_BL early boot code (0x000-0x050) and search for SVC
vector patching.

The code from 0x000 to 0x04C runs BEFORE VBAR=0x100 is set. This code
runs with MMU off, so all SRAM is directly accessible. Any STR to 0x108
would patch the SVC vector.

Also:
1. Decompile FUN_00005B40 (references [0x9280] = 0x100)
2. Manually decode ARM instructions at 0x000-0x098
3. Search for computed stores to address 0x108
4. Check ABL4's config buffer access via pointer parameter
"""
import struct

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

print("=" * 70)
print("PART 0: Raw ARM instruction decode of PSP_BL 0x000-0x0A8")
print("=" * 70)

def decode_arm(addr, word):
    """Basic ARM instruction decoder."""
    cond = (word >> 28) & 0xF
    cond_s = ["eq","ne","cs","cc","mi","pl","vs","vc",
              "hi","ls","ge","lt","gt","le","","nv"][cond]

    # Check instruction type
    bits_27_25 = (word >> 25) & 7
    bits_24_21 = (word >> 21) & 0xF

    # Branch (B/BL)
    if bits_27_25 == 5:
        link = "BL" if (word >> 24) & 1 else "B"
        offset = word & 0xFFFFFF
        if offset & 0x800000:
            offset -= 0x1000000
        target = addr + 8 + offset * 4
        return "{}{} 0x{:05X}".format(link, cond_s, target & 0xFFFFFFFF)

    # Data processing
    if bits_27_25 in (0, 1):
        opcodes = ["AND","EOR","SUB","RSB","ADD","ADC","SBC","RSC",
                    "TST","TEQ","CMP","CMN","ORR","MOV","BIC","MVN"]
        op = bits_24_21
        s = "S" if (word >> 20) & 1 else ""
        rd = (word >> 12) & 0xF
        rn = (word >> 16) & 0xF
        is_imm = (word >> 25) & 1

        if is_imm:
            imm = word & 0xFF
            rot = ((word >> 8) & 0xF) * 2
            if rot:
                val = ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF
            else:
                val = imm
            if op in (0xD, 0xF):  # MOV, MVN
                return "{}{}{} R{}, #0x{:X}".format(opcodes[op], cond_s, s, rd, val)
            elif op in (0x8, 0x9, 0xA, 0xB):  # TST, TEQ, CMP, CMN
                return "{}{} R{}, #0x{:X}".format(opcodes[op], cond_s, rn, val)
            else:
                return "{}{}{} R{}, R{}, #0x{:X}".format(opcodes[op], cond_s, s, rd, rn, val)
        else:
            rm = word & 0xF
            if op in (0xD, 0xF):
                return "{}{}{} R{}, R{}".format(opcodes[op], cond_s, s, rd, rm)
            else:
                return "{}{}{} R{}, R{}, R{}".format(opcodes[op], cond_s, s, rd, rn, rm)

    # Load/Store
    if bits_27_25 in (2, 3):
        is_load = (word >> 20) & 1
        is_byte = (word >> 22) & 1
        is_up = (word >> 23) & 1
        is_pre = (word >> 24) & 1
        rn = (word >> 16) & 0xF
        rd = (word >> 12) & 0xF
        offset = word & 0xFFF
        if not is_up:
            offset = -offset

        op = "LDR" if is_load else "STR"
        b = "B" if is_byte else ""
        if rn == 15:  # PC-relative
            pool = addr + 8 + offset
            if 0 <= pool < len(pspbl):
                pool_val = struct.unpack_from("<I", pspbl, pool)[0]
                return "{}{}{} R{}, [PC, #{}] → [0x{:03X}]=0x{:08X}".format(
                    op, cond_s, b, rd, offset, pool & 0xFFFF, pool_val)
        if is_pre:
            return "{}{}{} R{}, [R{}, #{}]".format(op, cond_s, b, rd, rn, offset)
        else:
            return "{}{}{} R{}, [R{}], #{}".format(op, cond_s, b, rd, rn, offset)

    # Coprocessor
    if (word & 0x0F000010) == 0x0E000010:
        cp = (word >> 8) & 0xF
        is_mrc = (word >> 20) & 1
        crn = (word >> 16) & 0xF
        rd = (word >> 12) & 0xF
        crm = word & 0xF
        opc1 = (word >> 21) & 7
        opc2 = (word >> 5) & 7
        op = "MRC" if is_mrc else "MCR"
        return "{} p{}, {}, R{}, c{}, c{}, {}".format(op, cp, opc1, rd, crn, crm, opc2)

    # BX/BLX
    if (word & 0x0FFFFFF0) == 0x012FFF10:
        rm = word & 0xF
        return "BX{} R{}".format(cond_s, rm)
    if (word & 0x0FFFFFF0) == 0x012FFF30:
        rm = word & 0xF
        return "BLX{} R{}".format(cond_s, rm)

    # MSR/MRS
    if (word & 0x0FBF0FFF) == 0x010F0000:
        rd = (word >> 12) & 0xF
        return "MRS R{}, {}".format(rd, "SPSR" if (word >> 22) & 1 else "CPSR")
    if (word & 0x0DBFF000) == 0x0129F000:
        rm = word & 0xF
        return "MSR {}, R{}".format("SPSR" if (word >> 22) & 1 else "CPSR", rm)

    # LDM/STM
    if bits_27_25 == 4:
        is_load = (word >> 20) & 1
        rn = (word >> 16) & 0xF
        regs = word & 0xFFFF
        reg_list = [str(i) for i in range(16) if regs & (1 << i)]
        op = "LDM" if is_load else "STM"
        return "{}{} R{}, {{{}}}".format(op, cond_s, rn, ",".join(reg_list))

    return "??? 0x{:08X}".format(word)

# Decode 0x000-0x0A8
for off in range(0x000, 0x0B0, 4):
    word = struct.unpack_from("<I", pspbl, off)[0]
    desc = decode_arm(off, word)
    marker = ""
    if off == 0x04C:
        marker = "  ← VBAR write"
    elif off == 0x108:
        marker = "  ← SVC VECTOR"
    print("  0x{:03X}: 0x{:08X}  {}{}".format(off, word, desc, marker))

# Part 1: Decode the vector table area (0x100-0x120) with the decoder
print("\n" + "=" * 70)
print("PART 1: Vector table at 0x100 decoded")
print("=" * 70)

vec_names = ["Reset", "Undef", "SVC", "PrefAbort", "DataAbort",
             "Reserved", "IRQ", "FIQ"]
for i in range(8):
    off = 0x100 + i * 4
    word = struct.unpack_from("<I", pspbl, off)[0]
    desc = decode_arm(off, word)
    print("  [0x{:03X}] {}: 0x{:08X}  {}".format(off, vec_names[i], word, desc))

# Part 2: Look at what's between the init code and the vector table
# The code at 0x0A8 seems to end the entry point (BX R12 at 0x0A8)
# Then there's more code from 0x0AC to 0x0FF
print("\n" + "=" * 70)
print("PART 2: Code between entry point and vector table (0x0A8-0x100)")
print("=" * 70)

for off in range(0x0A8, 0x100, 4):
    word = struct.unpack_from("<I", pspbl, off)[0]
    desc = decode_arm(off, word)
    print("  0x{:03X}: 0x{:08X}  {}".format(off, word, desc))

# Part 3: Decode 0x120-0x198 (between vector table and SVC handler)
print("\n" + "=" * 70)
print("PART 3: Code between vector table and SVC handler (0x120-0x198)")
print("=" * 70)

for off in range(0x120, 0x1A0, 4):
    word = struct.unpack_from("<I", pspbl, off)[0]
    desc = decode_arm(off, word)
    print("  0x{:03X}: 0x{:08X}  {}".format(off, word, desc))

# Part 4: What writes to the FIRST PAGE (0x000-0xFFF)?
# After FUN_000035A0 makes it R/W, check if FUN_000075A4 could
# accidentally write near 0x108 (it writes to 0x4F000 range, not 0x100 range)
print("\n" + "=" * 70)
print("PART 4: Search for STR instructions targeting 0x100-0x120 range")
print("=" * 70)

# Manual search: find ARM STR instructions that could target 0x108
# Pattern: STR Rd, [Rn, #imm] where the literal pool loaded into Rn is 0x100
# and imm is 8

# First, find ALL LDR instructions that load 0x100
ldr_100 = []
for off in range(0, len(pspbl), 4):
    word = struct.unpack_from("<I", pspbl, off)[0]
    # LDR Rd, [PC, #imm] = 0xE59F0xxx (unconditional, PC-relative)
    if (word & 0x0F7F0000) == 0x051F0000 or (word & 0x0F7F0000) == 0x059F0000:
        is_up = (word >> 23) & 1
        imm = word & 0xFFF
        rd = (word >> 12) & 0xF
        if is_up:
            pool_addr = off + 8 + imm
        else:
            pool_addr = off + 8 - imm
        if 0 <= pool_addr < len(pspbl) - 3:
            pool_val = struct.unpack_from("<I", pspbl, pool_addr)[0]
            if pool_val == 0x100:
                ldr_100.append((off, rd, pool_addr))

print("  LDR Rd, [PC, #x] loading 0x100:")
for off, rd, pa in ldr_100:
    func_name = "?"
    print("    0x{:04X}: LDR R{}, [pool 0x{:04X}]".format(off, rd, pa))

    # Now check the next ~20 instructions for a STR to [Rd, #8]
    for check in range(off + 4, min(off + 80, len(pspbl)), 4):
        w2 = struct.unpack_from("<I", pspbl, check)[0]
        # STR Rx, [Rn, #8] where Rn = rd
        if (w2 & 0x0FFF0FFF) == (0x05800008 | (rd << 16)):
            rx = (w2 >> 12) & 0xF
            print("    *** 0x{:04X}: STR R{}, [R{}, #8] → writes to 0x108! ***".format(
                check, rx, rd))

# Part 5: The BLX R2 at 0x070 — what function does it call?
print("\n" + "=" * 70)
print("PART 5: Function at 0x394D (called via BLX R2 at 0x070)")
print("=" * 70)

# From 0x06C: LDR R2, [PC, #0x31C] → pool at 0x390 = 0x0000394D
val = struct.unpack_from("<I", pspbl, 0x390)[0]
print("  [0x390] = 0x{:08X} → Thumb entry at 0x{:04X}".format(val, val & ~1))

# Part 6: Check 0x394C (Thumb function called at early boot)
import os
os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

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

    # Decompile function at 0x394C (Thumb, called from entry)
    func = func_mgr.getFunctionAt(space.getAddress(0x394C))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x394C))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            if '0x108' in c or '0x198' in c:
                print("  *** Contains vector table references! ***")
            if '0x100' in c:
                print("  Contains 0x100 reference")
            print(c[:4000] if len(c) > 4000 else c)
    else:
        print("  No function at 0x394C")

    # Decompile FUN_00005B40 (references VBAR value 0x100)
    print("\n" + "=" * 70)
    print("FUN_00005B40 — references [0x9280]=0x100")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x5B40))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x5B40))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            if '0x108' in c or 'DAT_00000108' in c:
                print("  *** WRITES TO SVC VECTOR! ***")
            print(c[:6000] if len(c) > 6000 else c)
    else:
        print("  No function at 0x5B40")

    # Part 7: Find ALL literal pool references to 0x198 (SVC handler)
    print("\n" + "=" * 70)
    print("PART 7: Literal pool references to 0x198 (SVC handler)")
    print("=" * 70)

    for i in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, i)[0]
        if val == 0x198 or val == 0x199:
            print("  [0x{:04X}] = 0x{:08X}".format(i, val))

    decomp.dispose()

print("\nDone.")
