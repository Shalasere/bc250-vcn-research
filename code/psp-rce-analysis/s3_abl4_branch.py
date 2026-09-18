#!/usr/bin/env python3
"""Check if ABL4 skips FUN_0006B590 on S3 resume — the CVE-2023-31316 question.

FUN_00000328 launches ABL4 with:
  Cold boot: FUN_00000328(0, fresh_context_addr)
  S3 resume: FUN_00000328(1, saved_context_addr)

ABL4 receives mode in R0 and context in R1.

If ABL4 skips initialization (FUN_0006B590) on S3 resume, and the saved
context contains a corrupted +0x660 from DRAM, Vector D is viable.

Also: decode raw bytes at 0x328 (launch function, 4 bytes).
And: what's at DAT_00005504 (S3 context address)?
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

# =====================================================================
# PART 1: Raw bytes at 0x328 (launch function)
# =====================================================================
print("=" * 70)
print("PART 1: Raw bytes at PSP_BL 0x328 (launch function)")
print("=" * 70)

# Check if this is ARM or Thumb
for off in range(0x320, 0x340, 4):
    word = struct.unpack_from("<I", pspbl, off)[0]
    # Try ARM decode
    desc = ""
    cond = (word >> 28) & 0xF
    if (word & 0x0FFFFFF0) == 0x012FFF10:
        rn = word & 0xF
        desc = "BX R{} (cond={})".format(rn, cond)
    elif (word & 0x0FFFFFF0) == 0x012FFF30:
        rn = word & 0xF
        desc = "BLX R{} (cond={})".format(rn, cond)
    elif (word & 0x0F000000) == 0x0B000000:
        imm24 = word & 0xFFFFFF
        if imm24 & 0x800000:
            imm24 = imm24 | 0xFF000000
            if imm24 >= 0x80000000:
                imm24 = imm24 - 0x100000000
        target = off + 8 + imm24 * 4
        desc = "BL 0x{:X} (cond={})".format(target, cond)
    elif (word & 0x0E5F0000) == 0x041F0000:
        rd = (word >> 12) & 0xF
        imm12 = word & 0xFFF
        desc = "LDR R{}, [PC, #0x{:X}]".format(rd, imm12)
    elif (word & 0x0FFF0FF0) == 0x01A00000:
        rd = (word >> 12) & 0xF
        rm = word & 0xF
        desc = "MOV R{}, R{} (cond={})".format(rd, rm, cond)
    elif (word & 0x0E000000) == 0x0A000000:
        imm24 = word & 0xFFFFFF
        if imm24 & 0x800000:
            imm24 = imm24 | 0xFF000000
            if imm24 >= 0x80000000:
                imm24 = imm24 - 0x100000000
        target = off + 8 + imm24 * 4
        link = "L" if (word >> 24) & 1 else ""
        desc = "B{} 0x{:X} (cond={})".format(link, target, cond)
    print("  0x{:03X}: 0x{:08X}  {}".format(off, word, desc))

# Also show Thumb decode at 0x328
print("\n  Thumb decode at 0x328:")
for off in range(0x328, 0x340, 2):
    hw = struct.unpack_from("<H", pspbl, off)[0]
    print("    0x{:03X}: 0x{:04X}".format(off, hw))

# =====================================================================
# PART 2: What's at DAT_00005504? (S3 context address source)
# =====================================================================
print("\n" + "=" * 70)
print("PART 2: DAT_00005504 and nearby (S3 resume data)")
print("=" * 70)

for addr in range(0x5500, min(0x5520, len(pspbl) - 3), 4):
    val = struct.unpack_from("<I", pspbl, addr)[0]
    print("  [0x{:04X}] = 0x{:08X}".format(addr, val))

# =====================================================================
# PART 3: ABL4 entry point — does it branch on mode parameter?
# =====================================================================
print("\n" + "=" * 70)
print("PART 3: ABL4 entry point — checking for S3 resume branch")
print("=" * 70)

# ABL4 starts at VA 0x60834 = file offset 0
# First 64 bytes of ABL4 code
print("  First 64 bytes of ABL4 (VA 0x60834):")
for off in range(0, 64, 4):
    word = struct.unpack_from("<I", abl4, off)[0]
    va = off + ABL4_BASE
    # Try ARM decode (entry trampoline is ARM)
    desc = ""
    cond = (word >> 28) & 0xF
    if (word & 0x0FFFFFF0) == 0x012FFF10:
        rn = word & 0xF
        desc = "BX R{} (cond={})".format(rn, cond)
    elif (word & 0x0E000000) == 0x0A000000:
        imm24 = word & 0xFFFFFF
        if imm24 & 0x800000:
            imm24 = imm24 | 0xFF000000
            if imm24 >= 0x80000000:
                imm24 = imm24 - 0x100000000
        target = va + 8 + imm24 * 4
        link = "L" if (word >> 24) & 1 else ""
        desc = "B{} 0x{:05X} (cond={})".format(link, target, cond)
    elif (word & 0x0FF000F0) == 0x01200070:
        desc = "BKPT"
    elif (word & 0x0E5F0000) == 0x041F0000:
        rd = (word >> 12) & 0xF
        imm12 = word & 0xFFF
        pool_va = va + 8 + imm12
        desc = "LDR R{}, [PC, #0x{:X}] -> pool 0x{:05X}".format(rd, imm12, pool_va)
    elif (word & 0x0FFF0FF0) == 0x01A00000:
        rd = (word >> 12) & 0xF
        rm = word & 0xF
        desc = "MOV R{}, R{} (cond={})".format(rd, rm, cond)
    elif (word & 0x0E000010) == 0x00000000:
        # Data processing (register)
        op = (word >> 21) & 0xF
        ops = ["AND","EOR","SUB","RSB","ADD","ADC","SBC","RSC",
               "TST","TEQ","CMP","CMN","ORR","MOV","BIC","MVN"]
        rd = (word >> 12) & 0xF
        rn = (word >> 16) & 0xF
        rm = word & 0xF
        desc = "{} R{}, R{}, R{} (cond={})".format(ops[op], rd, rn, rm, cond)
    print("  0x{:05X}: 0x{:08X}  {}".format(va, word, desc))

# =====================================================================
# PART 4: Ghidra — decompile ABL4 entry and FUN_0006BC64 for S3 branch
# =====================================================================
import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

pyghidra.start(install_dir=GHIDRA_DIR)

with pyghidra.open_program(
    ABL4_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_abl4_v3", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # ABL4 entry point
    print("\n" + "=" * 70)
    print("PART 4a: ABL4 entry point decompilation")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x60834))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x60834))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # FUN_0006BC64 — main boot (search for S3 branch)
    print("\n" + "=" * 70)
    print("PART 4b: FUN_0006BC64 — searching for S3/resume branching")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6BC64))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6BC64))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            lines = c.split('\n')
            print("  Total: {} lines".format(len(lines)))

            # Search for mode checks, param_1 comparisons, S3/resume indicators
            # Also search for FUN_0006B590 call
            for i, line in enumerate(lines):
                stripped = line.strip().lower()
                if any(kw in stripped for kw in ['param_1', '0x6b590', 'resume',
                        'cold', 'mode', '== 0', '== 1', '!= 0',
                        '6b590', '0x660']):
                    start_ctx = max(0, i - 2)
                    end_ctx = min(len(lines), i + 3)
                    for j in range(start_ctx, end_ctx):
                        marker = " <<<" if j == i else ""
                        print("  {:4d}: {}{}".format(j, lines[j], marker))
                    print()

            # Also show the FIRST 80 lines (function entry, parameter handling)
            print("\n  First 80 lines of FUN_0006BC64:")
            for i in range(min(80, len(lines))):
                print("  {:4d}: {}".format(i, lines[i]))

    # =====================================================================
    # PART 5: PSP_BL FUN_0000196C — real S3 validation
    # =====================================================================
    decomp.dispose()

print("\n" + "=" * 70)
print("PART 5: PSP_BL FUN_0000196C (S3 validation)")
print("=" * 70)

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

    func = func_mgr.getFunctionAt(space.getAddress(0x196C))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x196C))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:8000] if len(c) > 8000 else c)

    decomp.dispose()

print("\nDone.")
