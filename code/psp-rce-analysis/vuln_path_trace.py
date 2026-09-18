#!/usr/bin/env python3
"""Trace the vulnerability path from APCB to dispatch pointer.

Key findings so far:
- FUN_0006B590 writes param_1+0x660 = DAT_0006b5f8 (hardcoded)
- Condition: FUN_0006BC50(*(*(param_2+0x3c4))+0x5e) checks 2 bits
- If condition FAILS, context+0x660 keeps its previous value
- local_34 = context pointer (passed as param to ABL4)

Questions:
1. What's DAT_0006b5f8? (expected 0x60FE9 = ABL4 function pointer)
2. What does FUN_0006bbc0 do? (called before the dispatch writes)
3. What populates local_34 (context pointer)?
4. What's at context+0x660 BEFORE FUN_0006B590 runs?
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# Part 1: Read literal pool values from FUN_0006B590
print("=" * 70)
print("PART 1: FUN_0006B590 literal pool values (dispatch pointers)")
print("=" * 70)

pool_entries = {
    0x6B5F8: "+0x660 dispatch ptr",
    0x6B5FC: "+0x630",
    0x6B600: "+0x628",
    0x6B604: "+0x62c",
    0x6B608: "+0x5c0",
    0x6B60C: "+0x654",
    0x6B610: "+0x5b8",
    0x6B614: "+0x614",
}

for va, desc in pool_entries.items():
    file_off = va - ABL4_BASE
    if 0 <= file_off < len(abl4) - 3:
        val = struct.unpack_from("<I", abl4, file_off)[0]
        print("  DAT_{:05X} = 0x{:08X}  ({})".format(va, val, desc))
        # Check if it's a Thumb function pointer (odd = Thumb)
        if val & 1:
            print("    → Thumb function at 0x{:05X}".format(val & ~1))
        elif 0x60000 <= val <= 0x80000:
            print("    → ARM function at 0x{:05X}".format(val))

# Part 2: What's at 0xB814 in PSP_BL (config+0x660 source)
print("\n" + "=" * 70)
print("PART 2: PSP_BL config+0x660 source data")
print("=" * 70)

# DAT_000077e8 = 0xB814 (from previous run)
# FUN_000075A4 writes: _DAT_0004f660 = *DAT_000077e8 = *0xB814
val_b814 = struct.unpack_from("<I", pspbl, 0xB814)[0]
val_b818 = struct.unpack_from("<I", pspbl, 0xB818)[0]
val_b81c = struct.unpack_from("<I", pspbl, 0xB81C)[0]
val_b820 = struct.unpack_from("<I", pspbl, 0xB820)[0]
print("  [0xB814] = 0x{:08X}  (written to config+0x660)".format(val_b814))
print("  [0xB818] = 0x{:08X}".format(val_b818))
print("  [0xB81C] = 0x{:08X}".format(val_b81c))
print("  [0xB820] = 0x{:08X}  (written to config+0x664)".format(val_b820))

# Show context around 0xB814 to understand what data structure it's in
print("\n  Context around 0xB814 (APCB-related data area):")
for off in range(0xB800, 0xB840, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    marker = " ←" if off in (0xB814, 0xB820) else ""
    print("    [0x{:04X}] = 0x{:08X}{}".format(off, val, marker))

# Part 3: Check what PSP_BL has at the context structure area BEFORE ABL4 runs
print("\n" + "=" * 70)
print("PART 3: PSP_BL SRAM at context structure area (0x5D7AC)")
print("=" * 70)

# Static binary = pre-boot state. At runtime, BSS is zeroed and data is populated.
# Check what the static binary has at 0x5D7AC (context base) and 0x5DE0C (context+0x660)
context_base = 0x5D7AC
dispatch_offset = 0x660

if context_base + dispatch_offset + 4 <= len(pspbl):
    val = struct.unpack_from("<I", pspbl, context_base + dispatch_offset)[0]
    print("  [0x{:05X}] (context+0x660 in static binary) = 0x{:08X}".format(
        context_base + dispatch_offset, val))
else:
    print("  0x5DE0C is beyond PSP_BL binary ({} bytes)".format(len(pspbl)))
    print("  Context+0x660 is in the STACK/HEAP region → initialized at runtime")

# Check the config buffer area
config_base = 0x4F000
if config_base + dispatch_offset + 4 <= len(pspbl):
    val = struct.unpack_from("<I", pspbl, config_base + dispatch_offset)[0]
    print("  [0x{:05X}] (config+0x660 in static binary) = 0x{:08X}".format(
        config_base + dispatch_offset, val))
else:
    print("  0x4F660 is beyond PSP_BL binary")

# Part 4: Decompile FUN_0006BBC0 and check ABL4 entry setup
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

    # FUN_0006BBC0 — called from FUN_0006B590 before dispatch writes
    print("\n" + "=" * 70)
    print("FUN_0006BBC0 — context initialization before dispatch writes")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6BBC0))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6BBC0))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:8000] if len(c) > 8000 else c)

    # FUN_00069FAC — called early in FUN_0006BC64, might set local_34
    print("\n" + "=" * 70)
    print("FUN_00069FAC — early init (might set context pointer)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x69FAC))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x69FAC))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:6000] if len(c) > 6000 else c)

    # FUN_00069BE8 — called from FUN_0006B590 before condition check
    print("\n" + "=" * 70)
    print("FUN_00069BE8 — called before FUN_0006BC50 condition")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x69BE8))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x69BE8))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:05X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:4000] if len(c) > 4000 else c)

    # Now trace HOW local_34 gets its value in FUN_0006BC64
    # Decode the first ~60 Thumb instructions of FUN_0006BC64
    print("\n" + "=" * 70)
    print("PART 5: FUN_0006BC64 entry — raw Thumb decode (first 80 halfwords)")
    print("=" * 70)

    func_off = 0x6BC64 - ABL4_BASE  # file offset
    for i in range(func_off, func_off + 160, 2):
        if i + 1 >= len(abl4):
            break
        hw = struct.unpack_from("<H", abl4, i)[0]
        va = i + ABL4_BASE

        desc = ""
        if (hw & 0xFF00) == 0xDF00:
            desc = "SVC #{}".format(hw & 0xFF)
        elif (hw & 0xFE00) == 0xB400:
            regs = []
            for bit in range(8):
                if hw & (1 << bit):
                    regs.append("R{}".format(bit))
            if hw & 0x100:
                regs.append("LR")
            desc = "PUSH {{{}}}".format(",".join(regs))
        elif (hw & 0xFE00) == 0xBC00:
            regs = []
            for bit in range(8):
                if hw & (1 << bit):
                    regs.append("R{}".format(bit))
            if hw & 0x100:
                regs.append("PC")
            desc = "POP {{{}}}".format(",".join(regs))
        elif (hw & 0xF800) == 0x2000:
            desc = "MOVS R{}, #0x{:X}".format((hw >> 8) & 7, hw & 0xFF)
        elif (hw & 0xF800) == 0x2800:
            desc = "CMP R{}, #0x{:X}".format((hw >> 8) & 7, hw & 0xFF)
        elif hw == 0x4770:
            desc = "BX LR"
        elif hw == 0x46C0:
            desc = "NOP"
        elif (hw & 0xFF00) == 0xB000:
            if hw & 0x80:
                desc = "SUB SP, SP, #0x{:X}".format((hw & 0x7F) * 4)
            else:
                desc = "ADD SP, SP, #0x{:X}".format((hw & 0x7F) * 4)
        elif (hw & 0xFE00) == 0x4600:
            lo = hw & 7
            hi = ((hw >> 4) & 8) | lo
            src = (hw >> 3) & 0xF
            desc = "MOV R{}, R{}".format(hi, src)
        elif (hw & 0xF800) == 0xA800:
            desc = "ADD R{}, SP, #0x{:X}".format((hw >> 8) & 7, (hw & 0xFF) * 4)
        elif (hw & 0xF800) == 0x9000:
            desc = "STR R{}, [SP, #0x{:X}]".format((hw >> 8) & 7, (hw & 0xFF) * 4)
        elif (hw & 0xF800) == 0x9800:
            desc = "LDR R{}, [SP, #0x{:X}]".format((hw >> 8) & 7, (hw & 0xFF) * 4)
        elif (hw & 0xF800) == 0x4800:
            pool_off = (hw & 0xFF) * 4
            pool_va = (va & ~3) + 4 + pool_off
            pool_file = pool_va - ABL4_BASE
            if 0 <= pool_file < len(abl4) - 3:
                pool_val = struct.unpack_from("<I", abl4, pool_file)[0]
                desc = "LDR R{}, [PC, #0x{:X}] → [0x{:05X}]=0x{:08X}".format(
                    (hw >> 8) & 7, pool_off, pool_va, pool_val)
            else:
                desc = "LDR R{}, [PC, #0x{:X}]".format((hw >> 8) & 7, pool_off)
        elif (hw & 0xF800) == 0xF000:
            if i + 3 < len(abl4):
                hw2 = struct.unpack_from("<H", abl4, i + 2)[0]
                if (hw2 & 0xD000) == 0xD000:
                    s = (hw >> 10) & 1
                    imm10 = hw & 0x3FF
                    j1 = (hw2 >> 13) & 1
                    j2 = (hw2 >> 11) & 1
                    imm11 = hw2 & 0x7FF
                    i1 = (~(j1 ^ s)) & 1
                    i2 = (~(j2 ^ s)) & 1
                    imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
                    if s:
                        imm32 |= 0xFE000000
                        imm32 -= 0x100000000
                    target = (va + 4 + imm32) & 0xFFFFFFFF
                    desc = "BL 0x{:05X}".format(target)
                else:
                    desc = "[32-bit: 0x{:04X}{:04X}]".format(hw, hw2)

        print("  0x{:05X}: 0x{:04X}  {}".format(va, hw, desc))

    # Part 6: Check the APCB token that controls the capability bits
    # FUN_0006BC50 checks bits at *(*(param_2+0x3c4))+0x5e
    # param_2 = *local_34 (first word of context)
    # If param_2 points to a sub-structure that's APCB-derived...
    print("\n" + "=" * 70)
    print("PART 6: Search for offset 0x3c4 usage in ABL4")
    print("=" * 70)

    # Search for 0x3c4 as a 16-bit value in ABL4
    needle = struct.pack("<H", 0x3C4)
    idx = 0
    count = 0
    while True:
        idx = abl4.find(needle, idx)
        if idx < 0:
            break
        va = idx + ABL4_BASE
        if count < 30:
            # Check context: is this a LDR with offset?
            # Thumb LDR Rd, [Rn, #imm] with large offset uses 32-bit encoding
            # Check if part of a 32-bit Thumb instruction
            if idx >= 2:
                prev_hw = struct.unpack_from("<H", abl4, idx - 2)[0]
                if (prev_hw & 0xFFF0) == 0xF8D0:  # LDR.W Rt, [Rn, #imm12]
                    rn = prev_hw & 0xF
                    rt = (struct.unpack_from("<H", abl4, idx)[0] >> 12) & 0xF
                    print("  VA 0x{:05X}: LDR.W R{}, [R{}, #0x3C4]".format(
                        va - 2, rt, rn))
                    count += 1
                    idx += 1
                    continue
            count += 1
        idx += 1
    print("  Total 0x3C4 references: {}".format(count))

    decomp.dispose()

print("\nDone.")
