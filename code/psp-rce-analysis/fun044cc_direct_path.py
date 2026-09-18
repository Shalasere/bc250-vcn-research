#!/usr/bin/env python3
"""Investigate FUN_000044CC's direct-call path and its relationship to 0xB814.

KEY QUESTION: Is FUN_000044CC called directly from PSP_BL's init flow
(not via the dead SVC handler at 0x198)?

The SVC handler at 0x198 is dead (VBAR=0x100 makes SVCs NOPs), so if
FUN_000044CC executes at all, it must be via a direct BL/BLX call.

This script:
1. Find ALL callers of FUN_000044CC in PSP_BL (BL/BLX targets)
2. Find ALL callers of the dead SVC handler at 0x198 (should be none)
3. Decompile the section of FUN_000044CC that references 0xB814
4. Check if FUN_000044CC has any write primitives that could target context
5. Trace the data path: 0xB814 → what gets written where?
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

PSPBL_SIZE = len(pspbl)

# =====================================================================
# PART 1: Find ALL callers of FUN_000044CC
# =====================================================================
print("=" * 70)
print("PART 1: All callers of FUN_000044CC (0x44CC)")
print("=" * 70)

# Search for BL/BLX instructions targeting 0x44CC
# FUN_000044CC is Thumb code. Entry is 0x44CC (Thumb address = 0x44CD with bit0).
# We need to find Thumb BL instructions: F000 + F8xx/D8xx pattern
# Thumb BL: hw1 = 1111 0 Sii iiii iiii (S + imm10), hw2 = 11J1 1jjj jjjj jjjj (J1,J2 + imm11)
# Also check ARM BL: ExFF xxxx pattern

callers_44cc = []

# Thumb-2 BL search
for off in range(0, PSPBL_SIZE - 3, 2):
    hw1 = struct.unpack_from("<H", pspbl, off)[0]
    # Check for BL/BLX prefix: 11110 x xxxxxxxxxx
    if (hw1 & 0xF800) != 0xF000:
        continue
    hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]
    # BL: 11 J1 1 J2 xxxxxxxxxxx (bit 15:14 = 11, bit 12 = 1)
    if (hw2 & 0xD000) == 0xD000:
        s = (hw1 >> 10) & 1
        imm10 = hw1 & 0x3FF
        j1 = (hw2 >> 13) & 1
        j2 = (hw2 >> 11) & 1
        imm11 = hw2 & 0x7FF
        i1 = (~(j1 ^ s)) & 1
        i2 = (~(j2 ^ s)) & 1
        imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
        if s:
            imm32 |= 0xFE000000
            imm32 = imm32 - 0x100000000
        target = (off + 4 + imm32) & 0xFFFFFFFF
        if target == 0x44CC or target == 0x44CD:
            callers_44cc.append(off)
            print("  0x{:04X}: Thumb BL → 0x{:04X}".format(off, target))
    # BLX: 11 J1 0 J2 xxxxxxxxxxx (bit 12 = 0)
    elif (hw2 & 0xD000) == 0xC000:
        s = (hw1 >> 10) & 1
        imm10 = hw1 & 0x3FF
        j1 = (hw2 >> 13) & 1
        j2 = (hw2 >> 11) & 1
        imm10h = (hw2 >> 1) & 0x3FF
        i1 = (~(j1 ^ s)) & 1
        i2 = (~(j2 ^ s)) & 1
        imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm10h << 2)
        if s:
            imm32 |= 0xFE000000
            imm32 = imm32 - 0x100000000
        target = ((off + 4 + imm32) & 0xFFFFFFFC)  # BLX aligns to 4
        if target == 0x44CC or target == 0x44CD:
            callers_44cc.append(off)
            print("  0x{:04X}: Thumb BLX → 0x{:04X}".format(off, target))

# ARM BL search (in ARM code regions: 0x000-0x120 roughly)
for off in range(0, min(0x300, PSPBL_SIZE - 3), 4):
    word = struct.unpack_from("<I", pspbl, off)[0]
    cond = (word >> 28) & 0xF
    if (word & 0x0F000000) == 0x0B000000:  # BL
        imm24 = word & 0xFFFFFF
        if imm24 & 0x800000:
            imm24 |= 0xFF000000
            imm24 = imm24 - 0x100000000
        target = off + 8 + imm24 * 4
        if target == 0x44CC or target == 0x44CD:
            callers_44cc.append(off)
            print("  0x{:04X}: ARM BL → 0x{:04X} (cond={})".format(off, target, cond))

if not callers_44cc:
    print("  NO direct callers found for FUN_000044CC!")
    print("  FUN_000044CC is ONLY reachable via the dead SVC handler at 0x198")

# =====================================================================
# PART 2: Check if the dead SVC handler (0x198) has any callers
# =====================================================================
print("\n" + "=" * 70)
print("PART 2: Callers of dead SVC handler at 0x198")
print("=" * 70)

callers_198 = []
for off in range(0, PSPBL_SIZE - 3, 2):
    hw1 = struct.unpack_from("<H", pspbl, off)[0]
    if (hw1 & 0xF800) != 0xF000:
        continue
    hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]
    if (hw2 & 0xD000) == 0xD000:
        s = (hw1 >> 10) & 1
        imm10 = hw1 & 0x3FF
        j1 = (hw2 >> 13) & 1
        j2 = (hw2 >> 11) & 1
        imm11 = hw2 & 0x7FF
        i1 = (~(j1 ^ s)) & 1
        i2 = (~(j2 ^ s)) & 1
        imm32 = (s << 24) | (i1 << 23) | (i2 << 22) | (imm10 << 12) | (imm11 << 1)
        if s:
            imm32 |= 0xFE000000
            imm32 = imm32 - 0x100000000
        target = (off + 4 + imm32) & 0xFFFFFFFF
        if target == 0x198 or target == 0x199:
            callers_198.append(off)
            print("  0x{:04X}: Thumb BL → 0x{:04X}".format(off, target))

# ARM callers
for off in range(0, min(0x300, PSPBL_SIZE - 3), 4):
    word = struct.unpack_from("<I", pspbl, off)[0]
    if (word & 0x0F000000) == 0x0B000000:
        imm24 = word & 0xFFFFFF
        if imm24 & 0x800000:
            imm24 |= 0xFF000000
            imm24 = imm24 - 0x100000000
        target = off + 8 + imm24 * 4
        if target == 0x198 or target == 0x199:
            callers_198.append(off)
            print("  0x{:04X}: ARM BL → 0x{:04X}".format(off, target))

if not callers_198:
    print("  NO callers — 0x198 is only reachable via exception vector (SVC)")

# =====================================================================
# PART 3: How does FUN_000044CC reference 0xB814?
# =====================================================================
print("\n" + "=" * 70)
print("PART 3: FUN_000044CC's reference to 0xB814")
print("=" * 70)

# 0xB814 is in literal pool at 0x4E4C
# Check what instruction references 0x4E4C
print("  Literal pool [0x4E4C] = 0x{:08X}".format(
    struct.unpack_from("<I", pspbl, 0x4E4C)[0]))

# Find the LDR that loads from 0x4E4C
for off in range(0x44CC, min(0x4F00, PSPBL_SIZE - 1), 2):
    hw = struct.unpack_from("<H", pspbl, off)[0]
    # Thumb-1 LDR Rd, [PC, #imm8*4]
    if (hw & 0xF800) == 0x4800:
        imm = (hw & 0xFF) * 4
        pool = (off & ~3) + 4 + imm
        if pool == 0x4E4C:
            rd = (hw >> 8) & 7
            print("  0x{:04X}: LDR R{}, [PC, #0x{:X}] -> pool 0x{:04X} = 0xB814".format(
                off, rd, imm, pool))
    # Thumb-2 LDR.W Rd, [PC, #imm12]
    if (hw & 0xFFFF) == 0xF8DF and off + 2 < PSPBL_SIZE:
        hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]
        imm12 = hw2 & 0xFFF
        rd = (hw2 >> 12) & 0xF
        pool = (off & ~3) + 4 + imm12
        if pool == 0x4E4C:
            print("  0x{:04X}: LDR.W R{}, [PC, #0x{:X}] -> pool 0x{:04X} = 0xB814".format(
                off, rd, imm12, pool))

# Also check which instruction references the literal pool at 0x77E8
# (the other 0xB814 reference, used by FUN_000075A4)
print("\n  Literal pool [0x77E8] = 0x{:08X}".format(
    struct.unpack_from("<I", pspbl, 0x77E8)[0]))

for off in range(0x7500, min(0x7900, PSPBL_SIZE - 1), 2):
    hw = struct.unpack_from("<H", pspbl, off)[0]
    if (hw & 0xF800) == 0x4800:
        imm = (hw & 0xFF) * 4
        pool = (off & ~3) + 4 + imm
        if pool == 0x77E8:
            rd = (hw >> 8) & 7
            print("  0x{:04X}: LDR R{}, [PC, #0x{:X}] -> pool 0x{:04X} = 0xB814".format(
                off, rd, imm, pool))

# =====================================================================
# PART 4: FUN_000044CC context — what Thumb instructions surround the
# 0xB814 reference? Decode the area around it.
# =====================================================================
print("\n" + "=" * 70)
print("PART 4: Decode around the 0xB814 reference in FUN_000044CC")
print("=" * 70)

# We need to find which instruction loads from pool 0x4E4C
# The function spans 0x44CC to 0x44CC+2728 = 0x4F74
# The literal pool at 0x4E4C is INSIDE the function's range.
# Typically literal pools are interspersed between code blocks.

# Let's first check what other values are in the literal pool near 0x4E4C
print("  Literal pool contents near 0x4E4C:")
for addr in range(0x4E40, min(0x4E80, PSPBL_SIZE - 3), 4):
    val = struct.unpack_from("<I", pspbl, addr)[0]
    print("    [0x{:04X}] = 0x{:08X}".format(addr, val))

# =====================================================================
# PART 5: Decompile FUN_000044CC with Ghidra to find the 0xB814 usage
# =====================================================================
print("\n" + "=" * 70)
print("PART 5: Ghidra decompilation of FUN_000044CC (focused on 0xB814)")
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

    # Decompile FUN_000044CC — the full 2728 bytes
    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x44CC))

    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Search for references to 0xB814 in the decompiled C
            lines = c.split('\n')
            # Print lines around any 0xb814 or B814 reference
            for i, line in enumerate(lines):
                if '0xb814' in line.lower() or 'DAT_0000b814' in line or 'b814' in line.lower():
                    start_ctx = max(0, i - 5)
                    end_ctx = min(len(lines), i + 10)
                    print("  --- Context around 0xB814 reference (line {}) ---".format(i))
                    for j in range(start_ctx, end_ctx):
                        marker = " <<<" if j == i else ""
                        print("  {:4d}: {}{}".format(j, lines[j], marker))
                    print()

            # Also check for any STR to addresses near 0x5DE0C or context area
            for keyword in ['0x5de0c', '0x5d7ac', '0x660', '0x5b8', '0x614']:
                for i, line in enumerate(lines):
                    if keyword in line.lower():
                        print("  Found '{}' at line {}: {}".format(keyword, i, line.strip()))

            # Print total size
            print("\n  Total decompiled output: {} chars, {} lines".format(len(c), len(lines)))

            # Save the full decompilation for reference
            output_path = r"C:\Users\WORK~1.DES\AppData\Local\Temp\claude\C--Users-work-DESKTOP-SAM98TB\c5f1fa55-5f57-4770-9f66-592352064239\scratchpad\fun044cc_decompiled.c"
            with open(output_path, "w") as f:
                f.write(c)
            print("  Full decompilation saved to: {}".format(output_path))

    # =====================================================================
    # PART 6: Check FUN_00000300's direct callees for FUN_000044CC
    # =====================================================================
    print("\n" + "=" * 70)
    print("PART 6: FUN_00000300 callee tree — does it reach FUN_000044CC?")
    print("=" * 70)

    # Get FUN_00000300's references
    func_300 = func_mgr.getFunctionAt(space.getAddress(0x300))
    if not func_300:
        func_300 = func_mgr.getFunctionContaining(space.getAddress(0x300))

    if func_300:
        result = decomp.decompileFunction(func_300, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Search for FUN_000044CC calls
            if '44cc' in c.lower() or '44CD' in c.lower():
                print("  FUN_00000300 DIRECTLY calls FUN_000044CC!")
            else:
                print("  FUN_00000300 does NOT directly call FUN_000044CC")

            # List all function calls in FUN_00000300
            print("\n  All function calls in FUN_00000300:")
            for line in c.split('\n'):
                stripped = line.strip()
                if 'FUN_' in stripped and '(' in stripped:
                    print("    {}".format(stripped[:100]))

    # =====================================================================
    # PART 7: Check FUN_000082e6 and FUN_000075A4 for 044CC calls
    # =====================================================================
    print("\n" + "=" * 70)
    print("PART 7: Does the launch-prep chain call FUN_000044CC?")
    print("=" * 70)

    for fn_addr, fn_name in [(0x82E6, "FUN_000082e6"), (0x75A4, "FUN_000075A4"),
                              (0x66A0, "FUN_000066A0"), (0x7014, "FUN_00007014")]:
        func = func_mgr.getFunctionAt(space.getAddress(fn_addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(fn_addr))
        if func:
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                if '44cc' in c.lower() or '44CD' in c.lower():
                    print("  {} calls FUN_000044CC!".format(fn_name))
                else:
                    print("  {} does NOT call FUN_000044CC".format(fn_name))

    # =====================================================================
    # PART 8: Check the dead SVC handler at 0x198 — confirm it dispatches
    # to FUN_000044CC and is the ONLY path
    # =====================================================================
    print("\n" + "=" * 70)
    print("PART 8: Dead SVC handler at 0x198 decompilation")
    print("=" * 70)

    # The handler is at 0x198, which is ARM code
    func = func_mgr.getFunctionAt(space.getAddress(0x198))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x198))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print(c[:3000] if len(c) > 3000 else c)

    decomp.dispose()

print("\nDone.")
