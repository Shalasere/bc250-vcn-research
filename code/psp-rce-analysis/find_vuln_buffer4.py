"""
Phase 4: Final analysis.

Key insights so far:
- Zero MOVT, so all 32-bit addresses via literal pools
- 0x5DE0C not in any pool
- Must come from parameter, structure offset, or stack
- The binary loads at 0x60834 in SRAM
- 0x5DE0C is below code in SRAM data area
- LDR.W r11, [r6, #0xD7C] found at VA 0x67E9E - large struct offset
- Need to check entry point, large offsets, and how SRAM buffers are addressed

Focus:
1. Entry point / reset vector
2. ALL register+large_offset memory accesses (could reach 0xDE0C from a base)
3. The specific LDR.W r11, [r6, #0xD7C] instruction context
4. Look for the 0x50000 base literal and how offsets are applied
"""

import struct
import re
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BIN_PATH = Path(r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin")
LOAD_BASE = 0x60834

data = BIN_PATH.read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True

def va_to_off(va): return va - LOAD_BASE
def off_to_va(off): return LOAD_BASE + off

# Find prologues
prologues = []
for i in range(0, len(data) - 1, 2):
    if data[i + 1] == 0xB5:
        prologues.append(i)
for i in range(0, len(data) - 3, 2):
    if data[i] == 0x2D and data[i + 1] == 0xE9:
        reglist = struct.unpack_from("<H", data, i + 2)[0]
        if reglist & (1 << 14):
            prologues.append(i)
prologues = sorted(set(prologues))

def find_func(off):
    for i in range(len(prologues) - 1, -1, -1):
        if prologues[i] <= off:
            return prologues[i]
    return None

def disasm_range(start_off, end_off):
    chunk = data[start_off:end_off]
    va = off_to_va(start_off)
    return list(md.disasm(chunk, va))

# ============================================================
# PART 1: Entry point
# ============================================================
print("=" * 70)
print("PART 1: Binary entry point (first 128 bytes)")
print("=" * 70)

insns = disasm_range(0, min(256, len(data)))
for insn in insns[:40]:
    flag = ""
    if insn.mnemonic.lower().startswith("bl") and insn.mnemonic.lower() != "blt":
        flag = " <-- CALL"
    if "sp" in insn.op_str.lower() and ("sub" in insn.mnemonic.lower() or "mov" in insn.mnemonic.lower()):
        flag = " <-- SP SETUP"
    print(f"  0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}{flag}")

# ============================================================
# PART 2: ALL LDR/STR with register base + offset >= 0x800
# These could reach 0xDE0C from a base like 0x50000
# ============================================================
print()
print("=" * 70)
print("PART 2: Memory accesses with large immediate offsets (>= 0x400)")
print("=" * 70)

large_offset_accesses = []

for off in range(0, len(data) - 3, 2):
    hw1 = struct.unpack_from("<H", data, off)[0]

    # LDR.W Rt, [Rn, #imm12]: 1111 1000 1101 nnnn | tttt iiiiiiiiiiii (Rn != PC)
    if (hw1 & 0xFFF0) == 0xF8D0:
        rn = hw1 & 0xF
        if rn == 15: continue  # PC-relative, skip
        hw2 = struct.unpack_from("<H", data, off + 2)[0]
        rt = (hw2 >> 12) & 0xF
        imm12 = hw2 & 0xFFF
        if imm12 >= 0x400:
            va = off_to_va(off)
            large_offset_accesses.append(("LDR.W", va, rt, rn, imm12))

    # STR.W Rt, [Rn, #imm12]: 1111 1000 1100 nnnn | tttt iiiiiiiiiiii
    elif (hw1 & 0xFFF0) == 0xF8C0:
        rn = hw1 & 0xF
        if rn == 15: continue
        hw2 = struct.unpack_from("<H", data, off + 2)[0]
        rt = (hw2 >> 12) & 0xF
        imm12 = hw2 & 0xFFF
        if imm12 >= 0x400:
            va = off_to_va(off)
            large_offset_accesses.append(("STR.W", va, rt, rn, imm12))

print(f"\n  Found {len(large_offset_accesses)} large-offset memory accesses")

# Group by offset to find common structure offsets
from collections import Counter
offset_counts = Counter(a[4] for a in large_offset_accesses)
print(f"\n  Offset distribution (sorted by offset):")
for offset_val in sorted(offset_counts.keys()):
    count = offset_counts[offset_val]
    # Check if this offset, when added to common SRAM bases, reaches near 0x5DE0C
    matches = []
    for base in [0x50000, 0x500B0, 0x50100, 0x50200, 0x51050]:
        result = base + offset_val
        if abs(result - 0x5DE0C) <= 0x100:
            matches.append(f"0x{base:X}+0x{offset_val:X}=0x{result:X}")
    match_str = f"  *** {', '.join(matches)}" if matches else ""
    # Show all accesses with offsets that could construct 0x5DE0C
    locs = [a for a in large_offset_accesses if a[4] == offset_val]
    print(f"  offset 0x{offset_val:03X}: {count} access(es){match_str}")
    if matches or offset_val >= 0xD00:
        for typ, va, rt, rn, imm in locs[:5]:
            print(f"    {typ} r{rt}, [r{rn}, #0x{imm:X}] at VA 0x{va:05X}")

# ============================================================
# PART 3: Context around LDR.W r11, [r6, #0xD7C] at VA 0x67E9E
# ============================================================
print()
print("=" * 70)
print("PART 3: Context around large-offset access at 0x67E9E")
print("=" * 70)

target_off = va_to_off(0x67E9E)
func_off = find_func(target_off)
if func_off:
    func_va = off_to_va(func_off)
    print(f"  Function at VA 0x{func_va:05X}:")
    insns = disasm_range(func_off, min(func_off + 2048, len(data)))
    for insn in insns[:100]:
        flag = ""
        mn = insn.mnemonic.lower()
        if mn.startswith("bl") and mn != "blt":
            flag = " <-- CALL"
        if "0x67e9e" in f"{insn.address:x}":
            flag = " <<< TARGET"
        if "[pc" in insn.op_str.lower():
            m = re.search(r'\[pc,\s*#(-?0x[0-9a-fA-F]+|-?\d+)\]', insn.op_str.lower())
            if m:
                imm = int(m.group(1), 0)
                pc_aligned = (insn.address + 4) & ~3
                pool_addr = pc_aligned + imm
                pool_off = va_to_off(pool_addr)
                if 0 <= pool_off <= len(data) - 4:
                    pool_val = struct.unpack_from("<I", data, pool_off)[0]
                    flag += f" POOL=0x{pool_val:08X}"
        print(f"    0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}{flag}")

# ============================================================
# PART 4: Look for ADD with large immediate creating SRAM offsets
# ADD.W Rd, Rn, #modified_imm (where modified_imm can be large)
# ============================================================
print()
print("=" * 70)
print("PART 4: ADD/SUB with large immediates (constructing addresses)")
print("=" * 70)

# Thumb2 ADD.W Rd, Rn, #const encoding
# Also look at ADDW which can have 12-bit immediate
# ADDW: 1111 0x10 0000 nnnn | 0 imm3 dddd imm8
# Encodes: Rd, Rn, #imm12 (plain, not modified)

for off in range(0, len(data) - 3, 2):
    hw1 = struct.unpack_from("<H", data, off)[0]

    # ADDW Rd, Rn, #imm12: first hw = 11110 i 10 0000 nnnn = F200 + (i << 10) + Rn
    if (hw1 & 0xFBF0) == 0xF200:
        hw2 = struct.unpack_from("<H", data, off + 2)[0]
        if hw2 & 0x8000: continue
        rn = hw1 & 0xF
        i_bit = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 0x7
        rd = (hw2 >> 8) & 0xF
        imm8 = hw2 & 0xFF
        imm12 = (i_bit << 11) | (imm3 << 8) | imm8
        if imm12 >= 0xC00:  # large add offset
            va = off_to_va(off)
            # Check if this could construct 0x5DE0C
            for base_name, base_val in [("0x50100", 0x50100), ("0x50200", 0x50200), ("0x50000", 0x50000), ("0x51050", 0x51050)]:
                result = base_val + imm12
                if abs(result - 0x5DE0C) <= 0x100:
                    print(f"  ADDW r{rd}, r{rn}, #0x{imm12:X} at VA 0x{va:05X}  ({base_name}+0x{imm12:X}=0x{result:X} near 0x5DE0C!)")
            if imm12 in (0xDE0C, 0xDE00, 0xDE08, 0xE0C):
                print(f"  ADDW r{rd}, r{rn}, #0x{imm12:X} at VA 0x{va:05X}  *** KEY OFFSET ***")

    # SUBW Rd, Rn, #imm12: first hw = 11110 i 10 1010 nnnn
    if (hw1 & 0xFBF0) == 0xF2A0:
        hw2 = struct.unpack_from("<H", data, off + 2)[0]
        if hw2 & 0x8000: continue
        rn = hw1 & 0xF
        i_bit = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 0x7
        rd = (hw2 >> 8) & 0xF
        imm8 = hw2 & 0xFF
        imm12 = (i_bit << 11) | (imm3 << 8) | imm8
        if imm12 >= 0xC00:
            va = off_to_va(off)
            print(f"  SUBW r{rd}, r{rn}, #0x{imm12:X} at VA 0x{va:05X}")

# ============================================================
# PART 5: All BL (function call) targets - build call graph
# ============================================================
print()
print("=" * 70)
print("PART 5: Most-called functions (likely utility: memcpy, memset, etc)")
print("=" * 70)

bl_targets = Counter()
for off in range(0, len(data) - 3, 2):
    hw1 = struct.unpack_from("<H", data, off)[0]
    # BL: first hw = 1111 0Sxx xxxx xxxx, second hw = 11x1 xxxx xxxx xxxx
    if (hw1 & 0xF800) == 0xF000:
        hw2 = struct.unpack_from("<H", data, off + 2)[0]
        if (hw2 & 0xD000) == 0xD000:
            # Decode BL target
            S = (hw1 >> 10) & 1
            imm10 = hw1 & 0x3FF
            J1 = (hw2 >> 13) & 1
            J2 = (hw2 >> 11) & 1
            imm11 = hw2 & 0x7FF
            I1 = 1 - (J1 ^ S)
            I2 = 1 - (J2 ^ S)
            offset = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
            if S:
                offset |= 0xFE000000  # sign extend
                offset -= 0x100000000
            instr_va = off_to_va(off)
            target = instr_va + 4 + offset
            if 0 <= target - LOAD_BASE < len(data):
                bl_targets[target] += 1

print(f"\n  Top 20 most-called functions:")
for target, count in bl_targets.most_common(20):
    # Try to identify by disassembling first few instructions
    target_off = va_to_off(target)
    first_insns = list(md.disasm(data[target_off:target_off+16], target))
    summary = "; ".join(f"{i.mnemonic} {i.op_str}" for i in first_insns[:3])
    print(f"  0x{target:05X}: called {count:3d} times  [{summary}]")

# ============================================================
# PART 6: Disassemble functions that load 0x50000, 0x500B0, 0x50100
# and trace what offsets they apply
# ============================================================
print()
print("=" * 70)
print("PART 6: Looking at 0x50000 literal at VA 0x755CE")
print("=" * 70)

# The 0x50000 value at file 0x14D9A / VA 0x755CE
# This is in the data section at the end. Let's find what LDR references it.
pool_off = 0x14D9A
pool_va = off_to_va(pool_off)

# Search for LDR that loads from this pool entry
print(f"  Pool entry 0x50000 at VA 0x{pool_va:05X}")
# 16-bit LDR literal search
for soff in range(max(0, pool_off - 1020), pool_off, 2):
    hw = struct.unpack_from("<H", data, soff)[0]
    if (hw >> 11) == 0b01001:
        rd = (hw >> 8) & 0x7
        imm8 = hw & 0xFF
        instr_va = off_to_va(soff)
        eff = ((instr_va + 4) & ~3) + imm8 * 4
        if eff == pool_va:
            print(f"  LDR r{rd}, [PC, #0x{imm8*4:X}] at VA 0x{instr_va:05X}")
            # Disassemble surrounding function
            foff = find_func(soff)
            if foff:
                print(f"    In function at VA 0x{off_to_va(foff):05X}:")
                insns = disasm_range(foff, min(foff + 1024, len(data)))
                for insn in insns[:60]:
                    flag = ""
                    if insn.address == instr_va:
                        flag = " <<< LOADS 0x50000"
                    print(f"      0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}{flag}")

# 32-bit LDR.W literal search
for soff in range(max(0, pool_off - 4095), min(len(data) - 3, pool_off + 4095), 2):
    hw1 = struct.unpack_from("<H", data, soff)[0]
    if (hw1 & 0xFF7F) == 0xF85F:
        hw2 = struct.unpack_from("<H", data, soff + 2)[0]
        rt = (hw2 >> 12) & 0xF
        imm12 = hw2 & 0xFFF
        u = (hw1 >> 7) & 1
        instr_va = off_to_va(soff)
        pc_aligned = (instr_va + 4) & ~3
        eff = pc_aligned + imm12 if u else pc_aligned - imm12
        if eff == pool_va:
            print(f"  LDR.W r{rt}, [PC, #{'+'if u else '-'}0x{imm12:X}] at VA 0x{instr_va:05X}")

# ============================================================
# PART 7: Complete list of ALL literal pool values in the
# SRAM data region (0x50000-0x60834)
# Find ALL LDR instructions that reference them
# Then check: do any of these get used with ADD to reach 0x5DE0C?
# ============================================================
print()
print("=" * 70)
print("PART 7: How could 0x5DE0C be reached from known bases?")
print("=" * 70)

print("\n  Possible base + offset decompositions for 0x5DE0C:")
known_bases = {
    0x50000: "literal pool @ 0x755CE",
    0x500B0: "literal pool @ 0x74410",
    0x50100: "literal pool @ 0x68DA4",
    0x50124: "literal pool @ 0x69200",
    0x50200: "literal pool @ 0x6B2E8",
    0x51050: "literal pool @ 0x62294",
    0x58401: "literal pool",
    0x58559: "literal pool",
    0x58565: "literal pool",
    0x5A86C: "literal pool @ 0x6F9B8",
}

for base, source in sorted(known_bases.items()):
    offset = 0x5DE0C - base
    if offset < 0:
        print(f"  0x{base:05X} + ??? = need NEGATIVE offset ({offset}) -- unlikely")
    elif offset <= 0xFFF:
        print(f"  0x{base:05X} + 0x{offset:03X} = 0x5DE0C  (fits in 12-bit imm!)  [{source}]")
    elif offset <= 0xFFFF:
        print(f"  0x{base:05X} + 0x{offset:04X} = 0x5DE0C  (needs 16-bit, 2-step)  [{source}]")
    else:
        print(f"  0x{base:05X} + 0x{offset:05X} = 0x5DE0C  (too large for single ADD)  [{source}]")

# Check which offsets from each base actually appear as immediate operands
print("\n  Checking if any computed offsets appear as immediates in the code...")
for base, source in sorted(known_bases.items()):
    offset = 0x5DE0C - base
    if offset < 0 or offset > 0xFFFF:
        continue
    # Search for this offset as a MOVW immediate
    if offset in [imm for imm in range(0, 0x10000)]:
        # Search raw encoding
        # MOVW: imm16 = imm4:i:imm3:imm8
        imm4 = (offset >> 12) & 0xF
        i_bit = (offset >> 11) & 1
        imm3 = (offset >> 8) & 0x7
        imm8 = offset & 0xFF
        hw1_expected = 0xF240 | (i_bit << 10) | imm4
        hw2_mask = 0x70FF  # imm3 in bits 14-12, imm8 in bits 7-0
        hw2_expected = (imm3 << 12) | imm8

        found = False
        for off in range(0, len(data) - 3, 2):
            hw1 = struct.unpack_from("<H", data, off)[0]
            if hw1 == hw1_expected:
                hw2 = struct.unpack_from("<H", data, off + 2)[0]
                if (hw2 & hw2_mask) == hw2_expected and not (hw2 & 0x8000):
                    rd = (hw2 >> 8) & 0xF
                    va = off_to_va(off)
                    print(f"  MOVW r{rd}, #0x{offset:04X} at VA 0x{va:05X}  (base 0x{base:05X} + this = 0x5DE0C)")
                    found = True

        # Also check as ADDW immediate (12-bit, only if offset <= 0xFFF)
        if offset <= 0xFFF:
            for a in large_offset_accesses:
                if a[4] == offset:
                    print(f"  {a[0]} r{a[2]}, [r{a[3]}, #0x{a[4]:X}] at VA 0x{a[1]:05X}  (if r{a[3]} = 0x{base:05X}, reaches 0x5DE0C)")

print("\n\nDone.")
