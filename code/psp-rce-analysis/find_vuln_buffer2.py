"""
Follow-up: broader search for how 0x5DE0C could be reached.

1. Find ALL MOVW/MOVT pairs in the binary (any immediate) to understand addressing patterns
2. Investigate the pointer table at the tail (0x753A4-0x75464)
3. Look for base addresses that could reach 0x5DE0C via offset
4. Search for APCB-related references (the vulnerability is in APCB parsing)
5. Look for memcpy/memmove-like patterns near buffer operations
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

# ============================================================
# PART A: Find ALL MOVT instructions (any immediate)
# These reveal what address spaces this firmware operates in
# ============================================================
print("=" * 70)
print("PART A: All MOVT instructions (reveals address space usage)")
print("=" * 70)

movt_all = {}  # imm -> list of (va, reg, raw)

for off in range(0, len(data) - 3, 2):
    hw1 = struct.unpack_from("<H", data, off)[0]
    # MOVT T1: 11110 i 10 1100 imm4 | 0 imm3 Rd imm8
    # Mask for first hw: (hw1 & 0xFBF0) == 0xF2C0
    if (hw1 & 0xFBF0) == 0xF2C0:
        hw2 = struct.unpack_from("<H", data, off + 2)[0]
        # Verify second hw bit 15 = 0
        if hw2 & 0x8000:
            continue
        imm4 = hw1 & 0xF
        i_bit = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 0x7
        imm8 = hw2 & 0xFF
        rd = (hw2 >> 8) & 0xF
        imm16 = (imm4 << 12) | (i_bit << 11) | (imm3 << 8) | imm8
        va = LOAD_BASE + off

        if imm16 not in movt_all:
            movt_all[imm16] = []
        movt_all[imm16].append((va, rd, data[off:off+4].hex()))

print(f"\n  Distinct MOVT immediates found: {len(movt_all)}")
for imm in sorted(movt_all.keys()):
    entries = movt_all[imm]
    print(f"  MOVT #0x{imm:04X}  ({len(entries)} occurrence(s)):")
    for va, rd, raw in entries[:10]:
        print(f"    VA 0x{va:05X}  r{rd}  [{raw}]")
    if len(entries) > 10:
        print(f"    ... and {len(entries)-10} more")

# ============================================================
# PART B: Find ALL MOVW instructions
# ============================================================
print()
print("=" * 70)
print("PART B: All MOVW instructions")
print("=" * 70)

movw_all = {}  # imm -> list of (va, reg, raw)

for off in range(0, len(data) - 3, 2):
    hw1 = struct.unpack_from("<H", data, off)[0]
    # MOVW T3: 11110 i 10 0100 imm4 | 0 imm3 Rd imm8
    # Mask: (hw1 & 0xFBF0) == 0xF240
    if (hw1 & 0xFBF0) == 0xF240:
        hw2 = struct.unpack_from("<H", data, off + 2)[0]
        if hw2 & 0x8000:
            continue
        imm4 = hw1 & 0xF
        i_bit = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 0x7
        imm8 = hw2 & 0xFF
        rd = (hw2 >> 8) & 0xF
        imm16 = (imm4 << 12) | (i_bit << 11) | (imm3 << 8) | imm8
        va = LOAD_BASE + off

        if imm16 not in movw_all:
            movw_all[imm16] = []
        movw_all[imm16].append((va, rd, data[off:off+4].hex()))

print(f"\n  Distinct MOVW immediates found: {len(movw_all)}")
# Show all (there shouldn't be too many unique ones)
for imm in sorted(movw_all.keys()):
    entries = movw_all[imm]
    if len(entries) <= 3:
        locs = "  ".join(f"VA 0x{va:05X} r{rd}" for va, rd, _ in entries)
    else:
        locs = f"{len(entries)} occurrences"
    print(f"  MOVW #0x{imm:04X}  [{locs}]")

# ============================================================
# PART C: Pair MOVW+MOVT to reconstruct 32-bit addresses
# ============================================================
print()
print("=" * 70)
print("PART C: Reconstructing full addresses from MOVW+MOVT pairs")
print("=" * 70)

# Build a flat list of all MOV[WT] instructions sorted by VA
all_movs = []
for imm, entries in movw_all.items():
    for va, rd, raw in entries:
        all_movs.append(("MOVW", va, rd, imm, raw))
for imm, entries in movt_all.items():
    for va, rd, raw in entries:
        all_movs.append(("MOVT", va, rd, imm, raw))
all_movs.sort(key=lambda x: x[1])

# For each MOVW, look for a MOVT on the same register within 12 bytes ahead
pairs = []
for i, (typ, va, rd, imm, raw) in enumerate(all_movs):
    if typ != "MOVW":
        continue
    for j in range(i + 1, min(i + 6, len(all_movs))):
        typ2, va2, rd2, imm2, raw2 = all_movs[j]
        if va2 - va > 12:
            break
        if typ2 == "MOVT" and rd2 == rd:
            full = (imm2 << 16) | imm
            pairs.append((va, va2, rd, imm, imm2, full))
            break

print(f"\n  Found {len(pairs)} MOVW+MOVT pairs:")
for mw_va, mt_va, rd, lo, hi, full in pairs:
    flag = ""
    if 0x5D000 <= full <= 0x5F000:
        flag = "  *** IN TARGET RANGE ***"
    elif 0x50000 <= full <= 0x60000:
        flag = "  (near SRAM region)"
    print(f"  r{rd} = 0x{full:08X}  (MOVW@0x{mw_va:05X} #0x{lo:04X} + MOVT@0x{mt_va:05X} #0x{hi:04X}){flag}")

# ============================================================
# PART D: ALL 32-bit literal pool values in 0x00050000-0x00060000
# (broader SRAM range)
# ============================================================
print()
print("=" * 70)
print("PART D: All literal pool values in SRAM range 0x50000-0x60000")
print("=" * 70)

sram_vals = {}
for i in range(0, len(data) - 3, 4):
    val = struct.unpack_from("<I", data, i)[0]
    if 0x50000 <= val < 0x60000:
        va = LOAD_BASE + i
        if val not in sram_vals:
            sram_vals[val] = []
        sram_vals[val].append((i, va))

print(f"\n  Distinct values: {len(sram_vals)}")
for val in sorted(sram_vals.keys()):
    locs = sram_vals[val]
    delta = val - 0x5DE0C
    print(f"  0x{val:08X} (delta {delta:+6d}/0x{abs(delta):04X} from 0x5DE0C)  at {len(locs)} loc(s):", end="")
    for foff, va in locs[:3]:
        print(f"  file 0x{foff:05X}/VA 0x{va:05X}", end="")
    if len(locs) > 3:
        print(f"  +{len(locs)-3} more", end="")
    print()

# ============================================================
# PART E: Investigate the pointer table at tail of binary
# ============================================================
print()
print("=" * 70)
print("PART E: Pointer table at binary tail (file 0x14B70+)")
print("=" * 70)

# The cluster of 0x5Exxx values starts around file offset 0x14B70
# Let's dump the whole table region
TABLE_START = 0x14B70
TABLE_END = min(0x14C40, len(data))

print(f"\n  Dumping words from file 0x{TABLE_START:05X} to 0x{TABLE_END:05X}:")
for off in range(TABLE_START, TABLE_END, 4):
    val = struct.unpack_from("<I", data, off)[0]
    va = LOAD_BASE + off
    annotation = ""
    if 0x50000 <= val < 0x80000:
        annotation = f"  <- SRAM/code ptr"
    if 0x60834 <= val <= 0x75FF3:
        annotation = f"  <- code VA (func ptr?)"
    print(f"  [{off:05X}] VA 0x{va:05X}: 0x{val:08X}{annotation}")

# ============================================================
# PART F: Look for LDR instructions that load from the pointer table
# ============================================================
print()
print("=" * 70)
print("PART F: LDR instructions referencing literal pool entries in 0x50000-0x60000 range")
print("=" * 70)

# For each known SRAM literal pool entry, find LDR [PC, #imm] that reaches it
for pool_val, locs in sorted(sram_vals.items()):
    for foff, pool_va in locs:
        # Search for LDR that references this pool_va
        # LDR Rn, [PC, #imm] (Thumb 16-bit): opcode = 0100 1 ddd iiiiiiii (word aligned)
        # effective_addr = ((PC + 4) & ~3) + imm*4
        # 32-bit LDR literal: wider range, +/- 4095

        # For 16-bit LDR literal: range is +0 to +1020 bytes from aligned PC
        # So the LDR must be at VA in range [pool_va - 1020, pool_va]
        # But also pool must be word-aligned
        if foff % 4 != 0:
            continue  # skip unaligned pool entries

        # Search backward from pool entry for 16-bit LDR
        search_start = max(0, foff - 1020)
        for soff in range(search_start, foff, 2):
            hw = struct.unpack_from("<H", data, soff)[0]
            # 16-bit LDR literal: 0100 1 Rd(3) imm8
            if (hw >> 11) == 0b01001:
                rd = (hw >> 8) & 0x7
                imm8 = hw & 0xFF
                instr_va = LOAD_BASE + soff
                eff = ((instr_va + 4) & ~3) + imm8 * 4
                if eff == pool_va:
                    print(f"  LDR r{rd}, [PC, #0x{imm8*4:X}] at VA 0x{instr_va:05X} -> pool 0x{pool_va:05X} = 0x{pool_val:08X}")

        # Search for 32-bit LDR literal (Thumb2)
        # Encoding: 1111 1000 U101 1111 | Rt(4) imm12
        # U=1: add, U=0: subtract
        search_start32 = max(0, foff - 4095)
        search_end32 = min(len(data) - 3, foff + 4095)
        for soff in range(search_start32, search_end32, 2):
            hw1 = struct.unpack_from("<H", data, soff)[0]
            # Check for LDR.W Rt, [PC, #imm12]
            # hw1 = 1111 1000 x101 1111 where x = U bit
            if (hw1 & 0xFF7F) == 0xF85F:
                hw2 = struct.unpack_from("<H", data, soff + 2)[0]
                rt = (hw2 >> 12) & 0xF
                imm12 = hw2 & 0xFFF
                u = (hw1 >> 7) & 1
                instr_va = LOAD_BASE + soff
                pc_aligned = (instr_va + 4) & ~3
                if u:
                    eff = pc_aligned + imm12
                else:
                    eff = pc_aligned - imm12
                if eff == pool_va:
                    print(f"  LDR.W r{rt}, [PC, #{'+'if u else '-'}0x{imm12:X}] at VA 0x{instr_va:05X} -> pool 0x{pool_va:05X} = 0x{pool_val:08X}")

# ============================================================
# PART G: Search for APCB-related strings
# ============================================================
print()
print("=" * 70)
print("PART G: String search for APCB / buffer-related keywords")
print("=" * 70)

keywords = [b"APCB", b"apcb", b"buffer", b"BUFFER", b"copy", b"COPY",
            b"token", b"TOKEN", b"size", b"SIZE", b"length", b"header",
            b"parse", b"valid", b"check", b"ABL", b"PSP"]
for kw in keywords:
    idx = 0
    hits = []
    while True:
        pos = data.find(kw, idx)
        if pos == -1:
            break
        va = LOAD_BASE + pos
        # Get surrounding context
        ctx_start = max(0, pos - 4)
        ctx_end = min(len(data), pos + len(kw) + 20)
        ctx = data[ctx_start:ctx_end]
        # Filter to printable ASCII context
        ctx_ascii = ''.join(chr(b) if 32 <= b < 127 else '.' for b in ctx)
        hits.append((pos, va, ctx_ascii))
        idx = pos + 1
    if hits:
        print(f"\n  '{kw.decode()}' found {len(hits)} time(s):")
        for pos, va, ctx in hits[:10]:
            print(f"    file 0x{pos:05X} VA 0x{va:05X}: {ctx}")
        if len(hits) > 10:
            print(f"    ... +{len(hits) - 10} more")

# ============================================================
# PART H: Look for the value passed as function argument
# Could 0x5DE0C come from a register set by the CALLER?
# Check: what functions receive SRAM pointers as args?
# Look for BL instructions preceded by MOVW/MOVT that set r0-r3
# ============================================================
print()
print("=" * 70)
print("PART H: SRAM address construction via MOVW+MOVT into r0-r3 (function args)")
print("=" * 70)

# We already have all MOVW+MOVT pairs from Part C
# Filter to those targeting r0-r3 with SRAM-range values
arg_pairs = [(mw_va, mt_va, rd, lo, hi, full)
             for mw_va, mt_va, rd, lo, hi, full in pairs
             if rd <= 3 and 0x50000 <= full < 0x60000]

print(f"\n  MOVW+MOVT pairs targeting r0-r3 with SRAM addresses: {len(arg_pairs)}")
for mw_va, mt_va, rd, lo, hi, full in arg_pairs:
    delta = full - 0x5DE0C
    print(f"  r{rd} = 0x{full:08X} (delta {delta:+6d}/0x{abs(delta):04X} from 0x5DE0C)")
    print(f"    MOVW@0x{mw_va:05X}  MOVT@0x{mt_va:05X}")
    # Disassemble a few instructions after the MOVT to see what happens
    post_off = mt_va + 4 - LOAD_BASE
    post_data = data[post_off:post_off + 20]
    print(f"    Following instructions:")
    for insn in md.disasm(post_data, mt_va + 4):
        print(f"      0x{insn.address:05X}: {insn.mnemonic} {insn.op_str}")

print("\n\nDone.")
