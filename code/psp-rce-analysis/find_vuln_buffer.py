"""
Search for references to SRAM address 0x5DE0C (and nearby) in the PSP ABL4 firmware.

Binary: internal_abl4_decompressed.bin
Size:   ~88000 bytes, ARM Thumb code
Load base: 0x60834

Targets:
  Primary:   0x0005DE0C
  Nearby:    0x5DE00, 0x5DE08, 0x5DE10, 0x5DD00
  Page-aligned: 0x5D000, 0x5E000
"""

import struct
import sys
from pathlib import Path

# ---------- capstone setup ----------
try:
    import capstone
    print(f"capstone version: {capstone.__version__}")
except ImportError:
    print("ERROR: capstone not installed"); sys.exit(1)

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_DETAIL

BIN_PATH = Path(r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin")
LOAD_BASE = 0x60834

TARGET_ADDRS = [
    0x0005DE0C,  # primary
    0x0005DE00,
    0x0005DE08,
    0x0005DE10,
    0x0005DD00,
    0x0005D000,
    0x0005E000,
]

# Lower-half immediates we want MOVW to carry
MOVW_TARGETS = {
    0xDE0C: "0x5DE0C",
    0xDE00: "0x5DE00",
    0xDE08: "0x5DE08",
    0xDE10: "0x5DE10",
    0xDD00: "0x5DD00",
    0xD000: "0x5D000 or 0x5E000 (need MOVT context)",
    0xE000: "0x5E000 (or many others)",
}

# Upper-half immediates we want MOVT to carry
MOVT_TARGETS = {
    0x0005: "upper half for 0x5xxxx",
    0x0006: "upper half for 0x6xxxx (near SRAM end?)",
}

# ---------- load binary ----------
data = BIN_PATH.read_bytes()
print(f"Binary size: {len(data)} bytes (0x{len(data):X})")
print(f"Load base: 0x{LOAD_BASE:X}")
print(f"Address range: 0x{LOAD_BASE:X} - 0x{LOAD_BASE + len(data) - 1:X}")
print()

# ============================================================
# PART 1: Raw byte search for 32-bit literal pool entries
# ============================================================
print("=" * 70)
print("PART 1: Raw 32-bit literal pool scan (little-endian u32)")
print("=" * 70)

for target in TARGET_ADDRS:
    needle = struct.pack("<I", target)
    offset = 0
    hits = []
    while True:
        idx = data.find(needle, offset)
        if idx == -1:
            break
        va = LOAD_BASE + idx
        hits.append((idx, va))
        offset = idx + 1
    if hits:
        print(f"\n  0x{target:08X}  found {len(hits)} time(s):")
        for file_off, va in hits:
            # Check alignment (literal pools are usually word-aligned)
            aligned = "ALIGNED" if file_off % 4 == 0 else "unaligned"
            # Read surrounding context
            ctx_start = max(0, file_off - 8)
            ctx_end = min(len(data), file_off + 12)
            ctx_bytes = data[ctx_start:ctx_end].hex(" ")
            print(f"    file offset 0x{file_off:05X}  VA 0x{va:05X}  ({aligned})  context: {ctx_bytes}")
            # Try to find LDR instructions that reference this pool entry
            # In Thumb, LDR Rn, [PC, #imm] has effective address = (PC & ~3) + 4 + imm
            # PC at instruction = VA_of_instruction + 4 (pipeline)
            # So pool_va = (instr_va & ~3) + 4 + imm
            # => instr_va = pool_va - 4 - imm (for various imm values)
            # imm range for Thumb LDR literal: 0..1020 (step 4) for 16-bit encoding
            # For 32-bit Thumb2 LDR literal: +/- 4095
            print(f"    (LDR [PC, #imm] can reach this from VA 0x{max(0, va - 4095):05X} to 0x{va + 4095:05X})")
    else:
        print(f"\n  0x{target:08X}  NOT FOUND as raw 32-bit value")

# ============================================================
# PART 2: Raw 16-bit scan for MOVW lower-half immediates
# ============================================================
print()
print("=" * 70)
print("PART 2: Raw 16-bit scan for key lower-half values (u16 LE)")
print("=" * 70)

for imm16, desc in MOVW_TARGETS.items():
    needle = struct.pack("<H", imm16)
    offset = 0
    count = 0
    while True:
        idx = data.find(needle, offset)
        if idx == -1:
            break
        count += 1
        offset = idx + 1
    print(f"  0x{imm16:04X} ({desc}): {count} raw occurrences (most are coincidental)")

# ============================================================
# PART 3: Find function prologues (PUSH with LR)
# ============================================================
print()
print("=" * 70)
print("PART 3: Finding function prologues")
print("=" * 70)

prologues = []

# Narrow PUSH {rlist, LR}: encoding is 0xB5xx where xx encodes register list
# Byte pattern: data[i] = reglist_low, data[i+1] = 0xB5
for i in range(0, len(data) - 1, 2):  # Thumb instructions are halfword-aligned
    if data[i + 1] == 0xB5:
        va = LOAD_BASE + i
        prologues.append((i, va, "narrow"))

# Wide PUSH.W {rlist}: encoding 0xE92D xxxx
# Bytes (little-endian halfwords): [0x2D, 0xE9, low_regs, high_regs]
for i in range(0, len(data) - 3, 2):
    if data[i] == 0x2D and data[i + 1] == 0xE9:
        reglist = struct.unpack_from("<H", data, i + 2)[0]
        if reglist & (1 << 14):  # LR bit set
            va = LOAD_BASE + i
            prologues.append((i, va, "wide"))

prologues.sort()
print(f"  Found {len(prologues)} function prologues")
if prologues:
    print(f"  First: file 0x{prologues[0][0]:05X} VA 0x{prologues[0][1]:05X}")
    print(f"  Last:  file 0x{prologues[-1][0]:05X} VA 0x{prologues[-1][1]:05X}")

# ============================================================
# PART 4: Disassemble each function, look for target references
# ============================================================
print()
print("=" * 70)
print("PART 4: Disassembling functions - searching for MOVW/MOVT/LDR refs")
print("=" * 70)

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True

# Collect all findings
findings = []

MAX_FUNC_BYTES = 2048
MAX_INVALID = 8  # stop after this many consecutive invalid insns

# Also build a set of literal pool VA -> value for quick lookup
# (we already found the raw values, but let's be systematic)
pool_values = {}
for i in range(0, len(data) - 3, 4):
    val = struct.unpack_from("<I", data, i)[0]
    if val in TARGET_ADDRS:
        pool_va = LOAD_BASE + i
        pool_values[pool_va] = val

print(f"  Known literal pool entries with target values: {len(pool_values)}")
for pva, pval in sorted(pool_values.items()):
    print(f"    VA 0x{pva:05X} = 0x{pval:08X}")

print()
print("  Scanning functions...")

func_count = 0
for fidx, (foff, fva, ftype) in enumerate(prologues):
    # Determine function end: either next prologue or MAX_FUNC_BYTES
    if fidx + 1 < len(prologues):
        next_off = prologues[fidx + 1][0]
        func_len = min(next_off - foff, MAX_FUNC_BYTES)
    else:
        func_len = min(len(data) - foff, MAX_FUNC_BYTES)

    func_data = data[foff:foff + func_len]
    func_count += 1

    invalid_streak = 0
    for insn in md.disasm(func_data, fva):
        invalid_streak = 0  # reset on valid instruction

        mnemonic = insn.mnemonic.lower()
        op_str = insn.op_str

        # Check MOVW with target lower-half
        if mnemonic == "movw":
            # Parse immediate from op_str: "rN, #0xXXXX"
            if "#" in op_str:
                try:
                    imm_str = op_str.split("#")[-1].strip().rstrip("}")
                    imm_val = int(imm_str, 0)
                    if imm_val in MOVW_TARGETS:
                        findings.append({
                            "type": "MOVW",
                            "va": insn.address,
                            "foff": insn.address - LOAD_BASE,
                            "detail": f"movw {op_str}  (lower half = 0x{imm_val:04X} -> {MOVW_TARGETS[imm_val]})",
                            "func_va": fva,
                            "raw": data[insn.address - LOAD_BASE : insn.address - LOAD_BASE + insn.size].hex(),
                        })
                except ValueError:
                    pass

        # Check MOVT with target upper-half
        elif mnemonic == "movt":
            if "#" in op_str:
                try:
                    imm_str = op_str.split("#")[-1].strip().rstrip("}")
                    imm_val = int(imm_str, 0)
                    if imm_val in MOVT_TARGETS:
                        findings.append({
                            "type": "MOVT",
                            "va": insn.address,
                            "foff": insn.address - LOAD_BASE,
                            "detail": f"movt {op_str}  (upper half = 0x{imm_val:04X} -> {MOVT_TARGETS[imm_val]})",
                            "func_va": fva,
                            "raw": data[insn.address - LOAD_BASE : insn.address - LOAD_BASE + insn.size].hex(),
                        })
                except ValueError:
                    pass

        # Check LDR from literal pool
        elif mnemonic.startswith("ldr") and not mnemonic.startswith("ldrd"):
            # Capstone should give us the effective address for PC-relative LDR
            # Check if op_str references [pc, ...] pattern
            if "[pc" in op_str.lower():
                # Try to compute the pool address
                # For Thumb: pool_addr = (PC & ~3) + 4 + imm  (where PC = insn.address + 4 for pipeline,
                # but capstone often gives the final address)
                # Let's try to parse the immediate offset
                try:
                    # Format: "rN, [pc, #0xNN]" or "rN, [pc, #-0xNN]" or "rN, [pc, #NN]"
                    import re
                    m = re.search(r'\[pc,\s*#(-?0x[0-9a-fA-F]+|-?\d+)\]', op_str.lower())
                    if m:
                        imm = int(m.group(1), 0)
                        # Thumb PC-relative: effective = (insn_addr + 4) & ~3  + imm
                        # (The +4 is the pipeline offset for Thumb)
                        pc_aligned = (insn.address + 4) & ~3
                        pool_addr = pc_aligned + imm
                        # Read the pool value
                        pool_file_off = pool_addr - LOAD_BASE
                        if 0 <= pool_file_off <= len(data) - 4:
                            pool_val = struct.unpack_from("<I", data, pool_file_off)[0]
                            if pool_val in TARGET_ADDRS:
                                findings.append({
                                    "type": "LDR_POOL",
                                    "va": insn.address,
                                    "foff": insn.address - LOAD_BASE,
                                    "detail": f"ldr {op_str}  -> pool@0x{pool_addr:05X} = 0x{pool_val:08X}",
                                    "func_va": fva,
                                    "pool_va": pool_addr,
                                    "pool_val": pool_val,
                                    "raw": data[insn.address - LOAD_BASE : insn.address - LOAD_BASE + insn.size].hex(),
                                })
                            # Also check if it's close to a target (within 256 bytes)
                            for tgt in TARGET_ADDRS:
                                if abs(pool_val - tgt) <= 0x100 and pool_val != tgt and pool_val not in TARGET_ADDRS:
                                    findings.append({
                                        "type": "LDR_POOL_NEAR",
                                        "va": insn.address,
                                        "foff": insn.address - LOAD_BASE,
                                        "detail": f"ldr {op_str}  -> pool@0x{pool_addr:05X} = 0x{pool_val:08X} (near 0x{tgt:08X}, delta={pool_val - tgt:+d})",
                                        "func_va": fva,
                                        "raw": data[insn.address - LOAD_BASE : insn.address - LOAD_BASE + insn.size].hex(),
                                    })
                except Exception as e:
                    pass

        # Check ADD/SUB with immediate that could construct target
        # e.g., ADD Rd, Rn, #0xC where Rn already holds a base
        # We can't do full data-flow, but flag interesting immediates
        elif mnemonic in ("add", "adds", "sub", "subs", "addw", "subw"):
            if "#" in op_str:
                try:
                    imm_str = op_str.split("#")[-1].strip().rstrip("}")
                    imm_val = int(imm_str, 0)
                    # Flag if this immediate is exactly the offset from a page base to 0x5DE0C
                    # 0x5DE0C - 0x5D000 = 0xE0C
                    # 0x5DE0C - 0x5DE00 = 0xC
                    if imm_val in (0xE0C, 0xDE0C):
                        findings.append({
                            "type": "ADD_IMM",
                            "va": insn.address,
                            "foff": insn.address - LOAD_BASE,
                            "detail": f"{mnemonic} {op_str}  (offset 0x{imm_val:X} could construct 0x5DE0C from base)",
                            "func_va": fva,
                            "raw": data[insn.address - LOAD_BASE : insn.address - LOAD_BASE + insn.size].hex(),
                        })
                except ValueError:
                    pass

# ============================================================
# PART 5: Also do a brute-force disassembly of the ENTIRE binary
#          (not just prologue-anchored), looking for MOVW/MOVT
# ============================================================
print("  Doing full linear sweep for MOVW/MOVT (may hit data, but catches orphan code)...")

# Thumb2 MOVW encoding: 0xF240xxxx or 0xF2Cxxxxx (MOVT)
# Let's scan for the Thumb2 encoding patterns directly
# MOVW: first halfword = 0b 1111 0x10 0100 xxxx = F240-F64F range
# MOVT: first halfword = 0b 1111 0x10 1100 xxxx = F2C0-F6CF range

# More precisely:
# MOVW T3: 11110 i 10 0100 imm4 | 0 imm3 Rd imm8
#   first hw: 1111 0i10 0100 nnnn  where i is bit 10, nnnn is imm4 (bits 16-19 of value)
#   second hw: 0 iii dddd iiiiiiii  where iii = imm3 (bits 12-14), dddd = Rd, iiiiiiii = imm8 (bits 0-7)
#   Full immediate = imm4:i:imm3:imm8

# Let's just decode using capstone on every 2-byte boundary (brute force)
# and filter for MOVW/MOVT with our target immediates

# This is expensive but thorough
linear_findings = []
step = 2  # Thumb halfword aligned
for off in range(0, len(data) - 3, step):
    # Try to decode one instruction
    va = LOAD_BASE + off
    chunk = data[off:off + 4]  # max 4 bytes for Thumb2
    decoded = list(md.disasm(chunk, va, count=1))
    if not decoded:
        continue
    insn = decoded[0]
    mn = insn.mnemonic.lower()
    ops = insn.op_str

    if mn == "movw" and "#" in ops:
        try:
            imm_str = ops.split("#")[-1].strip()
            imm_val = int(imm_str, 0)
            if imm_val in MOVW_TARGETS:
                linear_findings.append({
                    "type": "MOVW_LINEAR",
                    "va": insn.address,
                    "foff": off,
                    "detail": f"movw {ops}  (0x{imm_val:04X} -> {MOVW_TARGETS[imm_val]})",
                    "raw": chunk[:insn.size].hex(),
                })
        except ValueError:
            pass

    elif mn == "movt" and "#" in ops:
        try:
            imm_str = ops.split("#")[-1].strip()
            imm_val = int(imm_str, 0)
            if imm_val in MOVT_TARGETS:
                linear_findings.append({
                    "type": "MOVT_LINEAR",
                    "va": insn.address,
                    "foff": off,
                    "detail": f"movt {ops}  (0x{imm_val:04X} -> {MOVT_TARGETS[imm_val]})",
                    "raw": chunk[:insn.size].hex(),
                })
        except ValueError:
            pass

# Merge linear findings that aren't already in function findings
existing_vas = {f["va"] for f in findings}
for lf in linear_findings:
    if lf["va"] not in existing_vas:
        findings.append(lf)

# ============================================================
# PART 6: Report
# ============================================================
print()
print("=" * 70)
print("RESULTS: All findings")
print("=" * 70)

if not findings:
    print("\n  *** NO REFERENCES FOUND to any target address ***")
    print("  The address 0x5DE0C may be constructed via:")
    print("    - Multi-step register arithmetic not captured here")
    print("    - Table-driven indirect addressing")
    print("    - A different base+offset decomposition")
else:
    # Sort by VA
    findings.sort(key=lambda f: f["va"])
    for i, f in enumerate(findings):
        print(f"\n  [{i+1}] {f['type']} at VA 0x{f['va']:05X} (file offset 0x{f['foff']:05X})")
        print(f"      {f['detail']}")
        print(f"      raw bytes: {f['raw']}")
        if "func_va" in f:
            print(f"      in function starting at VA 0x{f['func_va']:05X}")

# ============================================================
# PART 7: Cross-reference MOVW/MOVT pairs
# ============================================================
print()
print("=" * 70)
print("PART 7: Cross-referencing MOVW/MOVT pairs")
print("=" * 70)

movw_hits = [f for f in findings if "MOVW" in f["type"]]
movt_hits = [f for f in findings if "MOVT" in f["type"]]

print(f"\n  MOVW hits: {len(movw_hits)}")
print(f"  MOVT hits: {len(movt_hits)}")

# For each MOVW, look for a nearby MOVT (within 20 bytes, same function)
if movw_hits and movt_hits:
    print("\n  Checking for MOVW/MOVT pairs within 20 bytes:")
    for mw in movw_hits:
        for mt in movt_hits:
            if abs(mw["va"] - mt["va"]) <= 20:
                # Determine which register each uses
                mw_reg = mw["detail"].split(",")[0].split()[-1] if "," in mw["detail"] else "?"
                mt_reg = mt["detail"].split(",")[0].split()[-1] if "," in mt["detail"] else "?"
                # Reconstruct full value
                mw_imm = int(mw["detail"].split("#")[-1].split(")")[0].split()[0], 0) if "#" in mw["detail"] else 0
                mt_imm = int(mt["detail"].split("#")[-1].split(")")[0].split()[0], 0) if "#" in mt["detail"] else 0
                full_val = (mt_imm << 16) | mw_imm
                print(f"\n    PAIR: MOVW@0x{mw['va']:05X} + MOVT@0x{mt['va']:05X}")
                print(f"      Registers: MOVW->{mw_reg}, MOVT->{mt_reg}")
                print(f"      Constructed value: 0x{full_val:08X}")
                if full_val in TARGET_ADDRS:
                    print(f"      *** MATCH: This constructs target address 0x{full_val:08X} ***")

# ============================================================
# PART 8: Additional - search for APCB-related patterns
# ============================================================
print()
print("=" * 70)
print("PART 8: Searching for other interesting constants near 0x5DE0C")
print("=" * 70)

# Search for any 32-bit value in range 0x5D000-0x5F000
interesting_range_hits = {}
for i in range(0, len(data) - 3, 4):
    val = struct.unpack_from("<I", data, i)[0]
    if 0x5D000 <= val <= 0x5F000:
        va = LOAD_BASE + i
        if val not in interesting_range_hits:
            interesting_range_hits[val] = []
        interesting_range_hits[val].append((i, va))

if interesting_range_hits:
    print(f"\n  Found {len(interesting_range_hits)} distinct values in range 0x5D000-0x5F000:")
    for val in sorted(interesting_range_hits.keys()):
        locs = interesting_range_hits[val]
        delta = val - 0x5DE0C
        print(f"    0x{val:08X} (delta from 0x5DE0C: {delta:+d} / 0x{abs(delta):X})  at {len(locs)} location(s):")
        for foff, va in locs[:5]:  # limit display
            print(f"      file 0x{foff:05X}  VA 0x{va:05X}")
        if len(locs) > 5:
            print(f"      ... and {len(locs)-5} more")
else:
    print("\n  No 32-bit values found in range 0x5D000-0x5F000")

# ============================================================
# PART 9: Manual encoding search for MOVW #0xDE0C
# ============================================================
print()
print("=" * 70)
print("PART 9: Manual encoding search for Thumb2 MOVW/MOVT bit patterns")
print("=" * 70)

# Thumb2 MOVW encoding:
# First halfword:  1111 0 i 10 0100 imm4
# Second halfword: 0 imm3 Rd(4) imm8
# Where the 16-bit immediate = imm4 : i : imm3 : imm8
# For 0xDE0C: binary = 1101 1110 0000 1100
#   imm4 = 0xD (bits 15-12 of imm16)
#   i    = 1   (bit 11)
#   imm3 = 0x7 (bits 10-8) -- wait let me recalculate
#   Actually: imm16 = imm4:i:imm3:imm8
#   0xDE0C = 0b 1101_1_110_00001100
#   imm4 = 0b1101 = 0xD
#   i    = 0b1
#   imm3 = 0b110
#   imm8 = 0b00001100 = 0x0C
#
# First halfword: 11110 1 10 0100 1101 = 0xF64D
# Second halfword: 0 110 rrrr 00001100
#   = 0x6r0C where r = Rd (4 bits)
# So we search for first hw = 0xF64D, second hw = 0x6?0C

print("\n  Looking for MOVW #0xDE0C encoding: first hw=0xF64D, second hw=0x6?0C")
for i in range(0, len(data) - 3, 2):
    hw1 = struct.unpack_from("<H", data, i)[0]
    if hw1 == 0xF64D:
        hw2 = struct.unpack_from("<H", data, i + 2)[0]
        if (hw2 & 0xF0FF) == 0x600C:
            rd = (hw2 >> 8) & 0xF
            va = LOAD_BASE + i
            print(f"    FOUND MOVW r{rd}, #0xDE0C at file offset 0x{i:05X} VA 0x{va:05X}")
            print(f"      raw: {data[i:i+4].hex()}")
            # Now look ahead for MOVT rN, #0x0005
            # MOVT: first hw = 11110 i 10 1100 imm4
            # 0x0005: imm4=0, i=0, imm3=0, imm8=5
            # First hw: 11110 0 10 1100 0000 = 0xF2C0
            # Second hw: 0 000 rrrr 00000101 = 0x0r05
            for j in range(i + 4, min(i + 24, len(data) - 3), 2):
                hw1t = struct.unpack_from("<H", data, j)[0]
                if hw1t == 0xF2C0:
                    hw2t = struct.unpack_from("<H", data, j + 2)[0]
                    if (hw2t & 0xF0FF) == 0x0005:
                        rd_t = (hw2t >> 8) & 0xF
                        va_t = LOAD_BASE + j
                        print(f"    FOUND MOVT r{rd_t}, #0x0005 at file offset 0x{j:05X} VA 0x{va_t:05X}")
                        print(f"      raw: {data[j:j+4].hex()}")
                        if rd == rd_t:
                            print(f"      *** SAME REGISTER r{rd} -- constructs 0x0005DE0C ***")

# Also search MOVT #0x0005 globally
print("\n  Looking for all MOVT #0x0005 encoding: first hw=0xF2C0, second hw=0x0?05")
for i in range(0, len(data) - 3, 2):
    hw1 = struct.unpack_from("<H", data, i)[0]
    if hw1 == 0xF2C0:
        hw2 = struct.unpack_from("<H", data, i + 2)[0]
        if (hw2 & 0xF0FF) == 0x0005:
            rd = (hw2 >> 8) & 0xF
            va = LOAD_BASE + i
            print(f"    MOVT r{rd}, #0x0005 at file offset 0x{i:05X} VA 0x{va:05X}  raw: {data[i:i+4].hex()}")
            # Look backwards for a MOVW on same register
            for j in range(max(0, i - 24), i, 2):
                hw1w = struct.unpack_from("<H", data, j)[0]
                # Check if it's a MOVW T3 encoding
                # 11110 i 10 0100 nnnn
                if (hw1w & 0xFBF0) == 0xF240:
                    hw2w = struct.unpack_from("<H", data, j + 2)[0]
                    rd_w = (hw2w >> 8) & 0xF
                    if rd_w == rd:
                        # Reconstruct the immediate
                        imm4 = hw1w & 0xF
                        i_bit = (hw1w >> 10) & 1
                        imm3 = (hw2w >> 12) & 0x7
                        imm8 = hw2w & 0xFF
                        imm16 = (imm4 << 12) | (i_bit << 11) | (imm3 << 8) | imm8
                        va_w = LOAD_BASE + j
                        print(f"      Preceding MOVW r{rd_w}, #0x{imm16:04X} at VA 0x{va_w:05X}")
                        full = (0x0005 << 16) | imm16
                        print(f"      Full constructed value: 0x{full:08X}")

print("\n\nDone.")
