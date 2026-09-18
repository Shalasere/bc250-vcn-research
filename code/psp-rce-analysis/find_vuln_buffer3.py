"""
Phase 3: Trace how 0x5DE0C is reached.

Key findings so far:
- Zero MOVT instructions in the binary. All 32-bit addresses via literal pools.
- 0x5DE0C is NOT in any literal pool.
- Therefore: 0x5DE0C must come from a register (function arg or computed from pool-loaded base).
- "BUFFER OVERFLOW" string at VA 0x722F2
- APCB strings near VA 0x631CF, 0x67F9D, 0x683D4

Plan:
1. Find which functions reference the "BUFFER OVERFLOW" string
2. Find which functions reference the APCB strings
3. Trace SRAM base addresses through the code
4. Look for memcpy-like patterns with register-derived destinations
"""

import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

BIN_PATH = Path(r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin")
LOAD_BASE = 0x60834

data = BIN_PATH.read_bytes()
md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md.detail = True

def va_to_off(va):
    return va - LOAD_BASE

def off_to_va(off):
    return LOAD_BASE + off

# Find all function prologues
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

def find_containing_func(off):
    """Find the prologue that contains the given offset."""
    for i in range(len(prologues) - 1, -1, -1):
        if prologues[i] <= off:
            return prologues[i]
    return None

def disasm_func(func_off, max_bytes=4096):
    """Disassemble a function starting at func_off."""
    func_end = func_off + max_bytes
    # Limit to next prologue
    for p in prologues:
        if p > func_off:
            func_end = min(func_end, p)
            break
    func_end = min(func_end, len(data))
    func_data = data[func_off:func_end]
    va = off_to_va(func_off)
    return list(md.disasm(func_data, va))

# ============================================================
# PART 1: Find which LDR instructions load the "BUFFER OVERFLOW" string address
# ============================================================
print("=" * 70)
print("PART 1: Tracing 'BUFFER OVERFLOW' string reference")
print("=" * 70)

# The string is at VA 0x722F2 (file 0x11ABE)
# But actually, the string pointers in SRAM (the tail table) are 0x5Exxx addresses
# Those are SRAM addresses where strings are COPIED to at runtime
# The actual string in the binary at 0x722F2 might be referenced by its CODE VA

# Let's look for the code VA of the buffer overflow string
buf_overflow_va = 0x722F2
buf_overflow_off = va_to_off(buf_overflow_va)

# Check: is this address in a literal pool?
# Search for 0x722F2 as a u32
needle = struct.pack("<I", buf_overflow_va)
idx = data.find(needle)
if idx != -1:
    print(f"  Found literal pool entry for 'BUFFER OVERFLOW' string VA 0x{buf_overflow_va:X}")
    print(f"    at file 0x{idx:05X} VA 0x{off_to_va(idx):05X}")
else:
    # The string address might be with bit 0 set (for Thumb) or aligned differently
    # Or it could be at a slightly different address (the actual start of the string)
    # Let's search for nearby addresses
    print(f"  String 'BUFFER OVERFLOW' at VA 0x{buf_overflow_va:X} not found as literal pool entry")
    print(f"  Searching for nearby addresses...")
    for delta in range(-16, 17):
        target = buf_overflow_va + delta
        needle = struct.pack("<I", target)
        idx = data.find(needle)
        if idx != -1:
            print(f"    0x{target:X} found at file 0x{idx:05X} VA 0x{off_to_va(idx):05X} (delta {delta:+d})")

# Also check: ABL uses a different addressing model?
# Let's try lower values: if the binary is position-independent,
# maybe it uses offsets from the binary base
print()
print("  Checking if string is referenced as offset from LOAD_BASE...")
str_offset = buf_overflow_off  # offset within binary
needle = struct.pack("<I", str_offset)
idx = data.find(needle)
if idx != -1:
    print(f"    Found offset 0x{str_offset:X} at file 0x{idx:05X}")
else:
    print(f"    Offset 0x{str_offset:X} not found either")

# ============================================================
# PART 2: Search for ALL literal pool entries that point INTO the binary
# (i.e., code/data VAs in range 0x60834 - 0x75FF3)
# ============================================================
print()
print("=" * 70)
print("PART 2: Literal pool entries pointing into the binary itself")
print("=" * 70)

code_ptrs = {}
binary_end_va = LOAD_BASE + len(data)
for i in range(0, len(data) - 3, 4):
    val = struct.unpack_from("<I", data, i)[0]
    if LOAD_BASE <= val < binary_end_va:
        va = off_to_va(i)
        if val not in code_ptrs:
            code_ptrs[val] = []
        code_ptrs[val].append((i, va))

print(f"\n  Distinct code/data pointers found: {len(code_ptrs)}")
# Show ones that point to the string/data area (higher VAs tend to be data)
# The last ~4KB of the binary is likely data (strings, tables)
DATA_THRESHOLD_VA = 0x71000  # roughly where code ends and data begins
data_ptrs = {v: locs for v, locs in code_ptrs.items() if v >= DATA_THRESHOLD_VA}
print(f"  Of which point to high addresses (>{hex(DATA_THRESHOLD_VA)}, likely data): {len(data_ptrs)}")

# Show some interesting ones near the BUFFER OVERFLOW string
for val in sorted(data_ptrs.keys()):
    if abs(val - buf_overflow_va) <= 0x100:
        locs = data_ptrs[val]
        print(f"    0x{val:05X} at:", end="")
        for foff, va in locs[:5]:
            print(f" file 0x{foff:05X}/VA 0x{va:05X}", end="")
        print()

# ============================================================
# PART 3: Find LDR instructions that load SRAM addresses as function arguments
# then trace what happens to those registers
# ============================================================
print()
print("=" * 70)
print("PART 3: Functions using SRAM base addresses (full disassembly)")
print("=" * 70)

# Known SRAM literal pool entries from prior run
sram_pools = {
    0x000500B0: 0x74410,
    0x00050100: [0x68DA4, 0x68DE0],
    0x00050124: 0x69200,
    0x00050200: 0x6B2E8,
    0x00051050: 0x62294,
    0x00058401: [0x69444, 0x75FE8],
    0x00058405: [0x69448, 0x75FEC],
    0x00058409: [0x6944C, 0x75FF0],
    0x00058559: [0x6943C, 0x75FE4],
    0x00058565: 0x75F9C,
    0x0005A86C: 0x6F9B8,
}

# Focus on 0x5A86C - it's the closest lower SRAM address to 0x5DE0C
# 0x5DE0C - 0x5A86C = 0x35A0
# Trace the function that loads 0x5A86C
print("\n  --- Tracing 0x5A86C usage (closest lower SRAM addr to 0x5DE0C) ---")
pool_off = va_to_off(0x6F9B8)
func_off = find_containing_func(pool_off)
if func_off:
    func_va = off_to_va(func_off)
    # Actually, the pool entry is REFERENCED by LDR, not the function it lives in
    # Let's find the LDR that loads it, then trace that function
    # LDR r1, [PC, #0x10] at VA 0x6F9A6 was found earlier
    ldr_off = va_to_off(0x6F9A6)
    func_off = find_containing_func(ldr_off)
    if func_off:
        func_va = off_to_va(func_off)
        print(f"\n  Function at VA 0x{func_va:05X} loads 0x5A86C:")
        insns = disasm_func(func_off)
        for insn in insns[:80]:
            print(f"    0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")

# ============================================================
# PART 4: Disassemble the function containing 0x50100 load
# (at 0x68D8E) - this is likely APCB-related
# ============================================================
print()
print("=" * 70)
print("PART 4: Function loading 0x50100 (APCB buffer candidate)")
print("=" * 70)

ldr_off = va_to_off(0x68D8E)
func_off = find_containing_func(ldr_off)
if func_off:
    func_va = off_to_va(func_off)
    print(f"\n  Function at VA 0x{func_va:05X}:")
    insns = disasm_func(func_off)
    for insn in insns[:80]:
        print(f"    0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")

# ============================================================
# PART 5: Look for the APCB parsing function
# The string "APCB Config parameter" is at VA 0x67F9D (file 0x07769)
# Find what references it
# ============================================================
print()
print("=" * 70)
print("PART 5: Function referencing 'APCB Config parameter' string")
print("=" * 70)

# Find the function that is near the APCB string references
# "ing APCB parameters for Type" at file 0x07BA0 (VA 0x683D4)
# This string is in the code section, likely embedded in or near its function
apcb_str_off = 0x07BA0
func_off = find_containing_func(apcb_str_off)
if func_off:
    func_va = off_to_va(func_off)
    print(f"\n  Function near APCB string at VA 0x{func_va:05X}:")
    insns = disasm_func(func_off, max_bytes=2048)
    for insn in insns[:120]:
        print(f"    0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")

# ============================================================
# PART 6: Search for functions that write to SRAM via STR with register base
# Pattern: STR rN, [rM, #offset] where rM could hold SRAM base
# Focus on STR with large offsets that could reach 0xDE0C from a base
# ============================================================
print()
print("=" * 70)
print("PART 6: STR instructions with interesting offsets")
print("=" * 70)

# Scan for STR.W with immediate offsets >= 0x100
# STR.W Rt, [Rn, #imm12]: 1111 1000 1100 nnnn | tttt iiiiiiiiiiii
for off in range(0, len(data) - 3, 2):
    hw1 = struct.unpack_from("<H", data, off)[0]
    # STR.W Rt, [Rn, #imm12]: hw1 = 1111 1000 1100 nnnn
    if (hw1 & 0xFFF0) == 0xF8C0:
        hw2 = struct.unpack_from("<H", data, off + 2)[0]
        rn = hw1 & 0xF
        rt = (hw2 >> 12) & 0xF
        imm12 = hw2 & 0xFFF
        if imm12 >= 0xD00:  # large offset that could reach 0xDE0C area
            va = off_to_va(off)
            print(f"  STR.W r{rt}, [r{rn}, #0x{imm12:X}] at VA 0x{va:05X}")

    # LDR.W Rt, [Rn, #imm12]: hw1 = 1111 1000 1101 nnnn
    if (hw1 & 0xFFF0) == 0xF8D0:
        hw2 = struct.unpack_from("<H", data, off + 2)[0]
        rn = hw1 & 0xF
        rt = (hw2 >> 12) & 0xF
        imm12 = hw2 & 0xFFF
        if imm12 >= 0xD00:
            va = off_to_va(off)
            print(f"  LDR.W r{rt}, [r{rn}, #0x{imm12:X}] at VA 0x{va:05X}")

# ============================================================
# PART 7: Check if 0x5DE0C could be on the stack
# PSP stacks are typically in SRAM. Look for large SP offsets
# ============================================================
print()
print("=" * 70)
print("PART 7: Large SP-relative accesses")
print("=" * 70)

# SUB SP, SP, #large at function entry
for off in range(0, len(data) - 3, 2):
    hw1 = struct.unpack_from("<H", data, off)[0]
    # Check for SUB.W SP, SP, #imm12
    # Encoding: 1111 0x01 101s 1101 | 0 imm3 1101 imm8
    # That's: F1AD 0Dxx or F5AD 0Dxx
    if hw1 == 0xF5AD or hw1 == 0xF1AD:
        hw2 = struct.unpack_from("<H", data, off + 2)[0]
        rd = (hw2 >> 8) & 0xF
        if rd == 13:  # SP
            # Decode the modified immediate
            # This is the Thumb modified immediate constant
            imm8 = hw2 & 0xFF
            imm3 = (hw2 >> 12) & 0x7
            i_bit = (hw1 >> 10) & 1
            imm12_encoded = (i_bit << 11) | (imm3 << 8) | imm8
            # Decode thumb_expand_imm (simplified)
            if imm12_encoded < 256:
                value = imm12_encoded
            else:
                rotation = imm12_encoded >> 7
                unrotated = 0x80 | (imm12_encoded & 0x7F)
                value = (unrotated >> rotation) | (unrotated << (32 - rotation))
                value &= 0xFFFFFFFF
            if value >= 0x100:  # large stack frame
                va = off_to_va(off)
                print(f"  SUB SP, SP, #0x{value:X} ({value} bytes) at VA 0x{va:05X}")

# ============================================================
# PART 8: Search for the exact byte 0x0C at offset that makes 0xDE0C
# Maybe it's addr = base + 0xC (small offset from 0x5DE00)
# Look for 0x5DE00 constructed differently
# ============================================================
print()
print("=" * 70)
print("PART 8: Alternative decomposition search")
print("=" * 70)

# Maybe the address is computed as: some_sram_base + struct_offset
# Where some_sram_base comes from a global/parameter and struct_offset includes 0xDE0C

# Search for the value 0xDE0C as a 32-bit word (might be used as an offset)
for pattern_name, pattern_val in [
    ("0x0000DE0C (offset)", 0xDE0C),
    ("0x0000DE00 (aligned offset)", 0xDE00),
    ("0x00000E0C (page offset)", 0x0E0C),
    ("0x0000E000 (page base offset)", 0xE000),
    ("0x00050000 (SRAM 0x5xxxx page)", 0x50000),
    ("0x0005C000", 0x5C000),
    ("0x0005D000", 0x5D000),
    ("0x0005D800", 0x5D800),
    ("0x0005DC00", 0x5DC00),
    ("0x0005DE00", 0x5DE00),
]:
    needle = struct.pack("<I", pattern_val)
    results = []
    idx = 0
    while True:
        pos = data.find(needle, idx)
        if pos == -1:
            break
        results.append(pos)
        idx = pos + 1
    if results:
        print(f"  {pattern_name}: found at {len(results)} offset(s):", end="")
        for r in results[:5]:
            print(f" file 0x{r:05X}/VA 0x{off_to_va(r):05X}", end="")
        if len(results) > 5:
            print(f" +{len(results)-5} more", end="")
        print()
    else:
        print(f"  {pattern_name}: NOT FOUND")

# ============================================================
# PART 9: Look for how r0-r3 are set before BL calls in APCB functions
# The "BUFFER OVERFLOW" check likely guards a memcpy into the buffer
# ============================================================
print()
print("=" * 70)
print("PART 9: Function containing 'BUFFER OVERFLOW' string")
print("=" * 70)

# The actual "BUFFER OVERFLOW" string is at 0x722F2
# Let's find functions in the code section that could reference it
# In Thumb, strings are often referenced via ADR or LDR from literal pool
# The string VA 0x722F2 would need to be in a literal pool

# Search for 0x722F2 and nearby addresses as u32 in literal pools
for delta in range(-4, 5):
    target = 0x722F2 + delta
    needle = struct.pack("<I", target)
    idx = data.find(needle)
    if idx != -1:
        va = off_to_va(idx)
        print(f"  Literal pool entry 0x{target:X} at file 0x{idx:05X} VA 0x{va:05X}")
        # Find which function this is in
        foff = find_containing_func(idx)
        if foff:
            print(f"    In function at VA 0x{off_to_va(foff):05X}")

# The strings might be embedded directly in the code stream (not via pointer)
# In many PSP firmwares, debug strings are inline after a BL to a print function
# Let's look at the bytes around "BUFFER OVERFLOW"
print(f"\n  Context around 'BUFFER OVERFLOW' (VA 0x722F2, file 0x11ABE):")
ctx_start = max(0, 0x11ABE - 32)
ctx_end = min(len(data), 0x11ABE + 64)
# Disassemble the region before the string
pre_data = data[ctx_start:0x11ABE]
pre_va = off_to_va(ctx_start)
print(f"\n  Disassembly before string:")
for insn in md.disasm(pre_data, pre_va):
    print(f"    0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}")

# And the string itself
str_data = data[0x11ABE:0x11ABE+32]
print(f"\n  String bytes: {str_data[:24].hex(' ')}")
print(f"  ASCII: {''.join(chr(b) if 32<=b<127 else '.' for b in str_data[:24])}")

# Let's also look at the broader function this is embedded in
print(f"\n  Broader function context:")
func_off = find_containing_func(0x11ABE)
if func_off:
    func_va = off_to_va(func_off)
    print(f"  Function starts at file 0x{func_off:05X} VA 0x{func_va:05X}")
    insns = disasm_func(func_off, max_bytes=4096)
    # Show instructions, flagging interesting ones
    for insn in insns:
        flag = ""
        if "bl" in insn.mnemonic.lower() and insn.mnemonic.lower() != "blt":
            flag = " <-- CALL"
        if "str" in insn.mnemonic.lower():
            flag = " <-- STORE"
        if "ldr" in insn.mnemonic.lower() and "[pc" in insn.op_str.lower():
            # Try to resolve literal pool
            import re
            m = re.search(r'\[pc,\s*#(-?0x[0-9a-fA-F]+|-?\d+)\]', insn.op_str.lower())
            if m:
                imm = int(m.group(1), 0)
                pc_aligned = (insn.address + 4) & ~3
                pool_addr = pc_aligned + imm
                pool_off = va_to_off(pool_addr)
                if 0 <= pool_off <= len(data) - 4:
                    pool_val = struct.unpack_from("<I", data, pool_off)[0]
                    flag = f" <-- POOL@0x{pool_addr:05X}=0x{pool_val:08X}"
        if insn.address >= 0x722F2 - 4 and insn.address < 0x722F2 + 20:
            flag += " <<< BUFFER OVERFLOW STRING AREA"
        print(f"    0x{insn.address:05X}: {insn.mnemonic:8s} {insn.op_str}{flag}")
        if insn.address > 0x72400:
            break  # enough

print("\n\nDone.")
