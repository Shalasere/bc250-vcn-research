#!/usr/bin/env python3
"""Find the vulnerability function in decompressed ABL4 around the #BUFFER OVERFLOW# string."""
import struct
import os

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

print("ABL4 decompressed: {} bytes (0x{:X})".format(len(abl4), len(abl4)))

# The #BUFFER OVERFLOW# string is at +0x11ABD
OVERFLOW_STR_OFF = 0x11ABD
print("\nString at +0x{:05X}: \"{}\"".format(
    OVERFLOW_STR_OFF,
    abl4[OVERFLOW_STR_OFF:OVERFLOW_STR_OFF+20].decode("ascii", errors="replace")))

# In Thumb code, string references use ADR or LDR from literal pool
# Look for all instructions that load addresses near 0x11ABD
# Thumb: LDR Rd, [PC, #imm8*4] -> loads from PC+4+imm8*4 (aligned)
# Thumb-2: LDR Rd, [PC, #imm12] or ADR Rd, PC+/-imm
# Also: MOVW/MOVT pairs to construct the address

# First, let's find what references 0x11ABD (the string address)
# Since ABL4 probably loads at some VA base, we need to find the reference as:
#   load_base + 0x11ABD
# But we don't know load_base. Let's search for the raw offset in literal pools.

# Method 1: Search for 0x11ABD as a u32 literal (offset from ABL4 base)
needle_offsets = [0x11ABD]
# If ABL4 loads at 0x60834, the string VA would be 0x60834 + 0x11ABD = 0x722F1
# But ABL stages might load at other addresses too
for base in [0x0, 0x100, 0x60834, 0x15100, 0x10000]:
    va = base + 0x11ABD
    needle_offsets.append(va)

print("\n=== Searching for literal pool references to the overflow string ===")
for target_va in needle_offsets:
    needle = struct.pack("<I", target_va)
    for off in range(0, len(abl4) - 3, 4):
        if abl4[off:off+4] == needle:
            print("  VA 0x{:08X} found at +0x{:05X} (literal pool)".format(target_va, off))

# Method 2: Search for APCB-related strings near the overflow string
print("\n=== Strings near #BUFFER OVERFLOW# ===")
region_start = max(0, OVERFLOW_STR_OFF - 0x200)
region_end = min(len(abl4), OVERFLOW_STR_OFF + 0x200)
i = region_start
while i < region_end:
    if 0x20 <= abl4[i] < 0x7F:
        start = i
        while i < len(abl4) and 0x20 <= abl4[i] < 0x7F:
            i += 1
        if i - start >= 4:
            s = abl4[start:start+(i-start)].decode("ascii")
            print("  +0x{:05X}: \"{}\"".format(start, s))
    else:
        i += 1

# Method 3: Since we don't know the load base, look at how ABL4 starts
# It starts with 0xE92D4010 = PUSH {R4, LR} — this is the entry point
print("\n=== ABL4 entry analysis ===")
print("Entry instruction: 0x{:08X} = PUSH {{R4, LR}}".format(
    struct.unpack_from("<I", abl4, 0)[0]))

# Look for ARM/Thumb mode switching
# Check if all code is Thumb or mixed
# Thumb BL instructions to functions referencing the overflow string area
# Let's find all function prologues near the overflow string (within 0x200 before)
print("\n=== Functions near the overflow string region ===")
# The overflow string at 0x11ABD is in the DATA section (strings).
# The CODE that references it will be somewhere else.
# In ARM binaries, strings are usually after the code, or interleaved in literal pools.

# Let me find the "Failed to get internal APCB parameter" string and the
# "#BUFFER OVERFLOW#" string, and search backwards from them for code patterns

# Look for the pattern: a function that calls something and then references
# "#BUFFER OVERFLOW#" as an error message

# Method 4: PC-relative addressing
# In Thumb-2, a common pattern is:
#   ADR Rn, label  (T3 encoding: 11110x10xF00xxxx 0xxxxxxxxxxxxxxx)
#   or LDR Rn, [PC, #offset]
# Let's search for Thumb-2 LDR Rn, [PC, #imm] that would point to 0x11ABD

print("\n=== Scanning for PC-relative loads pointing to overflow string region ===")
string_range_start = 0x119E0  # A bit before the string
string_range_end = 0x11AE0    # A bit after

hits = []
for off in range(0, len(abl4) - 3, 2):
    # Thumb LDR Rd, [PC, #imm8*4]: 01001 rrr iiiiiiii
    hw = struct.unpack_from("<H", abl4, off)[0]
    if (hw & 0xF800) == 0x4800:
        rd = (hw >> 8) & 7
        imm8 = hw & 0xFF
        pc = (off + 4) & ~3  # PC is aligned to word
        target = pc + imm8 * 4
        if string_range_start <= target <= string_range_end:
            hits.append((off, "Thumb LDR R{}, [PC, #{}]".format(rd, imm8*4), target))

    # Thumb-2 LDR.W Rt, [PC, #imm12]: 11111000 U1011111 tttt iiiiiiiiiiii
    if off + 2 < len(abl4):
        hw2 = struct.unpack_from("<H", abl4, off + 2)[0]
        if (hw & 0xFF7F) == 0xF85F:  # LDR.W Rt, [PC, ...]
            U = (hw >> 7) & 1
            rt = (hw2 >> 12) & 0xF
            imm12 = hw2 & 0xFFF
            pc = (off + 4) & ~3
            if U:
                target = pc + imm12
            else:
                target = pc - imm12
            if string_range_start <= target <= string_range_end:
                hits.append((off, "Thumb-2 LDR.W R{}, [PC, #{}{}]".format(
                    rt, "+" if U else "-", imm12), target))

for off, desc, target in hits:
    # Show context
    ctx_start = max(0, off - 16)
    ctx_bytes = abl4[ctx_start:off+8].hex()
    print("  +0x{:05X}: {} -> +0x{:05X}".format(off, desc, target))
    # Check if target is a literal pool word pointing to the string
    if target + 4 <= len(abl4):
        word = struct.unpack_from("<I", abl4, target)[0]
        print("    Value at target: 0x{:08X}".format(word))

# Method 5: Look for all literal pool entries that might be pointers into the string area
print("\n=== Literal pool pointers into string region (0x11900-0x11C00) ===")
# If ABL4 loads at an unknown base, the literal pool will contain (base + string_offset)
# We can look for pairs of values that differ by known offsets
# Or just dump the code structure near the overflow string

# Actually, let's just find the function containing the APCB parsing code
# by looking for "GroupId" and "TypeId" pattern which is the core parser
print("\n=== Code near APCB GroupId/TypeId string (+0x07C96) ===")
# "GroupId : 0x%04X,  TypeId : 0x%04X" at +0x07C96
# Find what code references this string
groupid_str = 0x07C96
for off in range(0, min(len(abl4), 0x10000) - 3, 2):
    hw = struct.unpack_from("<H", abl4, off)[0]
    if (hw & 0xF800) == 0x4800:  # Thumb LDR Rd, [PC, #]
        imm8 = hw & 0xFF
        pc = (off + 4) & ~3
        target = pc + imm8 * 4
        if target + 4 <= len(abl4):
            word = struct.unpack_from("<I", abl4, target)[0]
            # Check if word looks like it could point to groupid_str
            # word = base + 0x7C96
            # We don't know base, but if it's 0 then word = 0x7C96
            if (word & 0xFFFF) == (groupid_str & 0xFFFF):
                print("  +0x{:05X}: LDR -> pool +0x{:05X} = 0x{:08X} (low bits match GroupId str)".format(
                    off, target, word))

# Method 6: Just dump the code region between strings
# The "Failed to get internal APCB parameter" is at 0x11A76
# The "#BUFFER OVERFLOW#" is at 0x11ABD
# There might be code between or right after
print("\n=== Region between 'Failed to get' and '#BUFFER OVERFLOW#' ===")
for off in range(0x11A76, 0x11AE0, 2):
    hw = struct.unpack_from("<H", abl4, off)[0]
    b = abl4[off]
    is_printable = all(0x20 <= abl4[off+j] < 0x7F for j in range(min(2, len(abl4)-off)))
    if is_printable:
        chars = chr(abl4[off]) + chr(abl4[off+1])
    else:
        chars = ""
    print("  +0x{:05X}: 0x{:04X}  {}".format(off, hw, chars))

# Method 7: ABL4 entry point analysis - trace from the beginning
print("\n=== ABL4 first few instructions (disasm) ===")
# 0xE92D4010 = PUSH {R4, LR}
# Let's decode first 40 instructions
for off in range(0, min(80, len(abl4)), 4):
    word = struct.unpack_from("<I", abl4, off)[0]
    print("  +0x{:04X}: 0x{:08X}".format(off, word))

# Method 8: Search for the overflow check pattern
# The bug is "saved_len uninitialized" - likely pattern:
# - Load a length value from APCB token
# - Compare against buffer size
# - On failure, reference "#BUFFER OVERFLOW#"
# In ARM: typically a CMP + BCC followed by error handling
# Let's find all references to a function that might be memcpy/buffer_write
# and look for missing bounds checks

# First, let's understand ABL4's section layout
print("\n=== ABL4 section analysis ===")
# Count consecutive strings vs code regions
code_regions = []
string_regions = []
in_string = False
region_start = 0

for off in range(len(abl4)):
    is_str = 0x20 <= abl4[off] < 0x7F
    if is_str and not in_string:
        if off > region_start:
            code_regions.append((region_start, off))
        region_start = off
        in_string = True
    elif not is_str and in_string:
        if off - region_start >= 8:  # only count significant string regions
            string_regions.append((region_start, off))
        region_start = off
        in_string = False

# Find the last code region before the string data
print("Code regions (start, end, size) — last 5:")
for start, end in code_regions[-5:]:
    print("  0x{:05X} - 0x{:05X}: {} bytes".format(start, end, end-start))

print("\nString regions near the overflow string:")
for start, end in string_regions:
    if 0x11000 <= start <= 0x12000:
        s = abl4[start:min(start+40, end)].decode("ascii", errors="replace")
        print("  0x{:05X} - 0x{:05X}: {} bytes \"{}...\"".format(start, end, end-start, s))
