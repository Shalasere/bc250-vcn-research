#!/usr/bin/env python3
"""Find code in ABL4 that references the #BUFFER OVERFLOW# string via literal pool."""
import struct

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834  # Confirmed from entry trampoline

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

# String "#BUFFER  OVERFLOW#" at binary offset 0x11ABD
# Preceded by 0x0A (newline), so the string "\n#BUFFER  OVERFLOW#\n" starts at 0x11ABC
# VA = ABL4_BASE + 0x11ABD = 0x722F1 (actual '#' character)
# But the debug print might use offset 0x11ABC (includes leading newline) = VA 0x722F0

overflow_str_off = 0x11ABD
overflow_str_va = ABL4_BASE + overflow_str_off

# Also check for 0x11ABC (the \n before #)
overflow_newline_va = ABL4_BASE + 0x11ABC

print("Overflow string: binary +0x{:05X} = VA 0x{:08X}".format(overflow_str_off, overflow_str_va))
print("With leading newline: VA 0x{:08X}".format(overflow_newline_va))

# Search ALL literal pool entries (aligned u32s) for VA values near the string
print("\n=== Literal pool entries pointing to overflow string region ===")
target_range = range(overflow_str_va - 4, overflow_str_va + 4)
for off in range(0, len(abl4) - 3, 4):
    word = struct.unpack_from("<I", abl4, off)[0]
    if word in target_range:
        print("  +0x{:05X}: 0x{:08X} (VA of string) -> binary offset 0x{:05X}".format(
            off, word, word - ABL4_BASE))
        # Find what code loads from this literal pool entry
        # Look for Thumb LDR Rd, [PC, #imm] that targets this offset
        for code_off in range(max(0, off - 1024), off, 2):
            hw = struct.unpack_from("<H", abl4, code_off)[0]
            if (hw & 0xF800) == 0x4800:  # Thumb LDR Rd, [PC, #imm8*4]
                imm8 = hw & 0xFF
                pc = (code_off + 4) & ~3
                target = pc + imm8 * 4
                if target == off:
                    rd = (hw >> 8) & 7
                    print("    Referenced by Thumb LDR R{} at +0x{:05X}".format(rd, code_off))

# Also search for the VA of nearby strings to understand the pattern
# "Failed to get internal APCB parameter" at offset 0x11A76 -> VA 0x722AA
failed_str_va = ABL4_BASE + 0x11A76
print("\n=== Also checking 'Failed to get internal APCB' string VA 0x{:08X} ===".format(failed_str_va))
for off in range(0, len(abl4) - 3, 4):
    word = struct.unpack_from("<I", abl4, off)[0]
    if abs(word - failed_str_va) <= 2:
        print("  +0x{:05X}: 0x{:08X}".format(off, word))
        for code_off in range(max(0, off - 1024), off, 2):
            hw = struct.unpack_from("<H", abl4, code_off)[0]
            if (hw & 0xF800) == 0x4800:
                imm8 = hw & 0xFF
                pc = (code_off + 4) & ~3
                target = pc + imm8 * 4
                if target == off:
                    rd = (hw >> 8) & 7
                    print("    Referenced by Thumb LDR R{} at +0x{:05X}".format(rd, code_off))

# Method 2: Search for MOVW/MOVT pairs that construct the VA
# MOVW Rd, #imm16: 11110x100100xxxx 0xxxxxxxxxxxxxxx
# MOVT Rd, #imm16: 11110x101100xxxx 0xxxxxxxxxxxxxxx
# For VA 0x000722F1: MOVW Rd, #0x22F1; MOVT Rd, #0x0007
print("\n=== MOVW/MOVT pairs constructing overflow string VA ===")
target_low = overflow_str_va & 0xFFFF  # 0x22F1
target_high = (overflow_str_va >> 16) & 0xFFFF  # 0x0007

# Also check with leading newline
nl_low = overflow_newline_va & 0xFFFF  # 0x22F0
nl_high = (overflow_newline_va >> 16) & 0xFFFF  # 0x0007

for off in range(0, len(abl4) - 7, 2):
    hw1 = struct.unpack_from("<H", abl4, off)[0]
    hw2 = struct.unpack_from("<H", abl4, off + 2)[0]

    # Check for MOVW (T3): 11110 i 10 0100 imm4 | 0 imm3 Rd imm8
    if (hw1 & 0xFBF0) == 0xF240:
        imm4 = hw1 & 0xF
        i = (hw1 >> 10) & 1
        imm3 = (hw2 >> 12) & 0x7
        rd = (hw2 >> 8) & 0xF
        imm8 = hw2 & 0xFF
        imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8

        if imm16 in (target_low, nl_low):
            # Check if next instruction is MOVT with matching high
            if off + 4 < len(abl4) - 1:
                hw3 = struct.unpack_from("<H", abl4, off + 4)[0]
                hw4 = struct.unpack_from("<H", abl4, off + 6)[0]
                if (hw3 & 0xFBF0) == 0xF2C0:  # MOVT
                    imm4_t = hw3 & 0xF
                    i_t = (hw3 >> 10) & 1
                    imm3_t = (hw4 >> 12) & 0x7
                    rd_t = (hw4 >> 8) & 0xF
                    imm8_t = hw4 & 0xFF
                    imm16_t = (imm4_t << 12) | (i_t << 11) | (imm3_t << 8) | imm8_t

                    if rd == rd_t and imm16_t in (target_high, nl_high):
                        full_va = (imm16_t << 16) | imm16
                        print("  +0x{:05X}: MOVW R{}, #0x{:04X} / MOVT R{}, #0x{:04X} -> 0x{:08X}".format(
                            off, rd, imm16, rd_t, imm16_t, full_va))

# Method 3: Also look for references to the "IDS OPTIONS" and "APCB parameter" strings
# to find the function that contains the overflow check
# These strings are all in the same region (0x119ED-0x11AD0)
print("\n=== Functions referencing APCB parameter strings ===")
apcb_strings = {
    "IDS_EXT": (0x119ED, "IDS OPTIONS GET EXTERNAL PARAMETER"),
    "IDS_INT": (0x11A31, "IDS OPTIONS GET INTERNAL PARAMETER"),
    "FAIL_APCB": (0x11A76, "Failed to get internal APCB parameter"),
    "BUF_OVFL": (0x11ABD, "#BUFFER  OVERFLOW#"),
}

for label, (str_off, desc) in apcb_strings.items():
    str_va = ABL4_BASE + str_off
    found = False
    # Check literal pool
    for off in range(0, len(abl4) - 3, 4):
        word = struct.unpack_from("<I", abl4, off)[0]
        if abs(word - str_va) <= 1:
            # Find referencing code
            for code_off in range(max(0, off - 1024), off, 2):
                hw = struct.unpack_from("<H", abl4, code_off)[0]
                if (hw & 0xF800) == 0x4800:
                    imm8 = hw & 0xFF
                    pc = (code_off + 4) & ~3
                    target = pc + imm8 * 4
                    if target == off:
                        print("  {}: string VA 0x{:X} in pool at +0x{:05X}, code at +0x{:05X}".format(
                            label, str_va, off, code_off))
                        found = True

    if not found:
        # Search for MOVW with the low 16 bits
        low16 = str_va & 0xFFFF
        for off in range(0, len(abl4) - 3, 2):
            hw1 = struct.unpack_from("<H", abl4, off)[0]
            hw2 = struct.unpack_from("<H", abl4, off + 2)[0]
            if (hw1 & 0xFBF0) == 0xF240:
                imm4 = hw1 & 0xF
                i = (hw1 >> 10) & 1
                imm3 = (hw2 >> 12) & 0x7
                imm8 = hw2 & 0xFF
                imm16 = (imm4 << 12) | (i << 11) | (imm3 << 8) | imm8
                if imm16 == low16:
                    print("  {}: MOVW with low16=0x{:04X} at +0x{:05X}".format(label, low16, off))

# Method 4: Let's look at what's RIGHT BEFORE the string data section
# The code section should end and strings begin
# Find the boundary between code and strings
print("\n=== Code/data boundary analysis ===")
# Scan backwards from 0x11A76 to find where code ends
boundary = 0x11A76
for off in range(0x11A76, 0, -2):
    b = abl4[off]
    if not (0x20 <= b < 0x7F):  # Not printable = probably code
        boundary = off + 1
        break

print("Last non-string byte before APCB strings: +0x{:05X}".format(boundary))
print("Bytes at boundary:")
for i in range(max(0, boundary - 32), boundary + 32, 2):
    hw = struct.unpack_from("<H", abl4, i)[0]
    marker = " <-- boundary" if i == boundary else ""
    is_str = all(0x20 <= abl4[i+j] < 0x7F for j in range(min(2, len(abl4)-i)))
    print("  +0x{:05X}: 0x{:04X} {}{}".format(i, hw, "str" if is_str else "   ", marker))

# Method 5: Just dump the Thumb code from 0x119A0 to 0x119EC to see the function
# that leads into the string data area
print("\n=== Thumb code region 0x119A0-0x119F0 (just before APCB param strings) ===")
for off in range(0x119A0, 0x119F0, 2):
    hw = struct.unpack_from("<H", abl4, off)[0]
    # Basic Thumb decode
    desc = ""
    if (hw & 0xFF00) == 0xB500:
        desc = "PUSH {..., LR}"
    elif (hw & 0xFF00) == 0xBD00:
        desc = "POP {..., PC}"
    elif hw == 0x4770:
        desc = "BX LR"
    elif (hw & 0xF800) == 0x4800:
        rd = (hw >> 8) & 7
        imm = (hw & 0xFF) * 4
        pc = (off + 4) & ~3
        target = pc + imm
        desc = "LDR R{}, [PC, #{}] -> +0x{:05X}".format(rd, imm, target)
        if target < len(abl4):
            w = struct.unpack_from("<I", abl4, target)[0]
            desc += " = 0x{:08X}".format(w)
    elif (hw & 0xFF00) == 0xDF00:
        desc = "SVC #0x{:02X}".format(hw & 0xFF)
    elif (hw & 0xF800) == 0xF000:
        desc = "(Thumb-2 prefix)"

    print("  +0x{:05X}: 0x{:04X}  {}".format(off, hw, desc))
