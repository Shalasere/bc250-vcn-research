#!/usr/bin/env python3
"""Search ABL4 binary for literal pool entries pointing to string section."""
import struct

path = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
with open(path, "rb") as f:
    abl4 = f.read()

BASE = 0x60834

# String section is roughly binary offsets 0x11000-0x15000
STR_VA_LO = BASE + 0x11000
STR_VA_HI = BASE + 0x15800

print("String section VA range: 0x{:X} - 0x{:X}".format(STR_VA_LO, STR_VA_HI))

# Scan ALL u32s for values in string VA range
print("\n=== Literal pool entries pointing to string section ===")
hits = 0
for off in range(0, len(abl4) - 3, 4):
    val = struct.unpack_from("<I", abl4, off)[0]
    if STR_VA_LO <= val <= STR_VA_HI:
        val_off = val - BASE
        s = ""
        for j in range(min(60, len(abl4) - val_off)):
            b = abl4[val_off + j]
            if b == 0:
                break
            if 0x20 <= b < 0x7F:
                s += chr(b)
            else:
                s += "."
        tag = ""
        if "BUFFER" in s or "OVERFLOW" in s:
            tag = " *** OVERFLOW ***"
        if "APCB" in s:
            tag = " *** APCB ***"
        if "oken" in s:
            tag = " *** TOKEN ***"
        print("  pool +0x{:05X}: VA 0x{:08X} -> str +0x{:05X}: {:60s}  {}".format(
            off, val, val_off, s[:60], tag))
        hits += 1

print("\nTotal literal pool hits: {}".format(hits))

if hits == 0:
    # Check: ANY values in the 0x6xxxx range?
    print("\nSearching for ANY VA-like values (0x0006xxxx - 0x0007xxxx):")
    for off in range(0, len(abl4) - 3, 4):
        val = struct.unpack_from("<I", abl4, off)[0]
        if 0x00060000 <= val <= 0x00080000:
            val_off = val - BASE
            note = ""
            if 0 <= val_off < len(abl4):
                note = "(in-binary offset 0x{:X})".format(val_off)
            print("  +0x{:05X}: 0x{:08X} {}".format(off, val, note))

    # Also check if strings might use a DIFFERENT base
    # Maybe the base address is 0 (position-independent)?
    print("\nSearching for values pointing to strings with base=0:")
    for off in range(0, len(abl4) - 3, 4):
        val = struct.unpack_from("<I", abl4, off)[0]
        if 0x11000 <= val <= 0x15800:
            val_off = val
            if val_off < len(abl4):
                s = ""
                for j in range(min(40, len(abl4) - val_off)):
                    b = abl4[val_off + j]
                    if b == 0:
                        break
                    if 0x20 <= b < 0x7F:
                        s += chr(b)
                    else:
                        s += "."
                if len(s) >= 6:
                    print("  +0x{:05X}: 0x{:08X} -> \"{}\"".format(off, val, s[:60]))
