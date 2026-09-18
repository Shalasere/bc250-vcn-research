#!/usr/bin/env python3
"""Analyze ABL4's section structure and string referencing mechanism."""
import struct
import math
from collections import Counter
from capstone import *

path = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
with open(path, "rb") as f:
    abl4 = f.read()

BASE = 0x60834

# 1. Block entropy analysis (1K blocks) to find code vs data boundaries
print("=== Block entropy (1K chunks) ===")
block_size = 1024
for i in range(0, len(abl4), block_size):
    chunk = abl4[i:i+block_size]
    if len(chunk) < 64:
        continue
    counts = Counter(chunk)
    entropy = -sum((c/len(chunk)) * math.log2(c/len(chunk)) for c in counts.values() if c > 0)

    # Check if mostly printable (string data)
    printable = sum(1 for b in chunk if 0x20 <= b < 0x7F or b in (0x0A, 0x0D, 0x00))
    pct_printable = printable / len(chunk) * 100

    kind = "CODE" if entropy > 5.5 and pct_printable < 60 else "DATA/STR" if pct_printable > 60 else "MIXED"
    print("  0x{:05X}-0x{:05X}: entropy={:.2f} printable={:5.1f}% {}".format(
        i, i + len(chunk), entropy, pct_printable, kind))

# 2. Look for section headers or relocation tables
print("\n=== Searching for section markers ===")
# Check for common section markers
for off in range(0, len(abl4) - 3, 4):
    val = struct.unpack_from("<I", abl4, off)[0]
    # Look for relocation table markers, GOT entries, etc
    # AGESA modules sometimes have a header with section offsets
    pass

# 3. Check the very beginning of ABL4 for a module header
# After the ARM trampoline (first 0x14 bytes), check if there's a header
print("\n=== Module header check (first 256 bytes) ===")
for off in range(0, min(0x100, len(abl4)), 4):
    val = struct.unpack_from("<I", abl4, off)[0]
    note = ""
    val_off = val - BASE
    if 0 < val_off < len(abl4):
        note = "(in-binary +0x{:X})".format(val_off)
    elif 0 < val < len(abl4):
        note = "(raw offset 0x{:X})".format(val)
    print("  +0x{:04X}: 0x{:08X} {}".format(off, val, note))

# 4. Disassemble a known function to see how it references strings
# The first hit was at pool +0x08388 loading VA 0x72000
# Let's find the function that contains the code at 0x08388 and see how it uses the value
print("\n=== Disassembly around pool ref at +0x08388 ===")
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
# Disassemble from a bit before 0x8388
start = 0x8300
chunk = abl4[start:start + 0x200]
for insn in cs.disasm(chunk, BASE + start):
    addr_off = insn.address - BASE
    marker = ""
    if addr_off == 0x8388:
        marker = " <-- literal pool (0x72000)"
    print("  0x{:08X} (+0x{:05X}): {:8s} {} {}".format(
        insn.address, addr_off, insn.mnemonic, insn.op_str, marker))
    if addr_off > 0x83C0:
        break

# 5. Check for a string table structure
# AGESA IDS typically has a debug string table with format:
# struct { uint32_t id; const char* str; } or just an array of string pointers
# Look for a dense array of pointers into the string section
print("\n=== Searching for string pointer tables ===")
# A string table would be a sequence of consecutive u32s all pointing to string data
for off in range(0, len(abl4) - 32, 4):
    # Check if 4+ consecutive u32s point to strings
    count = 0
    for j in range(0, 64, 4):
        if off + j + 4 > len(abl4):
            break
        val = struct.unpack_from("<I", abl4, off + j)[0]
        val_off = val - BASE
        # Check if it points to a string
        if 0x11000 <= val_off < 0x15800:
            b = abl4[val_off]
            if 0x20 <= b < 0x7F:
                count += 1
            else:
                break
        elif 0x11000 <= val < 0x15800:  # raw offset
            b = abl4[val]
            if 0x20 <= b < 0x7F:
                count += 1
            else:
                break
        else:
            break
    if count >= 4:
        print("  String table candidate at +0x{:05X}: {} consecutive string pointers".format(off, count))
        # Show the first few
        for j in range(min(count, 8)):
            val = struct.unpack_from("<I", abl4, off + j*4)[0]
            val_off = val - BASE if val >= BASE else val
            if 0 <= val_off < len(abl4):
                s = ""
                for k in range(min(50, len(abl4) - val_off)):
                    b = abl4[val_off + k]
                    if b == 0: break
                    if 0x20 <= b < 0x7F: s += chr(b)
                    else: s += "."
                print("    [{:2d}] 0x{:08X} -> \"{}\"".format(j, val, s))

# 6. Alternative: maybe strings are in the .rodata equivalent and referenced
# via a GOT-like mechanism. Check for an offset table at the end of the binary
print("\n=== Last 256 bytes of binary (potential relocation/offset table) ===")
end_start = len(abl4) - 256
for off in range(end_start, len(abl4), 4):
    if off + 4 <= len(abl4):
        val = struct.unpack_from("<I", abl4, off)[0]
        note = ""
        val_off = val - BASE
        if 0 <= val_off < len(abl4):
            note = "(ABL4 VA)"
        elif 0 < val < len(abl4):
            note = "(raw offset)"
        print("  +0x{:05X}: 0x{:08X} {}".format(off, val, note))
