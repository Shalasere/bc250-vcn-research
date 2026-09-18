#!/usr/bin/env python3
"""Decompress zlib-compressed ABL bodies from internal BIOS."""
import struct
import zlib
import os
import math
from collections import Counter

FW_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware"

abls = ["abl0", "abl1", "abl2", "abl3", "abl4"]

for name in abls:
    body_path = os.path.join(FW_DIR, "internal_{}_body.bin".format(name))
    if not os.path.exists(body_path):
        print("{}: body file not found".format(name))
        continue

    with open(body_path, "rb") as f:
        body = f.read()

    print("=== {} ===".format(name.upper()))
    print("  Compressed: {} bytes".format(len(body)))

    # Check for zlib header
    if len(body) >= 2:
        print("  First 2 bytes: 0x{:02X} 0x{:02X}".format(body[0], body[1]))
        if body[0] == 0x78:
            print("  Zlib header detected (CMF=0x78)")

    try:
        decompressed = zlib.decompress(body)
        print("  Decompressed: {} bytes (0x{:X})".format(len(decompressed), len(decompressed)))

        # Entropy
        byte_counts = Counter(decompressed)
        entropy = -sum((c/len(decompressed)) * math.log2(c/len(decompressed))
                       for c in byte_counts.values() if c > 0)
        print("  Entropy: {:.3f}".format(entropy))

        # Save decompressed
        out_path = os.path.join(FW_DIR, "internal_{}_decompressed.bin".format(name))
        with open(out_path, "wb") as f:
            f.write(decompressed)
        print("  Saved to: {}".format(out_path))

        # Quick analysis
        first_word = struct.unpack_from("<I", decompressed, 0)[0]
        first_hw = struct.unpack_from("<H", decompressed, 0)[0]
        print("  First word: 0x{:08X}".format(first_word))

        # ARM vector table?
        if (first_word & 0xFFFFF000) == 0xE59FF000:
            print("  ** ARM LDR PC vector table! **")

        # Thumb PUSH?
        if (first_hw & 0xFF00) == 0xB500 or first_hw == 0xE92D:
            print("  ** Starts with Thumb PUSH **")

        # Function count
        push_count = 0
        for off in range(0, len(decompressed) - 1, 2):
            hw = struct.unpack_from("<H", decompressed, off)[0]
            if (hw & 0xFF00) == 0xB500:
                push_count += 1
            if off + 2 < len(decompressed):
                hw2 = struct.unpack_from("<H", decompressed, off + 2)[0]
                if hw == 0xE92D and (hw2 & 0x4000):
                    push_count += 1
        print("  Function prologues: {}".format(push_count))

    except zlib.error as e:
        print("  Zlib decompress failed: {}".format(e))
        # Try wbits variations
        for wbits in [15, -15, 31, 47]:
            try:
                decompressed = zlib.decompress(body, wbits)
                print("  Success with wbits={}: {} bytes".format(wbits, len(decompressed)))
                break
            except:
                pass

    print()

# Now detailed analysis of decompressed ABL4
print("=" * 60)
print("DETAILED ABL4 ANALYSIS")
print("=" * 60)

abl4_path = os.path.join(FW_DIR, "internal_abl4_decompressed.bin")
if os.path.exists(abl4_path):
    with open(abl4_path, "rb") as f:
        abl4 = f.read()

    # Search for APCB references
    print("\n--- APCB magic ---")
    for off in range(len(abl4) - 3):
        if abl4[off:off+4] in (b"APCB", b"BCPA", struct.pack("<I", 0x41504342)):
            ctx = abl4[max(0,off-4):off+8].hex()
            print("  +0x{:05X}: {} ({})".format(off, ctx, abl4[off:off+4]))

    # Key constants
    print("\n--- Key constants ---")
    for val, desc in [(0x00AB1000, "APCB flash"), (0x44AB1000, "APCB SMN"),
                       (0x0005DE0C, "target VA"), (0x00050000, "SRAM 320K"),
                       (0x00060000, "SRAM 384K"), (0x44000000, "SMN flash"),
                       (0x03200048, "MMIO ver"), (0x0B07, "grp 0x0B07"),
                       (0x1701, "grp 0x1701"), (0x4150, "AP prefix"),
                       (0x4342, "CB suffix")]:
        needle = struct.pack("<I", val)
        for off in range(len(abl4) - 3):
            if abl4[off:off+4] == needle:
                print("  0x{:08X} ({}) at +0x{:05X}".format(val, desc, off))

    # All strings >= 6 chars
    print("\n--- Strings >= 8 chars ---")
    i = 0
    str_count = 0
    while i < len(abl4):
        if 0x20 <= abl4[i] < 0x7F:
            start = i
            while i < len(abl4) and 0x20 <= abl4[i] < 0x7F:
                i += 1
            if i - start >= 8:
                s = abl4[start:start+(i-start)].decode("ascii")
                str_count += 1
                # Print all strings, filtering for interesting ones
                interesting = any(kw in s.lower() for kw in [
                    "apcb", "token", "group", "buffer", "overflow", "saved", "len",
                    "size", "checksum", "parse", "agesa", "config", "error", "fail",
                    "hash", "verify", "sign", "key", "hmac", "spi", "flash",
                    "mem", "alloc", "copy", "dram", "sram", "stack"])
                if interesting:
                    print("  +0x{:05X}: \"{}\"".format(start, s[:120]))
        else:
            i += 1
    print("  Total strings >= 8 chars: {}".format(str_count))

    # Print ALL strings (not filtered) to see what's in there
    print("\n--- All strings >= 12 chars (first 100) ---")
    i = 0
    shown = 0
    while i < len(abl4) and shown < 100:
        if 0x20 <= abl4[i] < 0x7F:
            start = i
            while i < len(abl4) and 0x20 <= abl4[i] < 0x7F:
                i += 1
            if i - start >= 12:
                s = abl4[start:start+(i-start)].decode("ascii")
                print("  +0x{:05X}: \"{}\"".format(start, s[:120]))
                shown += 1
        else:
            i += 1
