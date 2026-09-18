#!/usr/bin/env python3
"""Extract ABL4 from internal BIOS and analyze its code for APCB parsing references."""
import struct
import os

INTERNAL_FD = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_p300\rom\P3.00.AMD\P3.00.AMD\P3.00.AMD.FD"
OUT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware"

# ABL4 at flash 0x9B9000, size 0x9FE0
ABL4_FLASH = 0x9B9000
ABL4_SIZE = 0x9FE0

with open(INTERNAL_FD, "rb") as f:
    f.seek(ABL4_FLASH)
    abl4_raw = f.read(ABL4_SIZE)

print("ABL4 raw: {} bytes".format(len(abl4_raw)))
print("First 64 bytes (with $PS1 header):")
print("  {}".format(abl4_raw[:64].hex()))

# $PS1 header check
ps1_off = None
if abl4_raw[:4] == b"$PS1":
    ps1_off = 0
elif abl4_raw[16:20] == b"$PS1":
    ps1_off = 16

if ps1_off is not None:
    print("$PS1 at offset {}".format(ps1_off))
    # $PS1 header: 4 bytes magic, 4 bytes body_size, ...
    # Standard PSP $PS1 header is 0x100 (256) bytes before the body
    body_size = struct.unpack_from("<I", abl4_raw, ps1_off + 4)[0]
    print("$PS1 body size field: {} (0x{:X})".format(body_size, body_size))

    # Body starts at 0x100 from the start of the directory entry data
    # But the $PS1 header starts at +16 (since first 16 bytes are the GUID)
    # So body = +16 (GUID) + 256 ($PS1 header + sig) + body
    # Actually: directory entry points to start of data. First 16 bytes may be a GUID.
    # $PS1 at +16 means: 16-byte prefix + $PS1 header
    # $PS1 header size: varies, typically the body_size field tells us the actual code size
    # Let's check where ARM code starts

    # Scan for ARM exception vector pattern or Thumb prologue
    for test_off in [0x100, 0x110, 0x120, 0x140, 0x200, 0x10 + 0x100]:
        if test_off + 4 <= len(abl4_raw):
            word = struct.unpack_from("<I", abl4_raw, test_off)[0]
            hw = struct.unpack_from("<H", abl4_raw, test_off)[0]
            is_ldr_pc = (word & 0xFFFFF000) == 0xE59FF000
            is_push = (hw & 0xFF00) == 0xB500 or hw == 0xE92D
            if is_ldr_pc:
                print("ARM LDR PC at +0x{:X}: 0x{:08X}".format(test_off, word))
            if is_push:
                print("Thumb PUSH at +0x{:X}: 0x{:04X}".format(test_off, hw))

    # The $PS1 header in AMD format:
    # +0: 16 bytes GUID (or zeros)
    # +16: 4 bytes "$PS1"
    # +20: 4 bytes body_size (including any alignment)
    # +24: rest of header/signature
    # Body starts at offset 0x100 from start of entry
    body_offset = 0x100
    abl4_body = abl4_raw[body_offset:]
    body_path = os.path.join(OUT_DIR, "internal_abl4_body.bin")
    with open(body_path, "wb") as f:
        f.write(abl4_body)
    print("\nABL4 body written to: {}".format(body_path))
    print("ABL4 body size: {} bytes (0x{:X})".format(len(abl4_body), len(abl4_body)))

    # Check what the body starts with
    print("\nABL4 body first 64 bytes:")
    print("  {}".format(abl4_body[:64].hex()))

    # Check for ARM vectors or Thumb code
    first_word = struct.unpack_from("<I", abl4_body, 0)[0]
    first_hw = struct.unpack_from("<H", abl4_body, 0)[0]
    print("  First word: 0x{:08X}".format(first_word))
    print("  First halfword: 0x{:04X}".format(first_hw))

    # Entropy check
    from collections import Counter
    byte_counts = Counter(abl4_body)
    import math
    entropy = -sum((c/len(abl4_body)) * math.log2(c/len(abl4_body)) for c in byte_counts.values() if c > 0)
    print("  Entropy: {:.3f} (plaintext ~6-7, encrypted ~8.0)".format(entropy))

    # Search for APCB-related patterns
    print("\n=== ABL4 body: APCB-related searches ===")

    # APCB magic
    for off in range(len(abl4_body) - 3):
        if abl4_body[off:off+4] in (b"APCB", b"BCPA"):
            print("  APCB/BCPA at body+0x{:04X}".format(off))

    # Key constants
    for val, desc in [(0x00AB1000, "APCB flash"), (0x44AB1000, "APCB SMN"),
                       (0x5DE0C, "target VA"), (0x0B07, "group 0x0B07"),
                       (0x1701, "group 0x1701"), (0x03200048, "MMIO ver"),
                       (0x44000000, "SMN flash"), (0x60834, "ABL4 load base?")]:
        needle = struct.pack("<I", val)
        for off in range(len(abl4_body) - 3):
            if abl4_body[off:off+4] == needle:
                print("  0x{:08X} ({}) at body+0x{:04X}".format(val, desc, off))

    # Strings
    print("\n=== ABL4 body: Strings >= 6 chars ===")
    i = 0
    while i < len(abl4_body):
        if 0x20 <= abl4_body[i] < 0x7F:
            start = i
            while i < len(abl4_body) and 0x20 <= abl4_body[i] < 0x7F:
                i += 1
            if i - start >= 6:
                s = abl4_body[start:start+(i-start)].decode("ascii")
                if any(kw in s.lower() for kw in ["apcb", "token", "group", "buffer", "overflow",
                                                     "saved", "len", "size", "checksum", "parse",
                                                     "agesa", "config", "error", "fail", "hash",
                                                     "verify", "sign", "key", "hmac"]):
                    print("  body+0x{:04X}: \"{}\"".format(start, s))
        else:
            i += 1

    # Count function prologues
    push_count = 0
    for off in range(0, len(abl4_body) - 1, 2):
        hw = struct.unpack_from("<H", abl4_body, off)[0]
        if (hw & 0xFF00) == 0xB500:
            push_count += 1
        if off + 2 < len(abl4_body):
            hw2 = struct.unpack_from("<H", abl4_body, off + 2)[0]
            if hw == 0xE92D and (hw2 & 0x4000):
                push_count += 1
    print("\nABL4 function prologues: {}".format(push_count))

else:
    print("No $PS1 header found!")
    print("First 16 bytes: {}".format(abl4_raw[:16].hex()))

# Also extract all other ABL stages for reference
print("\n=== Extracting all ABL stages ===")
abls = [
    ("ABL0", 0x99EA00, 0x440),
    ("ABL1", 0x99EF00, 0xBED0),
    ("ABL2", 0x9AAE00, 0x3F70),
    ("ABL3", 0x9AEE00, 0xA160),
    ("ABL4", 0x9B9000, 0x9FE0),
]

for name, flash_off, size in abls:
    with open(INTERNAL_FD, "rb") as f:
        f.seek(flash_off)
        raw = f.read(size)
    body = raw[0x100:]  # Skip $PS1 header region

    byte_counts = Counter(body)
    entropy = -sum((c/len(body)) * math.log2(c/len(body)) for c in byte_counts.values() if c > 0)

    print("  {}: raw={} body={} entropy={:.3f}".format(name, len(raw), len(body), entropy))

    # Save body
    out_path = os.path.join(OUT_DIR, "internal_{}_body.bin".format(name.lower()))
    with open(out_path, "wb") as f:
        f.write(body)
