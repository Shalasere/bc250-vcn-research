#!/usr/bin/env python3
"""Analyze plaintext PSP_BL body for APCB references, SVC calls, strings, and function count."""
import struct
import sys

BODY_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

with open(BODY_PATH, "rb") as f:
    body = f.read()

print("PSP_BL body: {} bytes (0x{:X})".format(len(body), len(body)))
print()

# 1. Search for APCB magic bytes
print("=== APCB magic references ===")
apcb_be = b"APCB"  # big-endian ASCII
apcb_le = struct.pack("<I", 0x41504342)  # 'A','P','C','B' as little-endian u32
found_apcb = False
for off in range(len(body) - 3):
    chunk = body[off:off+4]
    if chunk == apcb_be or chunk == apcb_le:
        ctx = body[max(0, off-8):off+12].hex()
        print("  Found at +0x{:04X}: ...{}...".format(off, ctx))
        found_apcb = True
if not found_apcb:
    print("  (none found)")

# Also search for "BCPA" (reversed)
for off in range(len(body) - 3):
    if body[off:off+4] == b"BCPA":
        print("  BCPA (reversed) at +0x{:04X}".format(off))

print()

# 2. Search for interesting constants
print("=== Key constants ===")
# 0xBC0B02A0 - Gate 3 check value (fn 0x944 checks 0x03200048 must = this)
# 0x03200048 - MMIO version register
# 0x5DE0C - the vulnerability VA
# 0x0B07, 0x1701 - APCB group IDs
# 0xAB1000 - APCB flash offset
constants = [
    (0xBC0B02A0, "Gate3 chip ID"),
    (0x03200048, "MMIO version reg"),
    (0x0005DE0C, "vuln target VA"),
    (0x00AB1000, "APCB flash offset"),
    (0x0B07, "APCB group 0x0B07"),
    (0x1701, "APCB group 0x1701"),
    (0x00050000, "SRAM size 320K"),
    (0x00060000, "SRAM size 384K"),
    (0x44000000, "SMN flash base"),
    (0x03000000, "CCP MMIO base"),
    (0x0004F000, "BRSP addr"),
]

for val, desc in constants:
    # Search for little-endian encoding
    if val < 0x10000:
        needle = struct.pack("<H", val)
        # Too many false positives for 2-byte values, search as 4-byte with zero padding
        needle = struct.pack("<I", val)
    else:
        needle = struct.pack("<I", val)
    for off in range(len(body) - len(needle) + 1):
        if body[off:off+len(needle)] == needle:
            print("  0x{:08X} ({}) at +0x{:04X}".format(val, desc, off))

print()

# 3. SVC instructions (Thumb-2 and ARM)
print("=== SVC / supervisor calls ===")
svc_list = []

# Thumb SVC: 0xDFxx
for off in range(0, len(body) - 1, 2):
    hw = struct.unpack_from("<H", body, off)[0]
    if (hw & 0xFF00) == 0xDF00:
        svc_num = hw & 0xFF
        svc_list.append((off, "Thumb", svc_num))

# ARM SVC: 0xEF0000xx (condition code varies in top nibble)
for off in range(0, len(body) - 3, 4):
    word = struct.unpack_from("<I", body, off)[0]
    if (word & 0x0F000000) == 0x0F000000 and (word & 0xF0000000) in (0xE0000000, 0x00000000):
        svc_num = word & 0xFFFFFF
        # Filter: only if svc_num < 0x200 (reasonable range)
        if svc_num < 0x200:
            svc_list.append((off, "ARM", svc_num))

for off, mode, num in sorted(svc_list):
    print("  {} SVC 0x{:02X} at +0x{:04X}".format(mode, num, off))
print("Total SVCs: {}".format(len(svc_list)))

print()

# 4. Printable ASCII strings >= 6 chars
print("=== Strings (>= 6 printable ASCII chars) ===")
i = 0
strings_found = []
while i < len(body):
    if 0x20 <= body[i] < 0x7F:
        start = i
        while i < len(body) and 0x20 <= body[i] < 0x7F:
            i += 1
        length = i - start
        if length >= 6:
            s = body[start:start+length].decode("ascii")
            strings_found.append((start, s))
    else:
        i += 1

for off, s in strings_found:
    print("  +0x{:04X}: \"{}\"".format(off, s))
print("Total strings: {}".format(len(strings_found)))

print()

# 5. Function prologues (Thumb PUSH with LR)
print("=== Function prologues ===")
push_count = 0
push_offsets = []
for off in range(0, len(body) - 1, 2):
    hw = struct.unpack_from("<H", body, off)[0]
    # Thumb PUSH {regs, lr}: 0xB5xx (bit 8 = LR)
    if (hw & 0xFF00) == 0xB500:
        push_count += 1
        push_offsets.append(off)
    # Thumb-2 PUSH.W: 0xE92D with bit 14 (LR) set in second halfword
    if off + 2 < len(body):
        hw2 = struct.unpack_from("<H", body, off + 2)[0]
        if hw == 0xE92D and (hw2 & 0x4000):
            push_count += 1
            push_offsets.append(off)

print("Function prologues (push {{..., lr}}): {}".format(push_count))
print("First 20:")
for off in push_offsets[:20]:
    ctx = body[off:off+8].hex()
    print("  +0x{:04X}: {}".format(off, ctx))

print()

# 6. Exception vector table analysis
print("=== Exception vector table (first 32 bytes) ===")
for i in range(8):
    word = struct.unpack_from("<I", body, i * 4)[0]
    print("  Vector[{}] = 0x{:08X}".format(i, word))

# Check reset vector target
reset_vec = struct.unpack_from("<I", body, 0)[0]
# ARM LDR PC, [PC, #offset] = 0xE59FF000 + offset
if (reset_vec & 0xFFFFF000) == 0xE59FF000:
    ldr_offset = reset_vec & 0xFFF
    # PC is 8 bytes ahead in ARM mode
    target_addr_offset = 8 + ldr_offset
    if target_addr_offset + 4 <= len(body):
        target = struct.unpack_from("<I", body, target_addr_offset)[0]
        print("  Reset vector loads PC from +0x{:X} -> target VA 0x{:08X}".format(target_addr_offset, target))

print()

# 7. Look for the APCB flash read pattern - loading from 0xAB1000 area
print("=== References to flash addresses near APCB (0xAB0000-0xAC0000) ===")
for off in range(0, len(body) - 3, 4):
    word = struct.unpack_from("<I", body, off)[0]
    if 0x00AB0000 <= word <= 0x00AC0000:
        print("  +0x{:04X}: 0x{:08X}".format(off, word))
    # Also check SMN-relative (0x44000000 + flash_offset)
    if 0x44AB0000 <= word <= 0x44AC0000:
        print("  +0x{:04X}: 0x{:08X} (SMN-relative)".format(off, word))

print()

# 8. Look for BL (branch-link) instructions to help map call graph
print("=== Branch targets > 0x9000 (near end of binary) ===")
# Thumb BL: 11110xxxxxxxxxxx 11xxxxxxxxxxxxxx
bl_targets_high = []
for off in range(0, len(body) - 3, 2):
    hw1 = struct.unpack_from("<H", body, off)[0]
    hw2 = struct.unpack_from("<H", body, off + 2)[0]
    if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xD000) == 0xD000:
        # Thumb BL
        S = (hw1 >> 10) & 1
        imm10 = hw1 & 0x3FF
        J1 = (hw2 >> 13) & 1
        J2 = (hw2 >> 11) & 1
        imm11 = hw2 & 0x7FF
        I1 = ~(J1 ^ S) & 1
        I2 = ~(J2 ^ S) & 1
        offset = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
        if S:
            offset |= 0xFE000000  # sign extend
            offset = offset - 0x100000000
        target = off + 4 + offset
        if target > 0x9000 and target < 0x10000:
            bl_targets_high.append((off, target))

print("BL calls targeting > 0x9000: {}".format(len(bl_targets_high)))
for off, tgt in bl_targets_high[:30]:
    print("  +0x{:04X} -> 0x{:04X}".format(off, tgt))
