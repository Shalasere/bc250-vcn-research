#!/usr/bin/env python3
"""Check ABL4 binary format: ARM vs Thumb, entry point, structure."""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

print("ABL4: {} bytes (0x{:X})".format(len(abl4), len(abl4)))

# Check first 64 bytes as raw hex
print("\nFirst 64 bytes:")
for i in range(0, 64, 16):
    hexstr = " ".join("{:02X}".format(abl4[i+j]) for j in range(min(16, len(abl4)-i)))
    ascstr = "".join(chr(abl4[i+j]) if 32 <= abl4[i+j] < 127 else '.' for j in range(min(16, len(abl4)-i)))
    print("  {:04X}: {} | {}".format(i, hexstr, ascstr))

# First 16 words
print("\nFirst 16 words:")
for i in range(0, 64, 4):
    val = struct.unpack_from("<I", abl4, i)[0]
    print("  +0x{:02X}: 0x{:08X}".format(i, val))

# Try ARM mode
print("\nARM mode first 20 instructions:")
cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
for insn in cs_arm.disasm(abl4[:80], 0):
    print("  0x{:04X}: {:8s} {}".format(insn.address, insn.mnemonic, insn.op_str))

# Try Thumb mode
print("\nThumb mode first 20 instructions:")
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
count = 0
for insn in cs_thumb.disasm(abl4[:80], 0):
    print("  0x{:04X}: {:8s} {}".format(insn.address, insn.mnemonic, insn.op_str))
    count += 1
    if count >= 20:
        break

# Check if it looks like it starts with a header
# PSP executables often have a header before the actual code
# Look for signatures
print("\nSignature search:")
sigs = [b'APCB', b'$PSP', b'$PS2', b'AGFP', b'AGBM', b'\x00\x00\xa0\xe1', b'AMDABL']
for sig in sigs:
    idx = abl4.find(sig)
    if idx >= 0:
        print("  '{}' found at offset 0x{:X}".format(sig, idx))

# Check for SVC in ARM mode
print("\nSVC in ARM mode:")
svc_count = 0
for insn in cs_arm.disasm(abl4, 0):
    if insn.mnemonic.lower() == 'svc':
        svc_count += 1
        if svc_count <= 20:
            print("  0x{:05X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))
print("  Total ARM SVC: {}".format(svc_count))

# Check for SVC in Thumb with base 0
print("\nSVC in Thumb (base 0):")
svc_count = 0
for insn in cs_thumb.disasm(abl4, 0):
    if insn.mnemonic.lower() == 'svc':
        svc_count += 1
        if svc_count <= 20:
            print("  0x{:05X}: {} {}".format(insn.address, insn.mnemonic, insn.op_str))
print("  Total Thumb SVC: {}".format(svc_count))

# Count valid vs invalid instructions in first 1KB for each mode
print("\nInstruction density check (first 4KB):")
arm_count = sum(1 for _ in cs_arm.disasm(abl4[:4096], 0))
thumb_count = sum(1 for _ in cs_thumb.disasm(abl4[:4096], 0))
print("  ARM instructions: {} (expected ~1024)".format(arm_count))
print("  Thumb instructions: {} (expected ~2048)".format(thumb_count))

# Check if it has PUSH/POP pairs (function prologue/epilogue)
print("\nFunction signatures in ARM mode (first 16KB):")
arm_funcs = 0
for insn in cs_arm.disasm(abl4[:16384], 0):
    if insn.mnemonic.lower() == 'push' or (insn.mnemonic.lower() == 'stmdb' and 'sp' in insn.op_str.lower()):
        arm_funcs += 1
print("  PUSH/STMDB SP: {}".format(arm_funcs))

print("\nFunction signatures in Thumb mode (first 16KB):")
thumb_funcs = 0
for insn in cs_thumb.disasm(abl4[:16384], 0):
    if insn.mnemonic.lower() in ['push', 'push.w']:
        thumb_funcs += 1
print("  PUSH: {}".format(thumb_funcs))

# Check for common ABL4 patterns: look for byte patterns of SVC in raw binary
# ARM SVC: 0xEF0000XX (swapped: XX 00 00 EF)
# Thumb SVC: 0xDFXX (2 bytes)
print("\nRaw SVC byte pattern search:")
arm_svc_count = 0
thumb_svc_count = 0
for i in range(0, len(abl4) - 3, 4):
    word = struct.unpack_from("<I", abl4, i)[0]
    if (word & 0xFF000000) == 0xEF000000:  # ARM SVC
        arm_svc_count += 1
        if arm_svc_count <= 10:
            print("  ARM SVC at 0x{:05X}: 0x{:08X} → SVC 0x{:06X}".format(
                i, word, word & 0xFFFFFF))

for i in range(0, len(abl4) - 1, 2):
    hw = struct.unpack_from("<H", abl4, i)[0]
    if (hw & 0xFF00) == 0xDF00:  # Thumb SVC
        # Check if this looks like a valid instruction context
        thumb_svc_count += 1

print("  Raw ARM SVC patterns: {}".format(arm_svc_count))
print("  Raw Thumb SVC-like halfwords: {} (many false positives expected)".format(thumb_svc_count))

# Check for entropy (is it encrypted/compressed?)
print("\nByte distribution (first 4KB):")
from collections import Counter
bc = Counter(abl4[:4096])
sorted_bc = sorted(bc.items(), key=lambda x: -x[1])
print("  Most common: {}".format([(hex(b), c) for b, c in sorted_bc[:5]]))
print("  Least common: {}".format([(hex(b), c) for b, c in sorted_bc[-5:]]))
print("  Unique bytes: {} / 256".format(len(bc)))

# Zero bytes
zero_count = abl4[:4096].count(0)
print("  Zero bytes in first 4KB: {} ({:.1f}%)".format(zero_count, zero_count/40.96))

print("\nDone.")
