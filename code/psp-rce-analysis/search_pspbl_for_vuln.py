#!/usr/bin/env python3
"""Search PSP_BL body for references to 0x5DE0C and surrounding addresses.
PSP_BL sets up SRAM structures before launching ABL stages.
The vulnerability buffer at 0x5DE0C is likely allocated/initialized by PSP_BL.
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

print("PSP_BL body: {} bytes (0x{:X})".format(len(pspbl), len(pspbl)))
print()

# PSP_BL typically loads at VA 0x0 or some low address.
# The interrupt vector table starts at 0x0.
# Let's check the first few words to determine the load base.
print("=== First 16 words (interrupt vectors) ===")
for i in range(16):
    val = struct.unpack_from("<I", pspbl, i * 4)[0]
    print("  +{:04X}: 0x{:08X}".format(i * 4, val))

# Try to determine load base from the reset vector
reset_vec = struct.unpack_from("<I", pspbl, 0)[0]
print("\nReset vector: 0x{:08X}".format(reset_vec))

# On ARM, interrupt vectors are either:
# - Absolute addresses (old ARM style)
# - LDR PC, [PC, #offset] instructions
# Let's check if the first word is a branch instruction or an address

# For PSP_BL, the code typically starts at 0x100 or so after the vector table
# Let's try multiple possible load bases
load_bases = [0x0, 0x10000, 0x15000, 0x100]

# 1. Search for 0x5DE0C as u32 LE
print("\n=== Searching for 0x5DE0C as u32 LE ===")
needle = struct.pack("<I", 0x5DE0C)
for off in range(len(pspbl) - 3):
    if pspbl[off:off+4] == needle:
        print("  FOUND at offset +0x{:04X}".format(off))

# 2. Search for nearby addresses
targets = [
    0x5DE0C, 0x5DE00, 0x5DE08, 0x5DE10, 0x5DD00, 0x5DF00,
    0x5D000, 0x5E000, 0x5F000,
    0x72000, 0x7A000,  # ABL4 heap and APCB group base
]
print("\n=== Searching for key addresses as u32 LE ===")
for target in targets:
    needle = struct.pack("<I", target)
    for off in range(len(pspbl) - 3):
        if pspbl[off:off+4] == needle:
            print("  0x{:08X} at offset +0x{:04X}".format(target, off))

# 3. Search for MOVW/MOVT pairs that construct 0x5DE0C
# MOVW encoding: 0xF240 xxxx (Thumb2) or 0xF64D xxxx
# MOVT encoding: 0xF2C0 xxxx (Thumb2) for upper half 0x0005
# But earlier we found ABL4 has NO MOVT. Let's check PSP_BL.
print("\n=== Searching for MOVT instructions in PSP_BL ===")

# Find PUSH prologues first
push_addrs = []
for off in range(0, len(pspbl) - 1, 2):
    if pspbl[off + 1] == 0xB5:  # Narrow PUSH {rX, LR}
        push_addrs.append(off)
    elif off + 3 < len(pspbl) and pspbl[off] == 0x2D and pspbl[off+1] == 0xE9:
        mask = struct.unpack_from("<H", pspbl, off + 2)[0]
        if mask & 0x4000:  # LR saved
            push_addrs.append(off)

print("  {} PUSH prologues found in PSP_BL".format(len(push_addrs)))

# Disassemble each function and look for MOVW/MOVT
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

movt_count = 0
movw_de0c = []
movt_0005 = []
movw_all = []

for func_off in push_addrs:
    end = min(func_off + 2000, len(pspbl))
    code = pspbl[func_off:end]

    for insn in cs.disasm(code, func_off, 500):
        mn = insn.mnemonic.lower()
        if mn == "movt":
            movt_count += 1
            for op in insn.operands:
                if op.type == 2 and op.imm == 0x0005:  # ARM_OP_IMM
                    movt_0005.append((func_off, insn.address, str(insn)))
        elif mn == "movw":
            for op in insn.operands:
                if op.type == 2:  # ARM_OP_IMM
                    if op.imm == 0xDE0C:
                        movw_de0c.append((func_off, insn.address, str(insn)))
                    movw_all.append((insn.address, op.imm))

        # Stop at POP {PC} or BX LR
        if mn in ("pop", "bx") and "pc" in insn.op_str.lower():
            break

print("  Total MOVT instructions: {}".format(movt_count))
print("  MOVW with 0xDE0C: {}".format(len(movw_de0c)))
for f, a, s in movw_de0c:
    print("    func +0x{:04X}, insn +0x{:04X}: {}".format(f, a, s))
print("  MOVT with 0x0005: {}".format(len(movt_0005)))
for f, a, s in movt_0005:
    print("    func +0x{:04X}, insn +0x{:04X}: {}".format(f, a, s))

# 4. Check ALL u32 values in PSP_BL that fall in the SRAM/extended range
print("\n=== All u32 literal pool values in SRAM range (0x50000-0x80000) ===")
sram_ptrs = []
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if 0x50000 <= val <= 0x80000:
        sram_ptrs.append((off, val))

for off, val in sram_ptrs:
    print("  +0x{:04X}: 0x{:08X}".format(off, val))

# 5. Check for base+offset decompositions
print("\n=== Base+offset decompositions of 0x5DE0C ===")
for off, val in sram_ptrs:
    diff = 0x5DE0C - val
    if 0 < diff < 0x2000:
        print("  0x{:X} + 0x{:X} = 0x5DE0C  (at +0x{:04X})".format(val, diff, off))
    diff2 = val - 0x5DE0C
    if 0 < diff2 < 0x2000:
        print("  0x5DE0C + 0x{:X} = 0x{:X}  (at +0x{:04X})".format(diff2, val, off))

# 6. Dump the "heap" magic check — look for 0x50414548 ("HEAP") in PSP_BL
print("\n=== Searching for HEAP magic (0x50414548) in PSP_BL ===")
needle = struct.pack("<I", 0x50414548)
for off in range(len(pspbl) - 3):
    if pspbl[off:off+4] == needle:
        print("  FOUND at +0x{:04X}".format(off))

# 7. Look for "APCB" magic in PSP_BL
print("\n=== Searching for APCB magic in PSP_BL ===")
needle = b"APCB"
for off in range(len(pspbl) - 3):
    if pspbl[off:off+4] == needle:
        print("  FOUND at +0x{:04X}".format(off))

print("\nDone.")
