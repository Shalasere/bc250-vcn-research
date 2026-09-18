#!/usr/bin/env python3
"""Find ALL call sites to FUN_00000458 (memcpy) and FUN_000004E0 (opt copy)
in PSP_BL at the ARM instruction level.

For each call site:
1. Decode the BL/BLX instruction to verify target
2. Backward-trace to determine how R0 (dest) was set — is it SP-relative?
3. Backward-trace R2 (size) — is it a constant or variable?
4. Flag sites where dest=stack and size=variable

Also check FUN_00000544 (memset) for stack-targeting calls with variable size.
"""
import struct, re

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

BINARY_SIZE = len(pspbl)
print("PSP_BL size: {} bytes (0x{:X})".format(BINARY_SIZE, BINARY_SIZE))

# Target addresses for copy functions
COPY_TARGETS = {
    0x458: "memcpy",
    0x4E0: "opt_copy",
    0x544: "memset",
}

def decode_thumb16(hw, addr):
    """Decode a Thumb-16 instruction."""
    if (hw & 0xF800) == 0x4800:
        rd = (hw >> 8) & 7
        imm = (hw & 0xFF) * 4
        pool = (addr & ~3) + 4 + imm
        return "LDR R{}, [PC, #0x{:X}] -> pool 0x{:04X}".format(rd, imm, pool), rd, pool
    elif (hw & 0xFF00) == 0x4600:
        rd = ((hw >> 4) & 8) | (hw & 7)
        rm = (hw >> 3) & 0xF
        return "MOV R{}, R{}".format(rd, rm), None, None
    elif (hw & 0xFFC0) == 0x0000 and (hw & 0x003F) != 0:
        rd = hw & 7
        rm = (hw >> 3) & 7
        imm = (hw >> 6) & 0x1F
        return "LSL R{}, R{}, #{}".format(rd, rm, imm), None, None
    elif (hw & 0xFF80) == 0xB080:
        imm = (hw & 0x7F) * 4
        return "SUB SP, SP, #0x{:X}".format(imm), None, None
    elif (hw & 0xFE00) == 0x1C00:
        rd = hw & 7
        rn = (hw >> 3) & 7
        imm3 = (hw >> 6) & 7
        return "ADD R{}, R{}, #{}".format(rd, rn, imm3), None, None
    elif (hw & 0xFF78) == 0x4468:
        rd = ((hw >> 4) & 8) | (hw & 7)
        return "ADD R{}, SP".format(rd), None, None
    elif (hw & 0xF800) == 0xA800:
        rd = (hw >> 8) & 7
        imm = (hw & 0xFF) * 4
        return "ADD R{}, SP, #0x{:X}".format(rd, imm), rd, imm
    elif (hw & 0xFE00) == 0x2000:
        rd = (hw >> 8) & 7
        imm = hw & 0xFF
        return "MOV R{}, #0x{:X}".format(rd, imm), rd, imm
    elif (hw & 0xFE00) == 0x3000:
        rd = (hw >> 8) & 7
        imm = hw & 0xFF
        return "ADD R{}, #0x{:X}".format(rd, imm), None, None
    return "?? 0x{:04X}".format(hw), None, None

def find_bl_targets(binary, target_addrs):
    """Find all BL/BLX instructions targeting given addresses.
    Returns list of (call_addr, target_addr) tuples."""
    results = []

    # Thumb-2 BL encoding: two halfwords
    # HW1: 11110_S_imm10
    # HW2: 11_J1_1_J2_imm11
    for off in range(0, len(binary) - 3, 2):
        hw1 = struct.unpack_from("<H", binary, off)[0]
        hw2 = struct.unpack_from("<H", binary, off + 2)[0]

        # Check for BL (Thumb-2)
        if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xD000) == 0xD000:
            S = (hw1 >> 10) & 1
            imm10 = hw1 & 0x3FF
            J1 = (hw2 >> 13) & 1
            J2 = (hw2 >> 11) & 1
            imm11 = hw2 & 0x7FF
            I1 = ~(J1 ^ S) & 1
            I2 = ~(J2 ^ S) & 1
            imm32 = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
            if S:
                imm32 = imm32 | 0xFE000000
                if imm32 >= 0x80000000:
                    imm32 -= 0x100000000
            target = off + 4 + imm32
            if target in target_addrs:
                results.append((off, target))

        # Check for BLX (Thumb-2 to ARM)
        if (hw1 & 0xF800) == 0xF000 and (hw2 & 0xD000) == 0xC000:
            S = (hw1 >> 10) & 1
            imm10H = hw1 & 0x3FF
            J1 = (hw2 >> 13) & 1
            J2 = (hw2 >> 11) & 1
            imm10L = (hw2 >> 1) & 0x3FF
            H = hw2 & 1
            I1 = ~(J1 ^ S) & 1
            I2 = ~(J2 ^ S) & 1
            imm32 = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10H << 12) | (imm10L << 2) | (H << 1)
            if S:
                imm32 = imm32 | 0xFE000000
                if imm32 >= 0x80000000:
                    imm32 -= 0x100000000
            target = ((off + 4) & ~3) + imm32
            if target in target_addrs:
                results.append((off, target))

    return results

# Find all calls
print("Searching for BL/BLX to copy functions...")
all_calls = find_bl_targets(pspbl, set(COPY_TARGETS.keys()))
print("Found {} call sites total".format(len(all_calls)))

for target_addr, func_name in sorted(COPY_TARGETS.items()):
    calls = [(ca, ta) for ca, ta in all_calls if ta == target_addr]
    print("  {} (0x{:04X}): {} calls".format(func_name, target_addr, len(calls)))

# For each memcpy call site, backward-trace R0 and R2
print("\n" + "=" * 70)
print("MEMCPY CALL SITE ANALYSIS")
print("=" * 70)

suspicious = []

memcpy_calls = [(ca, ta) for ca, ta in all_calls if ta == 0x458]

for call_addr, _ in memcpy_calls:
    # Backward trace: look at the preceding ~20 instructions
    # to determine how R0, R1, R2 were set
    r0_info = None  # (type, value) — 'sp_rel' or 'const' or 'reg' or 'pool'
    r2_info = None  # size argument
    r0_sp_offset = None
    r2_value = None

    # Look backward from call site
    trace_start = max(0, call_addr - 40)  # ~20 Thumb instructions back

    r0_source = "unknown"
    r2_source = "unknown"
    r0_detail = ""
    r2_detail = ""

    for look_addr in range(call_addr - 2, trace_start - 2, -2):
        hw = struct.unpack_from("<H", pspbl, look_addr)[0]

        # ADD Rd, SP, #imm — stack-relative pointer
        if (hw & 0xF800) == 0xA800:
            rd = (hw >> 8) & 7
            imm = (hw & 0xFF) * 4
            if rd == 0 and r0_source == "unknown":
                r0_source = "sp_rel"
                r0_detail = "SP+0x{:X}".format(imm)
                r0_sp_offset = imm
            elif rd == 2 and r2_source == "unknown":
                r2_source = "sp_rel"
                r2_detail = "SP+0x{:X}".format(imm)

        # MOV Rd, #imm
        if (hw & 0xF800) == 0x2000:
            rd = (hw >> 8) & 7
            imm = hw & 0xFF
            if rd == 0 and r0_source == "unknown":
                r0_source = "const"
                r0_detail = "0x{:X}".format(imm)
            elif rd == 2 and r2_source == "unknown":
                r2_source = "const"
                r2_detail = "0x{:X}".format(imm)
                r2_value = imm

        # LDR Rd, [PC, #imm] — pool load
        if (hw & 0xF800) == 0x4800:
            rd = (hw >> 8) & 7
            imm = (hw & 0xFF) * 4
            pool = (look_addr & ~3) + 4 + imm
            if pool < len(pspbl) - 3:
                pool_val = struct.unpack_from("<I", pspbl, pool)[0]
            else:
                pool_val = 0
            if rd == 0 and r0_source == "unknown":
                r0_source = "pool"
                r0_detail = "pool[0x{:04X}]=0x{:08X}".format(pool, pool_val)
            elif rd == 2 and r2_source == "unknown":
                r2_source = "pool"
                r2_detail = "pool[0x{:04X}]=0x{:08X}".format(pool, pool_val)
                r2_value = pool_val

        # MOV Rd, Rm (high register)
        if (hw & 0xFF00) == 0x4600:
            rd = ((hw >> 4) & 8) | (hw & 7)
            rm = (hw >> 3) & 0xF
            if rd == 0 and r0_source == "unknown":
                if rm == 13:
                    r0_source = "sp_rel"
                    r0_detail = "SP+0"
                else:
                    r0_source = "reg"
                    r0_detail = "R{}".format(rm)
            elif rd == 2 and r2_source == "unknown":
                r2_source = "reg"
                r2_detail = "R{}".format(rm)

        # ADD Rd, SP (high register form: 0x4468 + rd bits)
        if (hw & 0xFF78) == 0x4468:
            rd = ((hw >> 4) & 8) | (hw & 7)
            if rd == 0 and r0_source == "unknown":
                r0_source = "sp_rel"
                r0_detail = "SP+reg"

    is_suspicious = (r0_source == "sp_rel" and r2_source not in ["const", "pool"])
    is_interesting = (r0_source == "sp_rel" and r2_source in ["pool"])

    if is_suspicious:
        suspicious.append((call_addr, r0_source, r0_detail, r2_source, r2_detail))
        tag = "*** SUSPICIOUS ***"
    elif is_interesting and r2_value and r2_value > 0x100:
        tag = "LARGE CONST"
    elif r0_source == "sp_rel":
        tag = "stack dest"
    else:
        tag = ""

    if r0_source == "sp_rel" or is_suspicious:
        print("  0x{:04X}: memcpy(dest={} [{}], src=..., size={} [{}]) {}".format(
            call_addr, r0_source, r0_detail, r2_source, r2_detail, tag))

print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
print("Total memcpy calls: {}".format(len(memcpy_calls)))
print("Stack-destination calls: {}".format(
    sum(1 for ca, _ in memcpy_calls
        for r0s in ["sp_rel"] if True)))  # placeholder
print("\n*** SUSPICIOUS (stack dest + non-const size):")
for ca, r0s, r0d, r2s, r2d in suspicious:
    print("  0x{:04X}: dest={}, size={}".format(ca, r0d, r2d))
