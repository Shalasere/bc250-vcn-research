#!/usr/bin/env python3
"""
Final verification: literal pool values for page table setup function prologue,
and confirm the L1 descriptor construction for first 1MB.
"""

import struct, sys, os
sys.stdout.reconfigure(encoding='utf-8')

BINARY = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(BINARY, "rb") as f:
    blob = f.read()

def read_u32(offset):
    return struct.unpack_from("<I", blob, offset)[0]

print("=" * 80)
print("FINAL VERIFICATION: Page table setup literal pool + L1 descriptor")
print("=" * 80)

# The function at 0x384C loads several values from literal pools.
# Thumb PC-relative LDR: effective PC = instruction addr + 4 (Thumb pipeline)
# LDR Rx, [PC, #imm] -> loads from (PC + 4 + imm) aligned to 4

# 0x3852: ldr r0, [pc, #0x1c4]   -> 0x3854 + 0x1C4 = 0x3A18 (with +4 already in capstone)
# But capstone for Thumb shows the actual computed address in the operand.
# Let me just compute manually:
# For Thumb LDR Rx, [PC, #imm]:
#   load addr = Align(PC + 4, 4) + imm
#   where PC = instruction address

# Let me re-decode the literal pool loads from the prologue:
print("\nLiteral pool values for page table setup function (0x384C):")

# I'll manually trace the LDR instructions
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md_thumb.detail = True

region = blob[0x384C:0x3880]
for insn in md_thumb.disasm(region, 0x384C):
    if 'pc' in insn.op_str.lower() and insn.mnemonic.startswith('ldr'):
        # Parse the pool address from the instruction
        # Capstone includes the computed address for Thumb PC-relative loads
        # Format: "rN, [pc, #0xNNN]"
        # Effective address = (insn_addr + 4) & ~3 + offset
        ops = insn.op_str
        if '#' in ops:
            imm_str = ops.split('#')[-1].rstrip(']').strip()
            try:
                imm = int(imm_str, 0)
                pc_aligned = (insn.address + 4) & ~3
                pool_addr = pc_aligned + imm
                val = read_u32(pool_addr)
                reg = ops.split(',')[0].strip()
                ann = ""
                if val == 0x4E000: ann = " [L1 PAGE TABLE BASE]"
                elif 0x4E000 < val < 0x50000: ann = f" [within/near L1 table, +{val-0x4E000:#x}]"
                elif 0x40000 <= val <= 0x60000: ann = " [SRAM address]"
                print(f"  {insn.address:#06x}: LDR {reg} = 0x{val:08X}  (pool@{pool_addr:#06x}){ann}")
            except:
                pass

# Also check the DFF8 (ldr.w) instructions
# These use the same computation but 32-bit encoding
print("\nWide LDR instructions:")
for insn in md_thumb.disasm(region, 0x384C):
    if 'ldr.w' == insn.mnemonic and 'pc' in insn.op_str.lower():
        ops = insn.op_str
        if '#' in ops:
            imm_str = ops.split('#')[-1].rstrip(']').strip()
            try:
                imm = int(imm_str, 0)
                pc_aligned = (insn.address + 4) & ~3
                pool_addr = pc_aligned + imm
                val = read_u32(pool_addr)
                reg = ops.split(',')[0].strip()
                print(f"  {insn.address:#06x}: LDR.W {reg} = 0x{val:08X}  (pool@{pool_addr:#06x})")
            except:
                pass

# Now trace the key values:
print("\n" + "-" * 60)
print("KEY: [sp, #4] = L2 table base address")
print("-" * 60)

# 0x3856: ldr r1, [pc, #0x1c4] -> pool at (0x3856+4)&~3 + 0x1C4 = 0x3858 + 0x1C4 = 0x3A1C
# Wait, let me be more careful. (0x3856 + 4) = 0x385A, aligned to 4 = 0x3858. 0x3858 + 0x1C4 = 0x3A1C
val_3a1c = read_u32(0x3A1C)
print(f"  r1 from pool at 0x3A1C = 0x{val_3a1c:08X}")

# 0x3852: ldr r0, [pc, #0x1c4] -> (0x3852+4)&~3 = 0x3854, + 0x1C4 = 0x3A18
val_3a18 = read_u32(0x3A18)
print(f"  r0 from pool at 0x3A18 = 0x{val_3a18:08X} -> stored to [sp, #4]")

# 0x3854: ldr r4, [pc, #0x1bc] -> (0x3854+4)&~3 = 0x3858, + 0x1BC = 0x3A14
val_3a14 = read_u32(0x3A14)
print(f"  r4 from pool at 0x3A14 = 0x{val_3a14:08X}")

# 0x385A: ldr r0, [pc, #0x1d4] -> (0x385A+4)&~3 = 0x385C, + 0x1D4 = 0x3A30
val_3a30 = read_u32(0x3A30)
print(f"  r0 (-> [sp, #0x14]) from pool at 0x3A30 = 0x{val_3a30:08X}")

# 0x385E: ldr r0, [pc, #0x1d8] -> (0x385E+4)&~3 = 0x3860, + 0x1D8 = 0x3A38
val_3a38 = read_u32(0x3A38)
print(f"  r0 (-> [sp, #8]) from pool at 0x3A38 = 0x{val_3a38:08X}")

# 0x3862: ldr r0, [pc, #0x1d8] -> (0x3862+4)&~3 = 0x3864, + 0x1D8 = 0x3A3C
val_3a3c = read_u32(0x3A3C)
print(f"  r0 (-> [sp, #0xc]) from pool at 0x3A3C = 0x{val_3a3c:08X}")

# 0x3866: ldr r0, [pc, #0x1dc] -> (0x3866+4)&~3 = 0x3868, + 0x1DC = 0x3A44
val_3a44 = read_u32(0x3A44)
print(f"  r0 (-> [sp, #0x10]) from pool at 0x3A44 = 0x{val_3a44:08X}")

# r11 from 0x3868: ldr.w r11, [pc, #0x1b4] -> (0x3868+4)&~3 = 0x386C, + 0x1B4 = 0x3A20
val_3a20 = read_u32(0x3A20)
print(f"  r11 from pool at 0x3A20 = 0x{val_3a20:08X}")

# r6 from 0x386C: ldr r6, [pc, #0x1b4] -> (0x386C+4)&~3 = 0x3870, + 0x1B4 = 0x3A24
val_3a24 = read_u32(0x3A24)
print(f"  r6 from pool at 0x3A24 = 0x{val_3a24:08X}")

# r5 from 0x386E: ldr r5, [pc, #0x1b8] -> (0x386E+4)&~3 = 0x3870, + 0x1B8 = 0x3A28
val_3a28 = read_u32(0x3A28)
print(f"  r5 from pool at 0x3A28 = 0x{val_3a28:08X}")

# r10 from 0x3870: ldr.w r10, [pc, #0x1b8] -> (0x3870+4)&~3 = 0x3874, + 0x1B8 = 0x3A2C
val_3a2c = read_u32(0x3A2C)
print(f"  r10 from pool at 0x3A2C = 0x{val_3a2c:08X}")

# r9 from 0x3874: ldr.w r9, [pc, #0x1bc] -> (0x3874+4)&~3 = 0x3878, + 0x1BC = 0x3A34
val_3a34 = read_u32(0x3A34)
print(f"  r9 from pool at 0x3A34 = 0x{val_3a34:08X}")

# r8 from 0x3878: ldr.w r8, [pc, #0x1c4] -> (0x3878+4)&~3 = 0x387C, + 0x1C4 = 0x3A40
val_3a40 = read_u32(0x3A40)
print(f"  r8 from pool at 0x3A40 = 0x{val_3a40:08X}")

# r7 from 0x387C: ldr r7, [pc, #0x1c8] -> (0x387C+4)&~3 = 0x3880, + 0x1C8 = 0x3A48
val_3a48 = read_u32(0x3A48)
print(f"  r7 from pool at 0x3A48 = 0x{val_3a48:08X}")

print("\n" + "-" * 60)
print("REGISTER ASSIGNMENT FOR PAGE TABLE SETUP:")
print("-" * 60)
print(f"  r4 = 0x{val_3a14:08X}  (L1 table base)")
print(f"  [sp, #4] = 0x{val_3a18:08X}  (L2 table base / secondary table)")
print(f"  r5 = 0x{val_3a28:08X}  (page loop limit 2)")
print(f"  r6 = 0x{val_3a24:08X}  (page loop limit 1)")
print(f"  r7 = 0x{val_3a48:08X}  (page loop limit 5)")
print(f"  r8 = 0x{val_3a40:08X}  (page loop limit 4)")
print(f"  r9 = 0x{val_3a34:08X}  (page loop limit 5)")
print(f"  r10 = 0x{val_3a2c:08X}  (page loop limit 6)")
print(f"  r11 (init) = 0x{val_3a20:08X}  (bl 0x598 param)")

print("\n" + "-" * 60)
print("L1 DESCRIPTOR CONSTRUCTION:")
print("-" * 60)
# At 0x3894: addw r0, r0, #0x1E1
# r0 = [sp, #4] = L2 table base
# After: r0 = L2_table_base + 0x1E1
# At 0x3898: str r0, [r4]
# This writes L1[0] = L2_table_base | 0x1E1

l2_base = val_3a18
l1_desc = l2_base + 0x1E1
print(f"  L2 table base: 0x{l2_base:08X}")
print(f"  L1[0] descriptor: 0x{l2_base:08X} + 0x1E1 = 0x{l1_desc:08X}")
print(f"  L1 descriptor decode:")
print(f"    Type bits [1:0] = {l1_desc & 3:02b} -> {'Page Table' if (l1_desc & 3) == 1 else 'OTHER'}")
print(f"    Domain [8:5] = {(l1_desc >> 5) & 0xF}")
print(f"    L2 table base [31:10] = 0x{(l1_desc >> 10) << 10:08X}")
l2_pointed = (l1_desc >> 10) << 10
print(f"    -> L2 table at PA 0x{l2_pointed:08X}")

print(f"\n  First page entry (VA 0x0, identity mapped):")
print(f"    L2[0] = (0x0 & 0xFFFFF000) | 0x252 = 0x00000252")
print(f"    -> Maps VA 0x0000-0x0FFF to PA 0x0000-0x0FFF")
print(f"    -> VA 0x100 -> PA 0x100 (the VBAR table region)")
print(f"    -> VA 0x108 -> PA 0x108 = 0xE12FFF1E = BX LR")

print("\n" + "-" * 60)
print("SECTION MAPPING RANGES:")
print("-" * 60)
print(f"  VA 0x00000000 - 0x00FFFFFF:  L2 page tables (identity mapped)")
print(f"  VA 0x01000000 - 0x017FFFFF:  Section 0x1DF2 (identity)")
print(f"  VA 0x01800000 - 0x02BFFFFF:  Section 0x2DF2 (identity)")
print(f"  VA 0x02C00000 - 0x02FFFFFF:  Section 0x2DF2 (identity)")
print(f"  VA 0x03000000 - 0x03FFFFFF:  Section 0x2DF2 (identity)")
print(f"  VA 0x04000000 - 0x07FFFFFF:  Section 0x4DEE (device, identity)")
print(f"  VA 0x08000000 - 0x23FFFFFF:  Section 0x1DE2 (identity)")
print(f"  VA 0x24000000 - 0x3FFFFFFF:  Section 0x2DE2 (identity)")
print(f"  VA 0x40000000+:              Unmapped (TTBR1 disabled, fault)")

print(f"\nPage-level loops (all identity mapped):")
print(f"  Loop 1: VA 0 to r6=0x{val_3a24:08X}, step 4KB, attrs 0x252")
print(f"  Loop 2: VA r6 to r5=0x{val_3a28:08X}, step 4KB, attrs 0x53")
print(f"  Loop 3: [sp,8]/[sp,c] to r8=0x{val_3a40:08X}, step 4KB, attrs 0x5F")
print(f"  Loop 4: [sp,0x14] to r9=0x{val_3a34:08X}, step 4KB, attrs 0x5F")
print(f"  Loop 5: [sp,0x10] to r7=0x{val_3a48:08X}, step 4KB, attrs 0x6F")
print(f"  Loop 6: r5 to r10=0x{val_3a2c:08X}, step 4KB, attrs 0x72")

print("\n" + "=" * 80)
print("FINAL CONCLUSION")
print("=" * 80)
print("""
1. VBAR = 0x100 (single write at offset 0x4C, no other writes in binary)

2. SVC vector at VBAR+0x08 = 0x108:
   Physical memory at 0x108 = 0xE12FFF1E = BX LR (return immediately)

3. MMU Page Table:
   - TTBR0 = 0x4E000 (L1 table, 1024 entries for lower 1GB)
   - TTBCR.N = 2, PD1=1 (only TTBR0 active, upper 3GB faults)
   - First L1 entry = Page Table descriptor pointing to L2 table
   - L2 entries are IDENTITY MAPPED (VA = PA for all pages)
   - Remaining L1 entries are Section (1MB) IDENTITY MAPPED
   - VA 0x108 maps to PA 0x108 via L2 page table (identity)

4. NO virtual remapping of the VBAR region (0x100-0x120)

5. ZERO SVC instructions in the entire binary (ARM + Thumb)

6. FUN_000044CC is the real PSP command dispatcher, called DIRECTLY
   (via BLX from ARM exception dispatch), not through the SVC mechanism

7. The exception dispatch at 0x134/0x198:
   - Handles SVC #0 -> BLX to Thumb FUN_00005278
   - Handles SVC #N -> BLX to Thumb FUN_000044CC (at +0x100 = 0x45CC)
   - BUT this handler is NOT reachable via the VBAR table (which has BX LR)
   - It IS reachable via the original exception table at 0x00 (pre-VBAR)
""")
