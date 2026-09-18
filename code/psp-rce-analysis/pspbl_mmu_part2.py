#!/usr/bin/env python3
"""
Part 2: Literal pool decode + page table setup function disassembly.
"""

import struct, sys, os
sys.stdout.reconfigure(encoding='utf-8')

BINARY = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

with open(BINARY, "rb") as f:
    blob = f.read()

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md_arm.detail = True
md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md_thumb.detail = True

def read_u32(offset):
    return struct.unpack_from("<I", blob, offset)[0]

# ── 2a: Decode ALL literal pool references from init code 0x3C-0x100 ────
print("=" * 80)
print("2a. LITERAL POOL VALUES referenced from init code (0x3C-0xA8)")
print("=" * 80)

# LDR instructions and their pool addresses:
ldr_refs = [
    (0x48, "r0 (VBAR value)",       "LDR r0, [PC, #0x334]",  0x48 + 8 + 0x334),
    (0x60, "r0 (TTBR0 base)",       "LDR r0, [PC, #0x320]",  0x60 + 8 + 0x320),
    (0x68, "SP (init stack)",        "LDR SP, [PC, #0x31C]",  0x68 + 8 + 0x31C),
    (0x6C, "r2 (page table func)",   "LDR r2, [PC, #0x31C]",  0x6C + 8 + 0x31C),
    (0x84, "r0 (DACR value)",        "LDR r0, [PC, #0x308]",  0x84 + 8 + 0x308),
    (0x8C, "r12 (post-MMU target)",  "LDR r12, [PC, #0x304]", 0x8C + 8 + 0x304),
]

for addr, desc, insn_str, pool_addr in ldr_refs:
    val = read_u32(pool_addr)
    print(f"  [{addr:#06x}] {insn_str}")
    print(f"           Pool @ {pool_addr:#06x} = 0x{val:08X}  ({desc})")
    if val & 1:
        print(f"           -> Thumb function at 0x{val & ~1:08X}")
    print()

# ── 2b: Literal pool for second init sequence 0xAC-0x100 ────────────────
print("=" * 80)
print("2b. LITERAL POOL VALUES referenced from mode-setup code (0xAC-0x100)")
print("=" * 80)

ldr_refs2 = [
    (0xB0, "r0 (exception SP)",     "LDR r0, [PC, #0x2E4]",  0xB0 + 8 + 0x2E4),
    (0xE0, "r1 (BSS start)",        "LDR r1, [PC, #0x2B8]",  0xE0 + 8 + 0x2B8),
    (0xE4, "r3 (BSS end)",          "LDR r3, [PC, #0x2B8]",  0xE4 + 8 + 0x2B8),
    (0xF8, "SP (SVC stack)",        "LDR SP, [PC, #0x2A8]",  0xF8 + 8 + 0x2A8),
    (0xFC, "r12 (main entry)",      "LDR r12, [PC, #0x2A8]", 0xFC + 8 + 0x2A8),
]

for addr, desc, insn_str, pool_addr in ldr_refs2:
    val = read_u32(pool_addr)
    print(f"  [{addr:#06x}] {insn_str}")
    print(f"           Pool @ {pool_addr:#06x} = 0x{val:08X}  ({desc})")
    if val & 1:
        print(f"           -> Thumb function at 0x{val & ~1:08X}")
    print()

# ── 2c: Literal pool for exception dispatch at 0x134-0x1F4 ──────────────
print("=" * 80)
print("2c. LITERAL POOL VALUES from exception dispatch (0x134-0x1F4)")
print("=" * 80)

ldr_refs3 = [
    (0x148, "lr (return target)",    "LDR lr, [PC, #0x264]",  0x148 + 8 + 0x264),
    (0x190, "r12 (handler 1)",       "LDR r12, [PC, #0x220]", 0x190 + 8 + 0x220),
    (0x1CC, "r12 (handler 2)",       "LDR r12, [PC, #0x1E8]", 0x1CC + 8 + 0x1E8),
    (0x1E0, "r12 (handler 3)",       "LDR r12, [PC, #0x1D8]", 0x1E0 + 8 + 0x1D8),
]

for addr, desc, insn_str, pool_addr in ldr_refs3:
    val = read_u32(pool_addr)
    print(f"  [{addr:#06x}] {insn_str}")
    print(f"           Pool @ {pool_addr:#06x} = 0x{val:08X}  ({desc})")
    if val & 1:
        print(f"           -> Thumb function at 0x{val & ~1:08X}")
    print()

# ── 2d: Full literal pool dump (0x384-0x3C8) ────────────────────────────
print("=" * 80)
print("2d. LITERAL POOL DATA (0x384-0x3C8)")
print("=" * 80)

for off in range(0x384, 0x3C8, 4):
    val = read_u32(off)
    annotations = []
    if val == 0x100: annotations.append("VBAR value")
    if val == 0x4E000: annotations.append("page table base")
    if val == 0x55555555: annotations.append("DACR client-all")
    if val & 1 and 0 < (val & ~1) < len(blob): annotations.append(f"Thumb @ 0x{val&~1:X}")
    if not (val & 1) and 0 < val < len(blob): annotations.append(f"ARM code/data @ 0x{val:X}")
    ann_str = f"  ({', '.join(annotations)})" if annotations else ""
    print(f"  [{off:#06x}]: 0x{val:08X}{ann_str}")

# ── 2e: Page table setup function at 0x394C (Thumb) ─────────────────────
print("\n" + "=" * 80)
print("2e. PAGE TABLE SETUP FUNCTION (Thumb, starting at 0x394C)")
print("=" * 80)

# Disassemble a generous region from 0x394C
pt_func_start = 0x394C
pt_func_region = blob[pt_func_start:pt_func_start + 0x200]

print(f"\nThumb disassembly from 0x{pt_func_start:X}:")
insn_count = 0
for insn in md_thumb.disasm(pt_func_region, pt_func_start):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<10s} {insn.op_str}"
    marker = ""

    # Flag interesting operations
    if 'str' in insn.mnemonic and insn.mnemonic != 'strd':
        marker = " <<<< STORE"
    if '0x4e' in insn.op_str.lower():
        marker = " <<<< PAGE TABLE REF"
    if insn.mnemonic in ('bx', 'pop') and 'pc' in insn.op_str:
        marker = " <<<< RETURN"
        print(line + marker)
        insn_count += 1
        # Don't break immediately - there might be more after conditional returns
        if insn.mnemonic == 'bx' and insn.op_str == 'lr':
            break
        continue
    if insn.mnemonic == 'movw' or insn.mnemonic == 'movt':
        marker = f" <<<< {insn.mnemonic.upper()}"

    print(line + marker)
    insn_count += 1
    if insn_count > 150:
        print("  ... (truncated)")
        break

# ── 2f: Also check the function that the init calls at BLX 0x1178 ──────
print("\n" + "=" * 80)
print("2f. IRQ HANDLER (BLX target at 0x1178, Thumb)")
print("=" * 80)

irq_start = 0x1178
irq_region = blob[irq_start:irq_start + 0x80]
print(f"\nThumb disassembly from 0x{irq_start:X}:")
insn_count = 0
for insn in md_thumb.disasm(irq_region, irq_start):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<10s} {insn.op_str}"
    print(line)
    insn_count += 1
    if insn.mnemonic == 'bx' and insn.op_str == 'lr':
        break
    if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
        break
    if insn_count > 60:
        break

# ── 2g: Check what FUN_000044CC looks like ──────────────────────────────
print("\n" + "=" * 80)
print("2g. FUN_000044CC (Thumb, the SVC dispatch function)")
print("=" * 80)

svc_dispatch = 0x44CC
svc_region = blob[svc_dispatch:svc_dispatch + 0x200]
print(f"\nThumb disassembly from 0x{svc_dispatch:X}:")
insn_count = 0
for insn in md_thumb.disasm(svc_region, svc_dispatch):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<10s} {insn.op_str}"
    marker = ""
    if insn.mnemonic == 'svc':
        marker = " <<<< SVC CALL"
    if insn.mnemonic == 'bx' and insn.op_str == 'lr':
        marker = " <<<< RETURN"
    if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
        marker = " <<<< RETURN"
    if insn.mnemonic.startswith('mcr') or insn.mnemonic.startswith('mrc'):
        marker = " <<<< CP15"
    print(line + marker)
    insn_count += 1
    if insn_count > 100:
        print("  ... (truncated)")
        break

# ── 2h: SVC instruction search ──────────────────────────────────────────
print("\n" + "=" * 80)
print("2h. ALL SVC INSTRUCTIONS in the binary")
print("=" * 80)

print("\n  ARM mode:")
for insn in md_arm.disasm(blob, 0):
    if insn.mnemonic in ('svc', 'swi'):
        print(f"    {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")

print("\n  Thumb mode (from 0x400):")
for insn in md_thumb.disasm(blob[0x400:], 0x400):
    if insn.mnemonic in ('svc', 'swi'):
        print(f"    {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")

# ── 2i: Exception dispatch analysis ────────────────────────────────────
print("\n" + "=" * 80)
print("2i. EXCEPTION DISPATCH FUNCTION at 0x134 (full ARM disassembly)")
print("=" * 80)

# The function at 0x134 dispatches exceptions/SVC
exc_region = blob[0x134:0x22C]
for insn in md_arm.disasm(exc_region, 0x134):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<8s} {insn.op_str}"
    marker = ""
    if insn.mnemonic in ('blx',): marker = " <<<< BLX"
    if insn.mnemonic == 'bx': marker = " <<<< BX"
    if 'spsr' in insn.op_str.lower(): marker = " <<<< SPSR"
    if insn.mnemonic == 'pop' and 'pc' in insn.op_str: marker = " <<<< RETURN"
    print(line + marker)

# ── 2j: Analyze the SVC dispatch mechanism ──────────────────────────────
print("\n" + "=" * 80)
print("2j. SVC DISPATCH CHAIN ANALYSIS")
print("=" * 80)

# The SVC handler at VBAR+0x08 = 0x108 is BX LR (NOP).
# But the original exception table's SVC handler was at 0x298 (from pool at 0x28).
# Let's look at what addresses are in the pool for the exception dispatch handlers.

print("\nOriginal exception table handler addresses (from pool at 0x20):")
for i, name in enumerate(["Reset", "Undefined", "SVC", "Prefetch Abort",
                           "Data Abort", "Reserved", "IRQ", "FIQ"]):
    if i < 5:
        pool_off = 0x20 + i * 4
    elif i == 5:
        continue  # NOP
    else:
        pool_off = 0x34 + (i - 6) * 4
    val = read_u32(pool_off)
    print(f"  {name:>16s}: pool[{pool_off:#06x}] = 0x{val:08X}")

print("\nVBAR exception table at 0x100 (active after VBAR set):")
vnames = ["Reset(+0x00)", "Undefined(+0x04)", "SVC(+0x08)", "Prefetch Abort(+0x0C)",
          "Data Abort(+0x10)", "Reserved(+0x14)", "IRQ(+0x18)", "FIQ(+0x1C)"]
for i in range(8):
    off = 0x100 + i * 4
    word = read_u32(off)
    # Decode as ARM
    for insn in md_arm.disasm(struct.pack("<I", word), off):
        print(f"  {vnames[i]:>24s}: 0x{word:08X} = {insn.mnemonic} {insn.op_str}")

# ── 2k: Cross-check: is the data at 0x100-0x120 really a vector table?
print("\n" + "=" * 80)
print("2k. CROSS-CHECK: Does init code at 0xAC-0x100 fall through to 0x100?")
print("=" * 80)

print("\nInit code from 0xF0 to 0x108:")
for insn in md_arm.disasm(blob[0xF0:0x110], 0xF0):
    print(f"  {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")

print("\nSo the code at 0xFC loads r12 from pool, and 0x100 (= BX r12) executes.")
print("This is ALSO the VBAR Reset vector entry. Dual purpose: init fallthrough + Reset vector.")

# ── 2l: Search for STR instructions writing to 0x4E000 region ───────────
print("\n" + "=" * 80)
print("2l. SEARCH: Thumb STR instructions near page table setup (0x3900-0x3B00)")
print("=" * 80)

search_region = blob[0x3900:0x3B00]
for insn in md_thumb.disasm(search_region, 0x3900):
    if 'str' in insn.mnemonic:
        print(f"  {insn.address:#06x}: {insn.mnemonic:<10s} {insn.op_str}")

print("\n\n" + "=" * 80)
print("PART 2 COMPLETE")
print("=" * 80)
