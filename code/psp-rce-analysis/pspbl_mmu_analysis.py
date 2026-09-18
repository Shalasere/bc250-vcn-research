#!/usr/bin/env python3
"""
PSP_BL MMU / SVC handler / init sequence analysis for CVE-2025-29951 research.
Combines raw binary analysis (capstone) with Ghidra decompilation (pyghidra).
"""

import struct, sys, os

# Force UTF-8 output
sys.stdout.reconfigure(encoding='utf-8')

BINARY = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

# ── Part 1: Raw binary + capstone analysis ──────────────────────────────

print("=" * 80)
print("PART 1: RAW BINARY + CAPSTONE DISASSEMBLY")
print("=" * 80)

with open(BINARY, "rb") as f:
    blob = f.read()

print(f"\nBinary size: {len(blob)} bytes (0x{len(blob):X})")

# ── 1a: Exception vector table at 0x00 (ARM mode) ──────────────────────
print("\n" + "-" * 60)
print("1a. ARM EXCEPTION VECTOR TABLE (offset 0x00-0x20)")
print("-" * 60)

vector_names = ["Reset", "Undefined", "SVC", "Prefetch Abort",
                "Data Abort", "Reserved", "IRQ", "FIQ"]
for i in range(8):
    off = i * 4
    word = struct.unpack_from("<I", blob, off)[0]
    print(f"  [{off:#06x}] {vector_names[i]:>16s}: 0x{word:08X}", end="")
    # Decode as ARM instruction
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
    md_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
    md_arm.detail = True
    for insn in md_arm.disasm(struct.pack("<I", word), off):
        print(f"  →  {insn.mnemonic} {insn.op_str}", end="")
        # If it's a branch, compute target
        if insn.mnemonic in ('b', 'bl', 'bx'):
            pass  # target already in op_str
        elif insn.mnemonic == 'ldr' and 'pc' in insn.op_str:
            # LDR PC, [PC, #offset] — compute the load address
            # PC at execution = current addr + 8 (ARM pipeline)
            pass
    print()

# ── 1b: Second vector table at 0x100 (VBAR target) ─────────────────────
print("\n" + "-" * 60)
print("1b. VBAR VECTOR TABLE at 0x100 (set by MCR at 0x4C)")
print("-" * 60)

for i in range(8):
    off = 0x100 + i * 4
    word = struct.unpack_from("<I", blob, off)[0]
    print(f"  [{off:#06x}] {vector_names[i]:>16s}: 0x{word:08X}", end="")
    for insn in md_arm.disasm(struct.pack("<I", word), off):
        print(f"  →  {insn.mnemonic} {insn.op_str}", end="")
    print()

# ── 1c: Full ARM disassembly 0x00-0x400 ────────────────────────────────
print("\n" + "-" * 60)
print("1c. FULL INIT CODE DISASSEMBLY (ARM mode, 0x00-0x400)")
print("-" * 60)

# We know the init code is ARM mode. Disassemble 0x00-0x400.
# Mark MCR/MRC instructions specially.
region = blob[0:0x400]
md_arm2 = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md_arm2.detail = True

mcr_instructions = []
vbar_writes = []
ttbr_writes = []
sp_writes = []
mmu_enables = []

for insn in md_arm2.disasm(region, 0x0):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<8s} {insn.op_str}"
    marker = ""

    mnem = insn.mnemonic
    ops = insn.op_str

    # Flag coprocessor ops
    if mnem.startswith('mcr') or mnem.startswith('mrc'):
        marker = " <<<< CP15"
        mcr_instructions.append((insn.address, mnem, ops))
        # VBAR = MCR p15, 0, Rn, c12, c0, 0
        if 'c12' in ops and 'c0' in ops:
            vbar_writes.append((insn.address, ops))
            marker = " <<<< VBAR WRITE"
        # TTBR0 = MCR p15, 0, Rn, c2, c0, 0
        if 'c2' in ops and 'c0' in ops and '0' in ops.split(',')[-1].strip():
            ttbr_writes.append((insn.address, ops))
            marker = " <<<< TTBR0 WRITE"
        # SCTLR = MCR p15, 0, Rn, c1, c0, 0 (MMU enable)
        if 'c1' in ops and 'c0' in ops:
            parts = [p.strip() for p in ops.split(',')]
            if len(parts) >= 6 and parts[-1] == '0' and 'c1' in parts[3]:
                mmu_enables.append((insn.address, ops))
                marker = " <<<< SCTLR (MMU ENABLE?)"

    # Flag MSR CPSR writes (mode switches)
    if mnem == 'msr' and 'cpsr' in ops.lower():
        marker = " <<<< MODE SWITCH"

    # Flag SP writes
    if mnem in ('mov', 'ldr', 'add', 'sub') and ops.startswith('sp'):
        sp_writes.append((insn.address, mnem, ops))
        marker = " <<<< SP SETUP"

    # Flag BX (ARM/Thumb transitions)
    if mnem == 'bx' and insn.address > 0x20:
        marker = " <<<< BX (mode switch?)"
    if mnem == 'blx':
        marker = " <<<< BLX (call + mode switch)"

    print(line + marker)

print("\n" + "-" * 60)
print("SUMMARY: Coprocessor operations in 0x00-0x400")
print("-" * 60)
for addr, mnem, ops in mcr_instructions:
    print(f"  {addr:#06x}: {mnem} {ops}")

print(f"\nVBAR writes: {len(vbar_writes)}")
for addr, ops in vbar_writes:
    print(f"  {addr:#06x}: {ops}")

print(f"\nTTBR0 writes: {len(ttbr_writes)}")
for addr, ops in ttbr_writes:
    print(f"  {addr:#06x}: {ops}")

print(f"\nSCTLR writes (MMU enable candidates): {len(mmu_enables)}")
for addr, ops in mmu_enables:
    print(f"  {addr:#06x}: {ops}")

print(f"\nSP setup operations: {len(sp_writes)}")
for addr, mnem, ops in sp_writes:
    print(f"  {addr:#06x}: {mnem} {ops}")

# ── 1d: Decode the SVC handler region at 0x298 ─────────────────────────
print("\n" + "-" * 60)
print("1d. SVC HANDLER REGION at 0x298 (ARM mode, 0x280-0x380)")
print("-" * 60)

svc_region = blob[0x280:0x380]
for insn in md_arm2.disasm(svc_region, 0x280):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<8s} {insn.op_str}"
    marker = ""
    if insn.mnemonic == 'bx':
        marker = " <<<< BX"
    if insn.mnemonic == 'blx':
        marker = " <<<< BLX (mode switch)"
    if 'lr' in insn.op_str and insn.mnemonic in ('bx', 'mov'):
        marker = " <<<< RETURN"
    if insn.mnemonic.startswith('svc') or insn.mnemonic.startswith('swi'):
        marker = " <<<< SVC CALL"
    if insn.mnemonic.startswith('mcr') or insn.mnemonic.startswith('mrc'):
        marker = " <<<< CP15"
    print(line + marker)

# ── 1e: Search entire binary for ALL VBAR writes (MCR p15 c12) ─────────
print("\n" + "-" * 60)
print("1e. EXHAUSTIVE SEARCH: All VBAR writes in entire binary")
print("-" * 60)

# Search in ARM mode
print("\n  ARM mode search:")
md_full_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
md_full_arm.detail = True
count = 0
for insn in md_full_arm.disasm(blob, 0x0):
    if insn.mnemonic.startswith('mcr') and 'c12' in insn.op_str:
        print(f"    {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")
        count += 1
print(f"  Total ARM-mode VBAR writes: {count}")

# Search in Thumb mode
print("\n  Thumb mode search:")
md_full_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md_full_thumb.detail = True
count2 = 0
for insn in md_full_thumb.disasm(blob, 0x0):
    if insn.mnemonic.startswith('mcr') and 'c12' in insn.op_str:
        print(f"    {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")
        count2 += 1
print(f"  Total Thumb-mode VBAR writes: {count2}")

# ── 1f: Search entire binary for ALL TTBR0 writes ──────────────────────
print("\n" + "-" * 60)
print("1f. EXHAUSTIVE SEARCH: All TTBR0 writes in entire binary")
print("-" * 60)

print("\n  ARM mode search:")
count = 0
for insn in md_full_arm.disasm(blob, 0x0):
    if insn.mnemonic.startswith('mcr') and 'c2' in insn.op_str:
        print(f"    {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")
        count += 1
print(f"  Total ARM-mode TTBR writes: {count}")

print("\n  Thumb mode search:")
count2 = 0
for insn in md_full_thumb.disasm(blob, 0x0):
    if insn.mnemonic.startswith('mcr') and 'c2' in insn.op_str:
        print(f"    {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")
        count2 += 1
print(f"  Total Thumb-mode TTBR writes: {count2}")

# ── 1g: Search for ALL SCTLR writes (MMU enable/disable) ───────────────
print("\n" + "-" * 60)
print("1g. EXHAUSTIVE SEARCH: All SCTLR writes (MMU enable)")
print("-" * 60)

print("\n  ARM mode search:")
count = 0
for insn in md_full_arm.disasm(blob, 0x0):
    if insn.mnemonic.startswith('mcr'):
        parts = [p.strip() for p in insn.op_str.split(',')]
        # MCR p15, 0, Rn, c1, c0, 0
        if len(parts) >= 4 and 'c1' in parts[3] and 'c0' in parts[4] if len(parts) > 4 else False:
            print(f"    {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")
            count += 1
print(f"  Total ARM-mode SCTLR writes: {count}")

print("\n  Thumb mode search:")
count2 = 0
for insn in md_full_thumb.disasm(blob, 0x0):
    if insn.mnemonic.startswith('mcr'):
        parts = [p.strip() for p in insn.op_str.split(',')]
        if len(parts) >= 4 and 'c1' in parts[3] and 'c0' in parts[4] if len(parts) > 4 else False:
            print(f"    {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")
            count2 += 1
print(f"  Total Thumb-mode SCTLR writes: {count2}")


# ── 1h: Decode region around 0x108 vector entry ────────────────────────
print("\n" + "-" * 60)
print("1h. WHAT IS ACTUALLY AT 0x108? (raw bytes + ARM decode)")
print("-" * 60)

# The SVC vector at VBAR+0x08 = 0x108
word_at_108 = struct.unpack_from("<I", blob, 0x108)[0]
print(f"  Raw word at 0x108: 0x{word_at_108:08X}")

# Check if it's BX LR (0xE12FFF1E)
if word_at_108 == 0xE12FFF1E:
    print("  >>> This is BX LR — SVC returns immediately!")
else:
    for insn in md_arm2.disasm(struct.pack("<I", word_at_108), 0x108):
        print(f"  >>> Decodes as: {insn.mnemonic} {insn.op_str}")

# Also check what's at the vector table address 0x08 (original exception table)
word_at_08 = struct.unpack_from("<I", blob, 0x08)[0]
print(f"\n  Raw word at 0x08 (original SVC vector): 0x{word_at_08:08X}")
for insn in md_arm2.disasm(struct.pack("<I", word_at_08), 0x08):
    print(f"  >>> Decodes as: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic == 'b':
        # Branch: target = PC + offset; PC = addr + 8 in ARM
        # capstone gives us the target directly in op_str
        target_str = insn.op_str.strip()
        if target_str.startswith('#'):
            target = int(target_str[1:], 0)
            print(f"  >>> Branch target: {target:#x}")
            # Show what's at that target
            print(f"  >>> Code at target {target:#x}:")
            tgt_region = blob[target:target+0x40]
            for insn2 in md_arm2.disasm(tgt_region, target):
                line2 = f"      {insn2.address:#06x}: {insn2.bytes.hex():<12s} {insn2.mnemonic:<8s} {insn2.op_str}"
                print(line2)

# ── 1i: Look for the REAL SVC dispatch ──────────────────────────────────
print("\n" + "-" * 60)
print("1i. SEARCH: References to FUN_000044CC (0x44CC/0x44CD)")
print("-" * 60)

# Search for the Thumb address 0x44CD (bit 0 set for Thumb) or 0x44CC
# as a 32-bit word anywhere in the binary
target_thumb = 0x000044CD  # Thumb entry
target_arm = 0x000044CC

for name, target in [("0x44CD (Thumb)", target_thumb), ("0x44CC (ARM)", target_arm)]:
    print(f"\n  Searching for word {name} in binary:")
    for off in range(0, len(blob) - 3, 4):
        word = struct.unpack_from("<I", blob, off)[0]
        if word == target:
            print(f"    Found at offset {off:#06x}")

# Also search for BLX/BX instructions targeting near 0x44CC
print("\n  Searching for branch instructions targeting ~0x44CC:")
# In ARM mode
for insn in md_full_arm.disasm(blob, 0x0):
    if insn.mnemonic in ('b', 'bl', 'bx', 'blx'):
        try:
            target = int(insn.op_str.strip().lstrip('#'), 0)
            if 0x44C0 <= target <= 0x44D0:
                print(f"    ARM  {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")
        except ValueError:
            pass

# In Thumb mode - search from 0x400 onwards (where Thumb code likely starts)
for insn in md_full_thumb.disasm(blob[0x400:], 0x400):
    if insn.mnemonic in ('b', 'bl', 'bx', 'blx'):
        try:
            target_str = insn.op_str.strip().lstrip('#')
            target = int(target_str, 0)
            if 0x44C0 <= target <= 0x44D0:
                print(f"    Thumb {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")
        except ValueError:
            pass

# ── 1j: Page table analysis ────────────────────────────────────────────
print("\n" + "-" * 60)
print("1j. SEARCH: References to page table base 0x4E000")
print("-" * 60)

# 0x4E000 as a 32-bit value
pt_base = 0x0004E000
for off in range(0, len(blob) - 3, 4):
    word = struct.unpack_from("<I", blob, off)[0]
    if word == pt_base or (word & 0xFFFFF000) == pt_base:
        print(f"  Found 0x{word:08X} at offset {off:#06x}")

# Also common: the value might be built from shifts
# 0x4E000 = 0x4E << 12
# Search for MOV Rn, #0x4E in the init code
print("\n  Searching for immediate 0x4E or 0x4E000 in init code:")
for insn in md_arm2.disasm(blob[:0x400], 0x0):
    if '0x4e' in insn.op_str.lower() or '0x4e000' in insn.op_str.lower():
        print(f"    {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")

# ── 1k: Dump the complete init sequence from reset vector ───────────────
print("\n" + "-" * 60)
print("1k. RESET VECTOR HANDLER: Starting at 0x00 vector target")
print("-" * 60)

# The reset vector at 0x00 — decode it
word0 = struct.unpack_from("<I", blob, 0x00)[0]
print(f"  Reset vector word: 0x{word0:08X}")
for insn in md_arm2.disasm(struct.pack("<I", word0), 0x00):
    print(f"  Decodes as: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic == 'b':
        target_str = insn.op_str.strip().lstrip('#')
        target = int(target_str, 0)
        print(f"  Reset target: {target:#x}")
        print(f"\n  Disassembly from {target:#x}:")
        reset_code = blob[target:0x400]
        for insn2 in md_arm2.disasm(reset_code, target):
            line2 = f"    {insn2.address:#06x}: {insn2.bytes.hex():<12s} {insn2.mnemonic:<8s} {insn2.op_str}"
            marker = ""
            if insn2.mnemonic.startswith('mcr'):
                marker = " <<<<<"
                if 'c12' in insn2.op_str: marker = " <<<<< VBAR"
                elif 'c2' in insn2.op_str: marker = " <<<<< TTBR"
                elif 'c1' in insn2.op_str: marker = " <<<<< SCTLR"
                elif 'c7' in insn2.op_str: marker = " <<<<< CACHE"
                elif 'c8' in insn2.op_str: marker = " <<<<< TLB"
            if insn2.mnemonic == 'msr':
                marker = " <<<<< MSR (mode?)"
            if insn2.mnemonic in ('bx', 'blx') and insn2.address > target:
                marker = " <<<<< BRANCH"
            print(line2 + marker)

# ── 1l: Look at the LDR pool data referenced from init code ────────────
print("\n" + "-" * 60)
print("1l. LITERAL POOL: Data words near init code (0x120-0x180)")
print("-" * 60)
for off in range(0x120, 0x180, 4):
    word = struct.unpack_from("<I", blob, off)[0]
    print(f"  [{off:#06x}]: 0x{word:08X}", end="")
    # Annotate known values
    if word == 0xE12FFF1E:
        print("  (BX LR)")
    elif word == 0x0004E000:
        print("  (page table base)")
    elif word == 0x00000100:
        print("  (VBAR = 0x100)")
    elif (word & 0xFFFF0000) == 0:
        print(f"  (small value: {word})")
    elif word > 0x00000400 and word < len(blob):
        print(f"  (possible code ptr)")
    else:
        print()

print("\n" + "-" * 60)
print("1l-ext. LITERAL POOL: Data words 0x200-0x298")
print("-" * 60)
for off in range(0x200, 0x298, 4):
    word = struct.unpack_from("<I", blob, off)[0]
    print(f"  [{off:#06x}]: 0x{word:08X}", end="")
    if word == 0x0004E000:
        print("  (page table base!)")
    elif word == 0x00000100:
        print("  (VBAR address!)")
    elif word == 0x000044CC or word == 0x000044CD:
        print("  (FUN_000044CC!)")
    else:
        print()

# ── 1m: Extended literal pool / data scan ───────────────────────────────
print("\n" + "-" * 60)
print("1m. SCAN: All 32-bit words containing 0x4E (page table)")
print("-" * 60)
for off in range(0, min(0x1000, len(blob)), 4):
    word = struct.unpack_from("<I", blob, off)[0]
    if word == 0x0004E000 or word == 0x0004E014:
        print(f"  [{off:#06x}]: 0x{word:08X}")


print("\n\n" + "=" * 80)
print("PART 1 COMPLETE")
print("=" * 80)
