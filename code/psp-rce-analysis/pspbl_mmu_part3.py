#!/usr/bin/env python3
"""
Part 3: Page table helper functions + full function prologue + pyghidra decompilation.
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

# ── 3a: Page table helper at 0x30B0 (write_section_entry) ──────────────
print("=" * 80)
print("3a. WRITE SECTION ENTRY function at 0x30B0 (Thumb)")
print("=" * 80)

region_30b0 = blob[0x30B0:0x30B0 + 0x40]
for insn in md_thumb.disasm(region_30b0, 0x30B0):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<10s} {insn.op_str}"
    marker = ""
    if 'str' in insn.mnemonic:
        marker = " <<<< STORE"
    if insn.mnemonic == 'bx' and insn.op_str == 'lr':
        marker = " <<<< RETURN"
        print(line + marker)
        break
    if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
        marker = " <<<< RETURN"
        print(line + marker)
        break
    print(line + marker)

# ── 3b: Page table helper at 0x30C4 (write_page_entry) ─────────────────
print("\n" + "=" * 80)
print("3b. WRITE PAGE ENTRY function at 0x30C4 (Thumb)")
print("=" * 80)

region_30c4 = blob[0x30C4:0x30C4 + 0x80]
for insn in md_thumb.disasm(region_30c4, 0x30C4):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<10s} {insn.op_str}"
    marker = ""
    if 'str' in insn.mnemonic:
        marker = " <<<< STORE"
    if insn.mnemonic == 'bx' and insn.op_str == 'lr':
        marker = " <<<< RETURN"
        print(line + marker)
        break
    if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
        marker = " <<<< RETURN"
        print(line + marker)
        break
    print(line + marker)

# ── 3c: Full page table setup function (find prologue before 0x394C) ────
print("\n" + "=" * 80)
print("3c. FULL PAGE TABLE SETUP FUNCTION (prologue search)")
print("=" * 80)

# Search backwards from 0x394C for a PUSH instruction
print("\nSearching backwards from 0x394C for function prologue...")
# Try disassembling from various starting points
for try_start in range(0x3900, 0x394C, 2):
    region = blob[try_start:try_start + 4]
    for insn in md_thumb.disasm(region, try_start):
        if insn.mnemonic == 'push' or (insn.mnemonic == 'push.w'):
            print(f"  Found PUSH at 0x{try_start:X}: {insn.mnemonic} {insn.op_str}")

# Disassemble from 0x3900 to find the function structure
print("\nThumb disassembly 0x3900-0x394C:")
region = blob[0x3900:0x394C]
for insn in md_thumb.disasm(region, 0x3900):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<10s} {insn.op_str}"
    marker = ""
    if 'push' in insn.mnemonic: marker = " <<<< PROLOGUE"
    if 'pop' in insn.mnemonic and 'pc' in insn.op_str: marker = " <<<< RETURN"
    if insn.mnemonic == 'bx' and insn.op_str == 'lr': marker = " <<<< RETURN"
    print(line + marker)

# ── 3d: Decode section descriptor attributes ────────────────────────────
print("\n" + "=" * 80)
print("3d. PAGE TABLE DESCRIPTOR DECODE")
print("=" * 80)

def decode_section_desc(val):
    """Decode ARMv7-A L1 Section descriptor attributes (lower 20 bits)."""
    desc_type = val & 0x3
    if desc_type != 0x2:
        return f"  NOT a Section descriptor (type bits = {desc_type:#04b})"

    result = []
    result.append(f"  Type: Section (1MB)")
    result.append(f"  B (bufferable): {(val >> 2) & 1}")
    result.append(f"  C (cacheable): {(val >> 3) & 1}")
    result.append(f"  XN (execute-never): {(val >> 4) & 1}")
    domain = (val >> 5) & 0xF
    result.append(f"  Domain: {domain}")
    result.append(f"  P (implementation): {(val >> 9) & 1}")
    ap10 = (val >> 10) & 0x3
    ap2 = (val >> 15) & 1
    ap = (ap2 << 2) | ap10
    result.append(f"  AP[2:0]: {ap:03b} (AP[2]={ap2}, AP[1:0]={ap10:02b})")
    tex = (val >> 12) & 0x7
    result.append(f"  TEX[2:0]: {tex:03b}")
    s = (val >> 16) & 1
    result.append(f"  S (shareable): {s}")
    ng = (val >> 17) & 1
    result.append(f"  nG (not-global): {ng}")
    ns = (val >> 19) & 1
    result.append(f"  NS (non-secure): {ns}")

    # Memory type from TEX/C/B
    c = (val >> 3) & 1
    b = (val >> 2) & 1
    result.append(f"  TEX/C/B = {tex:03b}/{c}/{b}")
    if tex == 0 and c == 0 and b == 0:
        result.append("  Memory: Strongly-ordered")
    elif tex == 0 and c == 0 and b == 1:
        result.append("  Memory: Shareable Device")
    elif tex == 0 and c == 1 and b == 0:
        result.append("  Memory: Outer/Inner Write-Through, no Write-Allocate")
    elif tex == 0 and c == 1 and b == 1:
        result.append("  Memory: Outer/Inner Write-Back, no Write-Allocate")
    elif tex == 1 and c == 0 and b == 0:
        result.append("  Memory: Outer/Inner Non-cacheable")
    elif tex == 2 and c == 0 and b == 0:
        result.append("  Memory: Outer/Inner Non-cacheable (TEX=010)")
    elif tex == 1 and c == 1 and b == 1:
        result.append("  Memory: Outer/Inner Write-Back, Write-Allocate")
    else:
        result.append(f"  Memory: Implementation-defined or remapped (TEX={tex:03b}, C={c}, B={b})")

    return '\n'.join(result)

print("\nSection descriptor 0x2DE2:")
print(decode_section_desc(0x2DE2))

def decode_small_page_desc(val):
    """Decode ARMv7-A L2 Small Page descriptor attributes."""
    if (val & 0x2) != 0x2:
        return f"  NOT a Small Page descriptor (bit 1 = {(val >> 1) & 1})"

    result = []
    result.append(f"  Type: Small Page (4KB)")
    xn = val & 1
    result.append(f"  XN (execute-never): {xn}")
    b = (val >> 2) & 1
    c = (val >> 3) & 1
    result.append(f"  B (bufferable): {b}")
    result.append(f"  C (cacheable): {c}")
    ap10 = (val >> 4) & 0x3
    tex = (val >> 6) & 0x7
    ap2 = (val >> 9) & 1
    ap = (ap2 << 2) | ap10
    result.append(f"  AP[2:0]: {ap:03b} (AP[2]={ap2}, AP[1:0]={ap10:02b})")
    result.append(f"  TEX[2:0]: {tex:03b}")
    s = (val >> 10) & 1
    ng = (val >> 11) & 1
    result.append(f"  S (shareable): {s}")
    result.append(f"  nG (not-global): {ng}")
    result.append(f"  TEX/C/B = {tex:03b}/{c}/{b}")

    return '\n'.join(result)

print("\nSmall page descriptor 0x252:")
print(decode_small_page_desc(0x252))

# Other page attributes used in the function
for attrs_val, name in [(0x53, "third loop"), (0x5F, "fourth loop"),
                         (0x6F, "fifth loop"), (0x72, "sixth loop")]:
    print(f"\nSmall page descriptor 0x{attrs_val:X} ({name}):")
    print(decode_small_page_desc(attrs_val))

# ── 3e: Trace the init flow order ───────────────────────────────────────
print("\n" + "=" * 80)
print("3e. COMPLETE INIT FLOW RECONSTRUCTION")
print("=" * 80)

print("""
BOOT FLOW ANALYSIS:
===================

There are TWO separate init sequences in the binary:

PATH A: MMU Setup (0x3C - 0xA8)
  Called from: Unknown (possibly from PSP ROM or external code)
  0x3C: Read SCTLR, clear V bit (low vectors)
  0x44: Write SCTLR (disable high vectors)
  0x48: Load VBAR value = 0x100 from pool
  0x4C: MCR VBAR = 0x100 *** ONLY VBAR WRITE IN BINARY ***
  0x50: BL 0x22C (disable_mmu: clear I-cache enable, D-cache enable, MMU enable bits)
  0x54: BL 0x244 (invalidate TLB + I-cache)
  0x58: TTBCR = 0x22 (N=2: TTBR0 covers lower 1GB, TTBR1 disabled)
  0x64: TTBR0 = 0x4E000 (page table base in SRAM)
  0x68: SP = 0x54000
  0x6C: Load page table setup function address = 0x394D (Thumb)
  0x70: BLX page_table_setup(r0 = 0x4E000) *** PAGE TABLE POPULATION ***
  0x74: Read ACTLR
  0x78: ACTLR |= 0x1000 (SMP bit)
  0x80: Read DACR (ignored)
  0x84: Load DACR = 0x55555555 (all domains Client)
  0x88: DACR = 0x55555555
  0x8C: Load post-MMU target = 0x1AC
  0x90: Read SCTLR
  0x94: SCTLR |= 0x1000 (I-cache enable)
  0x98: SCTLR |= 0x4 (D-cache enable)
  0x9C: SCTLR &= ~0x2 (alignment check off)
  0xA0: SCTLR |= 0x1 *** MMU ENABLE ***
  0xA4: Write SCTLR (MMU + caches ON)
  0xA8: BX 0x1AC (continue to SVC dispatch area???)

PATH B: Mode Stack Setup + BSS Clear (0xAC - 0x100)
  Called from: Unknown (possibly from 0x1AC or external)
  0xAC: MSR CPSR = 0xD2 (IRQ mode, IRQ+FIQ disabled)
  0xB4: IRQ SP = 0x4DC00
  0xB8: MSR CPSR = 0xD1 (FIQ mode)
  0xBC: FIQ SP = 0x4DC00 (same!)
  0xC0: MSR CPSR = 0xD7 (ABT mode)
  0xC4: ABT SP = 0x4DC00
  0xC8: MSR CPSR = 0xDB (UND mode)
  0xCC: UND SP = 0x4DC00
  0xD0: MSR CPSR = 0x53 (SVC mode, IRQ disabled)
  0xD4: Clear Thumb bit in CPSR
  0xE0-F4: Clear BSS (0x9AC0 to 0xCD88)
  0xF8: SVC SP = 0x92000
  0xFC: Load main entry = 0xA45 (Thumb at 0xA44)
  0x100: BX R12 -> main Thumb code at 0xA44
""")

# ── 3f: What's at address 0x1AC? ────────────────────────────────────────
print("=" * 80)
print("3f. CODE AT 0x1AC (post-MMU BX target from Path A)")
print("=" * 80)

print("\nARM disassembly from 0x1AC:")
for insn in md_arm.disasm(blob[0x1AC:0x200], 0x1AC):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<8s} {insn.op_str}"
    marker = ""
    if insn.mnemonic == 'bx': marker = " <<<< BX"
    if insn.mnemonic == 'blx': marker = " <<<< BLX"
    if 'spsr' in insn.op_str.lower(): marker = " <<<< SPSR"
    print(line + marker)

print("""
NOTE: 0x1AC is in the MIDDLE of the SVC dispatch handler at 0x198.
At 0x1AC: LDRH R0, [LR, #-2] -- this reads the SVC instruction from Thumb code
This makes no sense as a post-MMU entry point unless Path A is called
FROM the SVC dispatch handler and returns INTO it.

ALTERNATIVE: Path A (0x3C-0xA8) might be the reset handler for the
ORIGINAL exception table (before VBAR change), not a standalone function.
The reset vector at 0x00 -> 0x13C. At 0x13C, ICIALLU + SUBS to 0x54100.
0x54100 is outside this binary. The external code might call back to 0x3C.
""")

# ── 3g: Confirm identity mapping by analyzing write_section at 0x30B0 ──
print("=" * 80)
print("3g. DETAILED ANALYSIS OF write_section_entry (0x30B0)")
print("=" * 80)

print("\nFull Thumb disassembly 0x30B0-0x30C4:")
for insn in md_thumb.disasm(blob[0x30B0:0x30C4], 0x30B0):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<10s} {insn.op_str}"
    marker = ""
    if 'str' in insn.mnemonic: marker = " <<<< STORE"
    if insn.mnemonic == 'orr': marker = " <<<< ORR (combine addr+attrs?)"
    if 'lsl' in insn.op_str: marker = " <<<< SHIFT"
    if insn.mnemonic == 'bx' and insn.op_str == 'lr': marker = " <<<< RETURN"
    print(line + marker)

print("\nFull Thumb disassembly 0x30C4-0x3130:")
count = 0
for insn in md_thumb.disasm(blob[0x30C4:0x3130], 0x30C4):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<10s} {insn.op_str}"
    marker = ""
    if 'str' in insn.mnemonic: marker = " <<<< STORE"
    if insn.mnemonic == 'orr': marker = " <<<< ORR"
    if insn.mnemonic == 'bx' and insn.op_str == 'lr':
        marker = " <<<< RETURN"
        print(line + marker)
        break
    if insn.mnemonic == 'pop' and 'pc' in insn.op_str:
        marker = " <<<< RETURN"
        print(line + marker)
        break
    print(line + marker)
    count += 1
    if count > 80:
        print("  ... truncated")
        break

# ── 3h: First L1 page table entry check ────────────────────────────────
print("\n" + "=" * 80)
print("3h. ANALYSIS: Can VA 0x100 be remapped?")
print("=" * 80)

print("""
KEY FINDINGS:
=============

1. TTBCR.N = 2: TTBR0 table has 1024 entries covering VA 0x0 - 0x3FFFFFFF
   Each L1 entry covers 1MB.
   Entry index for VA 0x100 = 0x100 >> 20 = 0 (first entry in table)
   L1 entry for VA 0x000xxxxx is at TTBR0 + 0 = 0x4E000

2. The page table setup at 0x394C first creates SECTION entries (1MB)
   for VA 0x0 through 0x3FFFFFFF with attributes 0x2DE2.
   Section descriptors encode the physical address in bits [31:20].
   Since the loop uses: descriptor = (VA & 0xFFF00000) | 0x2DE2
   This creates IDENTITY MAPPING: VA 0x0 -> PA 0x0, VA 0x100000 -> PA 0x100000

3. BUT then the function creates PAGE-LEVEL entries (4KB) for subsets.
   The page entry function (0x30C4) would need to:
   a) Replace the L1 Section entry with a Page Table pointer
   b) Populate L2 page entries
   If this affects the first 1MB (VA 0x0 - 0xFFFFF), it could remap VA 0x100.

4. The second loop (page entries with attrs 0x252) starts at VA 0
   and goes up to some limit (r6). If r6 > 0, it creates page-level
   mappings for the first N * 4KB of address space.

5. For identity mapping even at page level:
   L2 descriptor = (VA & 0xFFFFF000) | page_attrs
   VA 0x0000 -> PA 0x0000, VA 0x1000 -> PA 0x1000, etc.
   VA 0x0100 is within the first 4KB page (0x0000-0x0FFF)
   So VA 0x100 -> PA 0x100 (same physical address)

6. Unless the page table setup INTENTIONALLY maps a different PA for
   the first 4KB page, VA 0x100 = PA 0x100 = BX LR.

CONCLUSION ON VBAR REMAPPING:
  - ONE VBAR write: 0x4C sets VBAR = 0x100
  - NO second VBAR write found (exhaustive ARM + Thumb search)
  - Page tables create IDENTITY MAPPING (section-level for 1GB)
  - Even if replaced by page-level entries for the first MB,
    standard page table setup uses identity mapping (PA = VA)
  - VA 0x108 (SVC vector) = PA 0x108 = BX LR (confirmed)
  - ZERO SVC instructions in entire binary
  - The SVC handler IS a no-op (BX LR = return to caller)

SVC DISPATCH MECHANISM:
  - Original exception table (0x00): SVC -> 0x298 (cache code, likely vestigial)
  - VBAR table (0x100): SVC -> 0x108 = BX LR (no-op return)
  - Exception dispatch at 0x134-0x1F4: Real SVC handler EXISTS but is NOT
    connected to the VBAR table at 0x100
  - SVC #0 -> Thumb function at 0x5278 (via pool at 0x3BC)
  - SVC #N (N!=0) -> Thumb function at 0x45CC (via pool at 0x3C0)
  - FUN_000044CC at 0x44CC is a DIRECT CALL dispatch (not SVC-triggered)
""")

# ── 3i: Check what's at 0xA44 (main Thumb entry point) ─────────────────
print("=" * 80)
print("3i. MAIN THUMB ENTRY POINT at 0xA44")
print("=" * 80)

main_region = blob[0xA44:0xA44 + 0x60]
count = 0
for insn in md_thumb.disasm(main_region, 0xA44):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<10s} {insn.op_str}"
    marker = ""
    if insn.mnemonic in ('bl', 'blx'): marker = " <<<< CALL"
    if insn.mnemonic == 'svc': marker = " <<<< SVC!!!"
    print(line + marker)
    count += 1
    if count > 30:
        break

print("\n\n" + "=" * 80)
print("PART 3 COMPLETE")
print("=" * 80)
