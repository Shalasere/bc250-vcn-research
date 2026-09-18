#!/usr/bin/env python3
"""Disassemble PSP_BL vector handlers and find SP initialization.

Vector table (ARM mode):
  +0x00 Reset → 0x13C
  +0x04 Undef → 0x2F4
  +0x08 SVC   → 0x298
  +0x0C PAbrt → 0x2F8
  +0x10 DAbrt → 0x304
  +0x18 IRQ   → 0x310
  +0x1C FIQ   → 0x328

Key targets:
1. Reset handler (0x13C) — SP initialization for all modes
2. SVC handler (0x298) — dispatches to FUN_000044CC, sets SP_svc
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
cs_arm.detail = True
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs_thumb.detail = True

def disasm_region(offset, size, mode="arm", label=""):
    print("\n" + "=" * 70)
    print("{} (0x{:04X}, {} mode, {} bytes)".format(label, offset, mode, size))
    print("=" * 70)
    cs = cs_arm if mode == "arm" else cs_thumb
    data = pspbl[offset:offset+size]
    for insn in cs.disasm(data, offset):
        ops = insn.op_str
        ann = ""
        mn = insn.mnemonic.lower()

        # Annotate SP operations
        if 'sp' in ops.lower():
            ann = "  *** SP ***"
        if mn in ['msr', 'mrs']:
            ann = "  *** MODE/STATUS ***"
        if mn.startswith('cps'):
            ann = "  *** PROCESSOR MODE ***"
        if mn in ['bx', 'blx']:
            ann = "  *** MODE SWITCH ***"
        if mn in ['srs', 'rfe']:
            ann = "  *** EXCEPTION RETURN ***"

        # Try to resolve literal pool loads
        if mn == 'ldr' and '[pc' in ops:
            try:
                for op in insn.operands:
                    if hasattr(op, 'mem') and op.mem.base == 15:  # PC-relative
                        if mode == "arm":
                            pc = insn.address + 8  # ARM: PC = insn + 8
                        else:
                            pc = (insn.address + 4) & ~3  # Thumb: align
                        pool_addr = pc + op.mem.disp
                        if 0 <= pool_addr < len(pspbl):
                            val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                            ann += "  ; [0x{:X}] = 0x{:08X}".format(pool_addr, val)
            except:
                pass

        print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))

# Disassemble ALL handler entry points in ARM mode
handlers = [
    (0x13C, 0x160, "arm", "RESET handler"),
    (0x298, 0x060, "arm", "SVC handler (THE critical one)"),
    (0x2F4, 0x010, "arm", "Undefined handler"),
    (0x2F8, 0x010, "arm", "Prefetch Abort handler"),
    (0x304, 0x010, "arm", "Data Abort handler"),
    (0x310, 0x020, "arm", "IRQ handler"),
    (0x328, 0x020, "arm", "FIQ handler"),
]

for offset, size, mode, label in handlers:
    disasm_region(offset, size, mode, label)

# Also check what's at the literal pool addresses referenced by the handlers
# The vector table loads from 0x20-0x38
print("\n" + "=" * 70)
print("VECTOR TABLE LITERAL POOL")
print("=" * 70)
vectors = ["Reset", "Undefined", "SVC", "Prefetch_Abort",
           "Data_Abort", "Reserved", "IRQ", "FIQ"]
for i in range(8):
    pool_off = 0x20 + i * 4
    if pool_off < len(pspbl) - 3:
        val = struct.unpack_from("<I", pspbl, pool_off)[0]
        print("  +0x{:02X} ({}): 0x{:08X}  bit0={} → {}".format(
            pool_off, vectors[i] if i < len(vectors) else "?",
            val, val & 1, "Thumb" if val & 1 else "ARM"))

# Now check: is the SVC handler at 0x298 ARM or does it switch to Thumb?
# Also check code at 0x298 + a few dozen bytes more
print("\n" + "=" * 70)
print("SVC HANDLER EXTENDED (0x298-0x340)")
print("=" * 70)
# It's ARM mode initially (loaded via LDR PC with even address)
# But might BX to Thumb
data = pspbl[0x298:0x340]
for insn in cs_arm.disasm(data, 0x298):
    ops = insn.op_str
    ann = ""
    mn = insn.mnemonic.lower()
    if 'sp' in ops.lower():
        ann = "  *** SP ***"
    if mn in ['bx', 'blx']:
        ann = "  *** THUMB SWITCH ***"
        # Try to find target
    if mn in ['msr', 'mrs']:
        ann = "  *** STATUS REG ***"
    if mn == 'ldr' and '[pc' in ops:
        try:
            for op in insn.operands:
                if hasattr(op, 'mem') and op.mem.base == 15:
                    pc = insn.address + 8
                    pool_addr = pc + op.mem.disp
                    if 0 <= pool_addr < len(pspbl):
                        val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                        ann += "  ; [0x{:X}] = 0x{:08X}".format(pool_addr, val)
        except:
            pass
    print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))

# Also check the RESET handler more extensively — it sets up ALL mode stacks
print("\n" + "=" * 70)
print("RESET HANDLER EXTENDED (0x13C-0x298)")
print("=" * 70)
# The reset handler is ~0x15C bytes (0x298 - 0x13C = 0x15C)
# But could be shorter, followed by other data
data = pspbl[0x13C:0x298]
for insn in cs_arm.disasm(data, 0x13C):
    ops = insn.op_str
    ann = ""
    mn = insn.mnemonic.lower()
    if 'sp' in ops.lower():
        ann = "  *** SP ***"
    if mn in ['msr', 'mrs']:
        ann = "  *** STATUS REG ***"
    if mn.startswith('cps'):
        ann = "  *** PROCESSOR MODE ***"
    if mn in ['bx', 'blx']:
        ann = "  *** MODE SWITCH ***"
        # Check if target is Thumb (odd address in register)
    if mn == 'ldr' and '[pc' in ops:
        try:
            for op in insn.operands:
                if hasattr(op, 'mem') and op.mem.base == 15:
                    pc = insn.address + 8
                    pool_addr = pc + op.mem.disp
                    if 0 <= pool_addr < len(pspbl):
                        val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                        ann += "  ; [0x{:X}] = 0x{:08X}".format(pool_addr, val)
        except:
            pass
    # Also resolve MOV with shifted immediate
    if mn == 'mov' and '#' in ops:
        try:
            imm_str = ops.split('#')[1].strip().split(',')[0].split('}')[0]
            imm = int(imm_str, 0)
            if 0x50000 <= imm <= 0x80000:
                ann += "  *** POSSIBLE STACK ADDR ***"
        except:
            pass
    print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))

# Literal pool values near the handlers
print("\n" + "=" * 70)
print("LITERAL POOLS NEAR HANDLERS (0x100-0x400)")
print("=" * 70)
for off in range(0x100, 0x400, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    # Show values that look like SRAM addresses or could be SP values
    if (0x40000 <= val <= 0x80000) or (0 < val < 0x9A00):
        print("  pool[0x{:04X}] = 0x{:08X}".format(off, val))

print("\nDone.")
