#!/usr/bin/env python3
"""Resolve SP_abt from PSP_BL initialization.

Found: at 0x00C0: msr cpsr_c, #0xD7 (ABT mode), then 0x00C4: mov sp, r0.
Need to trace R0 value from the init code at 0x3C-0x13C.
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

cs = Cs(CS_ARCH_ARM, CS_MODE_ARM)
cs.detail = True

# Full ARM disassembly from 0x3C to 0x13C (the init code)
print("=" * 70)
print("FULL INIT CODE (ARM mode, 0x3C-0x13C)")
print("=" * 70)
for insn in cs.disasm(pspbl[0x3C:0x13C], 0x3C):
    ops = insn.op_str
    ann = ""
    mn = insn.mnemonic.lower()

    # Resolve LDR PC-relative loads
    if mn == 'ldr' and '[pc' in ops:
        try:
            for op in insn.operands:
                if hasattr(op, 'mem') and op.mem.base == 15:
                    pc = insn.address + 8
                    pool_addr = pc + op.mem.disp
                    if 0 <= pool_addr < len(pspbl):
                        val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                        ann = "  ; [0x{:X}]=0x{:08X}".format(pool_addr, val)
        except:
            pass

    # Annotate mode switches
    if mn == 'msr' and 'cpsr' in ops.lower():
        parts = ops.split('#')
        if len(parts) >= 2:
            try:
                imm = int(parts[1].strip(), 0)
                mode = imm & 0x1F
                modes = {0x10:'USR', 0x11:'FIQ', 0x12:'IRQ', 0x13:'SVC',
                         0x17:'ABT', 0x1B:'UND', 0x1F:'SYS'}
                ann = "  ← {} mode (I={} F={})".format(
                    modes.get(mode, "0x{:02X}".format(mode)),
                    (imm >> 7) & 1, (imm >> 6) & 1)
            except:
                pass

    # Annotate SP operations
    if ('sp' in ops.lower() and mn not in ['push', 'pop']) or mn == 'msr':
        ann_prefix = " ***" if 'sp' in ops.lower() else ""
        ann = ann_prefix + ann

    print("  0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))

# Also dump specific literal pool values referenced by the init code
print("\n" + "=" * 70)
print("KEY LITERAL POOL VALUES")
print("=" * 70)
for lp_off in [0x98, 0x9C, 0xA0, 0xA4, 0xA8, 0x100, 0x104, 0x108,
               0x10C, 0x110, 0x114, 0x118, 0x11C, 0x120, 0x124, 0x128,
               0x12C, 0x130, 0x134, 0x138]:
    if lp_off < len(pspbl) - 3:
        val = struct.unpack_from("<I", pspbl, lp_off)[0]
        print("  pool[0x{:04X}] = 0x{:08X}".format(lp_off, val))

# Read specific values needed
print("\n" + "=" * 70)
print("CRITICAL LITERAL POOL VALUES")
print("=" * 70)
# Also read the 0x384-0x3C4 region which has init-related values
for lp_off in range(0x384, 0x3C8, 4):
    val = struct.unpack_from("<I", pspbl, lp_off)[0]
    print("  pool[0x{:04X}] = 0x{:08X}".format(lp_off, val))

# And check 0x3A8 specifically (referenced by init code at 0x348)
val_3a8 = struct.unpack_from("<I", pspbl, 0x3A8)[0]
print("\n  *** pool[0x03A8] = 0x{:08X} ***".format(val_3a8))

print("\nDone.")
