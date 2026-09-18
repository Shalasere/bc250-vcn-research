#!/usr/bin/env python3
"""Disassemble PSP_BL functions that reference the context structure at 0x5D7AC.

The vulnerability is in PSP_BL, not ABL4. PSP_BL sets up the context structure
before ABL4 loads. The uninitialized `saved_len` bug causes PSP_BL to write
too much APCB data into the context structure, overflowing into the vtable
at +0x660.

PSP_BL load base is unknown — try 0x0 first (interrupt vectors at start).
The literal pool at +0x0BB8 has 0x5D7AC (context base).

We need to find:
1. Functions that load 0x5D7AC from the literal pool
2. Functions that write to context+0x500..+0x700 area
3. Functions with variable-length memory copy operations
4. The specific uninitialized length variable
"""
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

print("PSP_BL: {} bytes (0x{:X})".format(len(pspbl), len(pspbl)))

# Determine the load base from the vector table
# ARM vectors: LDR PC, [PC, #offset] instructions
print("\n=== Interrupt vector table ===")
for i in range(8):
    val = struct.unpack_from("<I", pspbl, i * 4)[0]
    insn_word = val
    # Check if it's LDR PC, [PC, #offset] = 0xE59FF000 + offset
    if (insn_word & 0xFFFFF000) == 0xE59FF000:
        ldr_offset = insn_word & 0xFFF
        # LDR target address = PC + 8 + offset (ARM pipeline)
        target_file_offset = i * 4 + 8 + ldr_offset
        if target_file_offset + 4 <= len(pspbl):
            target = struct.unpack_from("<I", pspbl, target_file_offset)[0]
            print("  [{:d}] 0x{:08X} -> LDR PC, [PC, #0x{:X}] -> target at +0x{:X} = 0x{:08X}".format(
                i, val, ldr_offset, target_file_offset, target))
        else:
            print("  [{:d}] 0x{:08X} -> LDR PC, [PC, #0x{:X}] -> target_offset 0x{:X} (out of range)".format(
                i, val, ldr_offset, target_file_offset))
    else:
        print("  [{:d}] 0x{:08X}".format(i, val))

# Load base analysis: the reset vector handler at +0x20 = 0x13C
# If load base = 0, then entry = 0x13C
# If load base = 0x100, then entry at file 0x3C
# The vectors being small values suggests load base = 0
LOAD_BASE = 0  # Try 0 first

# Find all PUSH prologues (Thumb mode, which is what PSP BL uses for most code)
print("\n=== Finding function prologues ===")
push_addrs = []
for off in range(0x100, len(pspbl) - 1, 2):  # Skip vector table
    # Narrow PUSH {rX, LR}
    if pspbl[off + 1] == 0xB5:
        push_addrs.append(off)
    # Wide PUSH.W {rlist, LR}
    elif off + 3 < len(pspbl) and pspbl[off] == 0x2D and pspbl[off+1] == 0xE9:
        mask = struct.unpack_from("<H", pspbl, off + 2)[0]
        if mask & 0x4000:  # LR saved
            push_addrs.append(off)

print("  {} function prologues found".format(len(push_addrs)))

# Find ALL literal pool entries that point to context structure area
print("\n=== Literal pool entries pointing to context area (0x5D000-0x5F000) ===")
context_pool_refs = []
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if 0x5D000 <= val <= 0x5F000:
        context_pool_refs.append((off, val))
        diff_from_ctx = val - 0x5D7AC
        if abs(diff_from_ctx) < 0x1000:
            print("  +0x{:04X}: 0x{:08X}  (context {:+d} = {:+#x})".format(
                off, val, diff_from_ctx, diff_from_ctx))
        else:
            print("  +0x{:04X}: 0x{:08X}".format(off, val))

# Now disassemble each function and find those that load context-area pointers
print("\n=== Functions referencing context structure ===")
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs_thumb.detail = True

context_funcs = {}  # func_offset -> [(insn_offset, loaded_value, context)]

for func_off in push_addrs:
    end = min(func_off + 4000, len(pspbl))
    code = pspbl[func_off:end]

    insns = list(cs_thumb.disasm(code, LOAD_BASE + func_off, 1000))

    # Track which registers hold context-area pointers
    reg_context = {}  # reg_name -> context_area_value

    for i, insn in enumerate(insns):
        mn = insn.mnemonic.lower()

        # LDR Rd, [PC, #imm] — literal pool load
        if mn == 'ldr' and len(insn.operands) == 2:
            op0, op1 = insn.operands[0], insn.operands[1]
            if op1.type == 4:  # ARM_OP_MEM
                if op1.mem.base == 15:  # PC-relative
                    # Calculate literal pool address
                    pc = insn.address + 4  # Thumb pipeline
                    pc = pc & ~3  # Align
                    pool_offset = pc + op1.mem.disp - LOAD_BASE
                    if 0 <= pool_offset < len(pspbl) - 3:
                        pool_val = struct.unpack_from("<I", pspbl, pool_offset)[0]
                        if 0x5D000 <= pool_val <= 0x5F000:
                            reg_name = insn.reg_name(op0.reg)
                            reg_context[reg_name] = pool_val
                            if func_off not in context_funcs:
                                context_funcs[func_off] = []
                            context_funcs[func_off].append((
                                insn.address - LOAD_BASE,
                                pool_val,
                                "{} {} -> {}=0x{:X}".format(mn, insn.op_str, reg_name, pool_val)
                            ))

        # STR Rd, [Rn, #imm] — store through context pointer
        elif mn.startswith('str') and len(insn.operands) == 2:
            op0, op1 = insn.operands[0], insn.operands[1]
            if op1.type == 4:  # ARM_OP_MEM
                base_reg = insn.reg_name(op1.mem.base)
                if base_reg in reg_context:
                    target_addr = reg_context[base_reg] + op1.mem.disp
                    if func_off not in context_funcs:
                        context_funcs[func_off] = []
                    context_funcs[func_off].append((
                        insn.address - LOAD_BASE,
                        target_addr,
                        "STORE {} [{}+0x{:X}] -> 0x{:X} (ctx+0x{:X})".format(
                            insn.reg_name(op0.reg), base_reg, op1.mem.disp,
                            target_addr, target_addr - 0x5D7AC)
                    ))

        # LDR Rd, [Rn, #imm] — load through context pointer
        elif mn.startswith('ldr') and len(insn.operands) == 2:
            op0, op1 = insn.operands[0], insn.operands[1]
            if op1.type == 4:  # ARM_OP_MEM
                base_reg = insn.reg_name(op1.mem.base)
                if base_reg in reg_context and base_reg != 'pc':
                    target_addr = reg_context[base_reg] + op1.mem.disp
                    if func_off not in context_funcs:
                        context_funcs[func_off] = []
                    context_funcs[func_off].append((
                        insn.address - LOAD_BASE,
                        target_addr,
                        "LOAD {} [{}+0x{:X}] <- 0x{:X} (ctx+0x{:X})".format(
                            insn.reg_name(op0.reg), base_reg, op1.mem.disp,
                            target_addr, target_addr - 0x5D7AC)
                    ))

        # Stop at POP {PC} or BX LR
        if mn in ("pop", "bx") and "pc" in insn.op_str.lower():
            break

for func_off in sorted(context_funcs.keys()):
    entries = context_funcs[func_off]
    stores = [e for e in entries if 'STORE' in e[2]]
    loads = [e for e in entries if 'LOAD' in e[2]]
    pool_loads = [e for e in entries if 'STORE' not in e[2] and 'LOAD' not in e[2]]

    # Check if any store targets the critical zone (+0x500 to +0x700)
    critical_stores = [e for e in stores if 0x5D7AC + 0x500 <= e[1] <= 0x5D7AC + 0x700]

    marker = " *** CRITICAL ZONE ***" if critical_stores else ""
    print("\n  func +0x{:04X}: {} pool loads, {} stores, {} loads{}".format(
        func_off, len(pool_loads), len(stores), len(loads), marker))

    for off, val, desc in entries:
        critical = " <<<" if ('STORE' in desc and 0x5D7AC + 0x500 <= val <= 0x5D7AC + 0x700) else ""
        print("    +0x{:04X}: {}{}".format(off, desc, critical))

# Full disassembly of functions that STORE to the critical zone
print("\n" + "=" * 70)
print("=== Full disassembly of functions that store to context+0x500..+0x700 ===")

for func_off in sorted(context_funcs.keys()):
    entries = context_funcs[func_off]
    critical_stores = [e for e in entries if 'STORE' in e[2] and
                       0x5D7AC + 0x500 <= e[1] <= 0x5D7AC + 0x700]
    if not critical_stores:
        continue

    print("\n  --- func +0x{:04X} (critical stores: {}) ---".format(
        func_off, len(critical_stores)))

    end = min(func_off + 2000, len(pspbl))
    code = pspbl[func_off:end]
    for insn in cs_thumb.disasm(code, LOAD_BASE + func_off, 500):
        print("    0x{:04X}: {:6s} {}".format(
            insn.address - LOAD_BASE, insn.mnemonic, insn.op_str))
        if insn.mnemonic.lower() in ("pop", "bx") and "pc" in insn.op_str.lower():
            break

# Also look for memcpy-like patterns (loop with LDR/STR through incrementing register)
print("\n" + "=" * 70)
print("=== Looking for memcpy/copy loops near context structure references ===")

for func_off in sorted(context_funcs.keys()):
    end = min(func_off + 2000, len(pspbl))
    code = pspbl[func_off:end]

    has_copy_loop = False
    insns = list(cs_thumb.disasm(code, LOAD_BASE + func_off, 500))

    for i, insn in enumerate(insns):
        mn = insn.mnemonic.lower()
        # Look for: LDRB Rd, [Rs, Ri] / STRB Rd, [Rs, Ri] pairs (byte copy loops)
        # or LDR/STR with post-increment
        if mn in ('ldrb', 'ldr') and i + 1 < len(insns):
            next_mn = insns[i+1].mnemonic.lower()
            if next_mn in ('strb', 'str'):
                # Check if both use the same offset register
                has_copy_loop = True

        # Also look for: BNE/BLT/BCC backward branches (loop back edges)
        if mn in ('bne', 'blt', 'bcc', 'bne.n', 'blt.n', 'bcc.n', 'b.n', 'bne.w'):
            if len(insn.operands) > 0 and insn.operands[0].type == 2:  # IMM
                target = insn.operands[0].imm
                if target < insn.address:  # backward branch = loop
                    has_copy_loop = True

        if insn.mnemonic.lower() in ("pop", "bx") and "pc" in insn.op_str.lower():
            break

    if has_copy_loop:
        entries = context_funcs[func_off]
        print("\n  func +0x{:04X}: has copy loop/backward branch".format(func_off))
        for off, val, desc in entries[:10]:
            print("    {}".format(desc))

print("\nDone.")
