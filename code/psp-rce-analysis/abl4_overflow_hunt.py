#!/usr/bin/env python3
"""Hunt for stack buffer overflow in ABL4 (88KB ARM code).

ABL4 runs AGESA code on PSP. It makes SVC calls to PSP_BL for APCB token operations.
If ABL4 reads an APCB token into a stack buffer and doesn't check the token size
against the buffer size, that's CVE-2025-29951.

Approach:
1. Decompile ALL functions with large stack frames (>= 256 bytes)
2. Look for SVC calls followed by copies to stack buffers
3. Search for APCB token type constants (0x60, 0x68, 0x73)
4. Find unbounded copy operations with APCB-controlled sizes
5. Also check the vector table at 0x100 in PSP_BL

First: verify the PSP_BL vector table at VBAR=0x100
"""
import os, struct, re
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()
with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

print("PSP_BL: {} bytes, ABL4: {} bytes".format(len(pspbl), len(abl4)))

# 0. PSP_BL vector table at VBAR=0x100
print("\n" + "=" * 70)
print("0. PSP_BL Vector Table at VBAR=0x100")
print("=" * 70)
cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
cs_arm.detail = True
# The vector table should have 8 entries (4 bytes each = 32 bytes)
vectors = ["Reset", "Undef", "SVC", "PAbort", "DAbort", "Reserved", "IRQ", "FIQ"]
for i in range(8):
    off = 0x100 + i * 4
    raw = struct.unpack_from("<I", pspbl, off)[0]
    insns = list(cs_arm.disasm(pspbl[off:off+4], off))
    if insns:
        insn = insns[0]
        # Check if it's LDR PC, [PC, #disp]
        ops = insn.op_str
        ann = ""
        if insn.mnemonic == 'ldr' and 'pc' in ops and '[pc' in ops:
            try:
                for op in insn.operands:
                    if hasattr(op, 'mem') and op.mem.base == 15:
                        pc = off + 8
                        pool_addr = pc + op.mem.disp
                        if 0 <= pool_addr < len(pspbl):
                            val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                            ann = " → [0x{:X}]=0x{:08X}".format(pool_addr, val)
            except:
                pass
        print("  +0x{:02X} {}: 0x{:08X} → {} {}{}".format(
            i*4, vectors[i], raw, insn.mnemonic, insn.op_str, ann))
    else:
        print("  +0x{:02X} {}: 0x{:08X} (decode failed)".format(i*4, vectors[i], raw))

# Also decode 0x100-0x140 as full ARM
print("\n  Full ARM decode 0x100-0x140:")
for insn in cs_arm.disasm(pspbl[0x100:0x140], 0x100):
    ops = insn.op_str
    ann = ""
    if insn.mnemonic == 'ldr' and '[pc' in ops:
        try:
            for op in insn.operands:
                if hasattr(op, 'mem') and op.mem.base == 15:
                    pc = insn.address + 8
                    pool_addr = pc + op.mem.disp
                    if 0 <= pool_addr < len(pspbl):
                        val = struct.unpack_from("<I", pspbl, pool_addr)[0]
                        ann = " ; [0x{:X}]=0x{:08X}".format(pool_addr, val)
        except:
            pass
    print("    0x{:04X}: {:8s} {}{}".format(insn.address, insn.mnemonic, ops, ann))

# 1. ABL4: Find all SVC instructions
print("\n" + "=" * 70)
print("1. ABL4: ALL SVC instructions")
print("=" * 70)
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs_thumb.detail = True

ABL4_BASE = 0x60834  # ABL4 load base in PSP SRAM
svc_locations = []
for insn in cs_thumb.disasm(abl4, ABL4_BASE):
    if insn.mnemonic.lower() == 'svc':
        svc_num = None
        for op in insn.operands:
            if op.type == 2:  # immediate
                svc_num = op.imm
        svc_locations.append((insn.address, svc_num))
        if len(svc_locations) <= 50:
            print("  0x{:05X}: SVC {}".format(insn.address,
                "0x{:02X}".format(svc_num) if svc_num is not None else "?"))

print("  Total SVC instructions: {}".format(len(svc_locations)))
# Count by SVC number
from collections import Counter
svc_counts = Counter(num for _, num in svc_locations if num is not None)
print("  SVC number distribution:")
for num, count in svc_counts.most_common(20):
    print("    SVC 0x{:02X}: {} calls".format(num, count))

# 2. ABL4: Find functions with large stack frames
print("\n" + "=" * 70)
print("2. ABL4: Functions with large stack frames (>= 128 bytes)")
print("=" * 70)

all_insns = list(cs_thumb.disasm(abl4, ABL4_BASE))
frames = []
for i, insn in enumerate(all_insns):
    if insn.mnemonic.lower() == 'push':
        func_addr = insn.address
        push_regs = len(insn.operands)
        sub_sp_total = 0
        for j in range(i+1, min(i+50, len(all_insns))):
            ninsn = all_insns[j]
            nmn = ninsn.mnemonic.lower()
            nops = ninsn.op_str.lower()
            if nmn == 'pop' or nmn == 'push':
                break
            if nmn in ['sub', 'sub.w', 'subw'] and nops.startswith('sp'):
                for op in ninsn.operands:
                    if op.type == 2:
                        sub_sp_total += op.imm
        total = push_regs * 4 + sub_sp_total
        if total >= 128:
            frames.append((func_addr, total, push_regs, sub_sp_total))

frames.sort(key=lambda x: -x[1])
print("  {} functions with frames >= 128 bytes".format(len(frames)))
for addr, total, pregs, sub in frames[:40]:
    # Check if this function contains SVC calls
    has_svc = any(s[0] > addr and s[0] < addr + 2000 for s in svc_locations)
    print("  0x{:05X}: {} bytes (push {} = {}, sub sp = {}){}".format(
        addr, total, pregs, pregs*4, sub, " [HAS SVC!]" if has_svc else ""))

# 3. ABL4: Search for APCB-related constants
print("\n" + "=" * 70)
print("3. ABL4: APCB token type constants and dispatch structures")
print("=" * 70)

# Search for common APCB-related values
for insn in all_insns:
    mn = insn.mnemonic.lower()
    ops = insn.op_str
    # Look for MOV/CMP with APCB token types
    if mn in ['movs', 'mov', 'movw', 'cmp'] and '#' in ops:
        for op in insn.operands:
            if op.type == 2 and op.imm in [0x60, 0x68, 0x73, 0x71, 0x72, 0xDE, 0xde, 222]:
                print("  0x{:05X}: {} {} ← APCB token type".format(
                    insn.address, insn.mnemonic, insn.op_str))

# 4. Check ABL4 for direct copy operations with variable sizes
print("\n" + "=" * 70)
print("4. ABL4: memcpy/copy function calls (BL targets)")
print("=" * 70)

bl_targets = Counter()
for insn in all_insns:
    if insn.mnemonic.lower() in ['bl', 'blx']:
        for op in insn.operands:
            if op.type == 2:
                bl_targets[op.imm & 0xFFFFFFFF] += 1

print("  Top 20 call targets:")
for target, count in bl_targets.most_common(20):
    print("    0x{:05X}: {} calls".format(target, count))

print("\nDone.")
