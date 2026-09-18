#!/usr/bin/env python3
"""Resolve the PSP address model and determine overflow target feasibility.

Critical questions:
1. What are the literal pool values at 0x800C-0x8024? (FUN_00007FA4 parameters)
2. What is *(0x9A24) initialized to? (the APCB offset mask)
3. Where is the PSP stack? Can stack growth reach context at 0x5D7AC?
4. Is there a path from DRAM corruption to SRAM context corruption?
5. Where does the 0x4F000 buffer sit relative to context?

Key insight: FUN_00003650's return is an SMN window address (0x24000000+),
NOT SRAM. DMA in FUN_000071AC targets DRAM, not PSP SRAM.
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# 1. Read ALL literal pool values in FUN_00007FA4 range
print("=" * 70)
print("1. FUN_00007FA4 literal pool values (memory mode parameters)")
print("=" * 70)
for off in range(0x8000, 0x8024, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    neg = (0x100000000 - val) & 0xFFFFFFFF
    names = {
        0x8004: "DAT_00008004 -> ptr to *(0x9A18)",
        0x8008: "DAT_00008008 -> ptr to *(0x9A20)",
        0x800C: "DAT_0000800C -> mode 0x13 value (iVar6)",
        0x8010: "DAT_00008010 -> mode 0x14 value (iVar2)",
        0x8014: "DAT_00008014 -> mode 0x15 value (iVar3)",
        0x8018: "DAT_00008018 -> mode 0x16 value (iVar4)",
        0x801C: "DAT_0000801C -> mode 0x17 value (iVar5) *** APCB MODE ***",
        0x8020: "DAT_00008020 -> ?"
    }
    desc = names.get(off, "")
    print("  +0x{:04X} = 0x{:08X} (signed={:11d}, neg=0x{:08X})  {}".format(
        off, val, struct.unpack('<i', struct.pack('<I', val))[0], neg, desc))

# For mode 0x17 (APCB):
val_801c = struct.unpack_from("<I", pspbl, 0x801C)[0]
neg_801c = (0x100000000 - val_801c) & 0xFFFFFFFF
print("\n  MODE 0x17 (APCB loading):")
print("    *(0x9A18) = 0x{:08X}  (DRAM base / SMN mapping source)".format(val_801c))
print("    *(0x9A20) = 0x{:08X}  (bounds check value = -DAT_0000801c)".format(neg_801c))
print("    FUN_00003650 input: param_1 = 0x{:08X}".format(val_801c))
print("    FUN_00003650 return: (0x{:08X} & 0x3FFFFFF) + slot*0x4000000 + 0x4000000".format(val_801c))
base_26 = val_801c & 0x3FFFFFF
print("    = 0x{:08X} + slot*0x4000000 + 0x4000000".format(base_26))
for slot in [8, 9, 10]:
    ret = base_26 + slot * 0x4000000 + 0x4000000
    print("    slot {}: *(0x9A10) = 0x{:08X}".format(slot, ret))

# 2. Check *(0x9A24) initialization
print("\n" + "=" * 70)
print("2. *(0x9A24) initialization — the APCB offset mask")
print("=" * 70)
# Find ALL literal pool entries pointing to 0x9A24
refs_9a24 = []
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if val == 0x9A24:
        refs_9a24.append(off)
        print("  LP at +0x{:04X} → 0x9A24".format(off))

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# For each ref, find STR patterns that WRITE to *(0x9A24)
print("\n  Looking for writes to *(0x9A24):")
for lp_off in refs_9a24:
    for code_off in range(max(0, lp_off - 1024), lp_off, 2):
        hw = struct.unpack_from("<H", pspbl, code_off)[0]
        if (hw & 0xF800) == 0x4800:
            rt = (hw >> 8) & 7
            imm8 = hw & 0xFF
            pc_val = ((code_off + 4) & ~3)
            target = pc_val + imm8 * 4
            if target == lp_off:
                # Search forward for STR [rt]
                search_end = min(len(pspbl), code_off + 80)
                insns = list(cs.disasm(pspbl[code_off:search_end], code_off))
                for insn in insns:
                    if insn.mnemonic.startswith('str') and '[r{}'.format(rt) in insn.op_str:
                        print("  WRITE at 0x{:04X}: {} {} (via LP+0x{:04X})".format(
                            insn.address, insn.mnemonic, insn.op_str, lp_off))
                    if insn.mnemonic in ['bl', 'blx', 'bx', 'pop', 'b.w']:
                        break

# Also check: is 0x9A24 EVER the target of FUN_00007FA4?
# FUN_00007FA4 writes to *(0x9A18) and *(0x9A20), but NOT 0x9A24
print("\n  FUN_00007FA4 writes to *(0x9A18) and *(0x9A20) ONLY, not *(0x9A24)")

# 3. Check who writes to 0x9A24 — is there an initialization path?
print("\n" + "=" * 70)
print("3. ALL writes to SRAM 0x9A20-0x9A30 (what initializes this region?)")
print("=" * 70)
for target in range(0x9A20, 0x9A30, 4):
    refs = []
    for off in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        if val == target:
            refs.append(off)
    if refs:
        print("  0x{:04X}: {} LP ref(s) at {}".format(
            target, len(refs), ", ".join("+0x{:04X}".format(r) for r in refs)))
    else:
        print("  0x{:04X}: NO literal pool references!".format(target))

# 4. PSP memory map analysis
print("\n" + "=" * 70)
print("4. PSP SRAM memory map (known addresses)")
print("=" * 70)
known = {
    0x00000: "PSP_BL code start (load base)",
    0x099C0: "PSP_BL code end (39,360 bytes)",
    0x09A00: "Runtime data area start",
    0x09A10: "DMA base pointer *(0x9A10)",
    0x09A18: "DRAM base *(0x9A18)",
    0x09A20: "Bounds check *(0x9A20)",
    0x09A24: "Offset mask *(0x9A24)",
    0x09C60: "Runtime data area ~end",
    0x4F000: "Config buffer (FUN_000075A4 writes here)",
    0x50000: "Config buffer end",
    0x5D7AC: "ABL4 context structure",
    0x5DE0C: "context + 0x660 (vtable dispatch target)",
}
for addr in sorted(known.keys()):
    print("  0x{:05X}  {}".format(addr, known[addr]))

print("\n  Gaps:")
print("  0x0-0x99C0: PSP_BL code (39,360 bytes)")
print("  0x99C0-0x4F000: ~280KB gap (stack? heap? other code?)")
print("  0x4F000-0x50000: Config buffer (4KB)")
print("  0x50000-0x5D7AC: ~55KB gap")
print("  0x5D7AC-0x5DE0C+: Context structure (at least 0x670 bytes)")

# 5. Stack pointer analysis
print("\n" + "=" * 70)
print("5. Stack pointer initialization")
print("=" * 70)
# The PSP initializes SP at reset. Look for MSR/MOV SP patterns at the start
# of PSP_BL or in the vector table
print("  PSP_BL vector table (first 64 bytes):")
for off in range(0, 64, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if off == 0:
        print("  +0x{:04X}: 0x{:08X}  (Initial SP)".format(off, val))
    elif off == 4:
        print("  +0x{:04X}: 0x{:08X}  (Reset vector)".format(off, val))
    else:
        names = {8: "NMI", 12: "HardFault", 16: "MemManage", 20: "BusFault",
                 24: "UsageFault", 28: "Reserved", 44: "SVC", 48: "DebugMon",
                 56: "PendSV", 60: "SysTick"}
        n = names.get(off, "IRQ")
        print("  +0x{:04X}: 0x{:08X}  ({})".format(off, val, n))

initial_sp = struct.unpack_from("<I", pspbl, 0)[0]
print("\n  Initial SP = 0x{:08X}".format(initial_sp))
if initial_sp < 0x100000:
    print("  Stack in PSP SRAM! Stack grows DOWN from 0x{:05X}".format(initial_sp))
    if 0x5D7AC < initial_sp:
        distance = initial_sp - 0x5DE0C
        print("  Distance from stack base to context+0x660: {} bytes (0x{:X})".format(
            distance, distance))
        print("  Stack frames needed to reach context+0x660: stack must grow {} bytes".format(
            distance))
else:
    print("  Stack NOT in low SRAM — possibly in mapped memory")

# 6. Check if the SVC handler runs on a different stack
print("\n" + "=" * 70)
print("6. SVC handler stack check")
print("=" * 70)
# SVC vector is at offset 0x2C in ARM's vector table
svc_vector = struct.unpack_from("<I", pspbl, 0x2C)[0]
print("  SVC vector: 0x{:08X}".format(svc_vector))
# Check for MSP/PSP switch in the handler
# The SVC handler (FUN_000044CC) uses the caller's stack
# In ARM Cortex-M, SVC uses the caller's stack by default

# 7. Key question: where does FUN_000066A0 store its results?
print("\n" + "=" * 70)
print("7. FUN_000066A0 output destinations (where does APCB data go?)")
print("=" * 70)

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

pyghidra.start(install_dir=GHIDRA_DIR)

with pyghidra.open_program(
    PSPBL_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_pspbl_v1", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # Check FUN_00008150 — called from FUN_000074C8, also processes APCB data
    print("\n  FUN_00008150 — APCB data validation/load:")
    func = func_mgr.getFunctionAt(space.getAddress(0x8150))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:3000])

    # Check FUN_00005758 — APCB token processing
    print("\n" + "-" * 60)
    print("  FUN_00005758 — APCB token processing:")
    func = func_mgr.getFunctionAt(space.getAddress(0x5758))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:3000])

    # Check FUN_000082E6 — called at end of FUN_00000300 for APCB processing
    print("\n" + "-" * 60)
    print("  FUN_000082E6 — APCB finalization:")
    func = func_mgr.getFunctionAt(space.getAddress(0x82E6))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x82E6))
    if func:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} at 0x{:04X}, {} chars".format(func.getName(), entry, len(c)))
            print(c[:3000])
    else:
        print("  No function at/near 0x82E6")

    # Check FUN_0000571A — called from FUN_00002C80 (processes APCB tokens)
    print("\n" + "-" * 60)
    print("  FUN_0000571A — APCB token extractor:")
    func = func_mgr.getFunctionAt(space.getAddress(0x571A))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x571A))
    if func:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} at 0x{:04X}, {} chars".format(func.getName(), entry, len(c)))
            if len(c) <= 4000:
                print(c)
            else:
                print(c[:4000])
                print("  ... ({} more)".format(len(c) - 4000))

    # Check DAT_00000bec — used in FUN_00000300's call to FUN_0000823C
    val_bec = struct.unpack_from("<I", pspbl, 0xBEC)[0]
    print("\n" + "-" * 60)
    print("  DAT_00000BEC = 0x{:08X} (destination for APCB header copy in FUN_00000300)".format(val_bec))
    if val_bec < 0x100000:
        print("  -> PSP SRAM address! Header copy goes to SRAM 0x{:05X}".format(val_bec))

    # Also check DAT_00000BB4 and DAT_00000BB8 — used in FUN_00000300
    val_bb4 = struct.unpack_from("<I", pspbl, 0xBB4)[0]
    val_bb8 = struct.unpack_from("<I", pspbl, 0xBB8)[0]
    print("  DAT_00000BB4 = 0x{:08X}".format(val_bb4))
    print("  DAT_00000BB8 = 0x{:08X}".format(val_bb8))

    # Check literal pool entries in FUN_00000300's range for SRAM targets
    print("\n  Literal pool entries in FUN_00000300 (0x300-0xC00):")
    for off in range(0xB80, 0xC00, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        if 0x10000 < val < 0x100000:
            print("    +0x{:04X}: 0x{:08X} (SRAM)".format(off, val))

    decomp.dispose()

print("\nDone.")
