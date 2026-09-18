#!/usr/bin/env python3
"""Trace ABL4's post-SVC code path: what happens between SVC return and first +0x660 use?

ABL4 orchestrator sequence:
  0x6BCA4: bl 0x6B590  ; VTABLE INIT (+0x660 = 0x60FE9)
  0x6BCBA: blx 0x60870 ; memcpy thunk
  0x6BCC4: bl 0x62908  ; logging
  0x6BCCC: svc #0x1c   ; PSP_BL processes APCB  ← SVC ENTRY
  0x6BCD2: bl 0x6A0D0  ; error handler
  ...
  0x6BD5C: bl 0x6F364  ; "Sync 1st MP0 settings" (USES +0x660!) ← FIRST DISPATCH
  0x6BDB4: bl 0x6BB9C  ; FIRST TOKEN READ via +0x660

KEY QUESTION: Between SVC return (0x6BCCE) and first +0x660 use (0x6BD5C),
does ABL4 copy data from the config buffer at 0x4F000 into context+0x660?

If so: attacker controls APCB → PSP_BL puts APCB data in config buffer →
ABL4 copies to context → +0x660 overwritten with attacker value.
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

def abl4_offset(va):
    return va - ABL4_BASE

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# 1. Disassemble the post-SVC region: 0x6BCCE to 0x6BD60
print("=" * 70)
print("1. ABL4 disassembly: 0x6BCCE (after SVC) to 0x6BD70")
print("=" * 70)
start_va = 0x6BCCE
end_va = 0x6BD70
off_s = abl4_offset(start_va)
off_e = abl4_offset(end_va)
insns = list(cs.disasm(abl4[off_s:off_e], start_va))
bl_targets = []
for insn in insns:
    ann = ""
    if insn.mnemonic in ('bl', 'blx'):
        target = int(insn.op_str.lstrip('#'), 0) if insn.op_str.startswith('#') else int(insn.op_str, 0) if insn.op_str.startswith('0x') else 0
        bl_targets.append((insn.address, target))
        ann = "  *** CALL"
    elif insn.mnemonic == 'svc':
        ann = "  *** SVC"
    print("  0x{:05X}: {:10s} {}{}".format(insn.address, insn.mnemonic, insn.op_str, ann))

# 2. Identify all functions called between SVC and first +0x660 use
print("\n" + "=" * 70)
print("2. Functions called between SVC (0x6BCCC) and first +0x660 (0x6BD5C)")
print("=" * 70)
for addr, target in bl_targets:
    if addr > 0x6BCCC and addr < 0x6BD5C:
        print("  0x{:05X}: bl 0x{:05X}".format(addr, target))

# 3. Ghidra decompile of each called function
print("\n" + "=" * 70)
print("3. Ghidra decompilation of post-SVC functions")
print("=" * 70)

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

pyghidra.start(install_dir=GHIDRA_DIR)

with pyghidra.open_program(
    ABL4_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_abl4_v3", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # First: decompile the ORCHESTRATOR function that contains the SVC
    print("\n--- ORCHESTRATOR containing SVC at 0x6BCCC ---")
    orch_func = func_mgr.getFunctionContaining(space.getAddress(abl4_offset(0x6BCCC)))
    if orch_func:
        entry = orch_func.getEntryPoint().getOffset() + ABL4_BASE
        size = orch_func.getBody().getNumAddresses()
        print("  {} at VA 0x{:05X} ({} bytes)".format(orch_func.getName(), entry, size))
        result = decomp.decompileFunction(orch_func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars total".format(len(c)))
            # Show 6000 chars — enough to capture the SVC and post-SVC region
            print(c[:8000])
            if len(c) > 8000:
                print("  ... ({} more chars)".format(len(c) - 8000))
    else:
        print("  No function found at SVC site")

    # Decompile each post-SVC callee
    for addr, target in bl_targets:
        if addr > 0x6BCCC and addr < 0x6BD5C:
            file_off = abl4_offset(target)
            func = func_mgr.getFunctionAt(space.getAddress(file_off))
            if not func:
                func = func_mgr.getFunctionContaining(space.getAddress(file_off))
            if func:
                entry_va = func.getEntryPoint().getOffset() + ABL4_BASE
                size = func.getBody().getNumAddresses()
                print("\n" + "-" * 60)
                print("Called at 0x{:05X}: {} at VA 0x{:05X} ({} bytes)".format(
                    addr, func.getName(), entry_va, size))
                print("-" * 60)
                result = decomp.decompileFunction(func, 600, flat.getMonitor())
                if result.decompileCompleted():
                    c = result.getDecompiledFunction().getC()
                    print("  {} chars".format(len(c)))
                    # Look for references to 0x660, 0x4F000, config buffer, context
                    for kw in ['0x660', '0x4f000', '0x5d7ac', '0x5de0c', 'param_1']:
                        if kw.lower() in c.lower():
                            print("  *** CONTAINS '{}' ***".format(kw))
                    if len(c) <= 5000:
                        print(c)
                    else:
                        print(c[:5000])
                        print("  ... ({} more)".format(len(c) - 5000))
            else:
                print("\n  No function at file offset 0x{:X} (VA 0x{:05X})".format(file_off, target))

    # 4. Critical: decompile FUN_0006F364 — "Sync 1st MP0 settings" — first +0x660 user
    print("\n" + "=" * 70)
    print("4. FUN_0006F364 — first function to USE +0x660 dispatch")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(abl4_offset(0x6F364)))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(abl4_offset(0x6F364)))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 5000:
                print(c)
            else:
                print(c[:5000])

    # 5. Check ABL4 code between SVC and +0x660 for memcpy patterns
    # Specifically: does ABL4 copy from 0x4F000 region into context?
    print("\n" + "=" * 70)
    print("5. Searching ABL4 for references to 0x4F000 (config buffer)")
    print("=" * 70)
    # Scan literal pool for 0x4F000 in ABL4 binary
    refs_4f = []
    for off in range(0, len(abl4) - 3, 4):
        val = struct.unpack_from("<I", abl4, off)[0]
        if val == 0x4F000:
            refs_4f.append(off)
            print("  ABL4 +0x{:04X} (VA 0x{:05X}): 0x{:08X} (0x4F000!)".format(
                off, off + ABL4_BASE, val))
    if not refs_4f:
        print("  No literal pool references to 0x4F000 in ABL4")
        # Check nearby values
        for target in [0x4F000, 0x4F660, 0x4F600, 0x4EFF0, 0x50000]:
            found = False
            for off in range(0, len(abl4) - 3, 4):
                val = struct.unpack_from("<I", abl4, off)[0]
                if val == target:
                    if not found:
                        print("  0x{:05X}: found at ABL4 +0x{:04X} (VA 0x{:05X})".format(
                            target, off, off + ABL4_BASE))
                    found = True
            if not found:
                print("  0x{:05X}: NOT FOUND in ABL4 literal pools".format(target))

    # 6. Search for how context+0x660 is accessed in ABL4
    # We know FUN_0006f1d8 reads it: (**(code **)(param_1 + 0x660))(param_1, 1, ...)
    # But does anything WRITE to +0x660 after vtable init?
    print("\n" + "=" * 70)
    print("6. ABL4 instructions that access offset 0x660 from any register")
    print("=" * 70)
    # Look for LDR/STR with offset 0x660 in Thumb encoding
    # Thumb32: LDR.W Rt, [Rn, #0x660]  or  STR.W Rt, [Rn, #0x660]
    all_insns = list(cs.disasm(abl4, ABL4_BASE))
    for insn in all_insns:
        if '0x660' in insn.op_str:
            va = insn.address
            func = func_mgr.getFunctionContaining(space.getAddress(abl4_offset(va)))
            fname = func.getName() if func else "???"
            fva = (func.getEntryPoint().getOffset() + ABL4_BASE) if func else 0
            is_write = insn.mnemonic.startswith('str')
            tag = "WRITE" if is_write else "READ"
            print("  0x{:05X}: {:10s} {} [{}] (in {} @ 0x{:05X})".format(
                va, insn.mnemonic, insn.op_str, tag, fname, fva))

    # 7. Also check: does the orchestrator pass 0x4F000 as a parameter?
    # The SVC return goes back into ABL4 code. Does ABL4 then
    # read from the config buffer?
    print("\n" + "=" * 70)
    print("7. Searching ABL4 for 0x4F660 specifically (config+0x660)")
    print("=" * 70)
    for off in range(0, len(abl4) - 3, 4):
        val = struct.unpack_from("<I", abl4, off)[0]
        if val == 0x4F660:
            # Find code that references this LP entry
            for code_off in range(max(0, off - 1024), off, 2):
                hw = struct.unpack_from("<H", abl4, code_off)[0]
                if (hw & 0xF800) == 0x4800:
                    imm8 = hw & 0xFF
                    pc_val = ((code_off + 4) & ~3)
                    target = pc_val + imm8 * 4
                    if target == off:
                        va = code_off + ABL4_BASE
                        func = func_mgr.getFunctionContaining(space.getAddress(code_off))
                        fname = func.getName() if func else "???"
                        print("  VA 0x{:05X}: loads 0x4F660 (in {})".format(va, fname))
    print("  (search complete)")

    decomp.dispose()

print("\nDone.")
