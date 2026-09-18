#!/usr/bin/env python3
"""PSP_BL: Find the SVC stack location and the actual CVE-2025-29951 overflow.

Vector A is dead: ABL4 has no references to 0x4F000 (config buffer).
Vector B (stack overflow near context) and Vector C (PSP_BL RCE) remain.

Investigation plan:
1. Parse the ARM reset handler at 0x13C to find SP initialization for each
   CPU mode (SVC, IRQ, FIQ, ABT, UND, SYS). Cortex-A5 uses CPS/MSR to
   switch modes and set banked SP.
2. If SVC stack is near 0x5D7AC, a stack overflow during APCB processing
   could corrupt context+0x660.
3. Search for the ACTUAL stack overflow: look for functions that copy
   attacker-controlled data to stack buffers without adequate size checks.

Key CVE-2025-29951 description: "PSP BL stack buffer overflow"
This implies a STACK buffer (local variable) overflow, not a heap or
global buffer overflow. The attack requires a function that:
  a) Allocates a fixed-size stack buffer
  b) Copies APCB data into it with an attacker-controlled size
  c) The overflow overwrites the function's return address or saved registers
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_ARM
cs_arm = Cs(CS_ARCH_ARM, CS_MODE_ARM)
cs_arm.detail = True
cs_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs_thumb.detail = True

# 1. Parse the ARM reset handler at 0x13C for SP initialization
print("=" * 70)
print("1. ARM Reset Handler at 0x13C — Stack Pointer Initialization")
print("=" * 70)

# Disassemble from 0x13C in ARM mode (Cortex-A5 reset handler)
reset_code = pspbl[0x13C:0x298]
insns = list(cs_arm.disasm(reset_code, 0x13C))

print("  Full reset handler disassembly:")
for insn in insns:
    ann = ""
    if 'sp' in insn.op_str.lower():
        ann = "  *** SP SETUP"
    elif 'cpsr' in insn.op_str.lower() or 'spsr' in insn.op_str.lower():
        ann = "  *** MODE SWITCH"
    elif insn.mnemonic.startswith('cps'):
        ann = "  *** MODE SWITCH"
    elif insn.mnemonic.startswith('msr'):
        ann = "  *** MODE/FLAG CHANGE"
    elif insn.mnemonic.startswith('mcr') or insn.mnemonic.startswith('mrc'):
        ann = "  (coprocessor)"
    print("  0x{:04X}: {:10s} {}{}".format(insn.address, insn.mnemonic, insn.op_str, ann))

# 2. Look for literal pool entries near the reset handler that could be SP values
print("\n" + "=" * 70)
print("2. Literal pool entries near reset handler (potential SP values)")
print("=" * 70)
# Check 0x160-0x298 for 32-bit values that look like SRAM addresses
for off in range(0x130, 0x2A0, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    # SRAM addresses are in range 0x10000-0x80000
    if 0x10000 <= val <= 0x80000:
        print("  +0x{:04X}: 0x{:08X} (SRAM — potential SP!)".format(off, val))
        if 0x5D000 <= val <= 0x60000:
            print("    *** NEAR CONTEXT at 0x5D7AC! ***")

# 3. Also check exception handler setup code for SP values
print("\n" + "=" * 70)
print("3. Exception handler code at 0x298 (SVC handler)")
print("=" * 70)
svc_code = pspbl[0x298:0x340]
insns = list(cs_arm.disasm(svc_code, 0x298))
for insn in insns:
    ann = ""
    if 'sp' in insn.op_str.lower():
        ann = "  *** SP ACCESS"
    print("  0x{:04X}: {:10s} {}{}".format(insn.address, insn.mnemonic, insn.op_str, ann))

# 4. CRITICAL: Look for the actual stack buffer overflow
# Strategy: find functions that:
#   a) Have large stack frames (SUB SP, SP, #size)
#   b) Call FUN_00000458 (memcpy) or FUN_00001C18 (DMA copy) with stack buffers
#   c) Use APCB-derived sizes
print("\n" + "=" * 70)
print("4. STACK OVERFLOW HUNT — functions with stack buffer + memcpy pattern")
print("=" * 70)

# First: find all functions with stack frames > 0x80 bytes
print("  Functions with stack frames > 0x80 bytes:")
# SUB SP patterns:
# Thumb16: SUB SP, SP, #imm7*4: 0xB080 | (imm7)
# Thumb32: SUB.W SP, SP, #imm12: varies

stack_frames = []
for off in range(0, len(pspbl) - 1, 2):
    hw = struct.unpack_from("<H", pspbl, off)[0]
    # Thumb16 SUB SP, #imm7*4
    if (hw & 0xFF80) == 0xB080:
        imm7 = hw & 0x7F
        frame_size = imm7 * 4
        if frame_size > 0x80:
            stack_frames.append((off, frame_size, "T16"))
    # Thumb32 SUB.W SP, SP, #const or SUBW SP, SP, #imm12
    if off < len(pspbl) - 3:
        hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]
        # T32 SUB SP: F1AD 0D** or F2AD 0D**
        if (hw & 0xFBEF) == 0xF1AD and (hw2 & 0x8F00) == 0x0D00:
            # Modified immediate: ThumbExpandImm
            i = (hw >> 10) & 1
            imm3 = (hw2 >> 12) & 7
            imm8 = hw2 & 0xFF
            imm12 = (i << 11) | (imm3 << 8) | imm8
            # Simplified: for small values, imm12 = actual value
            if imm12 < 256:
                frame_size = imm12
            else:
                # Need full ThumbExpandImm decode
                rot = imm12 >> 7
                val = imm12 & 0x7F
                if rot == 0:
                    frame_size = imm12
                else:
                    frame_size = imm12  # Simplified
            if frame_size > 0x80:
                stack_frames.append((off, frame_size, "T32_MOD"))
        # SUBW SP, SP, #imm12: F2AD 0Dxx (W-form, 12-bit imm)
        if (hw & 0xFBFF) == 0xF2AD and (hw2 & 0x8F00) == 0x0D00:
            i = (hw >> 10) & 1
            imm3 = (hw2 >> 12) & 7
            imm8 = hw2 & 0xFF
            imm12 = (i << 11) | (imm3 << 8) | imm8
            if imm12 > 0x80:
                stack_frames.append((off, imm12, "T32_W"))

for off, size, enc in sorted(stack_frames):
    # Is this near a function start? (within 20 bytes of a PUSH)
    is_func_prolog = False
    for check in range(max(0, off - 20), off, 2):
        hw = struct.unpack_from("<H", pspbl, check)[0]
        if (hw & 0xFE00) == 0xB400:  # PUSH
            is_func_prolog = True
            break
        if check < len(pspbl) - 3:
            hw2 = struct.unpack_from("<H", pspbl, check + 2)[0]
            if (hw & 0xFFFF) == 0xE92D:  # PUSH.W
                is_func_prolog = True
                break
    if is_func_prolog:
        print("  +0x{:04X}: frame = 0x{:X} ({}) bytes [{}]".format(off, size, size, enc))

# 5. Decompile LARGE-FRAME functions in the APCB processing chain
print("\n" + "=" * 70)
print("5. Ghidra: decompile APCB functions with large stack frames")
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

    # Key functions in the APCB processing chain that haven't been
    # fully examined for stack overflows:
    #
    # FUN_00000300 — main SVC handler, calls FUN_00008168 (init),
    #                FUN_000066A0 (2x), FUN_000035A0 (cache)
    # FUN_00007014 — APCB token processing (called by FUN_000066A0)
    # FUN_000037FC — APCB group search (called by FUN_00002C80)
    # FUN_00001F40 — alternative copy path (called by FUN_000062BE)
    # FUN_000062BE — called by FUN_000071AC when param_5 != 0
    # FUN_000018E4 — S3 resume path
    # FUN_000053C4 — token handler (called by FUN_00007014)

    targets = [
        0x300,    # Main SVC handler
        0x37FC,   # APCB group search
        0x7014,   # APCB token processing
        0x1F40,   # Alternative copy path
        0x62BE,   # Secondary copy in FUN_000071AC
        0x18E4,   # S3 resume
        0x53C4,   # Token handler
        0x44CC,   # SVC dispatcher
    ]

    for addr in targets:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if func:
            entry = func.getEntryPoint().getOffset()
            size = func.getBody().getNumAddresses()
            print("\n" + "-" * 60)
            print("{} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
            print("-" * 60)
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                print("  {} chars".format(len(c)))
                # Check for stack buffers and copy patterns
                has_stack_buf = False
                has_copy = False
                for kw in ['local_', 'FUN_00000458', 'FUN_00001c18',
                           'memcpy', 'param_1 +', 'param_2 +']:
                    if kw.lower() in c.lower():
                        pass  # Just flag
                # Check for LARGE local arrays (local_XX where XX > 100)
                import re
                locals_found = re.findall(r'local_([0-9a-f]+)', c, re.I)
                if locals_found:
                    max_local = max(int(x, 16) for x in locals_found)
                    if max_local > 0x40:
                        has_stack_buf = True
                        print("  *** LARGE STACK FRAME: max local offset 0x{:X}".format(max_local))
                if 'FUN_00000458' in c or 'FUN_00001c18' in c:
                    has_copy = True
                    print("  *** HAS COPY OPERATIONS")
                if has_stack_buf and has_copy:
                    print("  *** POTENTIAL STACK OVERFLOW CANDIDATE! ***")
                if len(c) <= 6000:
                    print(c)
                else:
                    print(c[:6000])
                    print("  ... ({} more chars)".format(len(c) - 6000))
        else:
            print("\n  No function at 0x{:04X}".format(addr))

    # 6. Check FUN_000062BE — this is the ALTERNATIVE copy path in FUN_000071AC
    # FUN_000071AC calls either FUN_00001C18 (DMA) or FUN_000062BE (non-DMA)
    # If FUN_000062BE copies to a stack buffer, THAT's the overflow
    print("\n" + "=" * 70)
    print("6. FUN_000062BE — alternative copy path (non-DMA)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x62BE))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x62BE))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:8000])
    else:
        print("  No function found")

    # 7. MOST CRITICAL: FUN_00000300 — the main SVC handler
    # This is where APCB processing starts. It has the largest scope.
    # Check if it has stack buffers that receive APCB data.
    print("\n" + "=" * 70)
    print("7. FUN_00000300 — FULL decompile (main SVC handler)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x300))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x300))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars total".format(len(c)))
            print(c)  # Print ALL of it — this is the most important function
    else:
        print("  No function found")

    decomp.dispose()

print("\nDone.")
