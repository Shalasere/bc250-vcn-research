#!/usr/bin/env python3
"""Resolve the SVC vector question definitively.

The static binary has BX LR at 0x108, but ABL4 has 96 SVC instructions.
PSP_BL must patch the vector at runtime.

This script:
1. Reads DAT_000035ec and DAT_000035f0 to confirm FUN_000035A0 covers page 0
2. Decompiles PSP_BL's main init after VBAR write to find the SVC vector patch
3. Searches for all writes to the 0x100-0x120 range (vector table area)
4. Decompiles ABL4's SVC #28 callers to see post-SVC behavior
5. Checks if PSP_BL constructs branch instructions at runtime
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

# Part 0: Raw literal pool values from PSP_BL
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

print("=" * 70)
print("PART 0: Key literal pool values for FUN_000035A0")
print("=" * 70)

dat_35ec = struct.unpack_from("<I", pspbl, 0x35EC)[0]
dat_35f0 = struct.unpack_from("<I", pspbl, 0x35F0)[0]
print("  DAT_000035ec (L2 base)  = 0x{:08X}".format(dat_35ec))
print("  DAT_000035f0 (loop end) = 0x{:08X}".format(dat_35f0))
print("  FUN_000035A0 maps pages 0x0000 to 0x{:X} with descriptor 0x52".format(dat_35f0))
if dat_35f0 > 0x108:
    print("  *** COVERS page 0 → makes 0x108 WRITABLE ***")

# Also read DAT_000037e8, DAT_000037ec, DAT_000037f0, DAT_000037f4, DAT_000037f8
# for FUN_0000373C
for off in [0x37E8, 0x37EC, 0x37F0, 0x37F4, 0x37F8]:
    val = struct.unpack_from("<I", pspbl, off)[0]
    print("  [0x{:04X}] = 0x{:08X}".format(off, val))

# Part 1: Check what instruction is at 0x108 in the binary
print("\n" + "=" * 70)
print("PART 1: SVC vector in static binary")
print("=" * 70)

vec_108 = struct.unpack_from("<I", pspbl, 0x108)[0]
print("  [0x108] = 0x{:08X}".format(vec_108))
# BX LR = 0xE12FFF1E
if vec_108 == 0xE12FFF1E:
    print("  *** BX LR confirmed ***")

# Show the full vector table at VBAR+0x00 through VBAR+0x1C
print("\n  Vector table at VBAR=0x100:")
vec_names = ["Reset", "Undef", "SVC", "Prefetch Abort", "Data Abort",
             "Reserved", "IRQ", "FIQ"]
for i in range(8):
    addr = 0x100 + i * 4
    val = struct.unpack_from("<I", pspbl, addr)[0]
    # Decode ARM instruction
    desc = ""
    if val == 0xE12FFF1E:
        desc = "BX LR (NOP)"
    elif (val & 0xFF000000) == 0xEA000000:
        offset = (val & 0xFFFFFF)
        if offset & 0x800000:
            offset -= 0x1000000
        target = addr + 8 + offset * 4
        desc = "B 0x{:03X}".format(target)
    elif (val & 0x0F7F0000) == 0x059F0000:
        # LDR Rn, [PC, #imm]
        imm = val & 0xFFF
        target = addr + 8 + imm
        desc = "LDR R{}, [PC, #0x{:X}] → pool at 0x{:03X}".format(
            (val >> 12) & 0xF, imm, target)
    print("  [0x{:03X}] {}: 0x{:08X} {}".format(
        addr, vec_names[i], val, desc))

# Part 2: Search for runtime vector writes
print("\n" + "=" * 70)
print("PART 2: Search for potential SVC vector patching in PSP_BL")
print("=" * 70)

# Strategy: Find all STR instructions that could target address 0x108
# In the decompiler, this would show as writes to DAT_00000108
# But since 0x108 is in the vector table, the decompiler might show it differently

# Search for literal pool entries containing 0x108 or 0x100
print("  Literal pool entries pointing to vector table area:")
for i in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, i)[0]
    if 0x100 <= val <= 0x120 and val != 0x108:  # skip the BX LR itself
        # Check if aligned
        if val & 0x3 == 0:
            print("    [0x{:04X}] = 0x{:08X}".format(i, val))

# Search specifically for 0x108
print("\n  32-bit values equal to 0x108:")
needle = struct.pack("<I", 0x108)
idx = 0
while True:
    idx = pspbl.find(needle, idx)
    if idx < 0:
        break
    if idx != 0x108:  # skip the vector entry itself
        print("    Found at offset 0x{:04X}".format(idx))
    idx += 1

# Part 3: Check the COMPLETE init sequence
# The entry point is at 0x0000. VBAR write is at 0x004C.
# Trace what happens after VBAR write until ABL4 launch.
print("\n" + "=" * 70)
print("PART 3: PSP_BL init sequence — raw instructions after VBAR write")
print("=" * 70)

# Show raw instructions from 0x050 to 0x100 (between VBAR write and vector table)
print("  Instructions from 0x050 to 0x0FF:")
for off in range(0x050, 0x100, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    desc = ""
    if (val & 0xFF000000) == 0xEB000000:  # BL
        offset = val & 0xFFFFFF
        if offset & 0x800000:
            offset -= 0x1000000
        target = off + 8 + offset * 4
        desc = "BL 0x{:05X}".format(target)
    elif (val & 0xFF000000) == 0xEA000000:  # B
        offset = val & 0xFFFFFF
        if offset & 0x800000:
            offset -= 0x1000000
        target = off + 8 + offset * 4
        desc = "B 0x{:05X}".format(target)
    elif val == 0xE12FFF1E:
        desc = "BX LR"
    elif (val & 0x0FFF0FFF) == 0x0E010F10:
        desc = "MCR/MRC p15"
    elif (val & 0x0FF00000) == 0x03A00000:  # MOV imm
        rd = (val >> 12) & 0xF
        imm = val & 0xFF
        rot = ((val >> 8) & 0xF) * 2
        if rot:
            imm = ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF
        desc = "MOV R{}, #0x{:X}".format(rd, imm)
    elif (val & 0x0FF00000) == 0x05900000:  # LDR
        rn = (val >> 16) & 0xF
        rd = (val >> 12) & 0xF
        imm = val & 0xFFF
        desc = "LDR R{}, [R{}, #0x{:X}]".format(rd, rn, imm)
    elif (val & 0x0FF00000) == 0x05800000:  # STR
        rn = (val >> 16) & 0xF
        rd = (val >> 12) & 0xF
        imm = val & 0xFFF
        desc = "STR R{}, [R{}, #0x{:X}]".format(rd, rn, imm)
    print("    [0x{:03X}] 0x{:08X}  {}".format(off, val, desc))

# Part 4: Check entry point and early boot through Ghidra
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

    # Decompile FUN_00000000 (entry point / reset handler)
    print("\n" + "=" * 70)
    print("PART 4: PSP_BL entry / reset handler")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x0000))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x0000))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Look for vector table writes
            if '0x108' in c:
                print("  *** Contains 0x108 reference! ***")
            if '0x35a0' in c.lower():
                print("  *** Calls FUN_000035A0 ***")
            print(c[:6000] if len(c) > 6000 else c)

    # Decompile the function called from the entry point (main init)
    # The entry point likely BLs to a main function
    # Let's find what's at offset 0x50-0x80 (after VBAR write)
    print("\n" + "=" * 70)
    print("PART 5: FUN_00000A44 — main PSP_BL init (from summary)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x0A44))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x0A44))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            if '0x35a0' in c.lower() or 'FUN_000035a0' in c:
                print("  *** Calls FUN_000035A0 ***")
            if '0x108' in c:
                print("  *** References 0x108 ***")
            # Print key parts — search for STR instructions near vector table
            print(c[:8000] if len(c) > 8000 else c)

    # Part 6: Find ALL callers of FUN_000035A0
    print("\n" + "=" * 70)
    print("PART 6: Callers of FUN_000035A0 (page table R/W)")
    print("=" * 70)

    ref_mgr = program.getReferenceManager()
    target = space.getAddress(0x35A0)
    refs = ref_mgr.getReferencesTo(target)
    for ref in refs:
        ca = ref.getFromAddress().getOffset()
        func = func_mgr.getFunctionContaining(ref.getFromAddress())
        fn = func.getName() if func else "?"
        fe = func.getEntryPoint().getOffset() if func else 0
        print("  Call at 0x{:04X} in {} (0x{:04X}), type={}".format(
            ca, fn, fe, ref.getReferenceType().toString()))

    # Part 7: Decompile ABL4's SVC #28 (0x1C) callers to see post-SVC behavior
    print("\n" + "=" * 70)
    print("PART 7: ABL4 SVC #28 (0x1C) callers — post-SVC behavior")
    print("=" * 70)

    decomp.dispose()

# Open ABL4
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

    # SVC #28 (0x1C) locations: VA 0x62878, 0x688A4, 0x6AFB6, 0x6BCCC
    svc28_addrs = [0x62878, 0x688A4, 0x6AFB6, 0x6BCCC]

    for va in svc28_addrs:
        func = func_mgr.getFunctionContaining(space.getAddress(va))
        if not func:
            print("\n  No function containing 0x{:05X}".format(va))
            continue

        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("\n  --- {} at 0x{:05X} ({} bytes) --- contains SVC #28 at 0x{:05X}".format(
            func.getName(), entry, fsize, va))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Find the SVC call and show surrounding context
            svc_idx = c.find('software_interrupt')
            if svc_idx >= 0:
                start = max(0, c.rfind('\n', 0, max(0, svc_idx - 500)))
                end = min(len(c), c.find('\n', min(len(c), svc_idx + 500)) if c.find('\n', svc_idx + 500) > 0 else svc_idx + 500)
                print(c[start:end])
            else:
                # SVC might not be decompiled as software_interrupt
                # Show full function if small
                if fsize < 600:
                    print(c)
                else:
                    print(c[:3000])

    decomp.dispose()

print("\nDone.")
