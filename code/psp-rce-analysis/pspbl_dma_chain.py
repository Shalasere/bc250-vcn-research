#!/usr/bin/env python3
"""Complete DMA destination chain trace.

DMA dest = *(0x9A10) + local_2c + 0x100
local_2c = APCB_group_offset & DAT_00002ccc_mask

Need:
1. DAT_00002CCC value (the mask)
2. FUN_00003650 (computes what goes into *(0x9A10))
3. Function containing 0x81A2 (writes to *(0x9A10))
4. FUN_0000823C revisit — it also reads *(0x9A10) at offset 0x8264
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# 1. Read DAT_00002CCC
print("=" * 70)
print("1. DAT_00002CCC (mask applied to APCB offset)")
print("=" * 70)
val_2ccc = struct.unpack_from("<I", pspbl, 0x2CCC)[0]
print("  DAT_00002CCC = 0x{:08X}".format(val_2ccc))
print("  Binary: {:032b}".format(val_2ccc))
print("  local_2c = APCB_offset & 0x{:08X}".format(val_2ccc))
print("  Max possible local_2c = 0x{:08X}".format(val_2ccc))

# 2. Read DAT_00003848 (pointer to APCB group table)
val_3848 = struct.unpack_from("<I", pspbl, 0x3848)[0]
print("\n  DAT_00003848 = 0x{:08X} (pointer to APCB group table)".format(val_3848))
if val_3848 < len(pspbl):
    print("    Within binary — contains 0x{:08X}".format(
        struct.unpack_from("<I", pspbl, val_3848)[0]))
else:
    print("    Runtime SRAM address")

# 3. Other key literal pool values
print("\n  Key literal pool values:")
for off, name in [(0x67BC, "DAT_000067BC"), (0x7564, "DAT_00007564"),
                   (0x940, "DAT_00000940"), (0x8234, "LP_8234"),
                   (0x82AC, "LP_82AC")]:
    if off < len(pspbl) - 3:
        val = struct.unpack_from("<I", pspbl, off)[0]
        print("    {} (+0x{:04X}) = 0x{:08X}".format(name, off, val))

# Now Ghidra decompilation
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

    # 4. FUN_00003650 — computes the base address for *(0x9A10)
    print("\n" + "=" * 70)
    print("4. FUN_00003650 — computes DMA destination base")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x3650))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x3650))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:5000])
    else:
        print("  No function at 0x3650")

    # 5. Function containing offset 0x81A2 (writes to *(0x9A10))
    print("\n" + "=" * 70)
    print("5. Function at/containing 0x81A2 (writes *(0x9A10))")
    print("=" * 70)
    func = func_mgr.getFunctionContaining(space.getAddress(0x81A2))
    if not func:
        # Try nearby addresses
        for delta in range(-32, 33, 2):
            func = func_mgr.getFunctionAt(space.getAddress(0x81A2 + delta))
            if func:
                break
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:6000])
    else:
        print("  No function found near 0x81A2")
        # List all functions in the 0x8100-0x8240 range
        print("  Functions in range 0x8100-0x8240:")
        fi = func_mgr.getFunctions(True)
        while fi.hasNext():
            f = fi.next()
            addr = f.getEntryPoint().getOffset()
            if 0x8100 <= addr <= 0x8240:
                print("    {} at 0x{:04X} ({} bytes)".format(
                    f.getName(), addr, f.getBody().getNumAddresses()))

    # 6. FUN_0000823C revisit — verify it reads *(0x9A10) in the large-copy path
    print("\n" + "=" * 70)
    print("6. FUN_0000823C — full decompile (reads *(0x9A10) at 0x8264)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x823C))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c)

    # 7. FUN_00005A00 — address translation function (used before DMA)
    print("\n" + "=" * 70)
    print("7. FUN_00005A00 — address translation (VA -> physical?)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x5A00))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x5A00))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:3000])

    # 8. What is at PSP_BL runtime data area 0x9A00-0x9C80?
    # These are global variables initialized by boot code
    print("\n" + "=" * 70)
    print("8. PSP_BL runtime data pointers (0x9A00-0x9C80)")
    print("=" * 70)
    # Search all literal pools for values in 0x9A00-0x9D00
    runtime_ptrs = {}
    for off in range(0, len(pspbl) - 3, 4):
        val = struct.unpack_from("<I", pspbl, off)[0]
        if 0x9A00 <= val <= 0x9D00:
            runtime_ptrs.setdefault(val, []).append(off)
    for addr in sorted(runtime_ptrs.keys()):
        refs = runtime_ptrs[addr]
        ref_str = ", ".join("0x{:04X}".format(r) for r in refs[:5])
        print("  0x{:04X}: {} ref(s) from literal pools: {}".format(
            addr, len(refs), ref_str))

    decomp.dispose()

# 9. Summary: DMA chain computation
print("\n" + "=" * 70)
print("9. SUMMARY: DMA destination chain")
print("=" * 70)
print("  DMA dest = *(0x9A10) + (APCB_group_offset & 0x{:08X}) + 0x100".format(val_2ccc))
print("  *(0x9A10) set by FUN_00003650 return value at offset 0x81A4")
print("  APCB_group_offset from APCB header entry[+8] (attacker controlled)")
print("  Mask limits offset to 0x{:08X} max".format(val_2ccc))
print()
print("  To reach context+0x660 (0x5DE0C):")
print("  Need: *(0x9A10) + offset + 0x100 <= 0x5DE0C")
print("  And:  *(0x9A10) + offset + 0x100 + DMA_size > 0x5DE0C")
print("  i.e., the DMA range [base+offset+0x100, base+offset+0x100+size)")
print("        must include 0x5DE0C")

print("\nDone.")
