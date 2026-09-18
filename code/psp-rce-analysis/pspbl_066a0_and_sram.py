#!/usr/bin/env python3
"""Two-pronged approach:
1. Decompile FUN_000066A0 (APCB group processor, called at boot + runtime)
2. Search literal pools for SRAM addresses near context (0x5D000-0x5E000)
3. Decompile FUN_00000300 to understand boot-time APCB processing
4. Map the stack pointer — check PSP ROM entry or find SP-related ops
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

# 1. Search literal pools for addresses in context region
print("=" * 70)
print("1. SRAM literal pool references (0x50000-0x70000)")
print("=" * 70)
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if 0x50000 <= val <= 0x70000:
        # This is in the SRAM region between config buffer and ABL4 code
        print("  LP at 0x{:04X}: 0x{:05X}".format(off, val))

# 2. Specifically look for addresses near context (0x5D000-0x5E000)
print("\n" + "=" * 70)
print("2. Context-region references (0x5D000-0x5F000)")
print("=" * 70)
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if 0x5D000 <= val <= 0x5F000:
        print("  LP at 0x{:04X}: 0x{:05X}".format(off, val))

# 3. Look for SRAM addresses that could be stack pointers (0x50000-0x60000 range)
print("\n" + "=" * 70)
print("3. Potential stack pointer values in literal pools (0x55000-0x62000)")
print("=" * 70)
for off in range(0, len(pspbl) - 3, 4):
    val = struct.unpack_from("<I", pspbl, off)[0]
    if 0x55000 <= val <= 0x62000:
        # Could be a stack pointer initial value
        # Check if this value is near context (0x5D7AC) or ABL4 (0x60834)
        print("  LP at 0x{:04X}: 0x{:05X} (delta from context: 0x{:X})".format(
            off, val, val - 0x5D7AC if val >= 0x5D7AC else 0x5D7AC - val))

# 4. Ghidra decompilation
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

    # FUN_000066A0 — APCB group processor
    print("\n" + "=" * 70)
    print("4. FUN_000066A0 — APCB group processor (CRITICAL)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x66A0))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x66A0))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            # Check for stack buffers and copy calls
            buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
            if buffers:
                print("  !!! STACK BUFFERS:")
                for name, size in buffers:
                    print("    {} [{}]".format(name, size))
            for kw in ['FUN_0000823c', 'FUN_00008150', 'FUN_000004e0',
                       'FUN_00000458', 'FUN_00001c18', 'FUN_000071ac']:
                matches = re.findall(kw + r'\([^)]+\)', c, re.I)
                if matches:
                    print("  CALLS {}:".format(kw))
                    for m in matches:
                        print("    {}".format(m))
            if len(c) <= 6000:
                print(c)
            else:
                print(c[:6000])
                print("\n  ... ({} more chars)".format(len(c) - 6000))

    # FUN_000071AC — DMA copy function (the one with no size check)
    print("\n" + "=" * 70)
    print("5. FUN_000071AC — DMA copy (no dest size check)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x71AC))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x71AC))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 6000:
                print(c)
            else:
                print(c[:6000])

    # FUN_00007014 — APCB data reader (previously analyzed but need full view)
    print("\n" + "=" * 70)
    print("6. FUN_00007014 — APCB data reader (full decompile)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x7014))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x7014))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 6000:
                print(c)
            else:
                print(c[:6000])

    # FUN_000068AC — called from FUN_00005850 after copy
    print("\n" + "=" * 70)
    print("7. FUN_000068AC — post-copy verification in FUN_00005850")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x68AC))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x68AC))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 6000:
                print(c)
            else:
                print(c[:6000])

    # FUN_00000300 — main boot handler (need to see its stack frame)
    print("\n" + "=" * 70)
    print("8. FUN_00000300 — main boot handler (stack frame)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x300))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x300))
    if func:
        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, fsize))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
            if buffers:
                print("  !!! STACK BUFFERS:")
                for name, size in buffers:
                    print("    {} [{}]".format(name, size))
            # Show the full decompile — it's the main function
            if len(c) <= 10000:
                print(c)
            else:
                print(c[:10000])
                print("\n  ... ({} more)".format(len(c) - 10000))

    decomp.dispose()

print("\nDone.")
