#!/usr/bin/env python3
"""Force-create and decompile the token dispatch function at 0x60FE8.

Ghidra didn't find this function because 0x60FE9 is stored as a data value
in a literal pool — it's only called through the vtable at context+0x660.
We need to manually create the function and analyze it.
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

# First, disassemble raw bytes at 0x60FE8 with capstone
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

target_va = 0x60FE8
target_off = target_va - ABL4_BASE  # 0x7B4

print("=" * 70)
print("Raw bytes at VA 0x{:X} (offset 0x{:X}):".format(target_va, target_off))
print("=" * 70)
print("  Hex: {}".format(abl4[target_off:target_off+64].hex()))

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

print("\nThumb disassembly from 0x{:X}:".format(target_va))
# Disassemble up to 200 bytes
insns = list(cs.disasm(abl4[target_off:target_off+256], target_va))
for insn in insns[:40]:
    print("  0x{:05X}: {:8s} {}".format(insn.address, insn.mnemonic, insn.op_str))
    # Stop if we hit a POP with PC (function return)
    if insn.mnemonic in ['pop', 'bx'] and 'pc' in insn.op_str.lower():
        print("  [FUNCTION RETURN]")
        break

# Also check: what literal pool value is at DAT_0006b5f8?
dat_off = 0x6B5F8 - ABL4_BASE  # offset in file
val = struct.unpack_from("<I", abl4, dat_off)[0]
print("\nDAT_0006b5f8 (offset 0x{:X}) = 0x{:08X}".format(dat_off, val))
print("  Confirms +0x660 contains 0x{:X} = Thumb function at 0x{:X}".format(val, val & ~1))

# Now check ALL 8 vtable literal pool values
vtable_dats = {
    '+0x660': 0x6B5F8,
    '+0x630': 0x6B5FC,
    '+0x628': 0x6B600,
    '+0x62C': 0x6B604,
    '+0x5C0': 0x6B608,
    '+0x654': 0x6B60C,
    '+0x5B8': 0x6B610,
    '+0x614': 0x6B614,
}
print("\nVtable literal pool values:")
for name, dat_va in sorted(vtable_dats.items()):
    off = dat_va - ABL4_BASE
    val = struct.unpack_from("<I", abl4, off)[0]
    print("  {} DAT_0x{:X} = 0x{:08X} (func at 0x{:X})".format(name, dat_va, val, val & ~1))

# Now use Ghidra to force-create the function and decompile
print("\n" + "=" * 70)
print("Ghidra: Force-creating function at 0x{:X}".format(target_va))
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
    listing = program.getListing()

    from ghidra.app.decompiler import DecompInterface
    from ghidra.program.model.symbol import SourceType

    decomp = DecompInterface()
    decomp.openProgram(program)

    addr = space.getAddress(target_va)

    # Check current state
    func = func_mgr.getFunctionAt(addr)
    print("  Existing function at 0x{:X}: {}".format(target_va, func))

    cu = listing.getCodeUnitAt(addr)
    if cu:
        print("  Code unit at 0x{:X}: {} ({})".format(target_va, cu, type(cu).__name__))

    # Try to create the function
    from ghidra.program.database.function import OverlappingFunctionException
    import ghidra.app.cmd.function as fcmd

    txid = program.startTransaction("Create dispatch function")
    try:
        # First, disassemble the code at the address if it's not already code
        from ghidra.app.cmd.disassemble import ArmDisassembleCommand
        from ghidra.program.model.address import AddressSet

        # Set Thumb mode for this address
        # The TMode register context for ARM processors
        reg = program.getRegister("TMode")
        if reg:
            from java.math import BigInteger
            program.getProgramContext().setValue(reg, addr, addr, BigInteger.valueOf(1))
            print("  Set TMode=1 (Thumb) at 0x{:X}".format(target_va))

        # Disassemble
        disasm_cmd = ArmDisassembleCommand(addr, AddressSet(addr, space.getAddress(target_va + 255)), True)
        disasm_cmd.applyTo(program, flat.getMonitor())
        print("  Disassembled at 0x{:X}".format(target_va))

        # Now create the function
        func = func_mgr.createFunction(
            "token_dispatch_0x660", addr,
            AddressSet(addr, space.getAddress(target_va + 200)),
            SourceType.USER_DEFINED
        )
        print("  Created function: {}".format(func))

    except Exception as e:
        print("  Error creating function: {}".format(e))
        # Try alternate approach
        try:
            func = flat.createFunction(addr, "token_dispatch")
            print("  Created via flat: {}".format(func))
        except Exception as e2:
            print("  Also failed: {}".format(e2))
    finally:
        program.endTransaction(txid, True)

    # Now try to decompile
    func = func_mgr.getFunctionAt(addr)
    if not func:
        func = func_mgr.getFunctionContaining(addr)

    if func:
        print("\n  Function: {} at 0x{:X} ({} bytes)".format(
            func.getName(), func.getEntryPoint().getOffset(),
            func.getBody().getNumAddresses()))

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars decompiled".format(len(c)))
            print(c[:15000])
        else:
            print("  Decompile FAILED: {}".format(result.getErrorMessage()))
    else:
        print("  Still no function at 0x{:X}!".format(target_va))
        # List nearby functions
        fi = func_mgr.getFunctions(True)
        while fi.hasNext():
            f = fi.next()
            entry = f.getEntryPoint().getOffset()
            if 0x60900 <= entry <= 0x61400:
                print("  Near: {} at 0x{:X} ({} bytes)".format(
                    f.getName(), entry, f.getBody().getNumAddresses()))

    # Also force-create functions for ALL vtable entries that Ghidra missed
    print("\n" + "=" * 70)
    print("Force-creating ALL missing vtable functions")
    print("=" * 70)

    # These are the function addresses with Thumb bit cleared
    vtable_funcs = {
        '+0x660': 0x60FE8,
        '+0x628': 0x60F40,
        '+0x62C': 0x60F9C,
    }

    for name, va in sorted(vtable_funcs.items()):
        if va == target_va:
            continue  # Already handled
        func = func_mgr.getFunctionAt(space.getAddress(va))
        if func:
            print("  {} (0x{:X}): already exists - {}".format(name, va, func.getName()))
            continue

        txid = program.startTransaction("Create vtable func {}".format(name))
        try:
            a = space.getAddress(va)
            reg = program.getRegister("TMode")
            if reg:
                from java.math import BigInteger
                program.getProgramContext().setValue(reg, a, a, BigInteger.valueOf(1))

            disasm_cmd = ArmDisassembleCommand(a, AddressSet(a, space.getAddress(va + 200)), True)
            disasm_cmd.applyTo(program, flat.getMonitor())

            try:
                func = flat.createFunction(a, "vtable_{}".format(name.strip('+0x')))
                print("  {} (0x{:X}): created - {}".format(name, va, func))

                result = decomp.decompileFunction(func, 300, flat.getMonitor())
                if result.decompileCompleted():
                    c = result.getDecompiledFunction().getC()
                    print("  {} chars".format(len(c)))
                    print(c[:3000])
            except Exception as e:
                print("  {} (0x{:X}): create failed - {}".format(name, va, e))
        finally:
            program.endTransaction(txid, True)

    decomp.dispose()
    print("\nDone.")
