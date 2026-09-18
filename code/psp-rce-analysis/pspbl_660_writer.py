#!/usr/bin/env python3
"""Find and decompile the PSP_BL function that writes to context+0x660.

Found: STR.W r1, [r4, #0x660] at PSP_BL offset 0x762A
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

# First: capstone disassembly around 0x762A
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

print("=" * 70)
print("Capstone disassembly around PSP_BL offset 0x762A")
print("=" * 70)
start = 0x7580
insns = list(cs.disasm(pspbl[start:start+256], start))
for insn in insns:
    marker = " >>>" if insn.address == 0x762A else "    "
    print("{} 0x{:04X}: {:8s} {}".format(marker, insn.address, insn.mnemonic, insn.op_str))

# Also find ALL STR instructions with large offsets to context in PSP_BL
print("\n" + "=" * 70)
print("ALL STR.W to context offsets >= 0x500 in PSP_BL")
print("=" * 70)
for off in range(0, len(pspbl) - 3, 2):
    hw1 = struct.unpack_from("<H", pspbl, off)[0]
    if (hw1 & 0xFFF0) == 0xF8C0:  # STR.W
        hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]
        imm12 = hw2 & 0xFFF
        if imm12 >= 0x500:
            rn = hw1 & 0xF
            rt = (hw2 >> 12) & 0xF
            print("  Offset 0x{:04X}: STR.W r{}, [r{}, #0x{:X}]".format(off, rt, rn, imm12))

# And LDR.W from +0x660
print("\n  LDR.W from +0x660:")
for off in range(0, len(pspbl) - 3, 2):
    hw1 = struct.unpack_from("<H", pspbl, off)[0]
    if (hw1 & 0xFFF0) == 0xF8D0:  # LDR.W
        hw2 = struct.unpack_from("<H", pspbl, off + 2)[0]
        imm12 = hw2 & 0xFFF
        if imm12 == 0x660:
            rn = hw1 & 0xF
            rt = (hw2 >> 12) & 0xF
            print("  Offset 0x{:04X}: LDR.W r{}, [r{}, #0x660]".format(off, rt, rn))

# Now use Ghidra
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

    # Find function containing 0x762A
    print("\n" + "=" * 70)
    print("Function containing STR.W to +0x660 (offset 0x762A)")
    print("=" * 70)
    func = func_mgr.getFunctionContaining(space.getAddress(0x762A))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} (0x{:X}, {} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            # Show the part with +0x660 write
            idx = c.find('0x660')
            if idx >= 0:
                start = max(0, idx - 800)
                end = min(len(c), idx + 800)
                print(c[start:end])
            else:
                print("  0x660 not in decompile! Showing first 5000 chars:")
                print(c[:5000])
    else:
        print("  No function contains 0x762A")
        # Try to find it
        for delta in range(0, -1000, -2):
            f = func_mgr.getFunctionAt(space.getAddress(0x762A + delta))
            if f:
                print("  Nearest: {} at 0x{:X}".format(f.getName(), 0x762A + delta))
                break

    # Also decompile FUN_000044CC (the largest PSP_BL function with APCB group IDs)
    print("\n" + "=" * 70)
    print("FUN_000044CC — largest PSP_BL function (APCB processing?)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x44CC))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            # Show parts with APCB processing
            for keyword in ['0x1701', '0x660', 'memcpy', 'copy', 'size', 'len',
                            'param_1', 'param_2', 'switch', 'case',
                            'alloc', 'buffer', 'heap', '0x5d7']:
                idx = c.lower().find(keyword.lower())
                if idx >= 0:
                    print("\n  [{}]:".format(keyword))
                    ctx = c[max(0,idx-100):min(len(c),idx+400)]
                    print("  " + ctx[:500].replace('\n', '\n  '))

    # Decompile FUN_000075A4 (532 bytes — contains the 0x762A write)
    print("\n" + "=" * 70)
    print("FUN_000075A4 — contains the +0x660 write?")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x75A4))
    if func:
        size = func.getBody().getNumAddresses()
        print("  {} bytes".format(size))
        # Check if 0x762A is in this function's range
        end = entry + size
        print("  Range: 0x{:X} - 0x{:X}".format(0x75A4, 0x75A4 + size))
        print("  Contains 0x762A: {}".format(0x75A4 <= 0x762A < 0x75A4 + size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            print(c[:10000])

    # Also check FUN_00000300 (the SVC dispatch, 1000 bytes)
    print("\n" + "=" * 70)
    print("FUN_00000300 — SVC dispatch (showing SVC 0x1c handling)")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x300))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Find software_interrupt / SVC 0x1c dispatch
            idx = c.find('0x1c')
            while idx >= 0:
                context = c[max(0,idx-200):min(len(c),idx+300)]
                if 'switch' in context.lower() or 'case' in context.lower() or 'unaff_r4' in context:
                    print(context)
                    print("\n---")
                idx = c.find('0x1c', idx + 1)

    decomp.dispose()
    print("\nDone.")
