"""
Follow-up analysis:
  1. FUN_000057c4 - writes into auStack_664 (1600 byte stack buf in FUN_000053C4)
  2. FUN_000056c4 - reads auStack_664
  3. FUN_00003ba4 - second-largest stack buffer (296 bytes)
  4. FUN_00004138 - byte copy loop detected
  5. FUN_00004118 - byte swap loop detected
  6. FUN_0000196c - XOR copy loops into what buffer?
"""

import os
os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects\bc250_pspbl_v1"
PROJECT_NAME = "bc250_pspbl_v1"

pyghidra.start(install_dir=GHIDRA_DIR)

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.base.project import GhidraProject

project = GhidraProject.openProject(PROJECT_DIR, PROJECT_NAME)
program = project.openProgram("/", "internal_pspbl_body.bin", False)

monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
opts = DecompileOptions()
opts.setMaxWidth(160)
decomp.setOptions(opts)
decomp.openProgram(program)

fm = program.getFunctionManager()
addr_space = program.getAddressFactory().getDefaultAddressSpace()

targets = [
    (0x000057c4, "FUN_000057c4 - fills auStack_664 in FUN_000053C4"),
    (0x000056c4, "FUN_000056c4 - reads auStack_664 in FUN_000053C4"),
    (0x00003ba4, "FUN_00003ba4 - second-largest stack buffer (296 bytes)"),
    (0x00004138, "FUN_00004138 - byte copy loop"),
    (0x00004118, "FUN_00004118 - byte swap loop"),
    (0x0000196c, "FUN_0000196c - XOR copy loops (HMAC inner/outer pad)"),
    (0x00005f9c, "FUN_00005f9c - called before APCB read in FUN_000053C4"),
    (0x000043a4, "FUN_000043a4 - LDRB/STRB detected"),
    (0x000044cc, "FUN_000044cc - APCB processing, ptr_inc_copy hit"),
    (0x00003650, "FUN_00003650 - while_copy hit (page table / MMIO setup?)"),
]

for addr_val, desc in targets:
    addr = addr_space.getAddress(addr_val)
    func = fm.getFunctionAt(addr)
    if func is None:
        print(f"\n{'#' * 80}")
        print(f"# {desc}")
        print(f"# NO FUNCTION AT 0x{addr_val:08x}")
        print(f"{'#' * 80}")
        continue

    result = decomp.decompileFunction(func, 120, monitor)
    if not result.decompileCompleted():
        print(f"\n# {desc} - DECOMPILE FAILED: {result.getErrorMessage()}")
        continue

    df = result.getDecompiledFunction()
    if df is None:
        print(f"\n# {desc} - getDecompiledFunction() returned None")
        continue

    c_code = df.getC()
    print(f"\n{'#' * 80}")
    print(f"# {desc}")
    print(f"# {func.getName()} @ 0x{addr_val:08x}")
    print(f"{'#' * 80}")
    print(c_code)

# Additional: check what calls FUN_000057c4 (callers)
print("\n" + "=" * 80)
print("CROSS-REFERENCE: Who calls FUN_000057c4?")
print("=" * 80)

addr_57c4 = addr_space.getAddress(0x000057c4)
refs = program.getReferenceManager().getReferencesTo(addr_57c4)
while refs.hasNext():
    ref = refs.next()
    from_addr = ref.getFromAddress()
    containing_func = fm.getFunctionContaining(from_addr)
    func_name = containing_func.getName() if containing_func else "UNKNOWN"
    print(f"  Called from 0x{from_addr.getOffset():08x} in {func_name}")

# Check what calls FUN_000056c4
print("\nCROSS-REFERENCE: Who calls FUN_000056c4?")
addr_56c4 = addr_space.getAddress(0x000056c4)
refs = program.getReferenceManager().getReferencesTo(addr_56c4)
while refs.hasNext():
    ref = refs.next()
    from_addr = ref.getFromAddress()
    containing_func = fm.getFunctionContaining(from_addr)
    func_name = containing_func.getName() if containing_func else "UNKNOWN"
    print(f"  Called from 0x{from_addr.getOffset():08x} in {func_name}")

# FUN_00002434: This is the MOST INTERESTING finding.
# auStack_6c is 68 bytes. param_2 is checked < 0x41 (65).
# But auStack_6c[param_2] writes at index param_2, which is up to 0x40 (64).
# auStack_6c is 68 bytes (0x6c - 0x28 = 0x44 = 68 in the stack frame).
# Let's verify: param_2 < 0x41, then writes auStack_6c[param_2..param_2+3].
# That's up to index param_2+3 = 0x40+3 = 0x43 = 67. Buffer is 68 bytes. EXACT FIT.
# But wait - FUN_00000458(auStack_6c, param_1, param_2) copies param_2 bytes first.
# Then writes 4 more bytes at auStack_6c[param_2..param_2+3].
# Total bytes used: param_2 + 4. Max: 0x40 + 4 = 0x44 = 68. EXACT buffer size.
print("\n" + "=" * 80)
print("FUN_00002434 DETAILED BOUNDS ANALYSIS")
print("=" * 80)
print("  auStack_6c declared as [68] bytes")
print("  Bounds check: param_2 < 0x41 (65)")
print("  FUN_00000458(auStack_6c, param_1, param_2): copies param_2 bytes (max 64)")
print("  Then writes auStack_6c[param_2+0..param_2+3]: 4 bytes at offset max 64")
print("  Max total written: 64 + 4 = 68 = buffer size. EXACT FIT, no overflow.")
print("  Also requires: (param_2 & 3) == 0, so param_2 is 4-byte aligned.")
print("  VERDICT: Properly bounded. The check param_2 < 0x41 prevents overflow.")

decomp.dispose()
project.close()
print("\nDone.")
