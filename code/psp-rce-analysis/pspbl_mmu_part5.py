#!/usr/bin/env python3
"""
Part 5: Decompile FUN_000037fc (page table setup parent), trace full PT setup.
"""

import sys, os, struct
sys.stdout.reconfigure(encoding='utf-8')

BINARY = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(BINARY, "rb") as f:
    blob = f.read()

# ── 5a: Capstone Thumb disassembly 0x37FC-0x3960 ───────────────────────
print("=" * 80)
print("5a. FULL PAGE TABLE SETUP: Thumb disassembly 0x37FC-0x3A12")
print("=" * 80)

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB
md_thumb = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
md_thumb.detail = True

region = blob[0x37FC:0x3A12]
for insn in md_thumb.disasm(region, 0x37FC):
    line = f"  {insn.address:#06x}: {insn.bytes.hex():<12s} {insn.mnemonic:<10s} {insn.op_str}"
    marker = ""
    if 'push' in insn.mnemonic: marker = " <<<< PROLOGUE"
    if 'pop' in insn.mnemonic and 'pc' in insn.op_str: marker = " <<<< RETURN"
    if insn.mnemonic == 'bx' and insn.op_str == 'lr': marker = " <<<< RETURN"
    if insn.mnemonic == 'bl':
        target_str = insn.op_str.strip().lstrip('#')
        try:
            target = int(target_str, 0)
            if target == 0x30B0: marker = " <<<< write_section_entry"
            elif target == 0x30C4: marker = " <<<< write_page_entry"
        except: pass
    if insn.mnemonic == 'movw' or insn.mnemonic == 'movt':
        marker = f" <<<< {insn.mnemonic.upper()}"
    if '0x4e' in insn.op_str.lower():
        marker = " <<<< PT BASE?"
    print(line + marker)

# ── 5b: Literal pools near page table setup ─────────────────────────────
print("\n" + "=" * 80)
print("5b. LITERAL POOL DATA near page table function")
print("=" * 80)

# The function at 0x37FC probably references data after 0x3A0E (the return)
print("\nData at 0x3A12-0x3A50:")
for off in range(0x3A12, 0x3A50, 4):
    val = struct.unpack_from("<I", blob, off)[0]
    ann = ""
    if val == 0x4E000: ann = " (L1 page table base)"
    elif val == 0x4DC00: ann = " (exception SP / L2 table?)"
    elif val == 0x54000: ann = " (init stack)"
    elif 0x4E000 <= val <= 0x4F000: ann = f" (within L1 table: +{val-0x4E000:#x})"
    elif 0x40000 <= val <= 0x60000: ann = f" (SRAM addr)"
    print(f"  [{off:#06x}]: 0x{val:08X}{ann}")

# ── 5c: Now use pyghidra ────────────────────────────────────────────────
print("\n" + "=" * 80)
print("5c. PYGHIDRA: Decompile FUN_000037fc")
print("=" * 80)

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

pyghidra.start(install_dir=GHIDRA_DIR)

from ghidra.app.decompiler import DecompInterface
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.base.project import GhidraProject

project_loc = os.path.join(PROJECT_DIR, "bc250_pspbl_v1")
project = GhidraProject.openProject(project_loc, "bc250_pspbl_v1")
prog = project.openProgram("/", "internal_pspbl_body.bin", False)

flat = FlatProgramAPI(prog)
monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
decomp.openProgram(prog)

# Decompile FUN_000037fc
addr = flat.toAddr(0x37FC)
func = flat.getFunctionContaining(addr)
if func:
    print(f"\n  Function: {func.getName()} at {func.getEntryPoint()}")
    print(f"  Range: {func.getBody()}")
    results = decomp.decompileFunction(func, 60, monitor)
    if results and results.decompileCompleted():
        code = results.getDecompiledFunction().getC()
        print(code)
    else:
        print(f"  Decompile failed")
else:
    print(f"  No function at 0x37FC, searching nearby...")
    fm = prog.getFunctionManager()
    for f in fm.getFunctions(addr, False):
        print(f"  Before: {f.getName()} at {f.getEntryPoint()}, body={f.getBody()}")
        # Decompile it
        results = decomp.decompileFunction(f, 60, monitor)
        if results and results.decompileCompleted():
            code = results.getDecompiledFunction().getC()
            lines = code.split('\n')
            if len(lines) > 150:
                print('\n'.join(lines[:150]))
                print(f"\n... ({len(lines) - 150} more lines)")
            else:
                print(code)
        break

# ── 5d: Decompile FUN_00000134 (exception dispatch) ────────────────────
print("\n" + "=" * 80)
print("5d. PYGHIDRA: Decompile FUN_00000134 (exception dispatch)")
print("=" * 80)

addr_134 = flat.toAddr(0x134)
func_134 = flat.getFunctionContaining(addr_134)
if func_134:
    print(f"\n  Function: {func_134.getName()} at {func_134.getEntryPoint()}")
    print(f"  Range: {func_134.getBody()}")
    results = decomp.decompileFunction(func_134, 60, monitor)
    if results and results.decompileCompleted():
        code = results.getDecompiledFunction().getC()
        print(code)

# ── 5e: Check what function contains 0x30B0 ────────────────────────────
print("\n" + "=" * 80)
print("5e. PYGHIDRA: Function containing 0x30B0 (write_section_entry)")
print("=" * 80)

addr_30b0 = flat.toAddr(0x30B0)
func_30b0 = flat.getFunctionContaining(addr_30b0)
if func_30b0:
    print(f"  Function: {func_30b0.getName()} at {func_30b0.getEntryPoint()}")
    print(f"  Range: {func_30b0.getBody()}")
    results = decomp.decompileFunction(func_30b0, 60, monitor)
    if results and results.decompileCompleted():
        code = results.getDecompiledFunction().getC()
        print(code)
else:
    print("  No function at 0x30B0")
    # Check if it's part of a larger function
    fm = prog.getFunctionManager()
    func_iter = fm.getFunctions(addr_30b0, False)
    if func_iter.hasNext():
        f = func_iter.next()
        print(f"  Nearest before: {f.getName()} at {f.getEntryPoint()}")
        end = f.getBody().getMaxAddress()
        print(f"  Ends at: {end}")
        if end.getOffset() >= 0x30B0:
            print(f"  -> 0x30B0 IS within this function!")
            results = decomp.decompileFunction(f, 60, monitor)
            if results and results.decompileCompleted():
                code = results.getDecompiledFunction().getC()
                lines = code.split('\n')
                print('\n'.join(lines[:60]))
                if len(lines) > 60:
                    print(f"... ({len(lines)-60} more lines)")

# ── 5f: Search for any L1->L2 conversion (page table descriptors) ──────
print("\n" + "=" * 80)
print("5f. SEARCH: L1 entries with Page Table type (bits [1:0] = 01)")
print("=" * 80)

# In the page table setup, look for writes that create L1 Page Table entries
# L1 Page Table descriptor: bits [1:0] = 01, bits [31:10] = L2 table base
# Let's search for values with bit pattern xxxx_xxxx_01 in the binary
# that could be L2 table addresses

print("""
For L1 Page Table descriptors:
  bits [1:0] = 01 (Page Table type)
  bits [4:2] = don't care
  bits [8:5] = Domain
  bit  [9]   = implementation defined
  bits [31:10] = L2 table base address (must be 1KB aligned)

Looking for code that writes L1 entries with type=01 (Page Table)...
This would involve ORing a base address with 0x01 and storing to the L1 table.
""")

# Look for the value 0x01 being used as a page table type marker
# In the Thumb code near the page table setup
print("Searching for 'orr' with #1 near page table setup:")
region = blob[0x3700:0x3A00]
for insn in md_thumb.disasm(region, 0x3700):
    if insn.mnemonic == 'orr' and '#1' in insn.op_str:
        print(f"  {insn.address:#06x}: {insn.mnemonic} {insn.op_str}")
    if insn.mnemonic == 'orr' and '#0x' in insn.op_str.lower():
        val_str = insn.op_str.split('#')[-1].strip()
        try:
            val = int(val_str, 0)
            if (val & 3) == 1:  # Page Table type
                print(f"  {insn.address:#06x}: {insn.mnemonic} {insn.op_str} <<<< PT TYPE?")
        except: pass

# Also search for movw/movt that build a descriptor with type=01
print("\nSearching for immediate values that could be L1 Page Table descriptors:")
for insn in md_thumb.disasm(region, 0x3700):
    if insn.mnemonic in ('movw', 'movt', 'mov', 'mov.w'):
        if '#' in insn.op_str:
            val_str = insn.op_str.split('#')[-1].strip()
            try:
                val = int(val_str, 0)
                if val > 0x40000 and (val & 0x3FF) == 1:
                    print(f"  {insn.address:#06x}: {insn.mnemonic} {insn.op_str} <<<< L2 TABLE PTR + TYPE 01?")
            except: pass

decomp.dispose()
project.close()

print("\n\n" + "=" * 80)
print("PART 5 COMPLETE")
print("=" * 80)
