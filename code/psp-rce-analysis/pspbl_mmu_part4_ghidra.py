#!/usr/bin/env python3
"""
Part 4: Pyghidra decompilation of key PSP_BL functions.
"""

import sys, os
sys.stdout.reconfigure(encoding='utf-8')

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

print("Starting pyghidra...")
pyghidra.start(install_dir=GHIDRA_DIR)

from ghidra.app.decompiler import DecompInterface
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.util.task import ConsoleTaskMonitor

# Open the project
print("Opening Ghidra project...")
from java.io import File
from ghidra.base.project import GhidraProject

project_loc = os.path.join(PROJECT_DIR, "bc250_pspbl_v1")
project = GhidraProject.openProject(project_loc, "bc250_pspbl_v1")

# Get the program
print("Getting program...")
prog = project.openProgram("/", "internal_pspbl_body.bin", False)
if prog is None:
    print("ERROR: Could not open program. Listing available programs...")
    root = project.getProjectData().getRootFolder()
    for f in root.getFiles():
        print(f"  Found: {f.getName()}")
    project.close()
    sys.exit(1)

flat = FlatProgramAPI(prog)
monitor = ConsoleTaskMonitor()

# Set up decompiler
decomp = DecompInterface()
decomp.openProgram(prog)

def decompile_at(addr_val, label=""):
    """Decompile the function containing the given address."""
    addr = flat.toAddr(addr_val)
    func = flat.getFunctionContaining(addr)
    if func is None:
        print(f"  No function at {addr} ({label})")
        # Try to find nearest function
        fm = prog.getFunctionManager()
        func_iter = fm.getFunctions(addr, True)
        if func_iter.hasNext():
            f = func_iter.next()
            print(f"  Nearest function after: {f.getName()} at {f.getEntryPoint()}")
        func_iter = fm.getFunctions(addr, False)
        if func_iter.hasNext():
            f = func_iter.next()
            print(f"  Nearest function before: {f.getName()} at {f.getEntryPoint()}")
        return None

    print(f"\n  Function: {func.getName()} at {func.getEntryPoint()}")
    print(f"  Range: {func.getBody()}")

    results = decomp.decompileFunction(func, 60, monitor)
    if results and results.decompileCompleted():
        code = results.getDecompiledFunction().getC()
        return code
    else:
        print(f"  Decompilation failed: {results.getErrorMessage() if results else 'null'}")
        return None

# ── 4a: List all functions in the binary ────────────────────────────────
print("\n" + "=" * 80)
print("4a. ALL FUNCTIONS IN THE BINARY")
print("=" * 80)

fm = prog.getFunctionManager()
func_count = 0
functions_list = []
for func in fm.getFunctions(True):
    entry = func.getEntryPoint().getOffset()
    name = func.getName()
    functions_list.append((entry, name))
    func_count += 1
    if func_count <= 50 or entry in [0x3C, 0xAC, 0x134, 0x198, 0x22C, 0x244,
                                       0x298, 0x30B0, 0x30C4, 0x394C, 0x44CC,
                                       0x45CC, 0x5278, 0x6CF0, 0xA44, 0x1178,
                                       0x3900, 0x38FE, 0x3860]:
        print(f"  0x{entry:04X}: {name}")

print(f"\nTotal functions: {func_count}")

# Print functions near key addresses
print("\nFunctions near key addresses:")
key_addrs = [0x3C, 0xAC, 0x100, 0x134, 0x198, 0x30B0, 0x30C4, 0x394C,
             0x44CC, 0x45CC, 0xA44, 0x3900]
for ka in key_addrs:
    addr = flat.toAddr(ka)
    func = flat.getFunctionContaining(addr)
    if func:
        print(f"  0x{ka:04X} -> {func.getName()} at {func.getEntryPoint()}")
    else:
        print(f"  0x{ka:04X} -> (no function)")

# ── 4b: Decompile the page table setup function ────────────────────────
print("\n" + "=" * 80)
print("4b. DECOMPILE: Page table setup function (near 0x394C)")
print("=" * 80)

code = decompile_at(0x394C, "page_table_setup")
if code:
    print(code)

# ── 4c: Decompile the write_section_entry helper ───────────────────────
print("\n" + "=" * 80)
print("4c. DECOMPILE: write_section_entry (0x30B0)")
print("=" * 80)

code = decompile_at(0x30B0, "write_section_entry")
if code:
    print(code)

# ── 4d: Decompile the write_page_entry helper ──────────────────────────
print("\n" + "=" * 80)
print("4d. DECOMPILE: write_page_entry (0x30C4)")
print("=" * 80)

code = decompile_at(0x30C4, "write_page_entry")
if code:
    print(code)

# ── 4e: Decompile init code (near 0x3C) ────────────────────────────────
print("\n" + "=" * 80)
print("4e. DECOMPILE: Init code (0x3C or containing function)")
print("=" * 80)

code = decompile_at(0x3C, "init_mmu")
if code:
    print(code)

# ── 4f: Decompile the exception dispatch (0x134/0x198) ─────────────────
print("\n" + "=" * 80)
print("4f. DECOMPILE: Exception dispatch (0x198)")
print("=" * 80)

code = decompile_at(0x198, "exception_dispatch")
if code:
    print(code)

# ── 4g: Decompile FUN_000044CC ──────────────────────────────────────────
print("\n" + "=" * 80)
print("4g. DECOMPILE: FUN_000044CC (direct call SVC dispatch)")
print("=" * 80)

code = decompile_at(0x44CC, "FUN_000044CC")
if code:
    # Truncate if very long
    lines = code.split('\n')
    if len(lines) > 100:
        print('\n'.join(lines[:100]))
        print(f"\n... ({len(lines) - 100} more lines)")
    else:
        print(code)

# ── 4h: Decompile the mode setup / BSS clear (0xAC) ────────────────────
print("\n" + "=" * 80)
print("4h. DECOMPILE: Mode setup / BSS clear (0xAC)")
print("=" * 80)

code = decompile_at(0xAC, "mode_setup")
if code:
    print(code)

# ── 4i: Decompile main entry (0xA44) ───────────────────────────────────
print("\n" + "=" * 80)
print("4i. DECOMPILE: Main Thumb entry (0xA44)")
print("=" * 80)

code = decompile_at(0xA44, "main")
if code:
    lines = code.split('\n')
    if len(lines) > 80:
        print('\n'.join(lines[:80]))
        print(f"\n... ({len(lines) - 80} more lines)")
    else:
        print(code)

# ── 4j: Check for any MCR VBAR writes via cross-references ─────────────
print("\n" + "=" * 80)
print("4j. CROSS-REFERENCE: VBAR address 0x100")
print("=" * 80)

# Search for references to address 0x100
addr_100 = flat.toAddr(0x100)
refs_to = prog.getReferenceManager().getReferencesTo(addr_100)
print(f"References TO 0x100:")
for ref in refs_to:
    print(f"  From {ref.getFromAddress()} type={ref.getReferenceType()}")

# Search for the literal 0x100 in data
print(f"\nSearching for data value 0x00000100 in binary:")
import struct
addr = flat.toAddr(0)
end = flat.toAddr(prog.getMemory().getMaxAddress().getOffset())

# Manual search in memory
mem = prog.getMemory()
buf = bytearray(4)
for off in range(0, 0x99C0 - 3, 4):
    a = flat.toAddr(off)
    try:
        mem.getBytes(a, buf)
        val = struct.unpack_from("<I", buf, 0)[0]
        if val == 0x100:
            # Check if this is referenced by MCR instruction area
            refs = prog.getReferenceManager().getReferencesTo(a)
            ref_list = list(refs)
            ref_str = f" (referenced from: {', '.join(str(r.getFromAddress()) for r in ref_list)})" if ref_list else ""
            print(f"  0x{off:04X}: 0x00000100{ref_str}")
    except:
        pass

# ── 4k: Decompile the function at 0x5278 (SVC #0 handler) ──────────────
print("\n" + "=" * 80)
print("4k. DECOMPILE: SVC #0 handler at 0x5278")
print("=" * 80)

code = decompile_at(0x5278, "svc0_handler")
if code:
    lines = code.split('\n')
    if len(lines) > 60:
        print('\n'.join(lines[:60]))
        print(f"\n... ({len(lines) - 60} more lines)")
    else:
        print(code)

# ── 4l: Decompile the function at 0x45CC (generic SVC handler) ─────────
print("\n" + "=" * 80)
print("4l. DECOMPILE: Generic SVC handler at 0x45CC")
print("=" * 80)

code = decompile_at(0x45CC, "svc_generic_handler")
if code:
    lines = code.split('\n')
    if len(lines) > 80:
        print('\n'.join(lines[:80]))
        print(f"\n... ({len(lines) - 80} more lines)")
    else:
        print(code)

# Clean up
decomp.dispose()
project.close()

print("\n\n" + "=" * 80)
print("PART 4 (PYGHIDRA) COMPLETE")
print("=" * 80)
