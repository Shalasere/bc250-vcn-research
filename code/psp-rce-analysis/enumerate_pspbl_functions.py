#!/usr/bin/env python3
"""Enumerate ALL PSP_BL functions and identify candidates for CVE-2025-29951.

CVE-2025-29951: "PSP BL stack buffer overflow" — HIGH 7.3, UNPATCHED.
We need to find a function where APCB-derived data (size/count/offset)
controls a copy into a stack buffer without bounds checking.

Strategy:
1. List every function with address, size, name
2. For each, get a quick decompilation
3. Flag functions with stack arrays + copy patterns
4. Skip the ~40 already-analyzed functions
"""
import os, struct, sys

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

# Functions we've already analyzed (from sessions 1-10+)
ANALYZED = {
    0x0300, 0x0328, 0x0458, 0x044CC, 0x0198,  # boot pipeline, launch, dead SVC
    0x18E4, 0x196C,  # S3 resume handler, HMAC validation
    0x1F40,  # alternative copy (decompression)
    0x151C,  # boot helper state machine
    0x3518, 0x34F0,  # SMN remap helpers
    0x5288,  # callee of 0x151C (mentioned but need to verify)
    0x62BE,  # alternative copy path
    0x75A4,  # config buffer builder
    0x82E6,  # ABL4 launch prep
    0x113E, 0x1094, 0x0EFC,  # copy path callees (mentioned)
    0x2C54, 0x5A00,  # DMA-related callees
}

OUTPUT = r"C:\Users\WORK~1.DES\AppData\Local\Temp\claude\C--Users-work-DESKTOP-SAM98TB\c5f1fa55-5f57-4770-9f66-592352064239\scratchpad\pspbl_function_catalog.txt"

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

    # Enumerate all functions
    all_funcs = []
    func_iter = func_mgr.getFunctions(True)  # forward iteration
    while func_iter.hasNext():
        f = func_iter.next()
        entry = f.getEntryPoint().getOffset()
        size = f.getBody().getNumAddresses()
        name = f.getName()
        all_funcs.append((entry, size, name))

    all_funcs.sort(key=lambda x: x[0])

    print("Total functions in PSP_BL: {}".format(len(all_funcs)))
    print("Already analyzed: {} unique addresses".format(len(ANALYZED)))

    # Categorize
    analyzed_list = []
    unanalyzed_list = []
    for entry, size, name in all_funcs:
        if entry in ANALYZED:
            analyzed_list.append((entry, size, name))
        else:
            unanalyzed_list.append((entry, size, name))

    print("Matched as analyzed: {}".format(len(analyzed_list)))
    print("Unanalyzed: {}".format(len(unanalyzed_list)))

    # Now decompile each unanalyzed function and look for overflow indicators
    # Priority indicators:
    #   - Stack arrays (local_XX with array indexing or large stack frame)
    #   - memcpy, memmove, copy loops
    #   - Parameters used as sizes
    #   - Pointer arithmetic with param-derived offsets
    #   - No bounds check before copy

    candidates = []  # (entry, size, name, reason, snippet)

    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("PSP_BL Function Catalog - CVE-2025-29951 Hunt\n")
        out.write("=" * 70 + "\n\n")
        out.write("Total functions: {}\n".format(len(all_funcs)))
        out.write("Unanalyzed: {}\n\n".format(len(unanalyzed_list)))

        # First pass: decompile all unanalyzed functions, flag suspicious ones
        for idx, (entry, size, name) in enumerate(unanalyzed_list):
            if idx % 20 == 0:
                print("  Progress: {}/{} ...".format(idx, len(unanalyzed_list)))

            func = func_mgr.getFunctionAt(space.getAddress(entry))
            if not func:
                continue

            result = decomp.decompileFunction(func, 120, flat.getMonitor())
            if not result or not result.decompileCompleted():
                out.write("[0x{:04X}] {} ({} bytes) -- DECOMPILE FAILED\n".format(entry, name, size))
                continue

            c = result.getDecompiledFunction().getC()
            lines = c.split('\n')

            # Heuristic checks for stack overflow candidates
            reasons = []

            # Check 1: Large stack frame (local arrays)
            # Look for stack variables with large offsets
            has_stack_array = False
            stack_size = 0
            for line in lines[:5]:  # Function signature area
                pass  # Stack size isn't directly visible in decompiled C

            # Check 2: memcpy / copy operations
            c_lower = c.lower()
            if 'memcpy' in c_lower or 'memmove' in c_lower:
                reasons.append("memcpy/memmove")

            # Check 3: Array indexing with param-derived index
            if 'param_' in c_lower and ('[' in c_lower):
                # More specific: param used in array index or size
                for line in lines:
                    stripped = line.strip()
                    if 'param_' in stripped and '[' in stripped:
                        reasons.append("param in array index")
                        break

            # Check 4: Large local buffers (auStack, local_ arrays)
            for line in lines:
                stripped = line.strip()
                if 'auStack' in stripped or 'local_' in stripped:
                    # Check for large stack allocations
                    import re
                    # auStack_XX pattern where XX is hex offset
                    matches = re.findall(r'auStack_([0-9a-fA-F]+)', stripped)
                    for m in matches:
                        offset = int(m, 16)
                        if offset > 0x40:  # Stack buffer > 64 bytes
                            if "large stack buffer (0x{:X})".format(offset) not in reasons:
                                reasons.append("large stack buffer (0x{:X})".format(offset))
                            has_stack_array = True

                    # Also check local_XX arrays
                    matches = re.findall(r'local_([0-9a-fA-F]+)\[', stripped)
                    for m in matches:
                        reasons.append("local array access")
                        break

            # Check 5: While loops with copy semantics
            if 'while' in c_lower and ('*' in c_lower) and ('++' in c_lower or '+=' in c_lower):
                reasons.append("copy loop pattern")

            # Check 6: Functions that handle APCB data
            # APCB-related markers
            apcb_markers = ['0xb814', '0xb82c', '0x7a000', '0x4f000',
                           'apcb', 'token', 'group', 'header']
            for marker in apcb_markers:
                if marker in c_lower:
                    reasons.append("APCB-related ({})".format(marker))
                    break

            # Check 7: Size parameter used in loop/copy without bounds
            if 'param_' in c_lower:
                for line in lines:
                    stripped = line.strip().lower()
                    if ('param_' in stripped and
                        ('< param_' in stripped or '<= param_' in stripped or
                         'param_' in stripped and 'do {' in c_lower)):
                        reasons.append("param controls loop bound")
                        break

            # Write to catalog
            tag = " ** CANDIDATE **" if reasons else ""
            out.write("[0x{:04X}] {} ({} bytes){}\n".format(entry, name, size, tag))
            if reasons:
                out.write("  Reasons: {}\n".format(", ".join(set(reasons))))
                candidates.append((entry, size, name, reasons, c[:2000]))
            out.write("\n")

        # Summary section
        out.write("\n" + "=" * 70 + "\n")
        out.write("CANDIDATES FOR CVE-2025-29951 (stack overflow)\n")
        out.write("=" * 70 + "\n\n")

        candidates.sort(key=lambda x: len(x[3]), reverse=True)  # Most reasons first

        for entry, size, name, reasons, snippet in candidates:
            out.write("[0x{:04X}] {} ({} bytes)\n".format(entry, name, size))
            out.write("  Flags: {}\n".format(", ".join(set(reasons))))
            out.write("  First 2000 chars of decompilation:\n")
            out.write(snippet)
            out.write("\n" + "-" * 40 + "\n\n")

        out.write("\nTotal candidates: {}\n".format(len(candidates)))

    decomp.dispose()

print("\nCatalog written to: {}".format(OUTPUT))
print("Total candidates: {}".format(len(candidates)))
for entry, size, name, reasons, _ in candidates[:20]:
    print("  0x{:04X} {} ({} bytes): {}".format(entry, name, size, ", ".join(set(reasons))))
