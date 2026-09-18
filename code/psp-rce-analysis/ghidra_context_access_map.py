#!/usr/bin/env python3
"""Map ALL accesses to the PSP boot context structure (base 0x5D7AC).

Goal: find which functions WRITE to offsets >= 0x500, and trace whether
those writes are bounded or APCB-controlled. The function pointer at
+0x660 (= 0x5DE0C) is the exploit target.

Approach:
1. Find all functions that receive the context pointer as param_1
   (callers of FUN_0006F1D8 / FUN_0006BB9C, which take context as param_1)
2. Decompile those functions and extract all param_1+offset accesses
3. Classify each as read (LDR) or write (STR)
4. Focus on offsets >= 0x500 — these are near the target

Also: decompile the PSP_BL functions that SET UP the context structure
to understand its layout.
"""
import os, struct, re
from collections import defaultdict

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
ABL4_BASE = 0x60834
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

print("Starting pyghidra...")
pyghidra.start(install_dir=GHIDRA_DIR)

with pyghidra.open_program(
    ABL4_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_abl4_v3", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()
    listing = program.getListing()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # Step 1: Find all callers of FUN_0006F1D8 and FUN_0006BB9C
    # These are the vtable dispatch functions — their callers pass the context ptr
    dispatch_funcs = [0x6F1D8, 0x6BB9C]
    context_users = set()

    print("=== Finding context structure users (callers of dispatch functions) ===")
    for dva in dispatch_funcs:
        addr = space.getAddress(dva)
        refs = list(ref_mgr.getReferencesTo(addr))
        for r in refs:
            caller_func = func_mgr.getFunctionContaining(r.getFromAddress())
            if caller_func:
                entry = caller_func.getEntryPoint().getOffset()
                context_users.add(entry)

    print("  {} functions call the vtable dispatch".format(len(context_users)))

    # Step 2: Also find functions that directly access offsets >= 0x500 on param_1
    # by scanning decompiled output for "param_1 + 0x5.." or "*(param_1 + 0x6.."
    # We'll decompile ALL functions and search for high-offset context accesses

    print("\n=== Scanning ALL functions for context structure high-offset accesses ===")

    offset_pattern = re.compile(r'param_1\s*\+\s*0x([0-9a-fA-F]+)')
    star_pattern = re.compile(r'\*\s*\(.*?param_1\s*\+\s*0x([0-9a-fA-F]+)')
    write_pattern = re.compile(r'\*\s*\(.*?param_1\s*\+\s*0x([0-9a-fA-F]+)\).*?=')

    all_funcs = []
    fi = func_mgr.getFunctions(True)
    while fi.hasNext():
        all_funcs.append(fi.next())

    print("  Total functions: {}".format(len(all_funcs)))

    high_offset_funcs = {}  # func_entry -> {offset: [access_type, ...]}
    all_offset_accesses = defaultdict(list)  # offset -> [(func, type), ...]

    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 120, flat.getMonitor())
        if not result.decompileCompleted():
            continue

        c = result.getDecompiledFunction().getC()

        # Find all param_1 + offset references
        offsets_in_func = {}
        for m in offset_pattern.finditer(c):
            off = int(m.group(1), 16)
            if off >= 0x100:  # only interested in high offsets
                if off not in offsets_in_func:
                    offsets_in_func[off] = []

                # Check if this is a write (assignment to dereferenced pointer)
                # Look at surrounding context
                start = max(0, m.start() - 40)
                end = min(len(c), m.end() + 40)
                ctx = c[start:end]

                # Simple heuristic: if "= " appears after the close paren, it's a write
                after_match = c[m.end():min(len(c), m.end() + 60)]
                if re.search(r'\)\s*=\s', after_match):
                    offsets_in_func[off].append('WRITE')
                elif '= *' in c[max(0, m.start()-20):m.start()]:
                    offsets_in_func[off].append('READ')
                else:
                    offsets_in_func[off].append('ACCESS')

        if offsets_in_func:
            high_offset_funcs[entry] = offsets_in_func
            for off, types in offsets_in_func.items():
                for t in types:
                    all_offset_accesses[off].append((entry, t))

    # Step 3: Report all accesses to offsets >= 0x500
    print("\n=== Context structure accesses at offset >= 0x500 ===")
    print("  (sorted by offset, showing function and access type)\n")

    for off in sorted(all_offset_accesses.keys()):
        if off < 0x500:
            continue
        accesses = all_offset_accesses[off]
        writes = [a for a in accesses if a[1] == 'WRITE']
        reads = [a for a in accesses if a[1] == 'READ']
        other = [a for a in accesses if a[1] == 'ACCESS']
        print("  +0x{:04X}:  {} total ({} WRITE, {} READ, {} other)".format(
            off, len(accesses), len(writes), len(reads), len(other)))
        for func_entry, atype in accesses:
            fname = func_mgr.getFunctionAt(space.getAddress(func_entry))
            name = fname.getName() if fname else "?"
            marker = " <<<" if atype == 'WRITE' and off >= 0x600 else ""
            print("           0x{:X} ({}) {}{}".format(func_entry, name, atype, marker))

    # Step 4: Special focus on offsets 0x600-0x680 (near the function pointer)
    print("\n=== CRITICAL ZONE: offsets 0x600-0x680 (near vtable ptr at +0x660) ===")
    critical_funcs = set()
    for off in sorted(all_offset_accesses.keys()):
        if 0x600 <= off <= 0x680:
            for func_entry, atype in all_offset_accesses[off]:
                critical_funcs.add(func_entry)
                if atype == 'WRITE':
                    print("  *** WRITE at +0x{:04X} by FUN_{:08X} ***".format(off, func_entry))

    # Step 5: Decompile functions that access the critical zone
    print("\n=== Decompiling functions that access offsets 0x600-0x680 ===")
    for func_entry in sorted(critical_funcs):
        func = func_mgr.getFunctionAt(space.getAddress(func_entry))
        if not func:
            continue
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()
        size = func.getBody().getNumAddresses()
        print("\n" + "=" * 70)
        print("=== FUN_{:08X} ({} bytes) — accesses near +0x660 ===".format(func_entry, size))
        if len(c) < 6000:
            print(c)
        else:
            # Print relevant excerpts around 0x6xx offsets
            print("[{} chars total — showing excerpts around 0x6xx offsets]".format(len(c)))
            for m in re.finditer(r'0x6[0-9a-fA-F]{2}', c):
                start = max(0, m.start() - 120)
                end = min(len(c), m.end() + 120)
                print("\n  ...{}...".format(c[start:end]))

    # Step 6: Find the maximum contiguous write span from any function
    print("\n=== Write span analysis ===")
    print("  Looking for functions that write to MULTIPLE consecutive offsets")
    print("  (potential buffer fill / memcpy target)\n")

    for func_entry, offsets in sorted(high_offset_funcs.items()):
        write_offsets = sorted([off for off, types in offsets.items()
                               if any(t == 'WRITE' for t in types) and off >= 0x400])
        if len(write_offsets) >= 3:
            fname = func_mgr.getFunctionAt(space.getAddress(func_entry))
            name = fname.getName() if fname else "?"
            span = write_offsets[-1] - write_offsets[0] if write_offsets else 0
            print("  FUN_{:08X} ({}): {} write offsets, span=0x{:X}".format(
                func_entry, name, len(write_offsets), span))
            print("    offsets: {}".format(
                ", ".join("0x{:X}".format(o) for o in write_offsets)))
            if write_offsets[-1] >= 0x600:
                print("    *** REACHES CRITICAL ZONE ***")

    # Step 7: Check for array/loop writes that could sweep through memory
    # Look for patterns like *(param_1 + var) = ... where var is loop-controlled
    print("\n=== Variable-offset writes (loop/array patterns) ===")
    var_offset_pattern = re.compile(
        r'\*\s*\([^)]*param_1\s*\+\s*[a-z_]\w*\s*\).*?='
    )
    computed_offset_pattern = re.compile(
        r'\*\s*\([^)]*param_1\s*\+\s*(?:0x[0-9a-f]+\s*\+\s*)?[a-z_]\w*'
    )

    for func in all_funcs:
        entry = func.getEntryPoint().getOffset()
        result = decomp.decompileFunction(func, 120, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        var_writes = list(var_offset_pattern.finditer(c))
        if var_writes:
            fname = func.getName()
            print("\n  FUN_{:08X} ({}): {} variable-offset writes".format(
                entry, fname, len(var_writes)))
            for m in var_writes[:5]:
                ctx = c[max(0, m.start()-20):min(len(c), m.end()+40)]
                print("    ...{}...".format(ctx.strip()))

        # Also look for computed offsets with a base >= 0x500
        for m in computed_offset_pattern.finditer(c):
            snippet = m.group()
            hex_match = re.search(r'0x([0-9a-fA-F]+)', snippet)
            if hex_match:
                base = int(hex_match.group(1), 16)
                if base >= 0x500:
                    print("  FUN_{:08X}: computed offset with base 0x{:X}: {}".format(
                        entry, base, snippet[:80]))

    decomp.dispose()
    print("\nDone.")
