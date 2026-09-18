#!/usr/bin/env python3
"""Load PSP_BL into Ghidra, auto-analyze, and decompile functions that
reference the context structure at 0x5D7AC.

PSP_BL binary: 39,360 bytes, ARM Cortex-A5
Vector table starts at 0x0, code at ~0x13C (reset handler)
Load base: 0x0 (vectors are absolute addresses within the binary)

Key questions:
1. Which function loads 0x5D7AC and writes to context+0x660?
2. What copy/parse operations use a length variable that could be uninitialized?
3. Is there an APCB parser in PSP_BL?
"""
import os, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

# PSP_BL load base = 0 (vectors at file start are absolute addresses)
LOAD_BASE = 0

print("Starting pyghidra...")
pyghidra.start(install_dir=GHIDRA_DIR)

# Use a separate project for PSP_BL
with pyghidra.open_program(
    PSPBL_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_pspbl_v1", analyze=True
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

    # Count functions found by analysis
    fi = func_mgr.getFunctions(True)
    func_count = 0
    while fi.hasNext():
        fi.next()
        func_count += 1
    print("Ghidra found {} functions in PSP_BL".format(func_count))

    # Step 1: Find references to the literal pool entries with context pointers
    # Key literal pool addresses (file offsets, which = VA since load base = 0):
    # 0x0BB8: 0x5D7AC
    # 0x0BC8: 0x5D5A4
    # 0x3DA0: 0x5D004
    print("\n=== References TO literal pool entries (context pointers) ===")
    context_func_entries = set()
    for pool_va in [0x0BB8, 0x0BC8, 0x3DA0]:
        addr = space.getAddress(pool_va)
        refs = list(ref_mgr.getReferencesTo(addr))
        for r in refs:
            from_addr = r.getFromAddress().getOffset()
            func = func_mgr.getFunctionContaining(r.getFromAddress())
            fname = func.getName() if func else "?"
            entry = func.getEntryPoint().getOffset() if func else 0
            print("  Pool 0x{:04X} (0x{:08X}) <- 0x{:04X} in {} (entry 0x{:04X})".format(
                pool_va, struct.unpack_from("<I", open(PSPBL_PATH, "rb").read(), pool_va)[0],
                from_addr, fname, entry))
            if func:
                context_func_entries.add(entry)

    # Step 2: Decompile functions that reference context pointers
    print("\n=== Decompiling functions that reference context structure ===")
    for entry in sorted(context_func_entries):
        func = func_mgr.getFunctionAt(space.getAddress(entry))
        if not func:
            continue
        size = func.getBody().getNumAddresses()
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if not result.decompileCompleted():
            print("\n  FUN_{:08X} ({} bytes): DECOMPILE FAILED".format(entry, size))
            continue

        c = result.getDecompiledFunction().getC()
        print("\n" + "=" * 70)
        print("=== FUN_{:08X} ({} bytes) ===".format(entry, size))
        if len(c) < 8000:
            print(c)
        else:
            print(c[:4000])
            print("\n... [truncated, {} total]".format(len(c)))
            # Show key excerpts
            import re
            for pattern in ['0x5d7', '0x5d5', '0x5de', '0x660', 'len', 'size', 'copy', 'saved']:
                for m in re.finditer(pattern, c, re.IGNORECASE):
                    start = max(0, m.start() - 80)
                    end = min(len(c), m.end() + 120)
                    print("\n  [{}]:".format(pattern))
                    print("  ...{}...".format(c[start:end].replace('\n', ' ')))

    # Step 3: Find ALL functions and look for ones with:
    # - Large function bodies (complex parsers)
    # - References to SRAM addresses in 0x5xxxx range
    # - memcpy-like patterns
    print("\n" + "=" * 70)
    print("=== Large functions in PSP_BL (>200 bytes, potential parsers) ===")
    fi = func_mgr.getFunctions(True)
    large_funcs = []
    while fi.hasNext():
        f = fi.next()
        size = f.getBody().getNumAddresses()
        if size > 200:
            large_funcs.append((f.getEntryPoint().getOffset(), size, f.getName()))

    for entry, size, name in sorted(large_funcs, key=lambda x: -x[1]):
        print("  0x{:04X}: {} bytes  {}".format(entry, size, name))

    # Step 4: Decompile the LARGEST functions (most likely to be parsers/handlers)
    print("\n=== Decompiling largest functions (potential APCB parsers) ===")
    for entry, size, name in sorted(large_funcs, key=lambda x: -x[1])[:10]:
        if entry in context_func_entries:
            continue  # Already decompiled above
        func = func_mgr.getFunctionAt(space.getAddress(entry))
        if not func:
            continue
        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Check if the decompiled code references context-area values
        import re
        has_context_ref = bool(re.search(r'0x5d[0-9a-f]{3}', c, re.IGNORECASE))
        has_apcb_ref = bool(re.search(r'apcb|APCB|0x7a000|token|type_size', c, re.IGNORECASE))
        has_copy = bool(re.search(r'memcpy|copy|saved.?len|while.*<|for.*<', c, re.IGNORECASE))
        has_660 = '0x660' in c

        if has_context_ref or has_apcb_ref or has_copy or has_660:
            print("\n" + "=" * 70)
            print("=== FUN_{:08X} ({} bytes) [ctx:{} apcb:{} copy:{} 660:{}] ===".format(
                entry, size, has_context_ref, has_apcb_ref, has_copy, has_660))
            if len(c) < 6000:
                print(c)
            else:
                print(c[:3000])
                print("\n... [truncated, {} total]".format(len(c)))

    # Step 5: Search ALL decompiled functions for 0x660 offset
    print("\n" + "=" * 70)
    print("=== Functions referencing offset 0x660 ===")
    fi = func_mgr.getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        result = decomp.decompileFunction(f, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()
        if '0x660' in c:
            entry = f.getEntryPoint().getOffset()
            size = f.getBody().getNumAddresses()
            print("\n  FUN_{:08X} ({} bytes):".format(entry, size))
            for m in re.finditer(r'0x660', c):
                ctx = c[max(0,m.start()-100):min(len(c),m.end()+100)].replace('\n',' ')
                print("    ...{}...".format(ctx[:200]))

    # Step 6: Search for uninitialized variable patterns
    # Look for local variables used before being assigned in all conditional paths
    print("\n" + "=" * 70)
    print("=== Functions with 'saved' or 'len' in decompiled output ===")
    fi = func_mgr.getFunctions(True)
    while fi.hasNext():
        f = fi.next()
        result = decomp.decompileFunction(f, 60, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()
        import re
        if re.search(r'saved|\.len|_len|_size|_count', c, re.IGNORECASE):
            entry = f.getEntryPoint().getOffset()
            print("  FUN_{:08X}: matches 'saved/len/size/count'".format(entry))

    decomp.dispose()
    print("\nDone.")
