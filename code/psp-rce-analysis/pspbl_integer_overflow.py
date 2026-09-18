#!/usr/bin/env python3
"""Hunt for integer overflow in APCB size field handling.

CVE-2025-48515 is classified as "integer overflow" in ASP Boot Loader.
CVE-2025-29951 is "stack buffer overflow" — likely the RESULT of the integer overflow.

Key hypothesis: APCB SizeOfType (u16) undergoes arithmetic that wraps,
causing a bounds check to pass when it shouldn't. The wrapped size is then
used to copy APCB data into a stack buffer, causing overflow.

Targets:
1. FUN_00000850 — APCB token reader, returns size to callers
2. FUN_00002C80 — APCB group walker, iterates using SizeOfType
3. FUN_00007014 — APCB installer, computes sizes from header fields
4. FUN_000071AC — Core copy, alignment computation on sizes
5. FUN_000037FC — Called by FUN_00002C80, returns APCB metadata
6. FUN_000082B0 — Calls FUN_0000823c
7. Any function that subtracts from an APCB-derived u16 size
"""
import os, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

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

    # Priority targets: functions in the APCB size chain
    targets = [
        (0x0850, "FUN_00000850 — APCB token reader (returns size to callers)"),
        (0x37FC, "FUN_000037FC — APCB metadata resolver"),
        (0x2C80, "FUN_00002C80 — APCB group walker"),
        (0x7014, "FUN_00007014 — APCB installer (size from header)"),
        (0x71AC, "FUN_000071AC — Core copy (alignment computation)"),
        (0x82B0, "FUN_000082B0 — calls FUN_0000823c"),
        (0x66A0, "FUN_000066A0 — APCB dispatcher"),
        (0x55C0, "FUN_000055C0 — calls FUN_000071AC"),
        (0x56C4, "FUN_000056C4 — in token read chain"),
        (0x5F9C, "FUN_00005F9C — in token processing chain"),
        (0x53C4, "FUN_000053C4 — SVC 0xDE, 1600-byte stack buffer"),
        (0x73D0, "FUN_000073D0 — APCB types 0x95/0x42/0x91"),
        (0x3BA4, "FUN_00003BA4 — copies to stack buffer auStack_128"),
    ]

    for addr, desc in targets:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        if not func:
            func = func_mgr.getFunctionContaining(space.getAddress(addr))
        if not func:
            print("\n  No function at 0x{:04X}".format(addr))
            continue

        entry = func.getEntryPoint().getOffset()
        fsize = func.getBody().getNumAddresses()
        print("\n" + "=" * 70)
        print("{} at 0x{:04X} ({} bytes)".format(desc, entry, fsize))
        print("=" * 70)

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if not result.decompileCompleted():
            print("  Decompile failed!")
            continue

        c = result.getDecompiledFunction().getC()

        # Analyze for integer overflow patterns
        print("\n--- INTEGER OVERFLOW ANALYSIS ---")

        # 1. Subtraction from size fields (u16 underflow)
        sub_patterns = re.findall(r'(\w+)\s*[-]\s*(0x[0-9a-fA-F]+|\d+)', c)
        if sub_patterns:
            for var, val in sub_patterns:
                if any(kw in var.lower() for kw in ['size', 'len', 'local_', 'param_', 'uvar']):
                    print("  SUBTRACT: {} - {}".format(var, val))

        # 2. Type casts (u16 to u32, sign extension)
        cast_patterns = re.findall(r'\((?:uint|ushort|short|int)\)\s*(\w+)', c)
        if cast_patterns:
            for var in cast_patterns:
                print("  CAST: ({}) {}".format("type", var))

        # 3. Multiplication or shift on size values
        mul_patterns = re.findall(r'(\w+)\s*[*]\s*(0x[0-9a-fA-F]+|\d+)', c)
        if mul_patterns:
            for var, val in mul_patterns[:5]:
                print("  MULTIPLY: {} * {}".format(var, val))

        # 4. Addition that could wrap (size + offset)
        add_patterns = re.findall(r'(\w+)\s*[+]\s*(0x[0-9a-fA-F]+)', c)
        if add_patterns:
            for var, val in add_patterns[:10]:
                if any(kw in var.lower() for kw in ['size', 'len', 'local_', 'param_', 'uvar']):
                    print("  ADD: {} + {}".format(var, val))

        # 5. Check for LDRH (16-bit loads from APCB data)
        if 'short' in c.lower() or 'ushort' in c.lower():
            print("  HAS 16-BIT OPERATIONS")

        # 6. Stack buffers
        buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
        if buffers:
            for name, size in buffers:
                print("  STACK BUFFER: {} [{}]".format(name, size))

        # 7. Calls to copy functions with variable sizes
        for copy_fn in ['FUN_0000823c', 'FUN_000004e0', 'FUN_00000458', 'FUN_00001c18']:
            idx = 0
            while True:
                idx = c.find(copy_fn, idx)
                if idx < 0:
                    break
                end = c.find(';', idx)
                if end > 0:
                    call_text = c[idx:end].strip()
                    has_var = any(kw in call_text for kw in ['param_', 'local_', 'uVar', 'iVar'])
                    if has_var:
                        print("  COPY WITH VARIABLE: {}".format(call_text[:120]))
                idx += 1

        # Print the FULL decompile for inspection
        print("\n--- FULL DECOMPILE ---")
        if len(c) <= 5000:
            print(c)
        else:
            print(c[:5000])
            print("\n... ({} more chars)".format(len(c) - 5000))

    # PART 2: Search ALL functions for specific integer overflow patterns
    print("\n\n" + "=" * 70)
    print("PART 2: ALL PSP_BL functions — integer overflow in size computations")
    print("=" * 70)

    func_iter = func_mgr.getFunctions(True)
    suspicious = []
    while func_iter.hasNext():
        f = func_iter.next()
        faddr = f.getEntryPoint().getOffset()
        result = decomp.decompileFunction(f, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        reasons = []

        # Check for subtraction patterns that could underflow
        # Pattern: variable - constant where the variable could be small
        if re.search(r'param_\d+\s*-\s*0x[1-9a-fA-F]', c):
            reasons.append("PARAM_SUBTRACT")
        if re.search(r'local_\w+\s*-\s*0x[1-9a-fA-F]', c):
            # Only flag if there's also a stack buffer or copy
            if 'auStack_' in c or 'FUN_000004e0' in c or 'FUN_00000458' in c or 'FUN_0000823c' in c:
                reasons.append("LOCAL_SUBTRACT_WITH_COPY")

        # Check for u16 truncation before comparison
        if '& 0xffff' in c and ('param_' in c or 'local_' in c):
            if 'FUN_000004e0' in c or 'FUN_00000458' in c or 'FUN_0000823c' in c:
                reasons.append("U16_MASK_WITH_COPY")

        # Check for cast-before-compare pattern (compare as u16, use as u32)
        if '(ushort)' in c or '(short)' in c:
            if 'auStack_' in c:
                reasons.append("SHORT_CAST_WITH_STACK")

        # Check for size computation: (x + y) where x is param and used in copy
        if re.search(r'\(param_\d+\s*\+\s*\w+\)\s*[&*]', c):
            reasons.append("PARAM_ARITH")

        if reasons:
            suspicious.append((faddr, f.getName(), reasons))

    print("  Suspicious functions: {}".format(len(suspicious)))
    for faddr, fname, reasons in suspicious:
        print("    0x{:04X} {}: {}".format(faddr, fname, ", ".join(reasons)))

    # PART 3: Cross-reference analysis for FUN_00000850's callers
    print("\n\n" + "=" * 70)
    print("PART 3: ALL callers of FUN_00000850 (APCB token reader)")
    print("=" * 70)

    ref_mgr = program.getReferenceManager()
    target = space.getAddress(0x850)
    refs = ref_mgr.getReferencesTo(target)
    callers = []
    for ref in refs:
        if ref.getReferenceType().isCall():
            caller_addr = ref.getFromAddress().getOffset()
            func = func_mgr.getFunctionContaining(ref.getFromAddress())
            if func:
                callers.append((caller_addr, func.getEntryPoint().getOffset(), func.getName()))

    print("  FUN_00000850 callers: {} refs".format(len(callers)))
    for call_addr, func_addr, fname in callers:
        print("    Call at 0x{:04X} in {} (0x{:04X})".format(call_addr, fname, func_addr))

        # Decompile the caller and show how it uses the returned size
        func = func_mgr.getFunctionAt(space.getAddress(func_addr))
        if func:
            result = decomp.decompileFunction(func, 600, flat.getMonitor())
            if result.decompileCompleted():
                c = result.getDecompiledFunction().getC()
                # Find calls to FUN_00000850 and the surrounding lines
                idx = c.find('FUN_00000850')
                if idx >= 0:
                    start = max(0, c.rfind('\n', 0, idx))
                    end = min(len(c), c.find('\n', idx + 200) if c.find('\n', idx + 200) > 0 else idx + 200)
                    context = c[start:end].strip()
                    print("      Context: {}".format(context[:200]))

                # Check for stack buffers in this function
                buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
                if buffers:
                    for name, size in buffers:
                        print("      STACK BUFFER: {} [{}]".format(name, size))

    # PART 4: Check FUN_000053C4 (SVC 0xDE) — does it call FUN_00000850?
    print("\n\n" + "=" * 70)
    print("PART 4: FUN_000053C4 callees (SVC 0xDE, 1600-byte buffer)")
    print("=" * 70)

    func_53c4 = func_mgr.getFunctionAt(space.getAddress(0x53C4))
    if func_53c4:
        # Get all callees from this function
        target_refs = []
        body = func_53c4.getBody()
        ref_iter = ref_mgr.getReferenceIterator(body.getMinAddress())
        while ref_iter.hasNext():
            ref = ref_iter.next()
            if ref.getFromAddress().compareTo(body.getMaxAddress()) > 0:
                break
            if ref.getReferenceType().isCall():
                target_refs.append((ref.getFromAddress().getOffset(), ref.getToAddress().getOffset()))

        print("  Callees from FUN_000053C4:")
        for from_addr, to_addr in target_refs:
            to_func = func_mgr.getFunctionAt(space.getAddress(to_addr))
            fname = to_func.getName() if to_func else "unknown"
            print("    0x{:04X} → 0x{:04X} ({})".format(from_addr, to_addr, fname))

    decomp.dispose()

print("\nDone.")
