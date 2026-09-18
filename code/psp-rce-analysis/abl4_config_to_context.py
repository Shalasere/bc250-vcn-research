#!/usr/bin/env python3
"""Check if ABL4 copies data from the PSP_BL config buffer (0x4F000) to
the context structure at 0x5D7AC. If so, the value at 0x4F660 would
map to context+0x660 = 0x5DE0C (the dispatch function pointer).

Also: Search for ALL references to 0x4F000/0x4F660/0x5D7AC in ABL4.
And: Trace the ABL4 post-SVC path (after SVC 0x1C returns) to see
how the context structure is populated.

ABL4 binary: 88,000 bytes, load base 0x60834
Ghidra project: bc250_abl4_v3
"""
import os, re, struct

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"
ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

# Part 0: Search ABL4 binary for 0x4F000 and 0x5D7AC literal values
print("=" * 70)
print("PART 0: Literal search in ABL4 binary for key addresses")
print("=" * 70)

with open(ABL4_PATH, "rb") as f:
    abl4 = f.read()

ABL4_BASE = 0x60834
# Search for 4-byte little-endian values
search_vals = {
    0x0004F000: "CONFIG_BUFFER_BASE",
    0x0004F660: "CONFIG_BUFFER+0x660",
    0x0005D7AC: "CONTEXT_BASE",
    0x0005DE0C: "CONTEXT+0x660 (DISPATCH PTR)",
    0x00060FE9: "DISPATCH_DEFAULT (0x60FE9)",
    0x000B82C: "APCB_HEADER_COPY",
}

for val, name in search_vals.items():
    # Search as 32-bit LE
    needle = struct.pack("<I", val)
    idx = 0
    hits = []
    while True:
        idx = abl4.find(needle, idx)
        if idx < 0:
            break
        va = ABL4_BASE + idx
        hits.append((idx, va))
        idx += 1
    if hits:
        print("  0x{:08X} ({}): {} hits".format(val, name, len(hits)))
        for file_off, va in hits[:10]:
            print("    File 0x{:05X} → VA 0x{:05X}".format(file_off, va))
    else:
        print("  0x{:08X} ({}): NOT FOUND".format(val, name))

    # Also search for upper/lower halves (MOVW/MOVT pattern)
    lower = val & 0xFFFF
    upper = (val >> 16) & 0xFFFF
    if upper != 0:
        lower_needle = struct.pack("<H", lower)
        upper_needle = struct.pack("<H", upper)
        # Count halfword matches (very approximate)
        lower_count = abl4.count(lower_needle)
        upper_count = abl4.count(upper_needle)
        if lower_count < 20 and upper_count < 20:
            print("    Halfword: lower 0x{:04X} = {} hits, upper 0x{:04X} = {} hits".format(
                lower, lower_count, upper, upper_count))

# Part 1: Ghidra analysis of ABL4
print("\n" + "=" * 70)
print("PART 1: ABL4 Ghidra — literal pool references to key addresses")
print("=" * 70)

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
    decomp = DecompInterface()
    decomp.openProgram(program)

    # Search for references to key addresses in ABL4
    ref_mgr = program.getReferenceManager()

    key_addrs = [0x4F000, 0x4F660, 0x5D7AC, 0x5DE0C]
    for target_val in key_addrs:
        target = space.getAddress(target_val)
        refs = ref_mgr.getReferencesTo(target)
        ref_list = []
        for ref in refs:
            ref_list.append((ref.getFromAddress().getOffset(), ref.getReferenceType().toString()))
        print("  References to 0x{:05X}: {} refs".format(target_val, len(ref_list)))
        for from_addr, ref_type in ref_list[:10]:
            func = func_mgr.getFunctionContaining(space.getAddress(from_addr))
            fname = func.getName() if func else "unknown"
            print("    0x{:05X} ({}) in {}".format(from_addr, ref_type, fname))

    # Part 2: Decompile FUN_0006B590 (vtable init) — this is where context gets populated
    print("\n" + "=" * 70)
    print("PART 2: FUN_0006B590 — context vtable init (sets +0x660)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6B590))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6B590))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Look for 0x660 offset or dispatch pointer writes
            if '0x660' in c:
                print("  Contains 0x660 reference!")
            if '0x4f000' in c.lower() or '0x4f' in c:
                print("  Contains config buffer reference!")
            # Print full
            if len(c) <= 8000:
                print(c)
            else:
                print(c[:8000])

    # Part 3: FUN_0006BC64 — the main ABL4 boot function (calls SVC and post-SVC init)
    print("\n" + "=" * 70)
    print("PART 3: FUN_0006BC64 — main boot (post-SVC context init)")
    print("=" * 70)

    func = func_mgr.getFunctionAt(space.getAddress(0x6BC64))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x6BC64))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Search for references to config buffer or context
            config_refs = re.findall(r'0x4[fF]\w+', c)
            context_refs = re.findall(r'0x5[dD]\w+', c)
            if config_refs:
                print("  Config buffer refs: {}".format(set(config_refs)))
            if context_refs:
                print("  Context refs: {}".format(set(context_refs)))

            # Show the SVC and immediate post-SVC code
            svc_idx = c.find('software_interrupt')
            if svc_idx >= 0:
                start = max(0, svc_idx - 200)
                end = min(len(c), svc_idx + 2000)
                print("\n  Around SVC call:")
                print(c[start:end])
            else:
                # Print beginning (pre-SVC setup)
                if len(c) <= 8000:
                    print(c)
                else:
                    print(c[:8000])

    # Part 4: Search ALL ABL4 functions for memcpy-like copies from 0x4F000 area
    print("\n" + "=" * 70)
    print("PART 4: ALL ABL4 functions copying from config buffer region")
    print("=" * 70)

    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        f = func_iter.next()
        result = decomp.decompileFunction(f, 300, flat.getMonitor())
        if not result.decompileCompleted():
            continue
        c = result.getDecompiledFunction().getC()

        # Look for references to 0x4F or config-buffer-like addresses
        # Also look for large block copies (memcpy with size >= 0x100)
        if '0x4f' in c.lower():
            faddr = f.getEntryPoint().getOffset()
            # Extract the context
            matches = re.findall(r'0x4[fF][0-9a-fA-F]{3}', c)
            if matches:
                print("  {} at 0x{:05X}: config refs = {}".format(
                    f.getName(), faddr, set(matches)))

    # Part 5: PSP_BL — what writes to 0xB814 (the value that becomes 0x4F660)
    print("\n" + "=" * 70)
    print("PART 5: PSP_BL — writes to 0xB814 and 0x77E8 (config value source)")
    print("=" * 70)

    decomp.dispose()

# Open PSP_BL to check what populates 0xB814
with pyghidra.open_program(
    PSPBL_PATH, language="ARM:LE:32:Cortex", compiler="default",
    project_location=PROJECT_DIR, project_name="bc250_pspbl_v1", analyze=False
) as flat:
    program = flat.getCurrentProgram()
    af = program.getAddressFactory()
    space = af.getDefaultAddressSpace()
    func_mgr = program.getFunctionManager()
    ref_mgr = program.getReferenceManager()

    from ghidra.app.decompiler import DecompInterface
    decomp = DecompInterface()
    decomp.openProgram(program)

    # Check what references 0x77E8 (literal pool for the 0xB814 pointer)
    for target_addr in [0x77E8, 0xB814, 0x4F660]:
        target = space.getAddress(target_addr)
        refs = ref_mgr.getReferencesTo(target)
        ref_list = []
        for ref in refs:
            ref_list.append((ref.getFromAddress().getOffset(), ref.getReferenceType().toString()))
        if ref_list:
            print("  References to 0x{:05X}: {} refs".format(target_addr, len(ref_list)))
            for from_addr, ref_type in ref_list:
                func = func_mgr.getFunctionContaining(space.getAddress(from_addr))
                fname = func.getName() if func else "unknown"
                fentry = func.getEntryPoint().getOffset() if func else 0
                print("    0x{:04X} ({}) in {} (0x{:04X})".format(
                    from_addr, ref_type, fname, fentry))

    # Read the raw bytes at 0x77E8
    with open(PSPBL_PATH, "rb") as f:
        pspbl = f.read()
    val = struct.unpack_from("<I", pspbl, 0x77E8)[0]
    print("\n  [0x77E8] = 0x{:08X}".format(val))
    val = struct.unpack_from("<I", pspbl, 0x77E4)[0]
    print("  [0x77E4] = 0x{:08X}".format(val))

    # Decompile FUN_000075A4 one more time to see the full 0x4F000 write pattern
    func = func_mgr.getFunctionAt(space.getAddress(0x75A4))
    if func:
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            # Count all writes to 0x4F000 region
            writes = re.findall(r'_DAT_0004f[0-9a-fA-F]+', c)
            print("\n  FUN_000075A4 writes to 0x4F000 region:")
            for w in sorted(set(writes)):
                count = writes.count(w)
                print("    {} ({} writes)".format(w, count))

            # Find the 0x660 write specifically
            idx = c.find('0x660')
            if idx < 0:
                idx = c.find('f660')
            if idx >= 0:
                start = max(0, c.rfind('\n', 0, idx))
                end = min(len(c), c.find('\n', idx + 100) if c.find('\n', idx + 100) > 0 else idx + 100)
                print("\n  The +0x660 write:")
                print("    " + c[start:end].strip())

    decomp.dispose()

print("\nDone.")
