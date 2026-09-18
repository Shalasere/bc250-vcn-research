#!/usr/bin/env python3
"""Final overflow hunt:
1. Decompile FUN_00002434 (param-dependent copy to stack buffer)
2. Check ALL 17 FUN_0000823c callers for param_5 value
3. Decompile unexplored callers: FUN_00008168, FUN_000082B0, FUN_000067DC,
   FUN_0000683C, FUN_00005850, FUN_00007160, FUN_00004412
4. Decompile FUN_00003BA4 (copies 0x100 to stack buffer)
5. Check FUN_000024FC (calls FUN_000004e0 at 0x2544)
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

    # Priority 1: FUN_00002434 (stack buffer + param-dependent copy)
    targets = [
        (0x2434, "*** FUN_00002434 — PARAM-DEPENDENT STACK BUFFER COPY ***"),
        (0x8168, "FUN_00008168 — calls FUN_0000823c"),
        (0x82B0, "FUN_000082B0 — calls FUN_0000823c"),
        (0x67DC, "FUN_000067DC — calls FUN_0000823c (x2)"),
        (0x683C, "FUN_0000683C — calls FUN_0000823c (x2)"),
        (0x5850, "FUN_00005850 — calls FUN_0000823c (x2)"),
        (0x7160, "FUN_00007160 — calls FUN_0000823c"),
        (0x4412, "FUN_00004412 — calls FUN_0000823c"),
        (0x3BA4, "FUN_00003BA4 — copies to stack buffer auStack_128"),
        (0x24FC, "FUN_000024FC — calls FUN_000004e0"),
        (0x300, "FUN_00000300 — calls FUN_0000823c and FUN_000004e0"),
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

        # Stack buffer analysis
        buffers = re.findall(r'(auStack_[0-9a-f]+)\s*\[(\d+)\]', c, re.I)
        if buffers:
            for name, size in buffers:
                print("  STACK BUFFER: {} [{}]".format(name, size))

        # Find FUN_0000823c calls with their param_5 value
        idx = 0
        while True:
            idx = c.find('FUN_0000823c', idx)
            if idx < 0:
                break
            end = c.find(';', idx)
            if end > 0:
                call_text = c[idx:end].strip()
                # Count args by commas
                paren_start = call_text.find('(')
                paren_end = call_text.rfind(')')
                if paren_start > 0 and paren_end > 0:
                    args = call_text[paren_start+1:paren_end].split(',')
                    if len(args) >= 5:
                        p5 = args[4].strip()
                        if p5 == '0':
                            print("  823c call param_5=0 (BOUNDED): {}".format(call_text))
                        else:
                            print("  823c call param_5={} *** CHECK ***: {}".format(p5, call_text))
                    else:
                        print("  823c call ({} args): {}".format(len(args), call_text))
                else:
                    print("  823c call: {}".format(call_text))
            idx += 1

        # Find FUN_000004e0/FUN_00000458 calls involving stack buffers
        for copy_fn in ['FUN_000004e0', 'FUN_00000458']:
            idx = 0
            while True:
                idx = c.find(copy_fn, idx)
                if idx < 0:
                    break
                end = c.find(';', idx)
                if end > 0:
                    call_text = c[idx:end].strip()
                    has_stack = any(b[0] in call_text for b in buffers)
                    has_param = 'param_' in call_text
                    if has_stack or has_param:
                        flags = []
                        if has_stack:
                            flags.append("STACK")
                        if has_param:
                            flags.append("PARAM")
                        print("  DIRECT COPY [{}]: {}".format("+".join(flags), call_text))
                idx += 1

        # Print full decompile
        if len(c) <= 4000:
            print(c)
        else:
            print(c[:4000])
            print("\n... ({} more chars)".format(len(c) - 4000))

    decomp.dispose()

print("\nDone.")
