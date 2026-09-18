#!/usr/bin/env python3
"""Find ALL callers of FUN_0000823C and FUN_00008150 (wrapper).
For each: determine if dest is stack var and size is variable.

The vulnerability is: FUN_0000823C copies N bytes to a buffer,
checks N < 0x800000 (DRAM window), but NOT N < buffer_size.
If buffer_size < N, overflow occurs.

Also: search for ALL functions with stack frames > 0x40 that call
ANY copy function (FUN_000004E0, FUN_00000458, FUN_0000823C,
FUN_00008150, FUN_00001C18).
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"
with open(PSPBL_PATH, "rb") as f:
    pspbl = f.read()

from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
cs = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
cs.detail = True

# Find ALL call sites to copy functions
copy_funcs = {
    0x823C: "FUN_0000823C (bounded DRAM copy)",
    0x8150: "FUN_00008150 (823C wrapper)",
    0x4E0: "FUN_000004E0 (memcpy)",
    0x458: "FUN_00000458 (memcpy small)",
    0x1C18: "FUN_00001C18 (DMA copy)",
}

print("=" * 70)
print("ALL call sites to copy functions")
print("=" * 70)

all_copy_calls = []
for target, name in copy_funcs.items():
    target_str = "0x{:x}".format(target)
    for off in range(0, len(pspbl) - 3, 2):
        insns = list(cs.disasm(pspbl[off:off+4], off))
        for insn in insns:
            if insn.mnemonic == 'bl' and target_str in insn.op_str:
                all_copy_calls.append((off, target, name))

print("  Found {} total copy call sites".format(len(all_copy_calls)))
for off, target, name in sorted(all_copy_calls):
    print("  0x{:04X}: bl 0x{:04X} ({})".format(off, target, name))

# Now: Ghidra decompile to check each caller
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

    # Get unique functions containing copy calls
    func_copy_calls = {}  # func_addr -> list of (call_off, target, name)
    for off, target, name in all_copy_calls:
        func = func_mgr.getFunctionContaining(space.getAddress(off))
        if func:
            addr = func.getEntryPoint().getOffset()
            if addr not in func_copy_calls:
                func_copy_calls[addr] = []
            func_copy_calls[addr].append((off, target, name))

    print("\n" + "=" * 70)
    print("Decompiling {} unique functions with copy calls".format(len(func_copy_calls)))
    print("=" * 70)

    vulnerables = []

    for func_addr in sorted(func_copy_calls.keys()):
        func = func_mgr.getFunctionAt(space.getAddress(func_addr))
        if not func:
            continue

        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if not result.decompileCompleted():
            continue

        c = result.getDecompiledFunction().getC()
        fname = func.getName()
        fsize = func.getBody().getNumAddresses()

        # Check for stack buffers
        stack_buffers = re.findall(r'(auStack_[0-9a-f]+)\s+\[(\d+)\]', c, re.I)
        has_stack_buf = len(stack_buffers) > 0

        # Check for variable-size copy calls
        # FUN_0000823C(dest, offset, SIZE, buf_size, flag)
        # FUN_00008150(dest, offset, SIZE, buf_size, flag)
        # FUN_000004E0(dest, src, SIZE) — memcpy
        # If SIZE is a constant (0x100, 0x200, etc.), it's bounded
        # If SIZE is a variable (param_*, local_*, *, etc.), it might overflow

        copy_patterns = re.findall(
            r'FUN_0000(?:823c|8150|04e0|0458|1c18)\([^)]+\)', c, re.I)

        # Check each copy call for variable sizes
        variable_size_copies = []
        for pattern in copy_patterns:
            # Parse the arguments
            args = pattern.split('(')[1].rstrip(')').split(',')
            # For memcpy (FUN_000004E0), 3rd arg is size
            # For FUN_0000823C/8150, 3rd arg is size
            if len(args) >= 3:
                size_arg = args[2].strip()
                # Is it a constant?
                is_const = bool(re.match(r'^0x[0-9a-f]+$', size_arg, re.I) or
                              re.match(r'^\d+$', size_arg))
                if not is_const:
                    variable_size_copies.append((pattern, size_arg))

        # Report interesting functions
        if has_stack_buf and variable_size_copies:
            vulnerables.append(func_addr)
            print("\n" + "!" * 60)
            print("POTENTIAL VULNERABILITY: {} at 0x{:04X} ({} bytes)".format(
                fname, func_addr, fsize))
            print("!" * 60)
            print("  Stack buffers: {}".format(
                [(n, s) for n, s in stack_buffers]))
            print("  Variable-size copies:")
            for pattern, size_arg in variable_size_copies:
                print("    {} (size={})".format(pattern, size_arg))
            print("\n  FULL DECOMPILE:")
            if len(c) <= 8000:
                print(c)
            else:
                print(c[:8000])
                print("  ... ({} more chars)".format(len(c) - 8000))
        elif variable_size_copies:
            # No stack buffer but variable copy — might overflow a global
            print("\n  {} at 0x{:04X}: variable-size copy to GLOBAL buffer".format(
                fname, func_addr))
            for pattern, size_arg in variable_size_copies:
                print("    {} (size={})".format(pattern, size_arg))
            if has_stack_buf:
                print("    Stack buffers: {}".format(
                    [(n, s) for n, s in stack_buffers]))
        elif has_stack_buf and copy_patterns:
            # Stack buffer with constant-size copies — might still overflow
            # if the constant exceeds the buffer
            for n, s in stack_buffers:
                for pattern in copy_patterns:
                    args = pattern.split('(')[1].rstrip(')').split(',')
                    if len(args) >= 3:
                        size_arg = args[2].strip()
                        try:
                            size_val = int(size_arg, 0)
                            buf_size = int(s)
                            if size_val > buf_size:
                                vulnerables.append(func_addr)
                                print("\n  {} at 0x{:04X}: CONSTANT OVERFLOW!".format(
                                    fname, func_addr))
                                print("    Buffer: {} [{}]".format(n, s))
                                print("    Copy: {} (size=0x{:X} > {})".format(
                                    pattern, size_val, s))
                        except ValueError:
                            pass

    print("\n" + "=" * 70)
    print("SUMMARY: {} potential vulnerabilities".format(len(vulnerables)))
    print("=" * 70)
    for addr in vulnerables:
        func = func_mgr.getFunctionAt(space.getAddress(addr))
        print("  0x{:04X}: {}".format(addr, func.getName() if func else "???"))

    # Also: decompile FUN_00008500 — called multiple times in token chain
    print("\n" + "=" * 70)
    print("BONUS: FUN_00008500 — signature/hash verification")
    print("=" * 70)
    func = func_mgr.getFunctionAt(space.getAddress(0x8500))
    if not func:
        func = func_mgr.getFunctionContaining(space.getAddress(0x8500))
    if func:
        entry = func.getEntryPoint().getOffset()
        size = func.getBody().getNumAddresses()
        print("  {} at 0x{:04X} ({} bytes)".format(func.getName(), entry, size))
        result = decomp.decompileFunction(func, 600, flat.getMonitor())
        if result.decompileCompleted():
            c = result.getDecompiledFunction().getC()
            print("  {} chars".format(len(c)))
            if len(c) <= 3000:
                print(c)
            else:
                print(c[:3000])

    decomp.dispose()

print("\nDone.")
