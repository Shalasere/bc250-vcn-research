#!/usr/bin/env python3
"""Hunt for INDIRECT stack buffer overflows in PSP_BL.

Pattern: a function allocates a stack buffer, passes a pointer to it
to a callee, and the callee writes more than the buffer size because
the size comes from attacker-controlled data (APCB).

Also: look for ANY function call where:
  arg1 = stack_buffer_ptr AND arg2 or arg3 = variable_size

And: look for functions processing APCB token data (variable-length
fields from the APCB binary).
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

OUTPUT = r"C:\Users\WORK~1.DES\AppData\Local\Temp\claude\C--Users-work-DESKTOP-SAM98TB\c5f1fa55-5f57-4770-9f66-592352064239\scratchpad\indirect_overflow_results.txt"

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

    # Get all functions
    all_funcs = []
    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        f = func_iter.next()
        entry = f.getEntryPoint().getOffset()
        all_funcs.append((entry, f))
    all_funcs.sort()
    print("Total functions: {}".format(len(all_funcs)))

    results = []

    for idx, (entry, func) in enumerate(all_funcs):
        if idx % 30 == 0:
            print("  Progress: {}/{} ...".format(idx, len(all_funcs)))

        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if not result or not result.decompileCompleted():
            continue

        c = result.getDecompiledFunction().getC()
        name = func.getName()
        size = func.getBody().getNumAddresses()

        # Find all stack variables (buffers AND scalars passed by address)
        stack_bufs = {}
        for m in re.finditer(r'(auStack_([0-9a-fA-F]+))\s*\[(\d+)\]', c):
            var_name = m.group(1)
            offset = int(m.group(2), 16)
            arr_size = int(m.group(3))
            stack_bufs[var_name] = arr_size

        for m in re.finditer(r'(local_([0-9a-fA-F]+))\s*\[(\d+)\]', c):
            var_name = m.group(1)
            offset = int(m.group(2), 16)
            arr_size = int(m.group(3))
            stack_bufs[var_name] = arr_size

        if not stack_bufs:
            continue

        findings = []

        # Find ALL function calls in this decompilation
        # Pattern: FUN_XXXXXXXX(args)
        call_pattern = re.compile(r'(FUN_[0-9a-fA-F]+)\(([^)]*)\)')
        for m in call_pattern.finditer(c):
            callee_name = m.group(1)
            args_str = m.group(2)

            # Parse arguments (handle nested parens)
            args = []
            depth = 0
            current = ""
            for ch in args_str:
                if ch == ',' and depth == 0:
                    args.append(current.strip())
                    current = ""
                else:
                    if ch == '(':
                        depth += 1
                    elif ch == ')':
                        depth -= 1
                    current += ch
            if current.strip():
                args.append(current.strip())

            # Check if ANY argument is a stack buffer reference
            for i, arg in enumerate(args):
                for buf_name, buf_size in stack_bufs.items():
                    if buf_name in arg:
                        # Stack buffer is passed as an argument!
                        # Check if any OTHER argument is a variable (param, iVar, etc.)
                        # that could be a size
                        other_args = args[:i] + args[i+1:]
                        var_size_args = []
                        for j, other in enumerate(other_args):
                            other_stripped = other.strip()
                            # Is this a variable that could be a size?
                            is_variable = ('param_' in other_stripped or
                                         'iVar' in other_stripped or
                                         'uVar' in other_stripped or
                                         'local_' in other_stripped)
                            # Skip if it's clearly a pointer (has & or *)
                            if is_variable and '&' not in other_stripped:
                                var_size_args.append(other_stripped)

                        if var_size_args:
                            # Check: is there a bounds check on the variable args?
                            # Simple heuristic: search for comparisons in context
                            has_check = False
                            for varg in var_size_args:
                                # Look for "varg < CONST" or "varg <= CONST" or
                                # "CONST < varg" patterns near the call
                                base_var = varg.split('[')[0].split('+')[0].split('*')[0].strip()
                                if base_var:
                                    check_patterns = [
                                        r'{}\s*<\s*0x[0-9a-fA-F]+'.format(re.escape(base_var)),
                                        r'{}\s*<=\s*0x[0-9a-fA-F]+'.format(re.escape(base_var)),
                                        r'{}\s*<\s*\d+'.format(re.escape(base_var)),
                                        r'0x[0-9a-fA-F]+\s*<\s*{}'.format(re.escape(base_var)),
                                    ]
                                    for cp in check_patterns:
                                        if re.search(cp, c):
                                            has_check = True
                                            break

                            tag = "CHECKED" if has_check else "*** UNCHECKED ***"
                            findings.append(
                                "{}: {}({}) -- stack buf {} ({} bytes) at arg {}, "
                                "variable args: {} {}".format(
                                    tag, callee_name, ', '.join(args[:3]) + ('...' if len(args) > 3 else ''),
                                    buf_name, buf_size, i,
                                    var_size_args, tag))

        # Also check: functions that take &stack_var (address of scalar on stack)
        # and a variable size
        addr_of_pattern = re.compile(r'&(local_[0-9a-fA-F]+|auStack_[0-9a-fA-F]+)')
        for m in addr_of_pattern.finditer(c):
            var_name = m.group(1)
            # This is address-of a stack variable passed to a function
            # Find the enclosing function call
            pos = m.start()
            # Walk backward to find the function name
            prefix = c[:pos]
            func_match = re.search(r'(FUN_[0-9a-fA-F]+)\([^)]*$', prefix)
            if func_match:
                findings.append("ADDR-OF stack var: &{} passed to {}".format(
                    var_name, func_match.group(1)))

        if findings:
            # Filter to only unchecked or interesting
            interesting = [f for f in findings if 'UNCHECKED' in f or 'ADDR-OF' in f]
            if interesting:
                results.append((entry, name, size, interesting, c))

    # Write output
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("Indirect Stack Buffer Overflow Analysis\n")
        out.write("=" * 70 + "\n\n")
        out.write("Functions with unchecked stack buffer passing: {}\n\n".format(len(results)))

        for addr, name, size, findings, c in results:
            out.write("=" * 70 + "\n")
            out.write("[0x{:04X}] {} ({} bytes)\n".format(addr, name, size))
            out.write("Findings:\n")
            for f in findings:
                out.write("  {}\n".format(f))
            out.write("\nFull decompilation:\n")
            out.write(c[:6000])
            if len(c) > 6000:
                out.write("\n... (truncated at 6000 chars)\n")
            out.write("\n\n")

    decomp.dispose()

print("\nResults written to: {}".format(OUTPUT))
print("\n*** UNCHECKED findings:")
for addr, name, size, findings, _ in results:
    unchecked = [f for f in findings if 'UNCHECKED' in f]
    if unchecked:
        print("\n  [0x{:04X}] {} ({} bytes):".format(addr, name, size))
        for f in unchecked:
            print("    {}".format(f))
