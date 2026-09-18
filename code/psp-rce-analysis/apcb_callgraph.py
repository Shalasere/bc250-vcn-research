#!/usr/bin/env python3
"""Build the complete call graph from FUN_00000300 (main boot) and identify
ALL functions reachable from the APCB processing path.

Then decompile each and look for:
1. Stack buffers with any variable-bound write (loops, pointer advances)
2. Unchecked size parameters used in any kind of copy/write
3. Array bounds violations
"""
import os, struct, re

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

PSPBL_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_pspbl_body.bin"

import pyghidra
GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects"

OUTPUT = r"C:\Users\WORK~1.DES\AppData\Local\Temp\claude\C--Users-work-DESKTOP-SAM98TB\c5f1fa55-5f57-4770-9f66-592352064239\scratchpad\apcb_callgraph_analysis.txt"

pyghidra.start(install_dir=GHIDRA_DIR)

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

    # Build call graph: for each function, find all functions it calls
    print("Building call graph...")
    call_graph = {}  # func_addr -> set of callee addrs
    func_map = {}    # addr -> (name, size, func_obj)

    func_iter = func_mgr.getFunctions(True)
    while func_iter.hasNext():
        f = func_iter.next()
        entry = f.getEntryPoint().getOffset()
        size = f.getBody().getNumAddresses()
        name = f.getName()
        func_map[entry] = (name, size, f)

        # Get called functions
        callees = set()
        called = f.getCalledFunctions(flat.getMonitor())
        for callee in called:
            callees.add(callee.getEntryPoint().getOffset())
        call_graph[entry] = callees

    print("Total functions: {}".format(len(func_map)))

    # BFS from FUN_00000300 to find all reachable functions
    root = 0x300
    visited = set()
    queue = [root]
    visited.add(root)
    depth_map = {root: 0}

    while queue:
        current = queue.pop(0)
        for callee in call_graph.get(current, set()):
            if callee not in visited:
                visited.add(callee)
                queue.append(callee)
                depth_map[callee] = depth_map[current] + 1

    print("Reachable from FUN_00000300: {} functions".format(len(visited)))

    # Now decompile ALL reachable functions and do deep overflow analysis
    # Focus on: any function with a stack frame that has variable-bound writes

    results = []

    reachable_sorted = sorted(visited)
    for idx, addr in enumerate(reachable_sorted):
        if idx % 20 == 0:
            print("  Analyzing: {}/{} ...".format(idx, len(reachable_sorted)))

        if addr not in func_map:
            continue

        name, size, func = func_map[addr]

        result = decomp.decompileFunction(func, 180, flat.getMonitor())
        if not result or not result.decompileCompleted():
            continue

        c = result.getDecompiledFunction().getC()
        c_lower = c.lower()
        lines = c.split('\n')

        findings = []

        # Check 1: Stack buffers (auStack_XX pattern)
        stack_bufs = re.findall(r'(auStack_([0-9a-fA-F]+))\s*\[(\d+)\]', c)
        local_arrays = re.findall(r'(local_([0-9a-fA-F]+))\s*\[(\d+)\]', c)

        all_stack_vars = []
        for full_name, offset_hex, arr_size in stack_bufs + local_arrays:
            all_stack_vars.append((full_name, int(offset_hex, 16), int(arr_size)))

        if not all_stack_vars:
            continue  # No stack buffers, skip

        for var_name, offset, arr_size in all_stack_vars:
            findings.append("Stack var: {} (offset 0x{:X}, {} bytes)".format(var_name, offset, arr_size))

        # Check 2: For each stack buffer, find ALL writes to it
        for var_name, offset, arr_size in all_stack_vars:
            # Look for writes: var_name[expr] = ... or via pointer arithmetic
            # Pattern 1: direct indexed write
            write_patterns = re.findall(
                r'{}(\[[^\]]*\])\s*='.format(re.escape(var_name)), c)
            for wp in write_patterns:
                index_expr = wp.strip('[]')
                # Check if index contains a param or variable (not just constant)
                if ('param_' in index_expr or
                    any(v in index_expr for v in ['iVar', 'uVar', 'local_'])):
                    findings.append("WRITE with variable index: {}{}".format(var_name, wp))

            # Pattern 2: memcpy/copy to this buffer with variable size
            copy_pattern = re.findall(
                r'FUN_00000458\([^,]*{}[^,]*,([^,]+),([^)]+)\)'.format(re.escape(var_name)), c)
            for src, size_arg in copy_pattern:
                size_arg = size_arg.strip()
                if ('param_' in size_arg or
                    any(v in size_arg for v in ['iVar', 'uVar', 'local_'])):
                    findings.append("MEMCPY variable size to {}: size={}".format(var_name, size_arg))

        # Check 3: Look for any loop that writes to stack memory
        # Pattern: for/while/do with stack-relative write inside
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Check for loops writing to stack buffers
            for var_name, offset, arr_size in all_stack_vars:
                if var_name in stripped and '=' in stripped and '[' in stripped:
                    # Is this inside a loop? Check surrounding context
                    ctx_start = max(0, i - 5)
                    ctx_end = min(len(lines), i + 2)
                    context_block = '\n'.join(lines[ctx_start:ctx_end])
                    if any(kw in context_block.lower() for kw in ['while', 'for (', 'do {']):
                        index_match = re.search(r'\[([^\]]+)\]', stripped)
                        if index_match:
                            idx_expr = index_match.group(1)
                            if ('param_' in idx_expr or
                                any(v in idx_expr for v in ['iVar', 'uVar', 'local_'])):
                                findings.append("LOOP WRITE to {} at line {}: {}".format(
                                    var_name, i, stripped.strip()))

        # Check 4: Functions receiving external data pointers + sizes
        # Look for parameter patterns suggesting buffer processing
        sig_match = re.search(r'FUN_[0-9a-f]+\(([^)]*)\)', lines[0] + lines[1] if len(lines) > 1 else lines[0])

        # Check 5: Pointer arithmetic past buffer end
        for var_name, offset, arr_size in all_stack_vars:
            # Look for var_name + expr where expr could exceed arr_size
            arith_patterns = re.findall(
                r'{}\s*\+\s*([^\s;,\)]+)'.format(re.escape(var_name)), c)
            for expr in arith_patterns:
                if ('param_' in expr or
                    any(v in expr for v in ['iVar', 'uVar', 'local_'])):
                    findings.append("PTR ARITH past {}: {} + {}".format(var_name, var_name, expr))

        # Only save if we found something interesting
        has_vuln_indicator = any(
            'WRITE with variable' in f or 'MEMCPY variable' in f or
            'LOOP WRITE' in f or 'PTR ARITH' in f
            for f in findings
        )

        if has_vuln_indicator:
            results.append((addr, name, size, depth_map.get(addr, -1), findings, c))

    # Write results
    with open(OUTPUT, "w", encoding="utf-8") as out:
        out.write("APCB Call Graph Overflow Analysis\n")
        out.write("=" * 70 + "\n\n")
        out.write("Reachable from FUN_00000300: {} functions\n".format(len(visited)))
        out.write("Functions with stack buffers: (analyzed above)\n")
        out.write("Functions with variable-bound writes to stack: {}\n\n".format(len(results)))

        # Sort by depth (closest to root = most directly reachable)
        results.sort(key=lambda x: x[3])

        for addr, name, size, depth, findings, c in results:
            out.write("=" * 70 + "\n")
            out.write("[0x{:04X}] {} ({} bytes) — depth {} from FUN_00000300\n".format(
                addr, name, size, depth))
            out.write("Findings:\n")
            for f in findings:
                out.write("  - {}\n".format(f))
            out.write("\nFull decompilation:\n")
            out.write(c)
            out.write("\n\n")

    decomp.dispose()

print("\nResults written to: {}".format(OUTPUT))
print("\nFunctions with variable-bound stack writes (reachable from boot):")
for addr, name, size, depth, findings, _ in sorted(results, key=lambda x: x[3]):
    vuln_findings = [f for f in findings if 'WRITE' in f or 'MEMCPY' in f or 'LOOP' in f or 'PTR ARITH' in f]
    print("  0x{:04X} {} (depth {}, {} bytes):".format(addr, name, depth, size))
    for f in vuln_findings:
        print("    {}".format(f))
