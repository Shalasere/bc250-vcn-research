"""
PSP_BL inline copy loop and unbounded stack write hunter.
Searches all 321 functions for:
  1. Inline copy loops (load+store with incrementing index)
  2. Variable-length writes to stack buffers
  3. APCB token reads into stack buffers with variable size
  4. Deep analysis of FUN_000053C4 (largest stack buffer)
  5. Full decompile of specific under-analyzed functions
"""

import os, sys, re, traceback

os.environ["JAVA_HOME"] = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\jdk\jdk-21.0.12+8"
os.environ["PATH"] = os.path.join(os.environ["JAVA_HOME"], "bin") + os.pathsep + os.environ.get("PATH", "")

import pyghidra

GHIDRA_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra-vcn\ghidra\ghidra_12.1.2_PUBLIC"
PROJECT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\ghidra_projects\bc250_pspbl_v1"
PROJECT_NAME = "bc250_pspbl_v1"

pyghidra.start(install_dir=GHIDRA_DIR)

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import CodeUnit
from java.io import File

# Open existing project
from ghidra.base.project import GhidraProject
project = GhidraProject.openProject(PROJECT_DIR, PROJECT_NAME)
program = project.openProgram("/", "internal_pspbl_body.bin", False)

monitor = ConsoleTaskMonitor()
decomp = DecompInterface()
opts = DecompileOptions()
opts.setMaxWidth(160)
decomp.setOptions(opts)
decomp.openProgram(program)

fm = program.getFunctionManager()
listing = program.getListing()

# Known copy functions to exclude from "inline" analysis
KNOWN_COPY_FUNCS = {
    0x000004e0,  # memcpy
    0x00000458,  # memmove
    0x0000823c,  # bounded_copy
    0x00008150,  # copy_wrapper
    0x00001c18,  # DMA_copy
    0x0000237c,  # DMA_decompress
}

KNOWN_COPY_NAMES = {"FUN_000004e0", "FUN_00000458", "FUN_0000823c", "FUN_00008150", "FUN_00001c18", "FUN_0000237c",
                    "memcpy", "memmove", "bounded_copy", "copy_wrapper", "DMA_copy", "DMA_decompress"}

# APCB token reader functions
APCB_READERS = {"FUN_00000850", "FUN_00004412"}

# Functions to fully decompile
TARGET_FUNCS = {
    0x000053c4: "FUN_000053C4 (largest stack buf, SVC 0xDE)",
    0x000062be: "FUN_000062BE (alt copy path from FUN_000071AC)",
    0x00001f40: "FUN_00001F40 (param_5 != 0 path in FUN_000071AC)",
    0x000018e4: "FUN_000018E4 (S3 resume path)",
    0x000067dc: "FUN_000067DC (calls bounded_copy x2)",
    0x0000683c: "FUN_0000683C (calls bounded_copy x2)",
    0x000082b0: "FUN_000082B0 (calls bounded_copy)",
}

print("=" * 100)
print("PSP_BL INLINE COPY LOOP AND UNBOUNDED STACK WRITE HUNTER")
print("=" * 100)

# Collect all functions
all_funcs = []
func_iter = fm.getFunctions(True)  # forward iterator
while func_iter.hasNext():
    all_funcs.append(func_iter.next())

print(f"\nTotal functions found: {len(all_funcs)}")

# ============================================================
# PHASE 1: Decompile all functions, search for patterns
# ============================================================
print("\n" + "=" * 100)
print("PHASE 1: DECOMPILING ALL FUNCTIONS - SEARCHING FOR INLINE COPY PATTERNS")
print("=" * 100)

# Patterns to detect inline copy loops
# Pattern 1: array index copy  dest[i] = src[i]  or  *(ptr + i) = *(ptr2 + i)
ARRAY_COPY_PAT = re.compile(
    r'\[([a-zA-Z_]\w*)\]\s*=\s*[^;]*\[\s*\1\s*\]', re.MULTILINE
)

# Pattern 2: pointer increment copy  *dst++ = *src++  or  *dst = *src; dst++; src++
PTR_INC_COPY_PAT = re.compile(
    r'\*\s*([a-zA-Z_]\w*)\s*=\s*\*\s*([a-zA-Z_]\w*)\s*;', re.MULTILINE
)

# Pattern 3: do/while with store pattern (common in Ghidra decompiler output)
DO_WHILE_COPY_PAT = re.compile(
    r'do\s*\{[^}]*(\w+)\s*\[\s*\w+\s*\]\s*=[^}]*\}\s*while', re.DOTALL
)

# Pattern 4: while loop with array write
WHILE_COPY_PAT = re.compile(
    r'while\s*\([^)]*\)\s*\{[^}]*(\w+)\s*\[\s*\w+\s*\]\s*=', re.DOTALL
)

# Pattern 5: for loop with array copy
FOR_COPY_PAT = re.compile(
    r'for\s*\([^)]*\)\s*\{[^}]*(\w+)\s*\[\s*\w+\s*\]\s*=', re.DOTALL
)

# Pattern 6: Variable-length stack buffer write
# Look for auStack_* with variable index
STACK_VAR_WRITE_PAT = re.compile(
    r'(auStack_\w+|local_\w+)\s*\[\s*([a-zA-Z_]\w*)\s*\]', re.MULTILINE
)

# Pattern 7: APCB token read into stack buffer
APCB_TO_STACK_PAT = re.compile(
    r'(FUN_00000850|FUN_00004412)\s*\([^)]*auStack_', re.MULTILINE
)

# Pattern 8: memcpy/memmove to stack buffer with variable size
COPY_TO_STACK_PAT = re.compile(
    r'(FUN_000004e0|FUN_00000458|memcpy|memmove)\s*\(\s*(auStack_\w+|&auStack_\w+|\(void\s*\*\)\s*auStack_\w+)[^)]*,\s*[^)]*,\s*([a-zA-Z_]\w+)\s*\)',
    re.MULTILINE
)

# Pattern 9: bounded_copy / copy_wrapper to stack buffer
BOUNDED_TO_STACK_PAT = re.compile(
    r'(FUN_0000823c|FUN_00008150)\s*\([^)]*auStack_', re.MULTILINE
)

inline_copy_hits = []
stack_var_write_hits = []
apcb_stack_hits = []
copy_to_stack_hits = []
bounded_to_stack_hits = []
large_stack_funcs = []

# Full decompile storage for target functions
target_decompiles = {}

decompile_failures = []

for i, func in enumerate(all_funcs):
    addr = func.getEntryPoint().getOffset()
    name = func.getName()

    result = decomp.decompileFunction(func, 120, monitor)
    if not result.decompileCompleted():
        decompile_failures.append(f"  {name} @ 0x{addr:08x}: {result.getErrorMessage()}")
        continue

    decomp_func = result.getDecompiledFunction()
    if decomp_func is None:
        decompile_failures.append(f"  {name} @ 0x{addr:08x}: getDecompiledFunction() returned None")
        continue

    c_code = decomp_func.getC()
    if c_code is None:
        continue

    # Store target function decompiles
    if addr in TARGET_FUNCS:
        target_decompiles[addr] = (name, TARGET_FUNCS[addr], c_code)

    # Skip known copy functions themselves
    if addr in KNOWN_COPY_FUNCS:
        continue

    # Check for inline copy patterns
    for pat_name, pat in [
        ("array_index_copy", ARRAY_COPY_PAT),
        ("ptr_inc_copy", PTR_INC_COPY_PAT),
        ("do_while_copy", DO_WHILE_COPY_PAT),
        ("while_copy", WHILE_COPY_PAT),
        ("for_copy", FOR_COPY_PAT),
    ]:
        matches = pat.findall(c_code)
        if matches:
            inline_copy_hits.append((name, addr, pat_name, matches, c_code))

    # Check for variable writes to stack buffers
    stack_writes = STACK_VAR_WRITE_PAT.findall(c_code)
    if stack_writes:
        # Filter: only report if the index is NOT a constant and IS in a loop-like context
        for buf_name, idx_var in stack_writes:
            # Skip if index is a constant number
            if re.match(r'^\d+$', idx_var):
                continue
            # Skip if it's just reading (not writing)
            # Look for the full line to check if it's an lvalue
            write_pat = re.compile(rf'{re.escape(buf_name)}\s*\[\s*{re.escape(idx_var)}\s*\]\s*=')
            if write_pat.search(c_code):
                stack_var_write_hits.append((name, addr, buf_name, idx_var, c_code))

    # Check APCB reads into stack
    if APCB_TO_STACK_PAT.search(c_code):
        apcb_stack_hits.append((name, addr, c_code))

    # Check memcpy/memmove to stack with variable size
    copy_matches = COPY_TO_STACK_PAT.findall(c_code)
    if copy_matches:
        copy_to_stack_hits.append((name, addr, copy_matches, c_code))

    # Check bounded_copy to stack
    if BOUNDED_TO_STACK_PAT.search(c_code):
        bounded_to_stack_hits.append((name, addr, c_code))

    # Track functions with large stack buffers
    stack_match = re.findall(r'auStack_([0-9a-fA-F]+)', c_code)
    if stack_match:
        max_stack = max(int(x, 16) for x in stack_match)
        if max_stack >= 0x80:  # 128+ bytes
            large_stack_funcs.append((name, addr, max_stack, c_code))

print(f"\nDecompilation complete. Failures: {len(decompile_failures)}")
if decompile_failures:
    for f in decompile_failures[:10]:
        print(f)

# ============================================================
# REPORT: INLINE COPY LOOPS
# ============================================================
print("\n" + "=" * 100)
print("RESULTS: INLINE COPY LOOPS")
print("=" * 100)

if inline_copy_hits:
    # Deduplicate by function
    seen = set()
    for name, addr, pat_name, matches, c_code in inline_copy_hits:
        key = (name, pat_name)
        if key in seen:
            continue
        seen.add(key)
        print(f"\n{'~' * 80}")
        print(f"INLINE COPY HIT: {name} @ 0x{addr:08x} (pattern: {pat_name})")
        print(f"{'~' * 80}")
        # Print relevant portion - find the loop context
        lines = c_code.split('\n')
        for j, line in enumerate(lines):
            # Print lines around any match
            for m in (matches if isinstance(matches, list) else [matches]):
                m_str = m if isinstance(m, str) else str(m)
                if m_str in line or '[' in line and '=' in line:
                    start = max(0, j - 5)
                    end = min(len(lines), j + 10)
                    print(f"  Lines {start}-{end}:")
                    for k in range(start, end):
                        marker = ">>>" if k == j else "   "
                        print(f"  {marker} {lines[k]}")
                    print()
                    break
else:
    print("\nNo inline copy loops detected via regex patterns.")

# ============================================================
# REPORT: VARIABLE-LENGTH STACK BUFFER WRITES
# ============================================================
print("\n" + "=" * 100)
print("RESULTS: VARIABLE-LENGTH STACK BUFFER WRITES")
print("=" * 100)

if stack_var_write_hits:
    seen = set()
    for name, addr, buf_name, idx_var, c_code in stack_var_write_hits:
        key = (name, buf_name, idx_var)
        if key in seen:
            continue
        seen.add(key)
        print(f"\n  {name} @ 0x{addr:08x}: {buf_name}[{idx_var}] = ...")
        # Find the line
        lines = c_code.split('\n')
        for j, line in enumerate(lines):
            if buf_name in line and idx_var in line and '=' in line:
                start = max(0, j - 3)
                end = min(len(lines), j + 5)
                for k in range(start, end):
                    marker = ">>>" if k == j else "   "
                    print(f"    {marker} {lines[k]}")
                break
else:
    print("\nNo variable-length stack buffer writes detected.")

# ============================================================
# REPORT: APCB TOKEN READS INTO STACK BUFFERS
# ============================================================
print("\n" + "=" * 100)
print("RESULTS: APCB TOKEN READS INTO STACK BUFFERS")
print("=" * 100)

if apcb_stack_hits:
    for name, addr, c_code in apcb_stack_hits:
        print(f"\n  {name} @ 0x{addr:08x}")
        lines = c_code.split('\n')
        for j, line in enumerate(lines):
            if ('FUN_00000850' in line or 'FUN_00004412' in line) and 'auStack' in line:
                start = max(0, j - 5)
                end = min(len(lines), j + 5)
                for k in range(start, end):
                    marker = ">>>" if k == j else "   "
                    print(f"    {marker} {lines[k]}")
                print()
else:
    print("\nNo APCB token reads into stack buffers detected.")

# ============================================================
# REPORT: MEMCPY/MEMMOVE TO STACK WITH VARIABLE SIZE
# ============================================================
print("\n" + "=" * 100)
print("RESULTS: MEMCPY/MEMMOVE TO STACK WITH VARIABLE SIZE")
print("=" * 100)

if copy_to_stack_hits:
    for name, addr, matches, c_code in copy_to_stack_hits:
        print(f"\n  {name} @ 0x{addr:08x}")
        for m in matches:
            print(f"    Call: {m[0]}(<stack>, ..., size={m[2]})")
        lines = c_code.split('\n')
        for j, line in enumerate(lines):
            if ('FUN_000004e0' in line or 'FUN_00000458' in line) and 'auStack' in line:
                start = max(0, j - 3)
                end = min(len(lines), j + 3)
                for k in range(start, end):
                    marker = ">>>" if k == j else "   "
                    print(f"    {marker} {lines[k]}")
                print()
else:
    print("\nNo memcpy/memmove to stack with variable size detected.")

# ============================================================
# REPORT: BOUNDED_COPY TO STACK
# ============================================================
print("\n" + "=" * 100)
print("RESULTS: BOUNDED_COPY / COPY_WRAPPER TO STACK")
print("=" * 100)

if bounded_to_stack_hits:
    for name, addr, c_code in bounded_to_stack_hits:
        print(f"\n  {name} @ 0x{addr:08x}")
        lines = c_code.split('\n')
        for j, line in enumerate(lines):
            if ('FUN_0000823c' in line or 'FUN_00008150' in line) and 'auStack' in line:
                start = max(0, j - 3)
                end = min(len(lines), j + 5)
                for k in range(start, end):
                    marker = ">>>" if k == j else "   "
                    print(f"    {marker} {lines[k]}")
                print()
else:
    print("\nNo bounded_copy/copy_wrapper to stack detected.")

# ============================================================
# REPORT: LARGE STACK BUFFER FUNCTIONS
# ============================================================
print("\n" + "=" * 100)
print("RESULTS: FUNCTIONS WITH LARGE STACK BUFFERS (>= 128 bytes)")
print("=" * 100)

large_stack_funcs.sort(key=lambda x: -x[2])
for name, addr, max_stack, c_code in large_stack_funcs[:30]:
    # Check if any call to copy functions targets the stack buffer
    has_copy = any(cn in c_code for cn in KNOWN_COPY_NAMES)
    flag = " [HAS COPY CALLS]" if has_copy else ""
    print(f"  {name} @ 0x{addr:08x}: max stack offset 0x{max_stack:x} ({max_stack} bytes){flag}")

# ============================================================
# PHASE 2: FULL DECOMPILES OF TARGET FUNCTIONS
# ============================================================
print("\n" + "=" * 100)
print("PHASE 2: FULL DECOMPILES OF TARGET FUNCTIONS")
print("=" * 100)

for addr in sorted(TARGET_FUNCS.keys()):
    if addr in target_decompiles:
        name, desc, c_code = target_decompiles[addr]
        print(f"\n{'#' * 100}")
        print(f"# {desc}")
        print(f"# {name} @ 0x{addr:08x}")
        print(f"{'#' * 100}")
        print(c_code)
    else:
        print(f"\n  WARNING: Could not decompile {TARGET_FUNCS[addr]} @ 0x{addr:08x}")

# ============================================================
# PHASE 3: DEEP ANALYSIS OF FUN_000053C4
# ============================================================
print("\n" + "=" * 100)
print("PHASE 3: DEEP ANALYSIS OF FUN_000053C4 (auStack_664)")
print("=" * 100)

if 0x000053c4 in target_decompiles:
    name, desc, c_code = target_decompiles[0x000053c4]

    # Find ALL references to auStack_664
    lines = c_code.split('\n')
    print("\nAll references to auStack_664:")
    for j, line in enumerate(lines):
        if 'auStack_664' in line:
            print(f"  Line {j}: {line.strip()}")

    # Find all function calls that take auStack_664 as argument
    print("\nFunction calls involving auStack_664:")
    call_pat = re.compile(r'(FUN_\w+|memcpy|memmove)\s*\([^)]*auStack_664[^)]*\)')
    for m in call_pat.finditer(c_code):
        print(f"  {m.group(0)}")

    # Find all writes to auStack_664 (direct or via pointer)
    print("\nDirect writes to auStack_664:")
    write_pat = re.compile(r'auStack_664\s*\[[^\]]*\]\s*=')
    for m in write_pat.finditer(c_code):
        # Get surrounding context
        pos = m.start()
        line_start = c_code.rfind('\n', 0, pos) + 1
        line_end = c_code.find('\n', pos)
        print(f"  {c_code[line_start:line_end].strip()}")

    # Check all function calls in FUN_000053C4 and their arguments
    print("\nALL function calls in FUN_000053C4:")
    all_calls = re.findall(r'(FUN_\w+)\s*\(([^)]*)\)', c_code)
    for func_name, args in all_calls:
        print(f"  {func_name}({args[:120]}{'...' if len(args) > 120 else ''})")

# ============================================================
# PHASE 4: CROSS-REFERENCE ANALYSIS
# Find any function that:
#   1. Reads from APCB (calls FUN_00000850/FUN_00004412)
#   2. AND has a stack buffer
#   3. AND copies data with size derived from APCB
# ============================================================
print("\n" + "=" * 100)
print("PHASE 4: APCB-TO-STACK COPY CHAIN ANALYSIS")
print("=" * 100)

apcb_chain_suspects = []
for func in all_funcs:
    addr = func.getEntryPoint().getOffset()
    if addr in KNOWN_COPY_FUNCS:
        continue

    result = decomp.decompileFunction(func, 120, monitor)
    if not result.decompileCompleted():
        continue
    decomp_func = result.getDecompiledFunction()
    if decomp_func is None:
        continue
    c_code = decomp_func.getC()
    if c_code is None:
        continue

    has_apcb_read = any(reader in c_code for reader in APCB_READERS)
    has_stack_buf = 'auStack_' in c_code
    has_copy = any(cn in c_code for cn in KNOWN_COPY_NAMES)

    if has_apcb_read and has_stack_buf:
        name = func.getName()
        # Extract the stack buffer sizes
        stack_sizes = [int(x, 16) for x in re.findall(r'auStack_([0-9a-fA-F]+)', c_code)]
        max_stack = max(stack_sizes) if stack_sizes else 0

        print(f"\n  {name} @ 0x{addr:08x}: APCB reader + stack buf (max 0x{max_stack:x})")

        # Show APCB read calls
        for line_num, line in enumerate(c_code.split('\n')):
            if any(reader in line for reader in APCB_READERS):
                print(f"    APCB read: {line.strip()}")

        # Show copy calls to stack
        for line_num, line in enumerate(c_code.split('\n')):
            if any(cn in line for cn in KNOWN_COPY_NAMES) and 'auStack' in line:
                print(f"    Copy to stack: {line.strip()}")

        apcb_chain_suspects.append((name, addr, max_stack, has_copy))

if not apcb_chain_suspects:
    print("\nNo APCB-read + stack-buffer combinations found.")

# ============================================================
# PHASE 5: INSTRUCTION-LEVEL SCAN FOR LDM/STM BLOCK COPIES
# These ARM instructions copy multiple registers at once and
# can implement fast inline copies without any function call
# ============================================================
print("\n" + "=" * 100)
print("PHASE 5: INSTRUCTION-LEVEL SCAN FOR LDM/STM BLOCK COPY PAIRS")
print("=" * 100)

addr_space = program.getAddressFactory().getDefaultAddressSpace()

for func in all_funcs:
    entry = func.getEntryPoint().getOffset()
    if entry in KNOWN_COPY_FUNCS:
        continue

    body = func.getBody()
    # Scan instructions in this function for LDM...STM pairs
    ldm_count = 0
    stm_count = 0

    inst = listing.getInstructionAt(body.getMinAddress())
    while inst is not None and body.contains(inst.getAddress()):
        mnemonic = inst.getMnemonicString().upper()
        if 'LDM' in mnemonic or 'LDMIA' in mnemonic or 'LDMIB' in mnemonic:
            ldm_count += 1
        if 'STM' in mnemonic or 'STMIA' in mnemonic or 'STMIB' in mnemonic:
            stm_count += 1
        inst = inst.getNext()

    if ldm_count >= 2 and stm_count >= 2:
        name = func.getName()
        print(f"  {name} @ 0x{entry:08x}: LDM={ldm_count} STM={stm_count} (potential block copy)")

# ============================================================
# PHASE 6: Check for Thumb-mode inline byte copy loops
# Pattern: LDRB Rx, [Ry, Rz] ; STRB Rx, [Rw, Rz] ; ADD Rz, #1 ; CMP
# ============================================================
print("\n" + "=" * 100)
print("PHASE 6: INSTRUCTION-LEVEL SCAN FOR BYTE COPY LOOPS (LDRB+STRB)")
print("=" * 100)

for func in all_funcs:
    entry = func.getEntryPoint().getOffset()
    if entry in KNOWN_COPY_FUNCS:
        continue

    body = func.getBody()
    # Collect instruction mnemonics in order
    instrs = []
    inst = listing.getInstructionAt(body.getMinAddress())
    while inst is not None and body.contains(inst.getAddress()):
        instrs.append((inst.getAddress().getOffset(), inst.getMnemonicString().upper(), str(inst)))
        inst = inst.getNext()

    # Look for LDRB followed within 4 instructions by STRB, then within 4 by ADD/ADDS + CMP
    for j in range(len(instrs) - 4):
        addr_j, mn_j, full_j = instrs[j]
        if 'LDRB' not in mn_j and 'LDR.B' not in mn_j:
            continue
        # Look for STRB within next 4
        for k in range(j+1, min(j+5, len(instrs))):
            addr_k, mn_k, full_k = instrs[k]
            if 'STRB' not in mn_k and 'STR.B' not in mn_k:
                continue
            # Look for ADD/CMP within next 4 after STRB
            for m in range(k+1, min(k+5, len(instrs))):
                addr_m, mn_m, full_m = instrs[m]
                if 'ADD' in mn_m or 'CMP' in mn_m:
                    name = func.getName()
                    print(f"\n  {name} @ 0x{entry:08x}: possible byte copy loop at 0x{addr_j:08x}")
                    # Print surrounding instructions
                    start = max(0, j - 2)
                    end = min(len(instrs), m + 3)
                    for idx in range(start, end):
                        marker = ">>>" if idx in (j, k, m) else "   "
                        print(f"    {marker} 0x{instrs[idx][0]:08x}: {instrs[idx][2]}")
                    break
            break

# ============================================================
# PHASE 7: Look for any function taking a size parameter that
# copies into a fixed-size local buffer without clamping
# Pattern: param used as size arg to copy into auStack
# ============================================================
print("\n" + "=" * 100)
print("PHASE 7: PARAM-AS-SIZE TO STACK BUFFER (NO BOUNDS CHECK)")
print("=" * 100)

param_size_pat = re.compile(
    r'(FUN_000004e0|FUN_00000458|memcpy|memmove)\s*\(\s*'
    r'(?:&?\s*auStack_\w+|(?:\(void\s*\*\))?\s*auStack_\w+)'
    r'[^,]*,\s*[^,]*,\s*(param_\d+)\s*\)',
    re.MULTILINE
)

for func in all_funcs:
    addr = func.getEntryPoint().getOffset()
    if addr in KNOWN_COPY_FUNCS:
        continue

    result = decomp.decompileFunction(func, 60, monitor)
    if not result.decompileCompleted():
        continue
    decomp_func = result.getDecompiledFunction()
    if decomp_func is None:
        continue
    c_code = decomp_func.getC()
    if c_code is None:
        continue

    matches = param_size_pat.findall(c_code)
    if matches:
        name = func.getName()
        for copy_func, param_name in matches:
            # Check if there's a bounds check on this param before the copy
            # Look for if (param < X) or if (param > X) or min(param, X)
            has_check = bool(re.search(
                rf'if\s*\([^)]*{param_name}\s*[<>]=?\s*', c_code
            ))
            flag = " [HAS BOUNDS CHECK]" if has_check else " [NO BOUNDS CHECK FOUND]"
            print(f"  {name} @ 0x{addr:08x}: {copy_func}(auStack_*, ..., {param_name}){flag}")

            # Show context
            lines = c_code.split('\n')
            for j, line in enumerate(lines):
                if copy_func in line and param_name in line and 'auStack' in line:
                    start = max(0, j - 8)
                    end = min(len(lines), j + 3)
                    for k in range(start, end):
                        marker = ">>>" if k == j else "   "
                        print(f"    {marker} {lines[k]}")
                    break

print("\n" + "=" * 100)
print("SCAN COMPLETE")
print("=" * 100)

# Cleanup
decomp.dispose()
project.close()
print("\nDone.")
