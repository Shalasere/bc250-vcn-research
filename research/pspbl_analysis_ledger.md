# PSP_BL Analysis Ledger

Structured tracking of per-function analysis for the BC-250 PSP Boot Loader
(39,360 bytes, 321 functions, ARM Cortex-A5 Thumb).

**Binary:** `firmware/internal_pspbl_body.bin`
**Ghidra project:** `ghidra_projects/bc250_pspbl_v1`
**Goal:** Find an exploitable vulnerability reachable from APCB-controlled input.

## How to use this ledger

Each function that matters has an entry below. The `verdict` field is the
current assessment; `confidence` says how much to trust it; `assumptions`
lists what would invalidate the verdict. Future sessions should:

1. Pick entries with LOW confidence or NEEDS_REVIEW verdict
2. Verify assumptions at the ARM instruction level (not just Ghidra decompile)
3. Update the entry and commit immediately

Verdicts: `SAFE`, `NEEDS_REVIEW`, `SUSPICIOUS`, `NOT_REVIEWED`, `DEAD_CODE`, `UTILITY`

---

## Known Functions (identity established)

### 0x0300 — Boot Entry (main)
- **size:** variable (calls into full boot chain)
- **role:** PSP_BL main boot sequence, orchestrates all other calls
- **apcb_contact:** YES — reads APCB header from 0xB82C, validates, dispatches
- **verdict:** SAFE (as orchestrator — individual callees are the attack surface)
- **confidence:** HIGH
- **last_reviewed:** session 11

### 0x0458 — memcpy
- **size:** 24 call sites throughout binary
- **role:** Standard memcpy(dest, src, size)
- **apcb_contact:** indirect (copies APCB-derived data)
- **verdict:** UTILITY — not vulnerable itself, callers are the attack surface
- **confidence:** HIGH
- **notes:** All 24 call sites traced at ARM instruction level (memcpy_callsite_trace.py). Only one has SP-relative dest + register size: 0x2468 inside FUN_00002434, which is bounds-checked.
- **last_reviewed:** session 11

### 0x04E0 — Optimized Copy
- **size:** 100 bytes, 8 call sites
- **role:** Word-aligned bulk copy
- **verdict:** UTILITY
- **confidence:** HIGH
- **last_reviewed:** session 11

### 0x0544 — memset
- **size:** 16 bytes
- **verdict:** UTILITY
- **confidence:** HIGH

### 0x0850 — Early APCB Handler
- **size:** 96 bytes
- **role:** APCB reference function (loads from 0xB82C area)
- **apcb_contact:** YES
- **verdict:** SAFE — no stack buffers, no variable-length copies
- **confidence:** MEDIUM — Ghidra decompile only, no ARM-level verification
- **last_reviewed:** session 11

### 0x1670 — APCB Size Validation
- **size:** 130 bytes
- **role:** Validates APCB structure size, enforces 0x4F0 cap + buffer bounds
- **apcb_contact:** YES — primary size validation gate
- **verdict:** SAFE — size capped, buffer check present
- **confidence:** MEDIUM — validated via Ghidra decompile, should verify the compare instruction is unsigned
- **assumptions:** Ghidra correctly decompiles the size comparison as unsigned
- **what_would_change:** If the compare is signed, a large APCB size (bit 31 set) could bypass the cap
- **last_reviewed:** session 11

---

## High-Priority Targets (detailed analysis exists)

### 0x2434 — RSA Key Buffer Handler
- **size:** 140 bytes (312 per catalog — discrepancy, verify)
- **role:** HKDF-expand-like key derivation, copies param_1 into stack buffer
- **stack_buffers:** auStack_6c (68 bytes)
- **bounds_check:** `param_2 < 0x41` at entry
- **copy:** `FUN_00000458(auStack_6c, param_1, param_2)` — memcpy to stack
- **apcb_contact:** INDIRECT — param_2 traces through crypto chain, origin unclear
- **verdict:** SAFE — 0x41 (65) fits in 68-byte buffer
- **confidence:** MEDIUM
- **assumptions:** (1) The `< 0x41` compare is UNSIGNED (Ghidra shows BHS/BLO). (2) param_2 genuinely comes from a code path, not directly from APCB token data.
- **what_would_change:** If compare is signed (BLT/BGE instead of BLO/BHS), negative param_2 bypasses. If param_2 traces to raw APCB data, attacker controls the size directly.
- **action_needed:** Verify compare instruction at ARM level. Trace param_2 origin through callers.
- **last_reviewed:** session 11

### 0x1D30 — RSA-PSS Signature Verifier
- **size:** 380 bytes
- **role:** RSA-PSS verification with MGF1
- **stack_buffers:** auStack_3c (8 bytes — small, part of larger structure)
- **copy:** `FUN_00000458(DAT_00001eac + local_44 + 0x608, pbVar5 + uVar2 + 1, iVar1)` — memcpy with computed size to GLOBAL buffer
- **bounds_check:** `param_4 == 0x100 || param_4 == 0x200` (key size), plus `local_44 * 2 + 2 <= param_4` and `uVar6 < 0x1df`
- **apcb_contact:** INDIRECT — processes signatures on APCB-adjacent data
- **verdict:** NEEDS_REVIEW
- **confidence:** LOW
- **assumptions:** Prior analysis dismissed this because copy destination is global (DAT_00001eac), not stack. But the INTERACTION between local_44 (hash-size dependent, from FUN_00001eb4), param_4 (key size, constrained to 0x100/0x200), and iVar1 (computed as `(param_4 - local_44) - uVar2 - 2`) is complex. An integer underflow in iVar1 computation could produce a large copy size.
- **what_would_change:** If iVar1 can underflow (e.g., uVar2 >= param_4 - local_44 - 1), the memcpy size wraps to ~4GB. The loop `for uVar2 = 0; uVar2 < (param_4 - local_44) - 2 && pbVar5[uVar2] == 0` controls uVar2 but depends on attacker-influenced data in pbVar5.
- **action_needed:** Manual analysis of the iVar1 computation path. Can uVar2 grow large enough to cause underflow? What controls the pbVar5 data the loop scans?
- **last_reviewed:** session 11

### 0x3BA4 — Boot Config / CCP Setup
- **size:** 242 bytes
- **stack_buffers:** auStack_128 (260 bytes)
- **copy:** `FUN_000004e0(iVar2, auStack_128, 0x100)` — optimized copy, HARDCODED 0x100 size
- **verdict:** SAFE — all copy sizes are compile-time constants
- **confidence:** HIGH
- **last_reviewed:** session 11

### 0x75A4 — Config Buffer Builder
- **size:** varies (part of larger chain)
- **role:** Reads APCB-derived data, writes to 0x4F000 region
- **apcb_contact:** YES — primary APCB data consumer
- **verdict:** SAFE — no stack buffers, no loops, all copy sizes hardcoded
- **confidence:** HIGH
- **notes:** Callee chain fully analyzed (apcb_parsing_deep.py)
- **last_reviewed:** session 11

---

## Dead Code / Unreachable

### 0x44CC — FUN_000044CC (874 lines decompiled)
- **verdict:** DEAD_CODE — no callers in entire binary
- **confidence:** HIGH — exhaustive call graph from 0x0300 confirms unreachable
- **notes:** Full decompilation in artifacts/psp-rce-outputs/fun044cc_decompiled.c
- **last_reviewed:** session 9

---

## Crypto Functions (analyzed, appear safe)

### 0x05F0 — AES Setup
- **size:** 346 bytes
- **stack_buffers:** 0x74 (116 bytes), 0x54 (84 bytes)
- **verdict:** SAFE — param_3 (key size) constrained to {0x10, 0x18, 0x20} by caller chain
- **confidence:** MEDIUM — constraint is in callers, not in this function
- **what_would_change:** If any caller passes unconstrained key size
- **last_reviewed:** session 11

### 0x0750 — AES Operation
- **size:** 232 bytes
- **stack_buffers:** 0x60 (96 bytes)
- **verdict:** SAFE — same key size constraint as 0x05F0
- **confidence:** MEDIUM
- **last_reviewed:** session 11

### 0x1720 — AES Variant
- **size:** 330 bytes
- **stack_buffers:** 0x54 (84 bytes)
- **verdict:** SAFE — key size {16, 24, 32}
- **confidence:** MEDIUM
- **last_reviewed:** session 11

### 0x1EB4 — Hash Algorithm Lookup
- **size:** 68 bytes
- **role:** Returns digest size for algorithm ID (SHA1=0x14, SHA224=0x1c, SHA256=0x20, SHA384=0x30, SHA512=0x40)
- **verdict:** SAFE — pure lookup, no writes
- **confidence:** HIGH
- **last_reviewed:** session 11

### 0x21A0 — CCP Crypto Setup
- **size:** 250 bytes
- **stack_buffers:** local_20 (8 bytes), local_28/local_24 (8 bytes)
- **verdict:** SAFE — writes to param_1[0..4] (20 bytes into caller-provided struct), not stack overflow
- **confidence:** MEDIUM — "8-byte stack buffers" from catalog are actually structure fields adjacent to other locals
- **last_reviewed:** session 11

### 0x22AA — Hash Digest
- **size:** 52 bytes
- **verdict:** SAFE — thin wrapper
- **confidence:** MEDIUM
- **last_reviewed:** session 11

### 0x25A4 — HKDF
- **size:** 238 bytes
- **bounds_check:** `uVar5 < 0x81`
- **copy_dest:** global DAT_00002694
- **verdict:** SAFE — writes to global, not stack; iteration capped at 0x80
- **confidence:** MEDIUM
- **last_reviewed:** session 11

---

## SVC / Exception Handling (closed vector)

### 0x0100 area — Vector Table
- **verdict:** SAFE — VBAR=0x100, all exception handlers are NOPs/stubs
- **confidence:** HIGH — verified by svc_final_resolution.py
- **last_reviewed:** session 10

---

## APCB-Referencing Functions (5 total, all analyzed)

Functions containing literal references to APCB addresses (0xB82C, 0xB814, 0x4F000, 0x4F200):
- 0x0300 — boot entry (see above)
- 0x0850 — early handler (see above)
- 0x1670 — size validation (see above)
- 0x44CC — dead code (see above)
- 0x75A4 — config builder (see above)

---

## Bulk Status: Remaining 97 CANDIDATE Functions

The function catalog (artifacts/psp-rce-outputs/pspbl_function_catalog.txt) flagged
97 functions as CANDIDATE based on heuristics (param in array index, param controls
loop bound, large stack buffer). The automated analysis (enumerate_pspbl_functions.py,
indirect_overflow_hunt.py) checked these for the specific pattern "memcpy/loop to
stack buffer with attacker-controlled size" and found none.

**However:** the automated check was PATTERN-BASED, not semantic. It would miss:
- Integer truncation before a bounds check
- Signed/unsigned confusion in comparisons
- Off-by-one errors
- Type confusion (treating a pointer as a size or vice versa)
- Multi-step corruption (function A writes slightly out of bounds, function B reads the corrupted value)
- Race conditions (unlikely in single-threaded PSP_BL, but not impossible with DMA)

### Priority candidates for manual re-analysis:

| Address | Size | Why re-check |
|---------|------|-------------|
| 0x1D30 | 380 | RSA-PSS verifier, complex bounds interaction (see detailed entry above) |
| 0x53C4 | 214 | Largest stack buffer in binary (0x664 = 1636 bytes), not deeply analyzed |
| 0x7014 | 320 | Two large stack buffers (0x4C + 0x5C), local array access |
| 0x1A60 | 248 | local array + param index + param loop bound — triple flag |
| 0x66A0 | 284 | Large function, param controls loop bound |
| 0x5850 | 420 | Large function, param controls loop bound |
| 0x3214 | 312 | param controls loop bound |
| 0x73D0 | 102 | Large stack buffer (0x58) |
| 0x74C8 | 146 | local array + param index — double flag |
| 0x2B80 | 164 | local array access |

All of these are `NOT_REVIEWED` at the manual/semantic level. The heuristic scan
said "no obvious memcpy-to-stack-with-variable-size" but that's a narrow check.

---

## Methodology Notes

### What the automated analysis DID check (sessions 4–11):
1. All 321 functions enumerated and heuristic-flagged (enumerate_pspbl_functions.py)
2. Stack buffer + copy function cross-reference (deep_overflow_hunt.py) — 3 hits, all safe
3. BFS call graph from 0x0300 — 258 reachable, 2 with variable-bound stack writes, both bounded (apcb_callgraph.py)
4. Stack buffers passed to callees with variable size — 22 functions checked (indirect_overflow_hunt.py)
5. ARM instruction-level memcpy call site trace — 24 sites (memcpy_callsite_trace.py)
6. APCB literal reference trace — 5 functions (apcb_parsing_deep.py)
7. 22 suspect functions fully decompiled (deep_decompile_suspects.py)

### What it DID NOT check:
- Semantic correctness of bounds checks (signed vs unsigned, off-by-one)
- Integer arithmetic overflow/underflow in size computations
- Indirect data flow through global buffers (function A writes to global, function B uses it unsafely)
- Dynamic behavior (PSPEmu tracing)
- Functions below 0x0300 (exception handlers, startup stubs — mostly covered by SVC analysis but not exhaustively)
