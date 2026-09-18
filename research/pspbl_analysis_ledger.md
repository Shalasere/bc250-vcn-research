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
- **confidence:** HIGH — ARM-level verification confirms ALL branches are unsigned (BHI, BLS)
- **assumptions:** None remaining
- **last_reviewed:** session 12 (skeptical validation pass)

---

## High-Priority Targets (detailed analysis exists)

### 0x2434 — RSA Key Buffer Handler
- **size:** 140 bytes (312 per catalog — discrepancy, verify)
- **role:** HKDF-expand-like key derivation, copies param_1 into stack buffer
- **stack_buffers:** auStack_6c (68 bytes), stack frame 80 bytes total
- **bounds_check:** `CMP R5, #0x40` + `BLS` (unsigned less-or-equal) at entry — max copy 64 bytes
- **copy:** `FUN_00000458(auStack_6c, param_1, param_2)` — memcpy to stack
- **apcb_contact:** INDIRECT — param_2 traces through crypto chain, origin unclear
- **verdict:** SAFE — 64 fits in 68-byte buffer, compare is unsigned
- **confidence:** HIGH — ARM-level verification: CMP R5, #0x40 + BLS (unsigned). Stack frame 80 bytes confirmed.
- **assumptions:** param_2 origin through callers not fully traced (but irrelevant — unsigned check catches all values > 0x40)
- **last_reviewed:** session 12 (skeptical validation pass, ARM bytes verified)

### 0x1D30 — RSA-PSS Signature Verifier
- **size:** 380 bytes
- **role:** RSA-PSS verification with MGF1
- **stack_buffers:** auStack_3c (8 bytes — small, part of larger structure)
- **copy:** `FUN_00000458(DAT_00001eac + local_44 + 0x608, pbVar5 + uVar2 + 1, iVar1)` — memcpy with computed size to GLOBAL buffer at 0xAB00
- **bounds_check:** Five defense layers verified at ARM level:
  1. FUN_00001eb4 hash algorithm ID check: `CMP r3, #6; BHS error` — only known digests (0x14..0x40)
  2. Caller match: `CMP local_44, param_2; BEQ` — digest size must match expected
  3. Structural bound: `2 + 2*local_44 <= param_4` — ensures room
  4. Loop guard: `CMP r0, r6; BHI` (unsigned) — uVar2 cannot exceed (param_4 - local_44 - 2)
  5. Total-size cap: `CMP r7, r11(=0x1DE); BHI error` — fires BEFORE memcpy
- **apcb_contact:** INDIRECT — processes signatures on APCB-adjacent data
- **verdict:** SAFE — iVar1 >= 0 structurally guaranteed by loop guard (Layer 4)
- **confidence:** HIGH — all five layers verified at ARM instruction level (session 12)
- **critical note:** Prior sessions dismissed this for the WRONG reason ("copy dest is global, not stack" — that is not a valid safety argument). The actual safety comes from the multi-layered input validation. The final `sub.w r8, r0, #2` at 0x1E4E has S-bit=0 (no flags set, no underflow check), but the loop guard makes underflow structurally impossible.
- **last_reviewed:** session 12 (skeptical validation pass, ARM bytes verified)

### 0x3BA4 — Boot Config / CCP Setup
- **size:** 242 bytes
- **stack_buffers:** auStack_128 (260 bytes)
- **copy:** `FUN_000004e0(iVar2, auStack_128, 0x100)` — optimized copy, HARDCODED 0x100 size
- **verdict:** SAFE — all copy sizes are compile-time constants
- **confidence:** HIGH
- **last_reviewed:** session 11

### 0x53C4 — PSP Command Handler (cmd 0x60/0x68)
- **size:** 214 bytes
- **role:** Command dispatch → fill stack buffer with PSP-internal data → copy out to mapped memory
- **stack_buffers:** SP+0xC through SP+0x64B = 1612 bytes available
- **stack_frame:** `SUB SP, SP, #0x658` (1624 bytes) + 6 regs pushed (24 bytes) = 1648 bytes total
- **copy:** FUN_000057C4 called with `MOVW R8, #0x640` (1600 bytes) — hardcoded immediate
- **bounds_check:** 1600 < 1612 (12-byte margin). Second operation uses constant 0x200.
- **apcb_contact:** NO — reads PSP-internal state, not APCB data
- **verdict:** SAFE — all copy sizes are hardcoded constants
- **confidence:** HIGH — ARM-level verification of SUB SP and MOVW R8 immediates
- **reachability:** No direct callers found (no BL/BLX targets 0x53C4/0x53C5 in binary). Likely dead code or externally dispatched via PSP mailbox command table.
- **last_reviewed:** session 12 (skeptical validation pass, ARM bytes verified)

### 0x75A4 — Config Buffer Builder
- **size:** varies (part of larger chain)
- **role:** Reads APCB-derived data from SRAM 0xB800 area, writes to 0x4F000 region
- **apcb_contact:** YES — primary APCB data consumer
- **verdict:** SAFE — no stack buffers, no loops, all copy sizes hardcoded
- **confidence:** HIGH
- **notes:** Callee chain fully analyzed (apcb_parsing_deep.py). Session 12 literal pool decode reveals config_buf+0x660 is sourced from SRAM 0xB814 (APCB header area). Pool entries: 0x77E4→0xB808, 0x77E8→0xB814, 0x77EC→0xB820. Value at 0xB814 is likely attacker-controlled (within APCB image). However, config_buf at 0x4F000 is never read by ABL4 (Vector A closure confirmed), so the attacker-controlled value is a dead end.
- **open_question:** Does PSP_BL itself ever read back config_buf+0x660 and use it as an address or function pointer? If so, write-what-where via APCB→config_buf→PSP_BL is possible.
- **last_reviewed:** session 12 (literal pool decode added)

---

## Dead Code / Unreachable

### 0x44CC — FUN_000044CC (874 lines decompiled)
- **verdict:** DEAD_CODE — no callers in entire binary
- **confidence:** HIGH — exhaustive call graph from 0x0300 confirms unreachable. Session 12: zero references of any kind (no BL/BLX, no pointer table entries, no 32-bit constant 0x44CC/0x44CD in data). Neighbor function has 72 call references proving the scanner works.
- **role:** Directory Entry Processor — large switch-based dispatcher on entry type (0x00-0x43 via TBB, plus special paths). Args: R0=entry type, R1=pointer to 16-byte directory entry. R10=0xB7F8 (from pool 0x48E4), R8=0xB808.
- **notes:** Full decompilation in artifacts/psp-rce-outputs/fun044cc_decompiled.c. Is the SOLE writer to the entire 0xB7F8-0xB81F SRAM region:
  - 0xB7F8-0xB807: unconditional writes from entry[0..3] (at 0x4500-0x4506)
  - 0xB808-0xB810: case 3, validation gate (calls 0x61E4), or from PSP_BL globals at 0x95C8
  - 0xB814-0xB81C: case 4 (entry[3]==0x10000000), writes entry[1]/entry[2]/constant
  - 0xB820-0xB82B: **NO WRITER FOUND** — not even in dead code
  Since FUN_000044CC is dead, PSP_BL never executes ANY of these writes. The 0xB800-0xB82B region is populated entirely by the prior boot stage (boot ROM APCB load).
- **last_reviewed:** session 12 (confirmed dead + mapped all write targets)

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
| ~~0x1D30~~ | ~~380~~ | ~~RSA-PSS verifier~~ — **RESOLVED session 12: SAFE** (5 defense layers, ARM-verified) |
| ~~0x53C4~~ | ~~214~~ | ~~Largest stack buffer~~ — **RESOLVED session 12: SAFE** (hardcoded 0x640, no callers) |
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

### What session 12 skeptical validation added:
1. ARM-level verification of signed/unsigned for FUN_00002434 (CMP+BLS = unsigned) and FUN_00001670 (BHI/BLS = unsigned)
2. ARM-level integer underflow analysis of FUN_00001D30 — 5 defense layers, iVar1 >= 0 structurally guaranteed
3. ARM-level stack frame analysis of FUN_000053C4 — hardcoded 0x640 copy into 1612-byte buffer, no callers
4. Confirmed FUN_000044CC dead code (zero references of any kind, neighbor has 72 proving scanner works)
5. Confirmed stack base 0x92000 (5 literal pool entries)
6. Decoded FUN_000075A4 literal pool — config_buf+0x660 sourced from SRAM 0xB814 (APCB header area)
7. Function pointer table scan — only 1 in entire binary (0x03B8, 3 entries), none reference dead code
8. **Identified new vulnerability class: write-what-where primitives** (analysis in progress)
9. Corrected FUN_00001D30 dismissal reasoning: "global buffer dest = safe" is WRONG; actual safety is from bounds checks

### What it DID NOT check (before session 12):
- ~~Semantic correctness of bounds checks (signed vs unsigned, off-by-one)~~ — **partially addressed session 12** for FUN_00002434, FUN_00001670, FUN_00001D30
- ~~Integer arithmetic overflow/underflow in size computations~~ — **addressed session 12** for FUN_00001D30
- Indirect data flow through global buffers (function A writes to global, function B uses it unsafely) — **OPEN**
- Dynamic behavior (PSPEmu tracing) — **OPEN** (requires emulator, out of scope for static analysis)
- Functions below 0x0300 (exception handlers, startup stubs — mostly covered by SVC analysis but not exhaustively)
- **Write-what-where primitives** — session 12 scanned all 26 APCB address loads and 32 memcpy/copy calls. **No hits.** No APCB-derived value is used as a memory write destination (STR base or memcpy dest) via direct double-dereference. Caveat: complex chains through function call boundaries not fully checked.
- **Arbitrary SRAM read at 0x7644** — FUN_000075A4 dereferences value at 0xB820 as a pointer (`ldr r0, [r1]` where r1=[0xB820]). If 0xB820 is attacker-controlled, this is an arbitrary read influencing control flow. READ primitive only, not exploitable for code execution alone.
