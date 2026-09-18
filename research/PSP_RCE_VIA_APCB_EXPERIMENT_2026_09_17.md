# PSP RCE via ABL4/APCB Parsing — Experiment Plan (2026-09-17)

## Objective

Achieve PSP (Platform Security Processor) code execution by triggering a
buffer overflow in PSP_BL's APCB token parser during ABL4 early boot.
If successful, PSP code exec enables clearing the VCN harvest latch
(`CC_UVD_HARVESTING` at 0x1f81c), setting the 0x6007 staging-slot gate,
and injecting the KDB usage-6 signing key — unblocking all three VCN
gates.

## Lead origin

**mergeconflicted** (community Discord, 2026-09-01/02):
- Target: PSP VA `0x0005DE0C`, inside PSP_BL's APCB parsing handler
- CVE reference: CVE-2023-31316 (adapted — the save/restore vector doesn't
  apply to BC-250 since VCN firmware never loads; the ABL4/APCB path runs
  unconditionally at every boot)
- Status as of last report: "blocked by `saved_len` uninitialized fault;
  investigation ongoing, not yet weaponized"

## Deep analysis results (2026-09-17 + 2026-09-17 session 2, zero board risk)

### ABL4 binary

- File: `firmware/internal_abl4_decompressed.bin`
- $PS1 envelope at +0x10, body at +0x100, zlib-compressed
- Decompressed: **88,000 bytes** (0x157C0)
- Architecture: ARM Cortex-A5, Thumb-2 mode (ARM entry trampoline at offset 0)
- Load base: **PSP VA 0x00060834**
- **178 PUSH prologues** (raw scan), **147 functions** (Ghidra auto-analysis)
- Ghidra project: `ghidra_projects/bc250_abl4_v3`
- Contains `#BUFFER OVERFLOW#` debug string at file offset 0x11ABD (VA 0x722F1)
  — **zero static references** (no ADR, no LDR pool, no MOVW/MOVT, no literal pool entry)
- Contains **zero MOVT instructions** in the entire binary — all addresses come
  from literal pools or pointer dereferencing, never MOVW+MOVT construction
- Key data structures:
  - HEAP at **VA 0x72000** (within ABL4 data, magic "HEAP" = 0x50414548)
  - APCB group data at **VA 0x7A000** (16K past ABL4 end, runtime-populated)
  - IDS dispatch table at **VA 0x6B8A8** (debug output handler function pointers)

### PSP VA 0x0005DE0C — VTABLE POINTER OVERWRITE (session 2 finding)

**0x5DE0C is NOT code.** It is a **function pointer** inside the PSP boot
context structure at SRAM **0x5D7AC**, at offset **+0x660**:

```
Context structure base: 0x5D7AC  (PSP_BL literal pool at offset +0x0BB8)
Function pointer:       0x5D7AC + 0x660 = 0x5DE0C
```

This function pointer is the dispatch target for ABL4's two most-called
functions:
- **FUN_0006F1D8** (316 calls): `(**(code **)(param_1 + 0x660))(param_1, 1, param_2, param_3);`
- **FUN_0006BB9C** (140 calls): `(**(code **)(param_1 + 0x660))(param_1, 0, param_2);`

**Vulnerability mechanism (REVISED session 3 — two-stage attack):**

Session 3 exhaustive analysis proved PSP_BL has **zero static writes** to
context+0x660 (0x5DE0C). No STR.W with #0x660, no MOVW for 0xD7AC/0xDE0C,
no ADD.W with 0x660, no literal for 0x5DE0C. The only 0x5D7AC reference
(offset 0x0958) is for a read operation via FUN_00006B76.

**Revised two-stage model:**
1. **Stage 1 — PSP_BL code execution:** CVE-2025-29951 stack overflow in
   PSP_BL's APCB processing gives arbitrary PSP code execution. The overflow
   is likely a DMA overshoot (APCB header size fields control DMA length in
   FUN_00001C18) or integer overflow in size computation (FUN_000071AC).
2. **Stage 2 — SRAM corruption:** PSP_BL shellcode writes a crafted address
   to SRAM 0x5DE0C (context+0x660), replacing the dispatch function pointer.
3. **Stage 3 — ABL4 hijack:** When SVC 0x1c returns and ABL4 resumes, the
   next token dispatch (FUN_0006F1D8 or FUN_0006BB9C, 456 total call sites)
   tail-calls through the corrupted pointer, executing attacker code in
   ABL4 context with full SRAM access.

**Evidence chain (updated):**
1. PSP_BL literal pool at +0x0BB8 contains 0x5D7AC (context structure base)
2. PSP_BL has ZERO writes to 0x5DE0C (exhaustive: no STR.W #0x660, no MOVW,
   no ADD.W 0x660, no literal 0x5DE0C — confirmed session 3)
3. 0x4F000 buffer is SEPARATE from ABL4 context (FUN_000075A4 writes to
   0x4F660, cache-flushes via FUN_0000120C — config block, not context)
4. ABL4 FUN_0006B590 sets +0x660 = 0x60FE9 — this IS the real dispatch
   function (Thumb ptr to 0x60FE8 = token_dispatch). **Session 4-10
   definitively proved: SVCs are NOPs (VBAR=0x100), FUN_00069BE8
   self-fulfills the condition gate, and this value is NEVER replaced.**
5. FUN_0006F364 USES +0x660 dispatch before FUN_0006BB9C — the dispatch
   works because 0x60FE9 IS valid (Thumb interworking: bit0=1 = Thumb flag)
6. The `#BUFFER OVERFLOW#` string (ABL4 VA 0x722F1) has zero static xrefs
7. CVE-2025-29951 is "PSP BL stack buffer overflow" — Stage 1 is PSP_BL level
8. Complete PSP_BL stack frame census: only FUN_000053C4 has a large buffer
   (1600 bytes), and it's correctly bounded. No classic stack overflow found.

**Key constraint:** 0x5DE0C appears NOWHERE in either ABL4 or PSP_BL
static binaries. It is purely a RUNTIME address: context base (0x5D7AC)
+ offset 0x660. Both PSP_BL and ABL4 share the context structure in
PSP SRAM.

### APCB full type entry map

```
APCB Header: sig="APCB" v0x0020 size=0xB64 (2916 bytes) checksum=0x9C
Authentication: 8-bit additive checksum only. No RSA signature.
Total flash: 8192 bytes (2916 active + 5276 bytes 0xFF padding)

Type entry header (16 bytes):
  +0x00: GroupId  (u16 LE)
  +0x02: TypeId   (u16 LE)
  +0x04: type_size (u16 LE) — TOTAL entry size incl. this header ← ATTACK VECTOR
  +0x06: reserved (u16)
  +0x08: reserved (u32)
  +0x0C: reserved (u32)
  +0x10: body starts (body_size = type_size - 0x10)

 #  Offset    GID      TID     type_size   body   ts_field    ends_at
--- -------- -------- -------- ----------- ------ ----------- --------
 0  +0x0030  0x0B07   0xFFFF   0x006C(108)   92   +0x0034    +0x009C
 1  +0x00AC  0x1701   0x0002   0x0028( 40)   24   +0x00B0    +0x00D4
 2  +0x00D4  0x1701   0x0060   0x0020( 32)   16   +0x00D8    +0x00F4
 3  +0x0104  0x1703   0x0005   0x003C( 60)   44   +0x0108    +0x0140
 4  +0x0140  0x1703   0x0006   0x003C( 60)   44   +0x0144    +0x017C
 5  +0x018C  0x1704   0x0007   0x00AC(172)  156   +0x0190    +0x0238
 6  +0x0238  0x1704   0x0008   0x00AC(172)  156   +0x023C    +0x02E4
 7  +0x02E4  0x1704   0x0031   0x0030( 48)   32   +0x02E8    +0x0314
 8  +0x0314  0x1704   0x0050   0x0024( 36)   20   +0x0318    +0x0338
 9  +0x0338  0x1704   0x0052   0x007C(124)  108   +0x033C    +0x03B4
10  +0x03B4  0x1704   0x0053   0x0030( 48)   32   +0x03B8    +0x03E4
11  +0x03F4  0x1706   0x000B   0x0020( 32)   16   +0x03F8    +0x0414
12  +0x0414  0x1706   0x000C   0x0020( 32)   16   +0x0418    +0x0434
13  +0x0444  0x1707   0x000D   0x0038( 56)   40   +0x0448    +0x047C
14  +0x047C  0x1707   0x000F   0x06E8(1768) 1752  +0x0480    +0x0B64

Stripped groups (NOT present in BC-250 APCB):
  CCXG (0x1702) — CPU complex config (Downcore, SMT)
  GNBG (0x1705) — GPU/NBIO config (CU mask, VCN, DCN, harvest)
```

### ABL4 APCB processing — complete call chain

**Group dispatch function** at file 0x7818 (PSP VA ~0x60C4C):
- Switch table (TBB) over GroupId: 0x1701-0x1707 (7 cases + 2 special)
- Each case configures: GroupId, min/max TypeId, upper bound, magic cookie
- Calls 0x9778 (HEAP buffer validator: checks magic "HEAP" at SRAM 0x72000)
- Calls 0x9544 (HEAP allocator setup: initializes from descriptor at r4)
- Calls 0x7BEC (type entry lookup in APCB at SRAM 0x7A000)
- Function is **RECURSIVE** — 0x7B82 calls back to 0x7818 for secondary pass

**Type entry lookup** at file 0x7BEC:
- Iterates through APCB entries starting from SRAM 0x7A000 + 0x20 (first group)
- Matches on GroupId (entry+4 in the iteration context) and TypeId
- Returns: **body_ptr** = entry + 0x10, **body_size** = `type_size - 0x10`
- The `type_size` comes directly from `ldrh [entry+4]` — READ FROM APCB DATA
- No bounds check on type_size in ABL4's code

**Byte copy loop** at file 0x7A28-0x7A38:
- `ldrb r3, [src, r0]` / `strb r3, [dst, r0]` / `uxtb r0, r0`
- **Loop counter truncated to 8 bits** (`uxtb` = AND 0xFF)
- **Count is also 8-bit** (`ldrb` from count pointer)
- ABL4 can copy at most 255 bytes per type entry — BOUNDED
- The overflow does NOT happen in ABL4's copy path

### SVC interface — APCB data flow

**SVC 0x16** (at 0xFE7C, 0x10BD0): PSP_BL query
- Command byte 0x61 (for APCB) or 0x62 (for IDS options)
- Returns target buffer address and memory-space identifier
- ABL4 uses this to find WHERE to write processed tokens

**SVC 0x0A** (at 0xFE9E, 0xFECE): PSP SRAM write
- Writes ABL4-processed data into PSP_BL's output buffer
- Fixed lengths: 4 bytes per word, 1 byte per tail byte
- NOT the overflow path — ABL4 passes bounded data

**SVC 0x1D** (at 0x10A56): HMAC/crypto operation on APCB buffer

### Revised conclusion: vtable pointer overwrite (session 2)

The vulnerability at 0x5DE0C is a **function pointer overwrite**, not a
simple stack/heap buffer overflow. ABL4's APCB handling is bounded at the
byte-copy level (255 bytes max, `uxtb` truncation), but the context
structure contains BOTH data buffers AND a dispatch function pointer at
+0x660. The attack chain is:

1. Modify the APCB in SPI flash (via flashrom)
2. On reboot, PSP_BL loads modified APCB into SRAM at 0x7A000
3. PSP_BL or ABL4 parses APCB tokens into context structure at 0x5D7AC
4. Crafted data overflows a buffer field within the context structure
5. Overflow reaches the function pointer at context+0x660 (= 0x5DE0C)
6. Next indirect call through +0x660 (one of 456 call sites) executes
   attacker-controlled code

The `saved_len` uninitialized variable (mergeconflicted's original finding)
is likely the mechanism that DISABLES the bounds check on the buffer write,
allowing data to reach +0x660.

### PSP runtime memory map (session 2, confirmed by Ghidra + PSP_BL analysis)

```
PSP SRAM layout (Zen 2, 320K nominal, possibly larger on BC-250):

0x5D5A4          Context-related structure (PSP_BL pool at +0x0BC8)
0x5D7AC          PSP boot context structure (PSP_BL pool at +0x0BB8)
  +0x554-0x578   Hot write region (85 accesses from ABL4)
  +0x660         Function pointer → dispatch target (THE vulnerability)
                 0x5D7AC + 0x660 = 0x5DE0C
0x5E639-0x5EBE3  SRAM pointer table (50 entries, debug string pointers)
0x60834-0x75FB4  ABL4 code + data (88,000 bytes)
  0x6B8A8        IDS dispatch table (within ABL4)
0x72000          HEAP (single heap, magic "HEAP" = 0x50414548)
                 Used by ABL4 allocator (FUN_00069D78)
                 Three independent literal pool refs all → 0x72000
0x7A000          APCB group data (runtime, 16K past ABL4 end)
                 Populated by earlier boot stages from SPI flash
```

### Decompiled function summary (session 2, Ghidra bc250_abl4_v3)

**FUN_0006804C** — Core APCB handler (864 bytes)
- Switch on param_1 maps to GroupIds
- Buffer allocated as `(uVar13 - uVar12) * 6 + 8` (6 bytes per token)
- Token entry format: 6 bytes, addressed as `base + 8 + (token_id - range_start) * 6`
- Validation allows tokens up to uVar14 > uVar13 but write loop gates on `uVar9 < uVar13`
- Cache hit path has NO bounds check on token ID
- Recursive self-call after initialization

**FUN_00069FAC** — APCB blob loader (114 bytes)
- Walks linked list in HEAP at 0x72000 matching type IDs
- Returns data pointer and size

**FUN_0006F1D8** — Most-called function (316 calls, 18 bytes)
- `(**(code **)(param_1 + 0x660))(param_1, 1, param_2, param_3);`
- Indirect dispatch through vtable pointer at +0x660

**FUN_0006BB9C** — Second-most-called (140 calls, 18 bytes)
- `(**(code **)(param_1 + 0x660))(param_1, 0, param_2);`
- Same dispatch mechanism as FUN_0006F1D8

**FUN_00069D78** — Heap allocator (294 bytes)
- Allocates from heap at 0x72000
- Walks free list, 16-byte aligned entries
- Assert on corruption: file 0xF702, line 1091

**FUN_00068420** — Type lookup (within ABL4)
- Reads APCB group data from 0x7A000
- type_size read without independent bounds validation

**FUN_00062950** — Debug output implementation (166 bytes)
- Uses 512-byte stack buffer
- Dispatches to registered handlers via IDS function pointer table at 0x6B8A8
- NOT writing to a fixed SRAM buffer (eliminates one overflow hypothesis)

**FUN_0006A0D0** — Assert handler
- Calls FUN_0006A140 (infinite loop) — dead hang on assertion failure

**FUN_00060870** — memcpy (used by config handler for table copies)
**FUN_0006A48A** — memset (used by allocator to zero buffers)

### PSP_BL characterization

- Encrypted at rest with IKEK (AES-128, key ID 6, fuse-derived from PDS)
- Public build: 43,008 bytes, entropy ~8.00 (AES-encrypted)
- Internal/plaintext build: 39,616 bytes, entropy 6.66 (code bytes identical)
- No $PS1 envelope (unique among PSP entries — encrypted-then-signed, not signed-only)
- ~247 functions (per project-ariel Ghidra analysis)
- Two signature-verification entry points: internal $PS1 verifier at 0x5C90,
  and TOS-callable export at 0x11B04
- Gate 3 (fn 0x944): hardware-fingerprint validator, reads 0x03200048 (must = 0xBC0B02A0)
- BL derives 7 key types from Platform Derivation Secret (PDS); IKEK is key 6

### Security model (from project-ariel bc250_manual.md §3)

**Four-layer trust chain (empirically characterized):**

| Layer | Name | Fires? | Effect |
|-------|------|--------|--------|
| 1 | Boot ROM Root Key | **NO** — inert on non-secure silicon | Would validate BL_PUBLIC_KEY vs fused root key |
| 2 | $KDB Key-Store Integrity | **ALWAYS FATAL** | Independent of $PS1/$PSB. 2 boards destroyed. |
| 3 | $PS1 Firmware Signatures | Fatal for TOS | RSA-2048 + SHA-256 (actually CCP HMAC-SHA-256) |
| 4 | DRIVER_ENTRIES Ring Cmds | Stubbed | LOAD_TA returns 0xFFFF000A |

**Critical implications:**
- $PS1 body hash is CCP HMAC-SHA-256 with hardware-derived key, NOT plain SHA-256.
  Standard re-hashing tools produce invalid signatures.
- $KDB blobs (dir 0x50/0x51) contain RSA-2048 key stores. ANY modification is
  hardware-fatal (Layer 2), regardless of recalculated hashes.
- APCB (0xAB1000) is unsigned, checksum-only. Modifications that correct the
  checksum are accepted — confirmed by project-ariel.
- SOC fuses (SMN 0x5D000-0x5D034) read all zeros — unprogrammed.
- PSB_STATUS (SMN 0x5D04C) = 0x0 — no Platform Secure Boot.
- CCP PCI device 0x143e present but x86-unusable (not in kernel driver table,
  target-aborts on MMIO reads).

### Hypotheses for `saved_len` uninitialization

**H1: Missing group path.** BC-250 strips CCXG (0x1702) and GNBG (0x1705).
If PSP_BL's parser initializes `saved_len` inside the handler for one of
these groups, their absence leaves it uninitialized for subsequent groups.
Test: add an empty CCXG or GNBG group header to see if behavior changes.

**H2: Zero-type-count path.** A group with zero type entries might skip
the initialization loop that sets `saved_len`. Test: add a group with
no types (just the 16-byte group header).

**H3: Specific type dependency.** `saved_len` is set when processing a
specific TypeId (e.g., a metadata type). If that type is missing or
reordered, `saved_len` stays uninitialized. Test: reorder types within
a group, or remove one.

**Session 3 update:** `saved_len` was NOT found in any of the 30+
decompiled PSP_BL functions. It may be:
- A local variable in a function reached via runtime-computed pointer
- Named differently in the actual source (mergeconflicted's naming)
- In a function we haven't decompiled (e.g., callees of FUN_000062BE
  or FUN_00001F40 in the alternative APCB copy paths)

## Experiment phases

### Phase 1: Deep ABL4 static analysis (DONE ✅)

Zero board risk. Full APCB type map, ABL4 call chain, SVC interface,
and overflow localization (PSP_BL not ABL4) established. Results above.

### Phase 2: Get decrypted PSP_BL (DONE ✅ — zero board risk)

**Goal:** Obtain decrypted PSP_BL code to disassemble and understand the
exact vulnerability mechanism.

**Status:** Internal plaintext PSP_BL obtained and analyzed. The key finding
is that 0x5DE0C is NOT a code address — it's a function pointer within
the context structure at 0x5D7AC + 0x660. See "VTABLE POINTER OVERWRITE"
section above.

**PSP_BL body analysis (session 2):**
- File: `firmware/internal_pspbl_body.bin` (39,360 bytes, code only, no $PS1 header)
- 248 PUSH prologues (raw byte scan)
- Interrupt vectors: ARM mode (0xE59FF018 = LDR PC, [PC, #0x18])
- Reset vector at +0x0020: 0x0000013C
- Contains **zero MOVT instructions** (same as ABL4)
- Contains NO "HEAP" magic (0x50414548) — heap is ABL4's structure
- Contains NO "APCB" magic — APCB parsing happens through shared context
- **Critical literal pool entries:**
  - +0x0BB8: **0x5D7AC** (context structure base)
  - +0x0BC8: **0x5D5A4** (0x5D5A4 + 0x868 = 0x5DE0C — alternative decomposition)
- Many SRAM pointers in 0x5xxxx-0x6xxxx range in literal pools

**Option A — PSPEmu: BLOCKED (preserved for reference)**

PSPEmu built and tested. FET field mapping fixed (confirmed +0x14 hypothesis).
Hit two walls during emulation:

1. **Missing AMD public key (type 0x00):** BC-250's PSP directory has NO type 0x00
   entry. Only type 0x50 (BL_PUBLIC_KEY, 3536 bytes with $PS1 envelope) and type
   0x09 (AMD_SEC_DBG_PUBLIC_KEY, 1088 bytes). PSPEmu's BRSP generator
   (`psp-brsp.c:95`) queries type 0x00 → fails → BRSP `abAmdPubKey` zeroed →
   on-chip BL prefetch-aborts at 0x1607abc during RSA signature verification.

2. **IKEK is fuse-derived:** PSP_BL (43008 bytes @ flash 0x8E0400) is
   AES-CBC encrypted with IKEK stored in CCP protected LSB slots. Protected
   LSBs are hardware-enforced: only accessible from PSP execution context,
   not from x86 CCP interface.

   PSPEmu's CCP emulation handles AES with protected LSB keys via proxy-CCP
   (`psp-dev-ccp-v5.c:1264-1269`), but the on-chip BL aborts at RSA
   verification BEFORE reaching the CCP decrypt step.

**PSPEmu technical detail (preserved for future reference):**
- BC-250 profile: `profiles/amd-psp-bc250.h` (Zen 2, 320KB SRAM)
- FET fallback: patched `pspFlashFsFetVerify` + `pspFlashFsPspDirLoad`
- Build: `/root/pspbuild/PSPEmu/build/PSPEmu` in WSL
- FET confirmed: +0x10=0x0 (legacy, empty), +0x14=0xFF8E0000 → $PSP @ 0x8E0000
- PSP dir: 19 entries, no type 0x00, no type 0x21 (WRAPPED_IKEK), no L2 dir
- PSP_BL: type 0x01, 43008 bytes, high-entropy (encrypted), no $PS1 envelope
- sys mode (`-m sys`): copies encrypted PSP_BL raw to SRAM → executes garbage
- on-chip-bl mode (`-m on-chip-bl`): needs BootROM binary → RSA verify fails
- `--bin-load` can load a pre-decrypted binary directly (if we had one)

**Option B — Community dump (Studebaker has one):**
- **Studebaker confirmed having Ghidra decompilations of PSP_BL** (Discord
  9/6/2026: "I have ghidra decompilations if you need something").
- project-ariel `bc250_manual.md` §3 confirms plaintext internal PSP_BL builds
  exist: 39,616 bytes, entropy 6.66 (vs 43,008 encrypted, entropy 8.00).
  Code bytes are byte-identical between internal and public builds.
- If obtained: use PSPEmu `--bin-load` to load directly, skip BootROM entirely.
- **ACTION: Ask Studebaker for the PSP_BL binary or Ghidra .gzf export.**

**Option C — Live SRAM dump via SMN: ~~DEAD~~**
- PSP SRAM is NOT x86-accessible via SMN. See "Option C is DEAD" analysis.

**Option D — TOCTOU (community consensus path):**
- Studebaker: "If you aren't working toward toctou, you aren't making progress.
  Once you have toctou, you have anything you want."
- Uses Pico (RP2040) as SPI interposer between PSP and flash chip.
- Substitutes modified firmware AFTER signature check but BEFORE use.
- **Studebaker shared: pico-toctou.zip, pico-toctou-wiki-docs.zip,
  spi-sniffer.zip** (Discord 9/7/2026).
- Requires: Pico2, SOIC-8 clip (or lifted SPI legs), custom firmware.
- Hardware attack — requires physical board modification.
- References: pAMDora (39C3, 2022), faulTPM, Positive Tech BC-250 TOCTOU.

**Option E — Blind APCB probing (Phase 3, skip Phase 2):**
- **project-ariel confirms APCB is unsigned, checksum-only** (§3.12):
  "modifications within slack that correct the checksum are accepted and
  the board boots cleanly."
- We know the vulnerability is at PSP VA 0x0005DE0C (mergeconflicted's lead).
- We have the APCB structure fully mapped (15 entries, checksums, padding).
- Additional unpatched CVEs from project-ariel §3.16:
  - CVE-2025-29951: PSP BL stack buffer overflow (HIGH 7.3, UNPATCHED)
  - CVE-2025-48515: PSP BL SPIROM integer overflow (MEDIUM, UNPATCHED)
  - CVE-2021-26391: TOS TA loader $PS1 size mismatch (HIGH 7.8, UNPATCHED)
- Risk: board may fail to POST. Recovery via flashrom or CH341A.
- Requires explicit user consent per "don't brick" constraint.

**Risk:** Zero for B. D requires hardware mod. E has board risk.

### Phase 3: Crafted APCB probing (BOARD RISK — needs explicit consent)

**Goal:** Trigger the vulnerability with crafted APCB data, observe behavior.

**Craft tool:** `work/apcb_craft.py` — already written. Commands:
- `map`: show all type entries with field offsets
- `inflate`: change a type_size field + recompute checksum
- `inject`: write raw bytes at an offset (e.g., payload in padding zone)
- `add-group`: insert an empty group header (CCXG/GNBG)
- `diff`: byte-level diff of two APCBs

**Probing sequence (conservative → aggressive):**

| Test | Modification | Hypothesis tested |
|------|-------------|-------------------|
| P3.1 | Add empty CCXG group (0x1702) at end | H1: missing group causes `saved_len` skip |
| P3.2 | Add empty GNBG group (0x1705) at end | H1 variant: GNBG specifically |
| P3.3 | Inflate PSPG type 0x0060 (entry #2): 0x20→0x24 (+4) | Minimal overflow, reads into DFG header |
| P3.4 | Inflate CBSG type 0x000F (entry #14): 0x06E8→0x0700 (+24) | Reads 24 bytes of 0xFF padding |
| P3.5 | Inflate CBSG type 0x000F: 0x06E8→0x1000 (+792) | Large overflow into controlled padding |
| P3.6 | Inject NOP sled + marker in padding (+0xB64) + P3.5 | Controlled overflow with known payload |

**Flash method:** `flashrom -p internal` (read backup first, write APCB
region only via `--layout` + `--image`).

**Recovery ladder:**
1. CMOS clear (jumper CLRCMOS1, 60s + battery out)
2. Reflash stock APCB via `flashrom -p internal` if board boots to Linux
3. Reflash full stock image via CH341A if hard brick

**Risk:** Board may fail to POST. CMOS clear covers most cases.
CH341A reflash for hard brick. This CONFLICTS with "don't brick,
don't force a BIOS reflash" hard limit. **Requires explicit user
override before proceeding.**

### Phase 4: Exploit development (requires Phase 2 or 3 success)

**Goal:** Craft a weaponized APCB that achieves controlled PSP code execution.

**Depends on:** knowing the exact overflow target (stack vs heap), the return
address layout, and whether ASLR/stack canaries exist in PSP_BL context.
Phase 2 (decrypted PSP_BL) makes this sighted; Phase 3 alone makes it blind.

**Payload targets (in priority order):**
1. Clear `CC_UVD_HARVESTING` at MMIO 0x1f81c → 0x00 (from PSP context)
2. Set `0x6007` PSP kernel-RAM byte to non-zero (staging-slot walker gate)
3. Program KDB usage-6 key (Cezanne: `c37290c310e64a62b027c56695492368`)
4. Clear SEC_GASKET entries at 0x1f820/0x1f8a4 and fabric-ACL writes
5. Resume normal boot (return to ABL4 → TOS → OS)

## What to execute now

**Phase 2.5 is substantially complete.** The two-stage attack model is
established, 30+ PSP_BL functions decompiled, full stack frame census done,
and the APCB processing chain traced from SVC entry to DMA copy. Three
open questions block Phase 3 exploit construction:

### Open question 1: The exact stack overflow mechanism

No PSP_BL function has the classic "unbounded copy into stack buffer"
pattern. Every copy we've traced has either:
- Hardcoded sizes matching the buffer (FUN_000057C4: 0x640→0x640)
- Bounds checks against the destination (FUN_0000823C: `param_3 <= param_4`)
- DMA with sizes from APCB headers (FUN_00001C18: no stack involvement)

**Most likely candidates:**
- **Linear SRAM overflow via DMA:** FUN_000071AC computes destination as
  `*DAT_0000729c + param_4 + 0x100` and size as `*(param_1 + 0x14)` or
  `*(param_1 + 0x54)`, both from APCB header data. If the APCB claims a
  larger size than the allocated SRAM region, the DMA (FUN_00001C18)
  overwrites adjacent memory. The overflow target is wherever the DMA
  destination sits relative to 0x5D7AC.
- **Integer overflow in FUN_000071AC:** The alignment computation
  `*(param_1 + 0x54) + 0x1fU & 0xffffffe0` could wrap for crafted values.
  If it wraps to a small number, the size check passes but the DMA copies
  the original large amount.
- **Stacked frame exhaustion:** The APCB processing is recursive
  (FUN_0006804C in ABL4 calls itself). If the PSP_BL side also recurses
  for each APCB group, many groups could exhaust the limited PSP stack.

**Next investigative step:** Decompile FUN_000062BE (called from
FUN_000071AC as alternative to FUN_00001C18), and trace the literal pool
value at DAT_0000729c to determine the DMA destination base address and
its proximity to 0x5D7AC. Also investigate whether the `param_5 != 0`
path in FUN_000071AC (calls FUN_00001F40 instead of FUN_00001C18) has
weaker bounds checking.

### Open question 2: How +0x660 gets its real dispatch function — RESOLVED ✅

**RESOLVED (sessions 4-10):** 0x60FE9 IS the real dispatch function.

- 0x60FE9 = Thumb pointer to 0x60FE8 (bit 0 = Thumb flag)
- 0x60FE8 = token_dispatch (258 bytes): inter-node UMC register communication
- FUN_00069BE8 self-fulfills the condition gate: `*addr = 2; addr[1] = 1`
  makes FUN_0006BC50 always return 1 → FUN_0006B590 always writes +0x660
- **SVCs are NOPs** (VBAR=0x100, only VBAR write in binary, SVC vector =
  BX LR). ABL4's 96 SVCs return immediately with no effect.
- PSP_BL never writes to context+0x660 (confirmed exhaustive search)
- The +0x660 value set by FUN_0006B590 is the ONLY value it ever holds

**Implication:** To corrupt +0x660, the attacker must achieve PSP code
execution first and directly write to SRAM 0x5DE0C. The dispatch pointer
is not populated from APCB data — it's hardcoded in ABL4's literal pool.

### Open question 3: `saved_len` identity

Mergeconflicted's "saved_len uninitialized fault" has not been located.
It may be:
- A local variable in one of the APCB processing functions
- A field in the config buffer at 0x4F000 (filled by FUN_000075A4)
- A stack variable in FUN_00000300's S3 resume path (FUN_000018E4)

**Next step:** Search for variables that control copy bounds and are
conditionally initialized (only set in certain GroupId/TypeId paths).

### Option C is DEAD — PSP SRAM is not x86-accessible via SMN

**Evidence (2026-09-17):**
1. The PSPEmu psp-ccd.c comment about "SMN base 0x0 → PSP SRAM" describes
   the PSP's OWN SMN aperture (PSP VA 0x01000000+ looking outward at other
   IPs), NOT an x86-side window into PSP SRAM.
2. Chip-wide SMN sweep (DLV-A25) found MP0 base 0x16000 has zero live regs
   in first 0x100 bytes — PSP SRAM is not mapped there.
3. IP discovery: MP0 bases are [0x16000, 0xDC0000, 0xE00000, 0xE40000,
   0x0243FC00] — mailbox/register regions, not SRAM.
4. PSP MP9 sweep (0xC000-0xD000) finds config registers (debug magic,
   feature mask, TMR alloc, TA digests) — not code/data SRAM.
5. PSP SRAM is internal to the Cortex-A5 core. From x86 it can only be
   reached through the PSP's mailbox/ring-buffer interface, not direct reads.

The existing PSP SRAM dump (psp_sram_0x7b_sweep_2026_05_24.json) was done
*inside PSPEmu* using SVC 0x7b as an in-PSP memory read primitive, NOT from
x86 via SMN. It captured 320KB at a post-TOS point (TOS code at 0x3000-0x6C00,
AMD property strings at 0xE000+), not PSP_BL-phase content.

### Flash write constraints — AND-only vs flashrom

Two write paths exist:
- **SMM SmiFlash handler** (recon `chip_smiflash_write`): AND-only. Can clear
  bits but not set them. No erase. Good for NVAR-append and writes into 0xFF
  padding (0xFF AND X = X → arbitrary data in padding regions).
- **flashrom -p internal**: Full read/write/erase via SPI controller. Can
  write arbitrary data anywhere. Available when Linux is booted.

**For Phase 3:** flashrom is the write method. It can inflate type_size values
(requires setting bits), add groups, inject payloads. The AND-only limitation
does NOT apply to flashrom.

**Recovery constraint:** if the modified APCB prevents POST, the board won't
reach Linux, so flashrom is unavailable. Recovery requires external SPI
programmer (CH341A). This is the "don't brick" risk.

### Revised path forward (updated session 3)

**Phases 1, 2, 2.5 are SUBSTANTIALLY COMPLETE.** The decrypted PSP_BL is in
hand, the vtable dispatch overwrite at context+0x660 is confirmed, the
two-stage attack model is established, and 30+ PSP_BL functions are
decompiled. Three open questions remain (see "What to execute now").

**Remaining zero-risk work:**
1. **DMA destination analysis:** Resolve DAT_0000729c to determine where APCB
   data lands in SRAM, and its proximity to context 0x5D7AC. This pins down
   whether linear overflow from DMA can reach +0x660.
2. **FUN_000062BE decompile:** Alternative copy path in FUN_000071AC — may have
   weaker bounds checking than FUN_00001C18.
3. **SVC return buffer analysis:** How PSP_BL passes data back to ABL4 after
   SVC 0x1c — may reveal the +0x660 write mechanism.
4. **PSPEmu validation (optional):** `--bin-load` with GDB stub would give
   dynamic confirmation of all static findings.

**Phase 3 decision point:** The craft tool (`work/apcb_craft.py`) is ready.
Phase 3 involves modifying APCB in SPI flash and carries brick risk.
We now know enough to design intelligent probes:
- **Probe A (safe):** Modify type_size of a padding-adjacent entry to extend
  into 0xFF space. If it boots, APCB size validation is weak.
- **Probe B (medium):** Inflate APCB data to cause DMA overshoot into context
  region. Requires knowing DMA dest (open question 1).
- **Probe C (aggressive):** Craft APCB with dispatch pointer replacement —
  requires all three open questions answered.

**Phase 3 still requires explicit user override per "don't brick" constraint.**

## Tools built

| Tool | Location | Purpose |
|------|----------|---------|
| `apcb_craft.py` | `work/apcb_craft.py` | APCB modification + checksum recompute |
| `recon find-svc` | `community-tools/recon/` | SVC call site enumeration |
| `recon disasm-fn` | `community-tools/recon/` | Annotated function disassembly |
| `recon apcb` | `community-tools/recon/` | APCB parsing/audit/diff |
| Ghidra scripts | scratchpad (session 2) | pyghidra decompilation + analysis |

**Session 2 Ghidra scripts** (in scratchpad, pyghidra-based):
- `ghidra_vuln_decompile.py` — Decompiled 7 key functions (FUN_0006804C, FUN_00069FAC, etc.)
- `ghidra_allocator_decompile.py` — Allocator, type lookup, APCB blob pointer analysis
- `ghidra_debug_print.py` — Debug output chain, memcpy, assert, literal pool values
- `ghidra_trace_output.py` — Debug output impl, exhaustive 0x5DE0C scan (zero matches)
- `search_pspbl_for_vuln.py` — PSP_BL literal pool analysis (found 0x5D7AC + 0x660)

**apcb_craft.py commands:**
```
py apcb_craft.py map --input APCB.bin            # show all type entries
py apcb_craft.py inflate --input X --output Y --entry 14 --size 0x1000
py apcb_craft.py add-group --input X --output Y --magic CCXG --gid 0x1702
py apcb_craft.py inject --input X --output Y --payload shell.bin --offset 0xb64
py apcb_craft.py diff --a stock.bin --b modified.bin
```

## Data files

| File | Description |
|------|-------------|
| `firmware/internal_abl4_decompressed.bin` | Decompressed ABL4, 88,000 bytes, ARM Thumb |
| `firmware/internal_pspbl_body.bin` | Decrypted PSP_BL body, 39,360 bytes, ARM |
| `firmware/live_apcb.bin` | APCB from live BC-250 (2,928 bytes, 6 groups) |
| `firmware/internal_apcb.bin` | APCB from internal BIOS (1,160 bytes, 6 groups) |
| `ghidra_projects/bc250_abl4_v3/` | Ghidra project for ABL4 (147 functions analyzed) |
| `work/extracted_stock/d01_e00_APCB~0x60` | Stock APCB binary (8192 bytes, 2916 active) |
| `work/extracted_stock/d00_e12_ABL4~0x34_21.11.26.0` | Raw ABL4 with $PS1 envelope |
| `community-tools/PSPEmu/` | PSP emulator source (Linux-only, needs build) |
| `work/apcb_craft.py` | APCB modification tool |
| `work/payloads/` | Directory for crafted APCB test images |

## PSP SRAM access (corrected understanding)

The PSPEmu comment (`psp-ccd.c:762`) about "SMN base 0x0 → PSP SRAM"
describes the PSP's OWN outward-facing SMN aperture — how the PSP reads
other IP blocks — NOT an x86-side window into PSP memory. See "Option C
is DEAD" section above for full evidence.

**PSP memory is NOT x86-addressable.** The only x86→PSP interface is
the mailbox (MP0 SMN region at 0x16000) and the ring buffer (used by
amdgpu's PSP driver). Neither provides arbitrary SRAM read capability.

**PSP VA 0x0005DE0C mapping:** Zen 2 SRAM is 320KB (0x50000) per the
profile. VA 0x5DE0C (384,524) exceeds this range, indicating the PSP
uses its ARM MPU to remap VA space. The on-chip BootROM maps to high VA
(0xFFFF0000 for ARM high vectors). PSP_BL's code segment likely has a
non-identity VA→SRAM mapping. Resolving this requires either PSPEmu
analysis or the PSP_BL binary itself.

## PSPEmu build + run (Linux)

**Copy these files to the Linux host:**
```
bc250-psp-rce/
├── community-tools/PSPEmu/    (full source tree)
├── firmware/BC250_live.bin     (16MB SPI dump)
├── work/build_pspemu.sh       (build script)
└── work/live_APCB.bin         (live board APCB, for reference)
```

**Build:**
```bash
sudo apt install cmake build-essential pkg-config libssl-dev zlib1g-dev
cd bc250-psp-rce/work
chmod +x build_pspemu.sh
./build_pspemu.sh
```

**Run (attempt 1 — standard Zen 2 IKEK):**
```bash
cd community-tools/PSPEmu/build
./PSPEmu --psp-profile bc250 --flash-rom ../../../firmware/BC250_live.bin \
  --trace-svcs --intercept-svc-6 --stop-after-bl-load 2>&1 | tee pspemu_bc250.log
```
If IKEK is correct, PSP_BL decrypts and ABL stages begin loading. Dump the
decrypted PSP_BL from emulated SRAM at that point (GDB stub at :1234).

**If IKEK fails:** PSPEmu will log a CCP decryption error. Options:
1. Check PSPEmu source for per-family IKEK selection (Cyan Skillfish may need
   a distinct key derived from different fuse values).
2. Ask community for the correct IKEK or a pre-decrypted binary.
3. Proxy-CCP mode (`-X`) — requires a running PSP on the board to proxy AES
   operations. Heavy setup; deferred unless needed.

## Cross-references

- `FIRMWARE_MAP.md` — full SPI image inventory
- `VCN_BLOCKERS_FINAL_2026_09_11.md` — the three VCN gates this would solve
- `COMMUNITY_REPORT_2026_09_06.md` — SMU-side work history
- `community-tools/recon/docs/bc250-smm-flash-rw.md` — SMM flash write capability
- Memory: `[[project_bc250_discord_findings]]` — mergeconflicted attribution
- PSPEmu SRAM comment: `community-tools/PSPEmu/psp-ccd.c:762`

## Session log

### Session 1 (2026-09-17, earlier)
- Loaded ABL4 into Ghidra, established call chain and APCB type map
- Fixed APCB structure parser (both live and internal APCBs validated)
- Confirmed ABL4 copy loop is bounded (255 bytes, `uxtb` truncation)
- Concluded overflow is in PSP_BL, not ABL4
- Mapped SVC interface (0x16, 0x0A, 0x1D)
- Built `apcb_craft.py` for Phase 3 probing
- PSPEmu blocked (no type 0x00, IKEK fuse-derived)

### Session 2 (2026-09-17)
- Loaded ABL4 into Ghidra project `bc250_abl4_v3` (147 functions)
- Decompiled 7 key functions via pyghidra:
  - FUN_0006804C (core APCB handler): token buffer allocation, recursive call
  - FUN_00069FAC (blob loader): heap linked-list walker
  - FUN_0006F1D8 + FUN_0006BB9C: vtable dispatch through context+0x660
  - FUN_00069D78 (allocator): heap at 0x72000
  - FUN_00062950 (debug output): 512-byte stack buffer, IDS dispatch
- Exhaustive search for 0x5DE0C in ABL4: ZERO matches (u32, u16, MOVW/MOVT,
  literal pool, base+offset decomposition with Ghidra xref checking)
- **KEY DISCOVERY:** Searched PSP_BL literal pools — found 0x5D7AC at
  +0x0BB8. Context structure base 0x5D7AC + offset 0x660 = 0x5DE0C.
  The vulnerability is a VTABLE POINTER OVERWRITE, not a simple buffer overflow.
- Mapped complete PSP runtime memory layout (context, heap, APCB groups, ABL4)
- Confirmed zero MOVT instructions in BOTH ABL4 and PSP_BL binaries
- PSPEmu build blocked on Windows (POSIX-only, no WSL); pivoted to static analysis
- Network share (10.0.0.41) unreachable — file sync deferred

### Session 3 (2026-09-17, Phase 2.5 — overflow path tracing)

**Goal:** Trace the exact overflow path from APCB data to context+0x660
in PSP_BL's code. All work zero board risk (static analysis only).

**ATTACK MODEL REVISION — Two-stage, not direct overflow:**

Prior assumption: PSP_BL's APCB parsing directly overflows a buffer inside
the context structure at 0x5D7AC, reaching the dispatch pointer at +0x660.

Revised (evidence-based): PSP_BL has **zero writes to 0x5DE0C** through any
mechanism — no STR.W with #0x660, no MOVW loading 0xD7AC or 0xDE0C, no
ADD.W with 0x660, no literal for 0x5DE0C. The only 0x5D7AC reference (at
PSP_BL offset 0x0958) is for a READ, not a write.

**Revised two-stage attack model:**
1. CVE-2025-29951 stack overflow in PSP_BL → PSP_BL code execution
2. Shellcode writes crafted function pointer to SRAM 0x5DE0C
3. ABL4 dispatches token ops through corrupted +0x660 → attacker code

This is consistent with CVE-2025-29951 being a "PSP BL stack overflow" —
the overflow gives PSP_BL-level code execution, and the shellcode then
has full SRAM access to corrupt ABL4's context.

**KEY FINDINGS — PSP_BL function decompilation:**

Decompiled **30+ PSP_BL functions** via pyghidra. Key results:

1. **FUN_000075A4** (532 bytes, config buffer builder):
   - Writes to 0x4F000+0x660 (NOT context 0x5D7AC+0x660!)
   - 0x4F000 is a SEPARATE config structure, cache-flushed via FUN_0000120C
   - `_DAT_0004f660 = *DAT_000077e8` — value from runtime data at 0xB814
   - This function builds a 0x1000-byte config block, NOT the ABL4 context

2. **FUN_00000300** (1000 bytes, main SVC dispatch handler):
   - Full boot pipeline: copies 0x440 bytes from caller at entry
   - Calls FUN_000066A0 twice for APCB groups 0x28 and 0x02 with 0x40000 sizes
   - Calls FUN_000082E6 → FUN_000075A4 (config buffer build)
   - Calls FUN_000018E4 for S3 resume path

3. **FUN_000044CC** (2728 bytes, SVC command dispatcher):
   - ~80 switch cases processing different SVC commands
   - Case 2: APCB data load via FUN_000066A0
   - Case 0xDE: Calls FUN_000053C4 (1600-byte stack buffer)
   - Case 0xF2: Direct memory write (bounds-checked to MMIO ≥0xC00000)
   - 58 distinct callees identified

4. **FUN_000066A0** (284 bytes, APCB data dispatcher):
   - Validates params, dispatches to FUN_00002C80 or FUN_0000083C+FUN_0000823C
   - Final call: FUN_00007014 (APCB data copy/install)
   - Table lookup via param_6 for alternative paths

5. **FUN_00007014** (320 bytes, APCB data installer):
   - Computes sizes from APCB header fields (attacker-controlled)
   - Calls FUN_000071AC for core copy, FUN_0000823C for header validation
   - Calls FUN_00008500 for signature verification
   - Has size checks but sizes come from APCB structures

6. **FUN_000071AC** (240 bytes, core APCB data copy):
   - Destination: `*DAT_0000729c + param_4 + 0x100` (SRAM address)
   - Size: computed from APCB header `*(param_1 + 0x14)` or `*(param_1 + 0x54)`
   - Dispatches to FUN_00001C18 (DMA copy) or FUN_0000237C (decompress)
   - Check: `if (param_3 < uVar4) return 3` — size validation

7. **FUN_00001C18** (124 bytes, DMA-based SRAM copy):
   - Uses CCP DMA engine (FUN_00000E30) for large copies
   - Cache flush via FUN_0000120C after copy
   - No stack buffers — pure DMA operation

8. **FUN_00000458** (136 bytes, memcpy):
   - 4-parameter: `(dest, src, size, alignment_hint)`
   - 32-byte-at-a-time inner loop with tail handling
   - Ghidra sometimes shows only 2 params (r2 left in register from caller)

**STACK FRAME CENSUS — all PSP_BL functions > 0x40 bytes:**

| Frame   | Entry   | Code   | Function         | Notes                        |
|---------|---------|--------|------------------|------------------------------|
| 0x0670  | 0x53C4  | 214B   | FUN_000053c4     | 1600-byte buffer (0xDE)      |
| 0x0088  | 0x05F0  | 346B   | FUN_000005f0     | Crypto (32+16 byte buffers)  |
| 0x0070  | 0x2434  | 140B   | FUN_00002434     | KDF (68-byte buffer)         |
| 0x0070  | 0x0750  | 232B   | FUN_00000750     | Crypto (32-byte buffer)      |
| 0x0068  | 0x73D0  | 102B   | FUN_000073d0     | APCB types 0x95/0x42/0x91   |
| 0x0068  | 0x7014  | 320B   | FUN_00007014     | APCB data installer          |
| 0x0060  | 0x1720  | 330B   | FUN_00001720     | Key processing               |
| 0x0058  | 0x5850  | 420B   | FUN_00005850     | Certificate processing       |
| 0x0050  | 0x7B00  | 136B   | FUN_00007b00     | PDS key encryption           |
| 0x0050  | 0x1D30  | 380B   | FUN_00001d30     | RSA signature verify         |
| 0x0048  | 0x24FC  | 154B   | FUN_000024fc     | Key derivation               |
| 0x0048  | 0x22A0  | 346B   | FUN_000022a0     | RSA key operations           |
| 0x0048  | 0x1B60  | 178B   | FUN_00001b60     | Crypto ops                   |
| 0x0048  | 0x1A60  | 248B   | FUN_00001a60     | Crypto ops                   |
| 0x0048  | 0x0D7C  | 94B    | FUN_00000d7c     | CCP ops                      |

Only FUN_000053C4 has a large stack buffer, and its 0x640-byte fill
(via FUN_000057C4 → FUN_000074C8) is correctly bounded to exactly
0x640 bytes. **No classic "copy N bytes to M-byte stack buffer where
N > M" found in any PSP_BL function.**

**ABL4 orchestrator call sequence (complete):**

```
0x6BCA4: bl 0x6B590   ; VTABLE INIT (sets +0x660 = 0x60FE9)
0x6BCBA: blx 0x60870  ; memcpy thunk
0x6BCC4: bl 0x62908   ; logging
0x6BCCC: svc #0x1c    ; PSP_BL processes APCB ← SVC entry point
0x6BCD2: bl 0x6A0D0   ; error handler (if SVC failed)
...logging calls...
0x6BD5C: bl 0x6F364   ; "Sync 1st MP0 settings" (USES +0x660 dispatch)
0x6BD74: bl 0x6F290   ; P-state selector (writes +0x2B0 only)
0x6BDA4: bl 0x6F214   ; channel select (through +0x3B0)
0x6BDB4: bl 0x6BB9C   ; FIRST TOKEN READ via +0x660 ← must be valid!
0x6BDFE: bl 0x6F1D8   ; first token write via +0x660
```

FUN_0006F364 ("Sync 1st MP0 settings") already USES the +0x660 dispatch,
calling FUN_0006F1D8 many times. So +0x660 must contain a valid function
pointer BEFORE this point. Yet FUN_0006B590 writes 0x60FE9, which is a
MISALIGNED mid-function entry point that clobbers r0 (context pointer).

**RESOLVED (sessions 4-10): 0x60FE9 IS the working dispatch function.**

The earlier session 3 analysis incorrectly concluded 0x60FE9 was
mid-function entry into FUN_00060F24. Ghidra decompilation in sessions
4-10 revealed 0x60FE8 (= 0x60FE9 & ~1) is its OWN function:
**token_dispatch** (258 bytes), an inter-node UMC register communication
handler that iterates slave nodes and manages training point data.

The session 3 register-clobber analysis was wrong because it decoded
the wrong function. 0x60FE8 has its own PUSH prologue and correct
parameter handling for dispatch(context, op, token_id[, value]).

Additionally, SVCs are NOPs (VBAR=0x100, exhaustive VBAR-write search
confirmed only ONE write at offset 0x04C), so SVC 0x1c never executes
any PSP_BL handler code. The dispatch pointer is never replaced.

**CONTEXT STRUCTURE LAYOUT (refined):**

```
+0x008: pointer (channel data)
+0x00C: computed channel pointer
+0x00F: byte flag (loaded by dispatch entry)
+0x014: string (written by FUN_0006f214)
+0x034: copied from +0x038
+0x038: pointer to channel table
+0x049: channel index byte
+0x04A: sub-channel byte
+0x04B: channel count byte
+0x0CC: = byte at +0x330 area — number of memory P-states
+0x124-0x2A3: zeroed (0x180 bytes)
+0x2A4: pointer to +0x124 + channel*0x18
+0x2B0: P-state index (written by FUN_0006f290)
+0x330: P-state count
+0x332-0x374: zeroed (0x43 bytes)
+0x343: set to 1 by vtable init
+0x378-0x50F: BULK VTABLE (102 function pointers, default 0x61465)
+0x3B0: channel-select method pointer
+0x510-0x5B7: data fields (APCB-derived config)
+0x5B8: 0x66D9F → FUN_000664d4 (memory timing override)
+0x5C0: 0x6147B → inside FUN_00061400 (log)
+0x614: 0x64F25 → FUN_00063D0C (SMN register config, 9936 bytes)
+0x620: 0x61469 → inside FUN_00061400 (log)
+0x624: 0x64AA5 → function
+0x628: 0x60F41 → debug sync (FUN_00060F24)
+0x62C: 0x60F9D → vtable entry
+0x630: 0x64F41 → inside FUN_00063D0C
+0x654: 0x66D9D → inside FUN_000664d4
+0x660: 0x60FE9 → token_dispatch (THE real dispatch fn — sessions 4-10 confirmed)
```

### VULNERABILITY FOUND: DMA overshoot in FUN_000071AC (session 3)

**The unbounded copy in FUN_000071AC → FUN_00001C18:**

```
APCB processing chain:
  FUN_00000300 (SVC handler)
  → FUN_000066A0 (APCB dispatcher, passes 0x40000 as source_size)
    → FUN_00002C80 (group lookup, returns offset from APCB header)
    → FUN_00007014 (APCB installer)
      → FUN_000071AC (core copy)
        → FUN_00001C18 (DMA engine copy) ← THE OVERFLOW
```

FUN_000071AC computes:
```c
uVar4 = *(param_1 + 0x14);  // DATA SIZE — from APCB header (attacker-controlled!)
iVar1 = *(0x9A10) + param_4 + 0x100;  // DESTINATION in SRAM

if (param_3 < uVar4) return 3;  // Only checks SOURCE buffer size!
// NO CHECK: destination + uVar4 within bounds

FUN_00001c18(iVar1, uVar2, uVar4, ...);  // DMA: copy uVar4 bytes to dest
```

**The source check passes** because `param_3` = 0x40000 (256KB, from FUN_00000300)
and `uVar4` can be up to 0x40000 from the crafted APCB header.

**The destination has no size check.** The DMA writes `uVar4` bytes starting at
`*(0x9A10) + offset + 0x100`. If the actual APCB region at the destination is
smaller than `uVar4`, the DMA overshoots into adjacent SRAM structures.

**Destination address computation:**
```
DMA destination = *(0x9A10) + (APCB_group_offset & *(0x9A24)) + 0x100
```

Where:
- `*(0x9A10)` = DMA base address, set by FUN_00008168 via FUN_00003650
  (CCP/DMA slot allocator, returns `(base & 0x3FFFFFF) + slot * 0x4000000 + 0x4000000`)
- `APCB_group_offset` = from APCB header entry[+8] (attacker-controlled)
- `*(0x9A24)` = alignment mask (runtime value)
- `+0x100` = header skip

**The bounds check in FUN_0000823C does NOT protect against this:**
FUN_0000823C checks `offset + size < *(0x9A20)` but this only guards the
HEADER copy (0x100 bytes via FUN_00000458). The DATA copy in FUN_000071AC
goes directly to FUN_00001C18 without passing through FUN_0000823C.

**Attack vector:** Craft APCB header with:
1. Valid group/type IDs (parser must find the entry)
2. Large `*(entry + 0x14)` size field (up to 0x40000 passes source check)
3. Correct 8-bit additive checksum
4. The DMA overshoots from the APCB destination region into the context
   structure at 0x5D7AC, reaching +0x660 with a controlled function pointer

**Relationship to CVE-2025-29951:** AMD calls this a "PSP BL stack buffer
overflow" but the actual mechanism is a DMA overshoot into SRAM. This is
consistent — "stack buffer overflow" may refer to the PSP_BL stack being
in the overshoot path, or AMD may classify all unbounded copies as "stack
buffer overflow" regardless of the actual memory region.

**Relationship to `saved_len`:** mergeconflicted's "saved_len uninitialized"
may refer to the size field at `*(param_1 + 0x14)` in FUN_000071AC. If the
APCB entry structure is partially initialized (missing group leaves the size
field uninitialized), it could contain a large value that causes the
overshoot. On BC-250's stripped APCB (no CCXG/GNBG groups), a missing
initialization path could leave this field as whatever was in SRAM.

### DMA destination — RESOLVED (session 3.5)

***(0x9A10) is an SMN-mapped DRAM window, NOT PSP SRAM.***

Complete chain:
```
FUN_00008168:
  FUN_00007fa4(0x17)               → sets *(0x9A18) = 0xFF800000, *(0x9A20) = 0x800000
  FUN_00003650(*(0x9A18), 0, 6, 0xC0800000) → allocates SMN slot 8+
  *(0x9A10) = (0xFF800000 & 0x3FFFFFF) + slot*0x4000000 + 0x4000000
            = 0x3800000 + 8*0x4000000 + 0x4000000
            = 0x27800000 (first free slot)
```

**Address model:**
- FUN_00003650 is an SMN mapping slot allocator. Mode 6 uses slots 8-14.
- Each slot maps a 64MB region. DAT_0000822c = 0xC0800000 is the SMN
  target (system DRAM physical address).
- Return = PSP virtual address of the SMN window.
- *(0x9A10) = ~0x27800000 — this is a DRAM-mapped virtual address.

**Consequence: the DMA in FUN_000071AC writes to DRAM, NOT PSP SRAM.**
The context structure at SRAM 0x5D7AC is unreachable via the DMA overshoot.
The DMA destination range is 0x27800100 to 0x27FFFFFF (8MB window).

**FUN_00007FA4 memory mode table (literal pool at 0x800C-0x801C):**
```
Mode 0x13: base=0xFFF80000, bound=0x80000  (512KB)
Mode 0x14: base=0xFFF00000, bound=0x100000 (1MB)
Mode 0x15: base=0xFFE00000, bound=0x200000 (2MB)
Mode 0x16: base=0xFFC00000, bound=0x400000 (4MB)
Mode 0x17: base=0xFF800000, bound=0x800000 (8MB)  ← APCB mode
Mode 0x18: base=0xFF000000, bound=0x1000000 (16MB)
```

### *(0x9A24) mask — NEVER INITIALIZED (session 3.5)

**The mask at SRAM 0x9A24 has ZERO write sites in PSP_BL code.**

Two literal pool references (0x2CCC and 0x7560) — both READ-only.
FUN_00007FA4 initializes *(0x9A18) and *(0x9A20) but NOT *(0x9A24).
No other function writes to this address.

The mask value depends on what SRAM 0x9A24 contains at boot. If SRAM
is zeroed by hardware reset, mask = 0 → all offsets masked to 0. If
SRAM retains previous contents, mask is unpredictable.

In FUN_00002C80: `*param_3 = local_18[0] & *(0x9A24)` — with mask=0,
all APCB group offsets become 0. With mask=0xFFFFFFFF, offsets pass
through unchanged. This affects WHERE in the 8MB DRAM window the data
lands, but the window is still DRAM (not SRAM).

### 0x9B60 — Fixed SRAM buffer, NOT uninitialized pointer (session 3.5)

DAT_000067bc = 0x9B60 is a LITERAL VALUE (fixed SRAM address), not a
runtime pointer. ZERO write sites to *(0x9B60) in the literal pool
scan — no code writes through *(0x9B60) as an indirect pointer.

FUN_000066A0 uses 0x9B60 as a destination buffer for APCB group
headers when param_7 = 0 (second call, GNBG group 0x02). When
param_7 = 1 (first call, CCXG group 0x28), it uses the caller's
buffer instead. FUN_0000823C copies 0x100 bytes of APCB header
from DRAM to SRAM 0x9B60.

### +0x660 dispatch function — 0x60FE9 IS the real implementation (session 3.5)

0x60FE9 is NOT a misaligned placeholder. In ARM Thumb interworking,
bit 0 = Thumb flag. 0x60FE9 & ~1 = 0x60FE8, which is ABL4 binary
offset 0x60FE8 - 0x60834 = 0x7B4. This is a valid Thumb function.

PSP_BL never writes to context+0x660 (confirmed session 3 exhaustive
search). The value 0x60FE9 set by ABL4's FUN_0006B590 (vtable init)
IS the default and only dispatch function. No replacement occurs.

**Implication:** To corrupt +0x660, the attacker must write directly
to SRAM 0x5DE0C. This requires PSP code execution first (Stage 1).

### PSP architecture — Cortex-A5 (session 3.5)

PSP_BL binary starts with ARM exception vectors (LDR PC, [PC, #0x18]),
NOT Cortex-M vector table (stack pointer + reset vector). This is
consistent with Zen 2 PSP = Cortex-A5.

Exception table:
```
0x00: Reset → 0x13C (ARM mode)
0x04: Undef → 0x2F4
0x08: SVC   → 0x298
0x0C: Prefetch Abort → 0x2F8
0x10: Data Abort → 0x304
0x14: Reserved (NOP)
0x18: IRQ → 0x328
0x1C: FIQ
```

SVC handler at 0x298 is cache maintenance code (MCR p15 instructions),
NOT an SVC handler. This is the initial vector table (VBAR=0). **Session
4-10 proved VBAR is set to 0x100 at offset 0x04C (the only VBAR write
in the binary), making the SVC vector at 0x108 = BX LR = NOP.** The dead
SVC handler at 0x198 (PUSH {R0-R12,LR}, extracts SVC number, dispatches
to FUN_00005278 or FUN_000044CC) is unreachable after VBAR=0x100. All 96
ABL4 SVCs are NOPs — ABL4 runs independently after launch.

### PSP SRAM memory map (refined, session 3.5)

```
0x00000-0x099C0   PSP_BL code (39,360 bytes, Thumb + ARM vectors)
0x09A00-0x09FFF   Runtime data area (pointers, configs)
  0x09A10         DMA base ptr → 0x27800000 (SMN-mapped DRAM)
  0x09A18         DRAM base = 0xFF800000
  0x09A20         Bounds check = 0x800000 (8MB)
  0x09A24         Offset mask (UNINITIALIZED)
  0x09B60         APCB header cache (0x100 bytes, fixed buffer)
0x0B82C           APCB header copy destination (DAT_00000BEC)
0x4F000-0x50000   Config buffer (FUN_000075A4, flushed to ABL4)
0x5A6A8-?         Unknown structure
0x5B13C-?         Unknown structure
0x5D5A4-?         Context-related structure
0x5D7AC-0x5DF00~  ABL4 context structure (~0x700 bytes)
  +0x660          Dispatch function pointer (= 0x5DE0C)
0x60834-0x75FB4   ABL4 code + data (88,000 bytes)
0x72000           HEAP ("HEAP" magic, ABL4 allocator)
0x7A000           APCB group data (runtime, from SPI flash)
0x7F000-?         Unknown structure (near SRAM top)
```

### REVISED ATTACK MODEL (session 3.5)

**The direct DMA-to-SRAM path is CLOSED.** The DMA destination is
SMN-mapped DRAM (0x27800000+), ~560MB above the context at SRAM
0x5D7AC. No amount of offset or size crafting can bridge this gap.

**Three remaining attack vectors:**

**Vector A — Config buffer injection:**
FUN_000075A4 reads APCB-derived runtime data and writes it to the
config buffer at 0x4F000. It writes to 0x4F660:
```c
_DAT_0004f660 = *DAT_000077e8;
```
If ABL4 later copies config buffer data to the context structure,
the value at 0x4F660 could reach context+0x660. This requires
tracing ABL4's config-buffer-to-context copy path.

**Vector B — PSP_BL stack overflow (CVE-2025-29951) → SRAM write:**
The CVE explicitly says "PSP BL stack buffer overflow." If the stack
is near the context structure in SRAM, a stack overflow could directly
overwrite context+0x660. Cortex-A5 stacks grow DOWN — if the SVC
stack is placed just above the context (e.g., at 0x5E000), deep call
chains during APCB processing could overflow into it. But this gives
STACK FRAME data (return addresses), not controlled values.

**Vector C — Two-stage: PSP_BL RCE → direct SRAM write:**
If CVE-2025-29951 gives PSP_BL code execution (via return address
overwrite from stack overflow), the shellcode can directly write any
value to SRAM 0x5DE0C. This is the most powerful but requires finding
the actual stack overflow first.

**What needs board probing / PSPEmu to resolve:**
1. SVC stack location — is it adjacent to context at 0x5D7AC?
2. SRAM 0x9A24 initial value at boot — zeroed or garbage?
3. ABL4's config buffer → context copy path (if any)
4. The actual PSP_BL stack overflow mechanism (not found statically)
5. Whether FUN_00003650's SMN slot mapping wraps at boundaries

**REMAINING OPEN QUESTIONS (updated session 3.5):**

1. **Where is the CVE-2025-29951 stack overflow?** Not found in any
   of the 40+ decompiled functions. May be in: (a) a runtime-computed
   indirect call target, (b) the Cortex-A5 exception handling path,
   (c) a function reached via the alternative copy path (FUN_000062BE
   → FUN_00001F40), or (d) the S3 resume path (FUN_000018E4).

2. **Does ABL4 copy from 0x4F000 config buffer to context 0x5D7AC?**
   If so, Vector A is viable: attacker controls APCB → FUN_000075A4
   puts APCB data in config buffer → ABL4 copies to context → +0x660
   overwritten. Needs ABL4 decompilation of the post-SVC code path.

3. **Where is the SVC stack?** Cortex-A5 SVC mode has banked SP. The
   reset handler at 0x13C sets it up. If SVC_SP is near 0x5E000
   (just above context), stack overflow → context corruption.

**SESSION 3 + 3.5 SCRIPTS** (in scratchpad, pyghidra-based):
- `pspbl_660_writer.py` — Found FUN_000075A4 writes to 0x4F000+0x660, NOT context
- `pspbl_context_resolution.py` — Proved 0x4F000 is separate from ABL4 context
- `pspbl_b814_and_dispatch.py` — Confirmed 0xB814 is runtime data; 4 SVC 0x1c sites
- `pspbl_5d7ac_access.py` — Exhaustive: NO writes to 0x5DE0C in PSP_BL
- `abl4_mystery_funcs.py` — FUN_0006f364 USES dispatch; FUN_0006f290 writes +0x2B0 only
- `pspbl_overflow_hunt2.py` — FUN_000044CC full decompile (SVC dispatcher)
- `pspbl_66a0_overflow.py` — 10 PSP_BL functions decompiled (APCB chain)
- `pspbl_overflow_deep.py` — FUN_00007014, FUN_0000823C, FUN_000057C4, FUN_00002C80
- `pspbl_overflow_deep2.py` — FUN_000071AC, FUN_00000458, FUN_00001C18, FUN_0000237C
- `pspbl_stack_scan.py` — Complete stack frame census (all functions > 0x40)
- `pspbl_dma_dest.py` — DAT_0000729c=0x9A10, DMA destination is indirect SRAM ptr
- `pspbl_9a10_trace.py` — FUN_000066A0 full decompile, FUN_000037FC re-check
- `pspbl_dma_chain.py` — Complete DMA chain: FUN_00003650, FUN_00008168, runtime map
- `pspbl_runtime_init.py` — *(0x9A20) init=0x800000, *(0x9A24) NEVER INITIALIZED
- `pspbl_3650_resolve.py` — FUN_00003650 slot allocator, mode 0x17 = SMN DRAM window
- `pspbl_address_model.py` — PSP address model, vector table, config buffer analysis
- `pspbl_9b60_trace.py` — *(0x9B60) = fixed SRAM 0x9B60 buffer, not uninitialized ptr

### Sessions 4-10 (2026-09-17, SVC resolution + dispatch mechanism + attack model revision)

**Goal:** Resolve the critical fork point — does PSP_BL patch the SVC vector
at runtime? — then trace the complete vulnerability path from APCB data to
the dispatch function pointer at context+0x660.

#### Finding 1: SVC VECTOR RESOLUTION — DEFINITIVE

**All 96 ABL4 SVCs are NOPs. ABL4 runs independently after PSP_BL launch.**

Evidence chain:
1. **VBAR set to 0x100 at offset 0x04C** — the ONLY VBAR write in the
   entire PSP_BL binary. Exhaustive byte-pattern search (both ARM and Thumb
   MCR p15,0,Rx,c12,c0,0 encodings) confirmed exactly 1 candidate at 0x04C.
2. **SVC vector at 0x108 = BX LR** — a NOP. The entire VBAR table at 0x100
   is: Reset=undef, Undef=BX LR, SVC=BX LR, PrefAbort=BX LR,
   DataAbort=BX LR, Reserved=0, IRQ=BX LR, FIQ=BX LR.
3. **Initial vector table at 0x000** has SVC → 0x298, but 0x298 is a cache
   maintenance loop (`ADD R0, R0, #0x20; CMP R0, #0x800; BNE`), NOT an SVC
   handler. The initial vectors are dummy targets for pre-VBAR boot.
4. **Dead SVC handler at 0x198** — fully functional ARM exception handler
   (PUSH {R0-R12,LR}, extracts SVC#, dispatches to FUN_00005278 for SVC#0
   or FUN_000044CC for others). But UNREACHABLE after VBAR=0x100.
5. **L2 page table functions** (FUN_000035A0, FUN_0000373C, FUN_00005A00)
   modify page descriptors but NEVER patch the SVC vector or VBAR.
6. **ABL4 post-SVC behavior:** CBZ R0 check after SVC — with NOP SVCs,
   R0 retains the buffer pointer (non-zero), so CBZ falls through to
   FUN_0006A0D0 (error/log handler), which continues execution.

**Implication:** PSP_BL sets up all SVC handlers (FUN_000044CC, etc.) but
then NOPs the SVC vector before launching ABL4. ABL4 was DESIGNED to work
with SVC support but runs without it on this platform. SVC failures are
handled gracefully — ABL4 continues and uses its hardcoded defaults.

#### Finding 2: CONFIG BUFFER ≠ CONTEXT STRUCTURE

**The config buffer at 0x4F000 and context structure at 0x5D7AC are
completely separate data structures. The +0x660 offset match is coincidental.**

Evidence:
- Config buffer: 0x4F000-0x4FFFF (PSP_BL's working config, written by
  FUN_000075A4, cache-flushed via FUN_0000120C)
- Context structure: 0x5D7AC-~0x5DF00 (ABL4's working context, passed as
  R1 parameter at launch)
- Gap: 0xE7AC bytes (59,308 bytes) apart
- Config+0x660 source: `DAT_000077e8 → 0xB814` (BSS, APCB-derived runtime data)
- Context+0x660 source: `DAT_0006b5f8 = 0x60FE9` (hardcoded ABL4 literal pool)
- **ABL4 has ZERO literal references to 0x4F000, 0x4F660, 0x5D7AC, or 0x5DE0C**
- The +0x660 offset in both structures serves different purposes:
  config+0x660 stores APCB-derived data, context+0x660 stores a function pointer

**Vector A (config→context copy) is CLOSED.** ABL4 never reads config+0x660
or copies it to context+0x660.

#### Finding 3: DISPATCH POINTER MECHANISM — FULLY TRACED

**FUN_0006B590 always writes context+0x660 = 0x60FE9 (token_dispatch).
The condition gate is self-fulfilling — it cannot fail.**

Complete mechanism:
```c
bool FUN_0006b590(int param_1, int param_2) {
    // param_2+0x3c4 → pointer to capability halfwords
    ushort *cap = *(param_2 + 0x3c4) + 0x5e;

    FUN_00069be8(cap);        // WRITES: *cap = 2, cap[1] = 1
    iVar1 = FUN_0006bc50(cap); // READS: bit1 of cap[0] AND bit0 of cap[1]

    // FUN_00069BE8 just set cap[0]=2 (bit1=1) and cap[1]=1 (bit0=1)
    // → FUN_0006BC50 ALWAYS returns 1 → condition ALWAYS passes

    if (iVar1 != 0) {
        FUN_0006bbc0(param_1);              // Zero/init context fields
        *(param_1 + 0x660) = 0x60FE9;       // token_dispatch
        *(param_1 + 0x630) = 0x64F41;       // inside FUN_00063D0C
        *(param_1 + 0x628) = 0x60F41;       // debug sync
        *(param_1 + 0x62c) = 0x60F9D;       // vtable entry
        *(param_1 + 0x5c0) = 0x6147B;       // log
        *(param_1 + 0x654) = 0x66D9D;       // inside FUN_000664d4
        *(param_1 + 0x5b8) = 0x66D9F;       // memory timing override
        *(param_1 + 0x614) = 0x64F25;       // SMN register config
        *(param_1 + 0x343) = 1;
        FUN_0006f214(param_1, 0);           // Channel select
    }
    return iVar1 != 0;
}
```

**FUN_0006BBC0** (context init, 120 bytes) zeroes fields at +0x124 (0x180
bytes), +0x332 (0x43 bytes), fills +0x378 (102 dwords) with defaults, and
sets +0x52c, +0x530, +0x620, +0x624. It does NOT touch +0x660.

**Caveat:** If FUN_00069BE8 writes to MMIO (not SRAM), the hardware could
ignore the write on harvested silicon (BC-250 with VCN disabled). In that
case the condition gate COULD fail, leaving context+0x660 uninitialized.
Determining MMIO vs SRAM requires knowing the address at `*(param_2+0x3c4)+0x5e`.

#### Finding 4: DISPATCH CALLERS AND WRITE EXCLUSIVITY

**Context+0x660 is read by exactly 2 functions and written by exactly 1.**

Readers (thin dispatch wrappers, 18 bytes each):
```c
// FUN_0006BB9C — register READ (140 call sites)
void FUN_0006bb9c(int ctx, int reg) {
    (*(code **)(ctx + 0x660))(ctx, 0, reg);
}

// FUN_0006F1D8 — register WRITE (316 call sites)
void FUN_0006f1d8(int ctx, int reg, int val) {
    (*(code **)(ctx + 0x660))(ctx, 1, reg, val);
}
```

Writer: **ONLY FUN_0006B590** — confirmed by exhaustive search for
`STR.W Rd, [Rn, #0x660]` across the entire ABL4 binary. No other
function writes to this offset.

#### Finding 5: token_dispatch (0x60FE8) DECOMPILED

The dispatch target is a 258-byte Thumb function managing inter-node
UMC (Unified Memory Controller) register access via a master/slave
protocol. It iterates slave nodes, collects training point data, and
dispatches register reads/writes. This is the UMC register communication
layer used by all 456 call sites (316 write + 140 read).

#### Finding 6: PSP_BL BOOT AND ABL4 LAUNCH SEQUENCE

**FUN_00000300** (1000 bytes, main boot pipeline):
```c
switch (boot_mode) {  // iVar1 from caller
    case 0: case 3: case 4: case 5:  // Cold boot
        FUN_000082e6(boot_mode);      // Launch prep (maps pages, builds config)
        FUN_00000328(0, *(DAT_3fc0+0x18) + 0x40100);  // Launch ABL4
        break;
    case 2:  // S3 resume
        FUN_000082e6(2);
        FUN_00000328(1, uVar4);  // Different params for resume
        break;
}
```

- `DAT_00003fc8 = 0x40100` — the offset added to a base pointer to compute
  the context structure address. `*(DAT_3fc0+0x18) + 0x40100 = 0x5D7AC`.
- FUN_000082e6 calls: FUN_000035A0 (R/W page mapping), FUN_000075A4 (config
  buffer build), FUN_00007BA4 (logging/assert)
- FUN_00007BA4: writes status codes to mailbox register; `param_1 != 0`
  triggers an infinite loop (fatal error handler)

#### Finding 7: FUN_000044CC REFERENCES 0xB814 — NEW INVESTIGATION LEAD

The 2728-byte command dispatcher (formerly the "SVC dispatcher") also
references BSS 0xB814 from literal pool at 0x4E4C. Since SVCs are NOPs,
FUN_000044CC is NOT reached via SVC dispatch on this platform. However,
it MAY be called directly from PSP_BL's init flow (FUN_00000300 or its
callees) before ABL4 launch. If so, it populates BSS data (including 0xB814)
that feeds into FUN_000075A4 → config+0x660.

Additionally, 0xB82C (APCB header copy base) has 3 literal pool references
at [0x08B4], [0x0BEC], [0x16F4], and 0x9B60 (APCB header cache) has 2 at
[0x67BC], [0x75A0].

**UPDATE (session 10+, FUN_000044CC investigation):**

FUN_000044CC is **DEAD CODE** on this platform. Exhaustive analysis:
- Zero direct BL/BLX callers in the entire PSP_BL binary
- Zero function pointer references (0x44CC/0x44CD not in any literal pool)
- The dead SVC handler at 0x198 is the ONLY path to FUN_000044CC
- The SVC handler at 0x198 has zero callers — reachable only via exception
- VBAR=0x100 makes the SVC vector at 0x108 = BX LR = NOP
- Therefore FUN_000044CC NEVER EXECUTES

The 0xB814 reference at instruction 0x4D08 (loads pointer, writes
`*0xB814 = param_2[1]` in command 0x44 case) never runs. BSS 0xB814 is
uninitialized on this platform. FUN_000075A4 reads from *0xB814 (garbage
or zero) and writes to config+0x660, but ABL4 never reads the config buffer.

**Vector E (FUN_000044CC command injection) is CLOSED.**

#### COMPLETE SRAM MEMORY MAP (sessions 4-10, final)

```
0x00000-0x0001F  ARM exception vector table (VBAR=0 default, pre-VBAR boot)
  0x008: SVC → 0x298 (cache loop, NOT SVC handler)
0x00020-0x00038  Vector target literal pool (dummy targets)
0x0003C-0x000FF  Early boot code:
  0x03C: Clear SCTLR V-bit
  0x04C: MCR VBAR = 0x100 (THE ONLY VBAR WRITE — exhaustive search confirmed)
  0x050: BL init functions
  0x058: TTBCR = 0x22
  0x068: TTBR0 = 0x4E000
  0x078: SP = 0x54000
  0x08C: DACR = 0x55555555
  0x098: Enable MMU
  0x0A8: BX R12 → 0x1AC (post-MMU init)
0x00100-0x0011F  VBAR vector table (active):
  0x100: Reset = undef
  0x104: Undef = BX LR
  0x108: SVC = BX LR ← ALL SVCs ARE NOPs
  0x10C: PrefAbort = BX LR
  0x110: DataAbort = BX LR
  0x114: Reserved = 0
  0x118: IRQ = BX LR
  0x11C: FIQ = BX LR
0x00120-0x00197  Post-MMU init (mode switches: IRQ/FIQ/ABT/UND/SVC)
0x00198-0x001F7  Dead SVC handler (UNREACHABLE — real but orphaned by VBAR=0x100):
  PUSH {R0-R12,LR}, extract SVC#, dispatch to FUN_00005278 or FUN_000044CC
0x00298           Cache maintenance loop (target of initial vector, NOT SVC handler)
0x00300-0x006FF  FUN_00000300 (main boot pipeline, 1000 bytes)
0x044CC-0x055AB  FUN_000044CC (command dispatcher, 2728 bytes, ~80 cases)
  References 0xB814 from pool at 0x4E4C
0x05278           FUN_00005278 (SVC #0 handler — dead, unreachable via VBAR=0x100)
0x075A4           FUN_000075A4 (config buffer builder, 532 bytes)
  Writes 0x4F660 from *0xB814
0x082E6           FUN_000082e6 (ABL4 launch prep, 32 bytes)
0x092000          SP_svc (SVC mode stack pointer — set at boot)
0x09A10           DMA base ptr → SMN-mapped DRAM (0x27800000)
0x09A18           DRAM base = 0xFF800000
0x09A20           Bounds = 0x800000 (8MB)
0x09A24           Offset mask (UNINITIALIZED — zero write sites)
0x09B60           APCB header cache (fixed 0x100-byte buffer)
0x0B814           APCB-derived runtime data (BSS, 7764 bytes beyond static binary)
  Source for config+0x660 (via FUN_000075A4)
  Referenced by FUN_000044CC (pool 0x4E4C) and FUN_000075A4 (pool 0x77E8)
0x0B82C           APCB header copy / token table 0
  3 literal pool refs at [0x08B4], [0x0BEC], [0x16F4]
0x4DC00           L2 page table (FUN_000035A0: descriptor 0x52 = R/W)
0x4E000           L1 page table (TTBR0)
0x4F000-0x50000   Config buffer (FUN_000075A4, cache-flushed to ABL4):
  +0x660 (0x4F660): APCB-derived value from *0xB814
  SEPARATE from context structure — ABL4 never reads this
0x54000-0x7EFFF   Stack/heap/context (FULL R/W, EXECUTABLE!):
  0x5D7AC: Context structure base (passed as R1 to ABL4)
    +0x660 (0x5DE0C): dispatch function pointer = 0x60FE9 (token_dispatch)
    ONLY written by FUN_0006B590 (hardcoded, not APCB-derived)
  0x60834: ABL4 load base (88,000 bytes)
0x72000           HEAP (ABL4 allocator, magic "HEAP" = 0x50414548)
0x7A000           APCB group data (runtime, populated from SPI flash)
```

#### REVISED ATTACK ASSESSMENT (sessions 4-10)

**CLOSED vectors:**

| Vector | Description | Why closed |
|--------|-------------|------------|
| SVC-mediated context corruption | SVCs carry data between PSP_BL↔ABL4 | SVCs are NOPs; no data flows |
| Config → context copy | APCB data at config+0x660 → context+0x660 | ABL4 has zero refs to 0x4F000 |
| Direct APCB → context+0x660 | APCB token writes dispatch pointer | FUN_0006B590 uses hardcoded 0x60FE9 |
| DMA overshoot → context | DMA overshoots into context SRAM | DMA targets DRAM (0x27800000+), not SRAM |
| Stack overflow → context | SVC stack at 0x92000 overflows down to 0x5D7AC | Gap = 0x34254 (213KB), impractical |

**OPEN vectors:**

**Vector C (two-stage PSP_BL RCE → direct SRAM write):** Still the most
viable. If CVE-2025-29951 gives PSP_BL code execution (e.g., return address
overwrite from a stack overflow in a function we haven't found), the shellcode
has full SRAM access and can write any value to 0x5DE0C. The stack at 0x92000
could overflow into BSS data structures, corrupting function pointers or
control flow within PSP_BL itself.

**~~Vector D (S3 resume context corruption)~~ — CLOSED (sessions 10+):**
FUN_0006BC64 (ABL4 main) calls FUN_0006B590 at line 56 UNCONDITIONALLY
— before any S3/cold boot branching (boot mode is checked at line 66+).
Context+0x660 is ALWAYS overwritten with 0x60FE9 regardless of boot mode.
Additionally, FUN_0000196C validates S3 save data with HMAC-SHA256
(XOR-0x36 ipad + XOR-0x5C opad), so forged S3 data fails integrity
check before reaching ABL4.

**~~Vector E (FUN_000044CC command injection)~~ — CLOSED:**
FUN_000044CC is dead code. Zero direct callers, zero function pointer
references. Only reachable via the dead SVC handler at 0x198, which is
unreachable because VBAR=0x100. The command dispatcher and its 0xB814
reference never execute on this platform.

#### REMAINING OPEN QUESTIONS (updated sessions 4-10)

1. **Where is CVE-2025-29951?** Not found in 40+ decompiled functions.
   May be in: (a) a runtime-computed indirect call, (b) the Cortex-A5
   exception path, (c) FUN_000062BE/FUN_00001F40 (alternative copy paths),
   (d) FUN_000018E4 (S3 resume), or (e) FUN_000044CC's command processing.

2. ~~Does FUN_000044CC have unguarded write primitives?~~ **RESOLVED: MOOT.**
   FUN_000044CC is dead code (zero callers, zero function pointer refs).
   Its write primitives never execute on this platform.

3. **Is FUN_00069BE8's target MMIO or SRAM?** If it writes to MMIO, the
   hardware could ignore the write on harvested silicon, making the condition
   gate fail and leaving context+0x660 uninitialized. The address depends on
   `*(param_2+0x3c4)+0x5e`, which requires runtime tracing.

4. ~~S3 resume context corruption path.~~ **RESOLVED: CLOSED.** FUN_0006BC64
   calls FUN_0006B590 UNCONDITIONALLY before any mode branching (line 56
   vs boot mode check at line 66+). +0x660 always reset. S3 data also
   HMAC-SHA256 validated by FUN_0000196C. Double protection.

5. ~~FUN_000044CC's direct-call path.~~ **RESOLVED: NO.** Exhaustive search
   confirms zero BL/BLX callers and zero function pointer references.
   FUN_000044CC is dead code — only reachable via the dead SVC handler.

**SESSION 4-10 SCRIPTS** (in scratchpad, pyghidra-based):
- `pspbl_early_boot.py` — Early boot ARM decode, initial vector table discovery
- `svc_vector_trace.py` — SVC vector question, literal pool analysis
- `svc_vector_patch_82e6.py` — FUN_000082e6 and FUN_000075A4 decompilation
- `svc_vector_writer.py` — Exhaustive search for SVC vector writers (none found)
- `pspbl_svc_patch.py` — L2 page table functions don't patch SVC vector
- `abl4_svc_search.py` — 96 Thumb SVCs across 17 numbers in ABL4
- `svc_final_resolution.py` — Definitive: only 1 VBAR write (0x04C), SVC=BX LR at 0x108
- `config_to_context.py` — Config buffer ≠ context; FUN_0006B590 condition gate traced
- `vuln_path_trace2.py` — FUN_0006BBC0 context init, 0x60FE8 dispatch target decompiled
- `dispatch_callers.py` — FUN_0006BB9C/FUN_0006F1D8 decompiled; all STR.W +0x660 → only FUN_0006B590
- `fun044cc_direct_path.py` — PROVED FUN_000044CC is dead code: zero callers, zero fn ptr refs
- `fun044cc_decompiled.c` — Full 24KB decompilation of FUN_000044CC (874 lines, academic)
- `s3_resume_trace.py` — FUN_000018E4, FUN_000062BE, FUN_00001F40, FUN_0000151C decompiled
- `s3_abl4_branch.py` — FUN_0006BC64 S3 branching: FUN_0006B590 is UNCONDITIONAL (line 56)
  + FUN_00000328 = BX R1 (1-instruction launch) + FUN_0000196C = HMAC-SHA256 S3 validation

### Sessions 10+ state assessment — ALL INDIRECT VECTORS CLOSED

**Every identified path to corrupt context+0x660 (dispatch function pointer
at 0x5DE0C) has been closed by static analysis:**

| Vector | Status | Why |
|--------|--------|-----|
| A — Config buffer copy | CLOSED | ABL4 never reads 0x4F000 |
| B — Stack overflow → context | CLOSED | Stack at 0x92000, gap = 213KB |
| C — Two-stage PSP_BL RCE | CLOSED | CVE-2025-29951 is FP5-platform only (see below) |
| D — S3 resume corruption | CLOSED | FUN_0006B590 unconditional + HMAC |
| E — FUN_000044CC commands | CLOSED | Dead code (no callers) |
| SVC-mediated corruption | CLOSED | SVCs are NOPs (VBAR=0x100) |
| DMA overshoot | CLOSED | DMA targets DRAM, not SRAM |

**ALL VECTORS ARE NOW CLOSED.** See session 11 findings below.

### Session 11 — CVE-2025-29951 DOES NOT AFFECT BC-250 (VECTOR C CLOSED)

**Date:** 2026-09-17 (continued session)

**Critical finding:** CVE-2025-29951 is platform-specific to **FP5 silicon only**
(Zen/Zen+ family). It does NOT exist in the BC-250's Cyan Skillfish PSP_BL binary.

**Evidence from AMD-SB-4013 bulletin (https://www.amd.com/en/resources/product-security/bulletin/amd-sb-4013.html):**

CVE-2025-29951 affected processors (exhaustive list):
- AMD Athlon 3000 Series Mobile (Picasso, FP5) — fix: PicassoPI-FP5_1.0.1.2d
- AMD Ryzen Embedded R1000 (FP5) — fix: EmbeddedPI-FP5 1.2.1.2
- AMD Ryzen Embedded R2000 (FP5) — fix: EmbeddedR2KPI-FP5 1.0.0.7
- AMD Ryzen Embedded V1000 "Raven Ridge" (FP5) — fix: EmbeddedPI-FP5 1.2.1.2

All are Zen/Zen+ on the FP5 platform. BC-250 is Zen 2 + RDNA2 (Cyan Skillfish/Ariel)
with a completely different PSP_BL binary (39,360 bytes, different code).
Researcher: Muyan Shen, Institute of Software, Chinese Academy of Sciences.

**Exhaustive verification of our PSP_BL (session 11 analysis):**

1. **All 321 functions enumerated** — Ghidra identifies 321 functions in the
   39,360-byte PSP_BL binary. 258 are reachable from FUN_00000300 (boot root).

2. **97 candidate functions flagged** by heuristic (stack buffers, param-derived
   indexing, loop bounds from parameters). Every candidate manually verified:
   - FUN_00002434: bounds-checked (param_2 < 0x41 for 68-byte buffer)
   - FUN_00007DE8: loop bound hardcoded (uVar3 < 2)
   - All crypto functions (0x5F0, 0x750, 0x1720): key size constrained to {16,24,32}
   - All hash functions (0x22AA, 0x8488): "small buffers" are structure bases
   - FUN_00001670: APCB size validated (0x4F0 cap + buffer size check)

3. **ARM instruction-level memcpy trace** — all 24 BL 0x458 call sites checked.
   Only one has SP-relative dest + register size (0x2468 in FUN_00002434), and
   it is bounds-checked as noted above.

4. **All 5 APCB-referencing functions analyzed** — 0x0300, 0x0850, 0x1670,
   0x44CC (dead code), 0x75A4. All use hardcoded copy sizes or validate bounds.

5. **FUN_000075A4 (config buffer builder)** — no stack buffers, no loops, all
   copy sizes are compile-time constants. Writes directly to 0x4F000 region.

**Conclusion:** There is NO stack buffer overflow in the BC-250's PSP_BL binary.
CVE-2025-29951 exists in a different PSP_BL (FP5 platform) that we don't have.

**Scripts produced (session 11):**
- `enumerate_pspbl_functions.py` — Full function catalog, 97 candidates flagged
- `deep_overflow_hunt.py` — Stack buf + copy function cross-reference (3 hits, all safe)
- `apcb_callgraph.py` — BFS from boot root, 258 reachable functions analyzed
- `indirect_overflow_hunt.py` — Stack buffers passed to callees (22 functions, all safe)
- `memcpy_callsite_trace.py` — ARM-level BL 0x458 trace (1 suspicious, bounds-checked)
- `apcb_parsing_deep.py` — APCB literal reference trace + FUN_000075A4 callees
- `deep_decompile_suspects.py` — Full decompilations of 22 priority suspects

### FINAL VECTOR STATUS TABLE (all sessions)

| Vector | Status | Why |
|--------|--------|-----|
| A — Config buffer copy | CLOSED | ABL4 never reads 0x4F000 |
| B — Stack overflow -> context | CLOSED | Stack at 0x92000, gap = 213KB |
| C — Two-stage PSP_BL RCE | CLOSED | CVE-2025-29951 is FP5-only, not in our binary |
| D — S3 resume corruption | CLOSED | FUN_0006B590 unconditional + HMAC |
| E — FUN_000044CC commands | CLOSED | Dead code (no callers) |
| SVC-mediated corruption | CLOSED | SVCs are NOPs (VBAR=0x100) |
| DMA overshoot | CLOSED | DMA targets DRAM, not SRAM |

**The APCB-to-dispatch-pointer attack path is definitively closed on BC-250.**

### Where this leaves PSP code execution for VCN enablement

The dispatch function pointer at context+0x660 (0x5DE0C) cannot be corrupted
via APCB manipulation on this platform. Alternative paths to PSP code execution
that remain theoretically possible but are outside the scope of this experiment:

1. **CVE-2025-48515** — "Insufficient parameter sanitization in ASP Boot Loader"
   with SPI ROM access (CVSS 5.4, physical). Affects Renoir/Cezanne/Phoenix,
   NOT confirmed for Cyan Skillfish. Would require separate investigation.
2. **Undiscovered 0-day in our PSP_BL** — possible but session 11 found no
   candidates after exhaustive static analysis of all 321 functions.
3. **PSP debug interface** — CVE-2025-52533 (on-chip debug) is mitigated via
   KDS, not a viable software-only path.
4. **Different attack surface** — SMM (CVE-2025-29950), TOS syscalls
   (CVE-2021-26381), or PCIe (CVE-2024-21961) are platform-dependent and
   none are confirmed for Cyan Skillfish.
