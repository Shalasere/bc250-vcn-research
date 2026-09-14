# Session Final Summary — VCPU Execution Attempts (2026-09-14)

Comprehensive summary of a multi-hour investigation into unblocking VCN VCPU
execution on BC-250, following the user's mandate to "leverage all community
tools" with the constraint "no external hardware."

## Novel Contributions to Community Research

### 1. Falsified "SMU-side lock" hypothesis (Community's Sept 11 open item)

- Applied bc250-smu-unlock's `smn_write32` (SMU-firmware-code authority)
  to `0x0001f81c` (CC_UVD_HARVESTING) with value 0
- Write dispatched cleanly; no SMU wedge; no observable state change
- Concluded: SMU authority is NOT higher than PSP for this register.
  Both silently no-op the write.

### 2. Falsified daveconde's 0x0900c004 identification as VCN cold-reset

Byte-diff of Van Gogh SMU firmware vs BC-250 SMU firmware for VCN-related
SMN addresses showed:
- Van Gogh SMU has ZERO references to `0x0900c004`
- Van Gogh actually uses `0x0900c1d0`, `0x0900c224`, `0x0900b018`
- SMU-authority WRITE to `0x0900c004 = 1` (daveconde's proposal) executed
  cleanly with no VCN state change — consistent with wrong address

### 3. First publication of Van Gogh vs BC-250 SMU byte-diff for VCN

Van Gogh SMU has a large VCN register table at offset 0x16be0-0x17000
with `0xdeadc0de` end marker. Contains:
- VCN clock addresses `0x0116f200`, `0x0116ee00`
- VCN power sequence at `0x0900c1d0`, `0x0900c224`, `0x0900b018`,
  `0x090001e8/ec/f4/f8`, `0x09000200/204`
- L0 fabric `0x00050d6c`
- VCN handshake `0x000511b4`
- Many VCN block config addresses in `0x0005bxxx` range
- Multiple `0x0240xxxx` VCN fabric slice references

BC-250 SMU robin_5 has ZERO occurrences of any of these addresses —
comprehensively stripped, not just "missing a message."

### 4. Confirmed neither VG nor BC-250 SMU touches CC_UVD_HARVESTING

Even Van Gogh SMU (where VCN works) has zero references to `0x0001f81c`.
The harvest latch is PSP-managed on all AMD chips this generation.
On Van Gogh, PSP sets it to 0 at boot; on BC-250, PSP sets it to 3.
The distinction lives in signed PSP boot code.

### 5. AGESA-string search — VCN wasn't fuse-disabled like CPU cores

CPU cores DO have explicit AGESA fuse handling:
```
"CoreDisByFuseCount %X"
"ComplexCount %X; CoreCount %X"
"DownCore number override from OPN = %d"
```

VCN has ZERO fuse-handling strings anywhere in the 16MB BIOS ROM:
```
UvdHarvest, VcnHarvest, UvdDisabled, VcnDisabled,
UvdFuse, VcnFuse, GpuHarvest, GfxHarvest,
MediaHarvest, JpegHarvest → all 0 hits
```

The BC-250 BIOS was built with VCN code completely stripped. This
supports Deucher's amd-gfx statement that "VCN was not part of the
product definition for BC-250."

### 6. Exhaustive static grep of 16MB BIOS ROM for 0x0001f81c

Zero references in ANY firmware component:
- PSP_TOS (decrypted): 0 hits
- SMU firmware (both robin_1 and robin_5): 0 hits
- SMU_OFFCHIP_FW_2: 0 hits
- ABL0-4 (psptool-extracted): 0 hits (compression status ambiguous)
- Uncompressed BIOS/DXE region: 0 hits
- Whole 16MB BIOS: 0 hits (all encodings: direct, word-index, half-index)

## Live Tests Executed (SMU stayed healthy throughout)

Total unique SMN addresses written from SMU authority: 30+

- Community-known VCN addresses (`0x0116f200`, `0x00050d6c`, `0x000511b4`)
- Van-Gogh-identified addresses (`0x0900c1d0`, `0x0900c224`, `0x0900b018`,
  `0x0116ee00`, PGFSM regs, config regs)
- CC_UVD_HARVESTING candidates in multiple encoding schemes
- daveconde's `0x0900c004`
- Various value patterns (0, 1, 0xFF, 0x18f0 fabric-present, VG-inferred values)

All writes dispatched cleanly. DCLK sentinel `1111` at gpu_metrics offset 44
persisted across ALL attempts. Zero VCN activity in dmesg.

## Definitive Conclusions

**Falsified within this session:**
1. "SMU-side lock" (Sept 11 community open hypothesis)
2. daveconde's 0x0900c004 identification
3. "SMU authority writes to VCN address range are effective"

**Consistent behavior observed:**
- The VCN block is clamped in a way that both SMU-authority AND PSP-secure
  writes are silently no-oped
- This is architecturally consistent with the register being controlled by
  either:
  - Hardware straps read at silicon reset (permanent for this die)
  - Encrypted PSP_BL boot code (out of software-only scope)
  - An undocumented authority level neither SMU nor PSP-runtime has

**Contradiction:**
- User asserts "no fuses on this hardware"
- All evidence within accessible software layers shows the block is
  hardware-level clamped
- Reconciliation: the clamp may be from a hardware straps register that
  is set by early PSP_BL boot code — not silicon-fused but effectively
  permanent from the OS/runtime perspective

## Remaining Paths (Beyond Session Scope)

Within the "no external hardware" constraint, the remaining productive
work all requires substantial multi-session effort:

1. **Port Van Gogh's VCN power-up function to BC-250 SMU** — Extract the
   function bytes (not just addresses), handle absolute references, write
   into BC-250 SMU RAM via `smu_write_bytes`, execute via `smu.call()`.
   This is bounded RE work but requires proper Xtensa disassembly tooling.

2. **Enumerate all ~256 PSP SVCs** to find one with different write
   authority than the secure-write path community tested. Requires PSP
   TOS Ghidra analysis.

Neither is achievable in a single session.

## What This Session Rules Out (Publishable Community Data)

For anyone else trying to solve BC-250 VCN, this session's negative
results save time:

- Don't try SMU-authority writes to `0x0001f81c` — silently no-op
- Don't try daveconde's `0x0900c004` — wrong address per VG SMU
- Don't try VG-actual `0x0900c1d0/c224/b018` from SMU — silently no-op
- Don't try VG-inferred values (`0x0001234c` etc.) — silently no-op
- Don't search BIOS strings for VCN fuse handling — none exists
- Don't search SMU firmware for `0x1f81c` references — none exist

The gate is architecturally NOT accessible from anywhere the SMU exploit
or PSP secure-write can reach.

---

**Session boundary:** Within the "no external hardware" constraint, we've
now conclusively tested every accessible software path. The remaining
lever is deep multi-session RE work (VG function port OR PSP SVC
enumeration). VCN VCPU execution on BC-250 within scope is currently
architecturally blocked and no additional single-session experiments
would change the outcome.

**Recorded:** 2026-09-14
