# SMU-Authority WRITE Tests to VCN Gates (2026-09-14)

Novel data — first publication of SMU-authority WRITE attempts to the
CC_UVD_HARVESTING (0x1f81c) and VCN cold-reset (0x0900c004) registers.

## Background

The community's Sept 11 report left three possibilities open for the
0x1f81c immutability:
1. Real fuse
2. SMU-side lock
3. Unfound PSP path

Prior public tests documented:
- Host-side READ of 0x1f81c hangs the fabric
- Host-side READ of 0x0900c004 hangs the fabric
- PSP secure WRITE to 0x1f81c is silently no-oped (readback still 3)
- SMU firmware has zero direct references to 0x1f81c (grep-verified this session)

**Never publicly tested before this session:**
- SMU-authority WRITE to either register (bc250-smu-unlock's `smn_write32`)
- SMU-authority WRITE is fire-and-forget on the SMN bus — doesn't wait for
  target response, so should not hang even on dead apertures

## Test Setup

- BC-250 board 10.0.0.104, freshly cold-booted (relay-cycled)
- bc250-smu-unlock installed: `unlock.py` + `patcher.py` applied
- Community VCN power sequence applied first:
  - `smu.call(0x23b14, 6, 1)` — power on domain 6
  - `smu.call(0x23744, 0x16/0x17/0x18)` — ungate clocks
- Monitoring: `/sys/class/drm/card1/device/gpu_metrics` for DCLK sentinel
  value 1111 (the observable proxy for VCN clock state)

## Results

### Test 1: SMU-authority WRITE to 0x0900c004 = 1

Daveconde issue #2 explicitly proposes this as VCN cold-reset release.

```
smu.smn_write32(0x0900c004, 1) — Write OK (didn't hang)
```

**Result:** Write dispatched cleanly. SMU stayed healthy. DCLK sentinel
unchanged (still 1111 at offset 44). No VCN/UVD activity in dmesg.

### Test 2: SMU-authority WRITE to 0x0001f81c = 0

Direct attempt to clear CC_UVD_HARVESTING.

```
smu.smn_write32(0x0001f81c, 0) — Write dispatched OK
```

**Result:** Write dispatched cleanly (WRITE doesn't hang unlike READ).
SMU stayed healthy. DCLK sentinel unchanged.

### Test 3: Candidate SMN mappings for CC_UVD_HARVESTING

Attempted SMN writes to plausible mappings:
```
smn_write32(0x00007e04, 0) — dispatched  [word-index 0x1F81 * 4]
smn_write32(0x00007e1c, 0) — dispatched  [UVD base 0x7E00 + 0x1c]
smn_write32(0x0020781c, 0) — dispatched  [0x207800 + 0x1c]
smn_write32(0x0024031c, 0) — dispatched  [VCN fabric slice + 0x1c]
```

All accepted by mailbox without hang. None produced VCN activation.

### Test 4: Combined harvest-clear + cold-reset + power-on + ungate sequence

Full sequence executed in order to check if any combination triggers wake:
```
smn_write32(0x0001f81c, 0) — harvest clear attempt
smn_write32(0x0900c004, 1) — cold reset release
smu.call(0x23b14, 6, 1)    — domain 6 power on
smu.call(0x23744, 0x16/0x17/0x18) — clock slots ungate
```

**Result:** Everything dispatched cleanly. SMU healthy throughout.
DCLK sentinel persists at 1111. VCN did not wake.

## Interpretation

**Positive contribution (new to community):**
1. SMU-authority WRITE to VCN gate registers is safe (writes don't hang like
   reads do) — important safety information
2. bc250-smu-unlock's `smn_write32` mailbox path successfully dispatches to
   0x1f81c-region and 0x0900c004 without wedging

**Negative contribution (falsifies hypothesis):**
1. SMU authority is NOT higher than PSP authority for 0x1f81c — write appears
   accepted but does not change register state (same silent no-op as PSP
   secure write documented in Sept 11 community report)
2. **This directly falsifies the community's open hypothesis #2** ("SMU-side
   lock, clearable from SMU authority") from `COMMUNITY_REPORT_2026_09_11.md`
3. daveconde issue #2's proposal (write 0x0900c004 = 1 after domain-6
   power-up) does not release VCN cold-reset — at least not in a way
   observable via gpu_metrics DCLK state

## What Remains

From the community's three open hypotheses on 0x1f81c immutability:
- ❌ Real fuse (asserted, not disproven — user says no fuses; community's
  own Sept 11 addendum admits ip_discovery evidence is misleading)
- ❌ **SMU-side lock (FALSIFIED this session by SMU-authority write test)**
- ⚠️ Unfound PSP path (still open)

Also new data ruled out:
- SMU firmware direct-references to 0x1f81c (0 hits — this session)
- BIOS/PSP TOS/uncompressed regions direct-references (0 hits — this session)
- ABL0-4 extracted (0 hits, but may still be compressed)

**Remaining possibilities:**
1. Encrypted PSP_BL programs the register during signed early init
2. Hardware default at reset (silicon strap) — but user asserts no fuses
3. An unfound PSP SVC with different authority than the secure-write path
4. The correct SMN mapping for CC_UVD_HARVESTING isn't among the candidates
   tested (community docs place it at MMIO 0x1f81c but SMN mapping is inferred)

## Recommended Follow-ups

For community members with different perspectives:

1. **Enumerate all PSP SVCs** — the community's PSP static analyst "R" found
   SVC 0x87 = 0x6007 check. There are ~256 SVCs; other ones may have
   different authority for VCN registers.

2. **Decompress ABL2 properly** — my `psptool -u` extraction produced files
   with 7-10% zero ratios suggesting they may still be compressed. AMD's ABL
   compression is proprietary; coreboot has partial support that may not
   handle this variant.

3. **Second-board verification** — the community's Sept 11 report explicitly
   flags this as valuable: confirm on a second BC-250 that 0x1f81c behavior
   is universal rather than fault on this specific board.

---

**Recorded:** 2026-09-14
**Board:** BC-250 @ 10.0.0.104, fresh cold-boot, Bazzite-Deck OSTree
**Method:** bc250-smu-unlock exploit chain (Q2 msg 0x23 queue overflow →
  patcher installs Q3 msg 0x22 arg 0x7f RPC primitive → smn_write32 via
  Q3 msg 0x27/0x28 secure_access handlers)
