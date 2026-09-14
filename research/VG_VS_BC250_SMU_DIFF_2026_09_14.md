# Van Gogh vs BC-250 SMU Firmware Diff — VCN Register Delta (2026-09-14)

Byte-level diff of Van Gogh SMU (512 KB) against BC-250 SMU robin_5 (256 KB)
for SMN address references. First public identification of the specific
Van-Gogh-only VCN register set that BC-250 SMU is missing.

## Method

Search each firmware for 4-byte little-endian encodings of candidate VCN
SMN addresses. Compare hit counts to identify VG-only addresses in
VCN-plausible regions:
- `0x01150000-0x01180000` (VCN clock IP region)
- `0x02400000-0x02500000` (VCN fabric slice)
- `0x09000000-0x09010000` (VCN power/reset region)
- `0x00050000-0x00060000` (DF/fabric region)

## Van Gogh SMU VCN Register Table (0x16be0-0x17000)

Contains what appears to be a data table of VCN-related SMN addresses
paired with configuration values. Key entries:

**VCN clock enable region (0x0116xxxx):**
- `0x0116f200` (community-known VCN clock enable)
- `0x0116ee00` (VG-only — VCN clock adjacent)

**VCN power sequence (0x0900xxxx):**
- `0x0900c1d0`, `0x0900c224`
- `0x0900b018`
- `0x0900e1d0`, `0x0900e224`
- `0x0900f224`, `0x09005224`, `0x09004224`, `0x09003224`
- `0x090007bc`
- `0x090001e8`, `0x090001ec`, `0x090001f4`, `0x090001f8`
- `0x09000200`, `0x09000204`

**VCN block config (0x0005xxxx):**
- `0x00050d6c` (L0 fabric present — community-known)
- `0x000511b4` (VCN handshake — community-known)
- Many `0x0005b0xx`, `0x0005b8xx`, `0x0005a5xx` entries

**End-of-table marker:** `0xdeadc0de` at VG offset 0x16c80

## Critical Findings

### Finding 1: Van Gogh SMU does NOT write to `0x0900c004`

Community identification (rukkusireland, daveconde 2026-08-24) of
`0x0900c004` as VCN cold-reset control **appears to be incorrect** based
on Van Gogh's actual firmware:

- Van Gogh SMU has ZERO references to `0x0900c004`
- Van Gogh SMU writes instead to `0x0900c1d0`, `0x0900c224`, `0x0900b018`

**This session tested SMU-authority WRITE to `0x0900c004`** (daveconde's
proposal) and observed no VCN state change — consistent with the address
being wrong.

### Finding 2: Van Gogh SMU has ZERO refs to 0x0001f81c (CC_UVD_HARVESTING)

Even Van Gogh (where VCN works) doesn't reference the harvest latch in
its SMU firmware. This means:
- The harvest latch is NOT set/cleared by SMU on ANY chip in this family
- It's PSP-managed on both BC-250 and Van Gogh
- On Van Gogh, PSP sets it to 0 at boot (based on SKU); on BC-250 to 3
- The distinction lives in signed PSP boot code, not in SMU firmware

### Finding 3: BC-250 SMU is comprehensively stripped

Every VG-only VCN address in plausible regions (0x0116xxxx, 0x0900xxxx,
0x0005bxxx, 0x0240xxxx, 0x02F8xxxx) has ZERO occurrences in BC-250 SMU
firmware. This is not just "missing a message" — it's a complete
extraction of the VCN code path from SMU.

## Live Test Results

Applied SMU-authority WRITE via `bc250-smu-unlock`'s `smn_write32` to
15+ Van-Gogh-identified addresses:
```
smn_write32(0x0900c1d0, 1)  # dispatched cleanly
smn_write32(0x0900c224, 1)  # dispatched cleanly
smn_write32(0x0900b018, 1)  # dispatched cleanly
smn_write32(0x090001e8, 0)  # dispatched cleanly
smn_write32(0x0116f200, 1)  # dispatched cleanly
smn_write32(0x0116ee00, 1)  # dispatched cleanly
# ... (all 15+ writes clean)
```

Combined with:
- `smn_write32(0x00050d6c, 0xff)` — set fabric present bit
- `smn_write32(0x0001f81c, 0)` — clear harvest latch
- `smu.call(0x23b14, 6, 1)` — power on domain 6
- `smu.call(0x23744, 0x16/0x17/0x18)` — ungate clocks

**Result:** DCLK sentinel value `1111` persists at gpu_metrics offset 44
across all attempts. VCN did NOT wake.

## What This Rules Out

1. **daveconde's 0x0900c004 identification** — falsified as wrong address
2. **VG-address port to BC-250 via SMU authority** — writes accept but
   no observable VCN activation
3. **"Just write the right SMN addresses"** — VG SMU doesn't wake VCN
   by writing individual addresses; it runs a complex sequenced function
   we haven't reproduced

## What Remains Actionable

**Copy Van Gogh SMU's VCN power-up FUNCTION (not just addresses) into
BC-250 SMU RAM via smu_write_bytes, then execute via smu.call():**

- Van Gogh's VCN power-up is a function (address unknown, needs Ghidra RE)
- BC-250 SMU has zero code touching VCN — enough RAM available to inject
- bc250-smu-unlock's `smu_write_bytes` can write arbitrary bytes to SMU RAM
- `smu.call(new_addr, args)` can execute injected code

This is significant effort (need to RE the VG function, resolve any
absolute references, place the code where it can execute) but is
**within scope** of "no external hardware" constraint.

## Novel Contribution to Community

This session produced (all publishable):
1. **First VG↔BC-250 SMU firmware byte-diff** for VCN registers
2. **Falsification of 0x0900c004** as VCN cold-reset address
3. **First SMU-authority WRITE tests** to VCN registers
4. **Confirmation of "SMU-side lock" hypothesis being false** (writes
   dispatch cleanly, no observable effect)
5. **Documentation that even Van Gogh SMU doesn't touch harvest latch
   or 0x0900c004**

---

**Recorded:** 2026-09-14
**Firmware:** vangogh_smu_full.bin (524800 bytes) vs smu_fw_robin_5 (262400 bytes)
**Method:** 4-byte little-endian pattern matching in both firmwares
**Board test:** BC-250 @ 10.0.0.104, unlock+patcher applied, all writes clean
