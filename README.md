# BC-250 VCN Enablement

**Enable VCN (Video Core Next 2.0.3) hardware on AMD BC-250 by overcoming firmware-imposed isolation gates.**

## Latest Status: 2026-09-30 — Direct-load driver-side proven; SMU-side `PowerUpVcn` confirmed present but PREREQ-locked

📄 **`research/SESSION_SUMMARY_2026_09_30.md`** — Two-day session updating the picture on two fronts:

1. **Driver-side `LOAD_IP_FW(VCN)` wall is bypassable.** A new `amdgpu.vcn_direct` module parameter routes VCN firmware through the driver's own `AMDGPU_FW_LOAD_DIRECT` path: allocate a driver-managed BO, `memcpy` the 405 KB `vcn_2_0_3.bin` into it, program LMI VCPU_CACHE_64BIT_BAR to point there, skip PSP autoload registration. **`amdgpu` fully loads with VCN 2.0 enumerated in the IP-block list**, `/dev/dri/card1` present, board stable. The `TEE_ERROR_ITEM_NOT_FOUND` wall from the earlier reports is never hit because PSP is never asked to load VCN. Full source + `PATCHES.md` + WSL cross-build recipe in `code/direct-load/`.

2. **The SMU firmware DOES ship `PowerUpVcn` handlers** at msg IDs 0x2A and 0x2B — they return `RESP=0xFD REJECTED_PREREQ`, not `0xFE UNKNOWN_CMD`. This directly confirms the community's "seems accessible if some flag is passed to SMU at boot from BIOS" hypothesis (`api_q3.py` note): **the code is present, gated by an unmet prerequisite**. The unlock lives at BIOS-init time in a msg sequence we haven't extracted. `research/SESSION_SUMMARY_2026_09_30.md` has the full mailbox transcript.

3. **Q0 and Q3 mailboxes are the same underlying SMU mailbox.** Sweeping msgs 0x3E–0x50 via the Q0-address SMN pair returned the same clock values (100/1200/1254/3500/1500 MHz) prior work found via the Q3-address pair, byte-for-byte. One msg-ID space, two SMN transports.

**Combined picture**: driver-side wall down, SMU-side wall standing. Direct-load is a working half of the puzzle — reusable once an SMU unlock is discovered. Session author is halting active research on this specific board; the writeup is intended as a reference for future attempts.

## Status: 2026-09-20 — TOCTOU Analysis Complete, All Runtime Paths DEAD

📄 **`research/TOCTOU_ANALYSIS_2026_09_20.md`** — Systematic
Time-of-Check-Time-of-Use analysis across all 6 gates in the VCN enablement
chain. **No exploitable race condition exists from software at runtime.**

Gate 2 (permission table: populated at boot, queried minutes later at runtime)
was the only candidate with a meaningful time window. Three independent access
vectors were investigated and all are closed:

1. **CCP MEMTYPE_LOCAL** (board-tested): CCP command queue registers are
   completely invisible from the host on BC-250. Full 1MB BAR2 scan found
   only PSP mailbox/status registers and TRNG. Scripts: `code/toctou-analysis/`
2. **PSP SRAM via SMN**: Architecturally invisible on Zen2/Zen3 — no
   index/data window register pair exists.
3. **Known CVEs**: CVE-2023-31316 requires TMR bypass (circular), Sinkclose
   targets SMRAM not PSP, CVE-2021-46757 requires TA context we don’t have.

**All remaining VCN enablement paths require taking the board offline:**
- APCB Variant G flash (Robin5.00 DFG+CBSG transplant — built, pending flash)
- Voltage glitch (PSPReverse SVI2 attack, needs Teensy ~$24)

### Session 13 (2026-09-18): CCP Overflow Chain Resolved

All 4 exploitation avenues from the CCP alignment overflow chain were
systematically tested and resolved. The chain was confirmed as a real
vulnerability in the CCP descriptor parser, but the copy sizes are
**hardcoded** (0x100/0x2F00/0x4F0), not derived from entry.size —
buffer-contained by design.

## Status: 2026-09-14/15 — Mechanism Understood End-to-End

📄 **`research/BC250_VCN_UNLOCK_STATE_2026_09_14.md`** — The "island isolation
gate" from the 09-06/09-11 reports is now identified precisely: BC-250's PSP
firmware directory ships a **`SEC_GASKET~0x24`** entry (926 signed `(addr,
value)` writes) that a community researcher first flagged part of
(`[0x1f820] = 0x00185103`, verified byte-for-byte in our ROM and confirmed
**absent from Steam Deck's F7A0133 BIOS**). We found a second write in the
same table (`[0x1f8a4] = 0x0000000b`) and mapped the other ~816 entries as
**DF fabric access-control programming** — the mechanism that makes runtime
writes to VCN registers get silently dropped for every non-PSP master (host,
SMU mailbox, GPU `regs_pcie`), independent of which register you target.

Reversed the PSP TOS SVC dispatch table (128 slots): the syscall PSP itself
uses to perform these writes (`svc #0x7c`, and 3 siblings) routes through an
address-resolution gate that is **almost entirely permissive** — it blocks
only 2MB of unrelated SMN space. VCN is not specially denied at the PSP
kernel level. The only thing standing between "userspace root" and "VCN
aperture write" is **execution inside a PSP TA/userspace context** — which we
do not have and could not find a working public CVE for (see the doc for the
full walk: `CVE-2023-31316` has a circular dependency on BC-250, `CVE-2021-
46747` shows no exposed surface on our BIOS, and the community's own
"uninitialized `saved_len`" lead sits inside encrypted PSP_BL, unreachable
from our position).

Both known SMU-side exec primitives (this repo's `bc250-smu-unlock`-based
approach and daveconde's `msg-0x61` stub-repoint) were re-validated on fresh
hardware and run cleanly — no wedge, ~50ms round trip. The "register file
stays clamped even once SMU reports dom6 UP" observation from `bc250-vcn-
enable` is the same wall we describe (downstream of the fabric ACL, not a
separate bug) — good independent convergence between the two projects.

Read the new doc first. Everything below (09-06 through 09-11) is preserved
as historical record — the empirical results still stand, this update just
explains *why* they came out the way they did.

## Status: 2026-09-11 (Afternoon)

📄 **`research/COMMUNITY_REPORT_2026_09_11.md`** — A firmware register audit
found no code path in the borrowed Navi10/Renoir VCN firmware that touches
BC-250's harvest register, and a live probe confirmed that register
(`CC_UVD_HARVESTING` at `0x1f81c`) reads `3` and **stays `3` through a PSP
secure write**. Separately, a missing KDB (key database) signing key was
found and worked around via a transient interposer injection — firmware
authentication now passes cleanly for two independent firmware candidates,
but the VCPU still never executes. Authentication is solved; a hardware-level
harvest latch is the current blocker.

### Three Parallel Experiments Ready for Testing

📋 **`research/EXPERIMENT_CANDIDATES_2026_09_11.md`** — Three independent
research threads are now ready for parallel execution, each addressing a
different aspect of the VCN blockers:

1. **SPI MITM Verify-then-Use Capture** (0 risk, passive)  
   `tools/spi-mitm-prep/parse_spi_trace.py` ready to analyze boot captures.  
   Precondition: pico2 wired to BIOS flash in TAP MODE.

2. **Q0 SMU Message IDs 0x0B/0x0C Test** (low risk, live hardware)  
   `tools/vcn_q0_power_test_board.py` ready to probe untested VCN power handlers.  
   Precondition: board reachable, bc250_smu deployed.

3. **SVC 0x87 Literal-Pool Verification** (0 risk, static analysis)  
   Pending agent completion on firmware binary analysis.  
   Outcome: confirms whether 0x6007 gate is PSP bootloader's actual check.

Each experiment is independent; parallel execution safe and recommended.

Read the 09-11 update and experiment plan first if you're new here. The 09-09
report is preserved below as a historical snapshot — its PSP-context findings
and the `0x6007` staging-slot-walker analysis remain valid, but it's now
understood to be one of at least three gates in the pipeline rather than the
whole story.

## Status (2026-09-09)

Updated framing after two of the four hypotheses in the 09-06 report were
independently tested and both shown insufficient from host-side software.
Both succeed from PSP context. The binding blocker was narrowed to a
**single byte of PSP boot-config** at PSP kernel RAM address `0x6007`.
Silicon proven functional (`UVD_VERSION = 0x0002001B` from PSP hook).

## Status (2026-09-06)

🔓 **Breakthrough Achieved (September 2026)**

- ✅ SMU arbitrary code execution exploit working (queue-overflow vulnerability)
- ✅ VCN power sequencing verified via hardware testing (25 iterations)
- ✅ Multi-cycle polling implementation with error handling
- 🔴 Root blocker identified: Island-level isolation gate (separate from SMU sequencer)

MMIO access remains clamped at `0xffffffff` despite SMU successfully powering up VCN domain. Next step: firmware analysis to identify isolation gate unlock mechanism.

## Quick Start

### Prerequisites
- BC-250 board with SMU exploit access (bc250-smu-unlock library)
- Python 3.7+
- `paramiko` for remote execution

### Run Power-Up Sequence

```bash
cd code
python3 execute_fix_hw.py
```

Expected output:
- Stages 1-3: Clock release, power request, rail power
- Stage 4: State machine cycles (PGFSM transitions)
- Stage 5-6: Verification
- Stage 7: MMIO test (currently FAILS due to isolation gate)

### Code Structure

```
code/
  ├── vcn_powerup_fixed.py    : Multi-cycle polling sequencer (298 lines)
  │                             All 8 code review findings fixed
  ├── vcn_smu_adapter.py      : SMU communication with error handling (215 lines)
  │                             Message validation, format verification
  ├── execute_fix_hw.py       : Hardware-aware runner (imports real bc250-smu)
  ├── execute_fix.py          : Mock/demo harness (testing without hardware)
  ├── psp-rce-analysis/       : 26 PSP bootloader binary analysis scripts
  └── toctou-analysis/        : CCP SRAM probe + BAR2/BAR5 scan (board-tested)
```

## What's Included

### Code
- **vcn_powerup_fixed.py**: Corrected power-up sequence with polling loops
  - Fixed issues: floating-point timing, status mask width, error indistinguishability
  - Verified state machine cycles against SMU firmware analysis
  - Configurable status masks for cross-platform compatibility
  
- **vcn_smu_adapter.py**: SMU interface layer with validation
  - Message protocol verification (bc250-smu-unlock)
  - Debugfs format validation before use
  - Proper error handling (raises exceptions instead of silent failures)
  
- **execute_fix_hw.py**: Hardware execution harness
  - Imports real `bc250_smu` library
  - Runs full power-up sequence on live board
  - Reports MMIO access status

### Research
- **COMMUNITY_REPORT_2026_09_06.md**: Main findings & breakthrough summary
- **SESSION_SUMMARY_2026_09_06.md**: Technical deep-dive with before/after
- **EXHAUSTION_LOG.md**: Complete 25-iteration history with findings per iteration
- **GHIDRA_ANALYSIS_GUIDE.md**: Next steps—firmware decompilation procedure
- **HANDOFF_TO_NEXT_SESSION.md**: Complete context handoff for analysis
- **READY_FOR_COMMUNITY.md**: Community contribution checklist

### Hardware Artifacts
- **vcn_exploit_execution_2026_09_06.txt**: Real hardware test logs with power oracle readings
- **vangogh_smu_full.bin**: Van Gogh SMU firmware (512 KB) for Ghidra analysis

## Technical Details

### VCN Power Sequencing (VERIFIED)

The corrected sequence implements multi-cycle PGFSM state transitions:

```
[1] Release clock gates (0x6d0f8 = 0x00)
[2] Power request (0x6d17c = 0x01) + poll
[3] Rail power (0x6d184 = 0x10000) + poll
[4] State machine cycles (cmd 0x01 → 0x02 → 0x03)
[5] Final verification
[6] Confirm full power state
```

Status register polling validates each transition before proceeding. Retry loops handle transient timeouts.

**Verified Against:**
- BC-250 hardware testing (multiple successful runs)
- SMU firmware analysis (FUN_00023b14 decompilation)
- Reference implementations (daveconde/bc250-vcn-enable)

### Root Blocker: Island-Level Isolation Gate

**Superseded 2026-09-14 — see `research/BC250_VCN_UNLOCK_STATE_2026_09_14.md`.**
The "island-level isolation gate" described below is the DF fabric access
control mechanism, now identified as programmed by the signed `SEC_GASKET~0x24`
PSP directory entry. It's not a separate silicon-level gate independent of
SMU — it's the same fabric ACL that also blocks direct host/GPU writes,
applied uniformly regardless of which runtime master (SMU included, for most
addresses) issues the write. Kept below for historical context.

Despite successful SMU power-up sequence:
- All SMU register writes complete successfully
- Status register reads confirm power state transitions
- VCN MMIO still returns `0xffffffff` (clamped/isolated)

This indicates a secondary isolation mechanism at the island (GPU complex) level, independent of SMU sequencer. Likely triggers:
- Register write to 0x0900c004 (cold-reset gate)
- Firmware loading via PSP (Power State Processor)
- Kernel module power management

**Next Research:** Ghidra decompilation of SMU firmware to identify gate unlock sequence.

### SMU Exploit (Prior Art)

Queue-overflow vulnerability in SMU message handling (bc250-smu-unlock library):
- Enables arbitrary code execution on SMU Xtensa processor
- Used to reprogram VCN clock sequencers (slots 0x16/0x17/0x18)
- Public disclosure: rw-r-r-0644/bc250-smu-unlock

## Code Review Findings (All Fixed)

| Finding | File | Issue | Fix |
|---------|------|-------|-----|
| Error indistinguishability | vcn_smu_adapter.py:83 | `read32()` returns 0xffffffff on error = actual clamp | Raises `RuntimeError` instead |
| Mock data contradiction | execute_fix.py:49 | Mock returns 0x00090053, hardware returns 0xffffffff | Fixed to return 0xffffffff |
| Unverified message IDs | vcn_smu_adapter.py:57 | Queue 1, msg 0x00/0x01 assumed | Added `hasattr()` validation |
| Unverified debugfs format | vcn_smu_adapter.py:128 | Format 'addr value' not verified | Added `_verify_debugfs_format()` |
| Speculative state machine | vcn_powerup_fixed.py:186 | Cycle values (0x01/0x02/0x03) seemed arbitrary | Documented as verified via firmware RE |
| SMUInterface duplication | execute_fix.py:17 | Same class in two files | Consolidated with modern error semantics |
| Floating-point timing | vcn_powerup_fixed.py:80 | `(time.time() - start) * 1000` in tight loop | Changed to integer millisecond arithmetic |
| Status mask width | vcn_powerup_fixed.py:29 | 0xFF mask may exclude high bits | Made configurable via constructor |

## Hardware Setup

**Board:** BC-250 @ 10.0.0.104
- **SMU Firmware:** robin_1 (0.58.6.0)
- **BIOS:** P3 (latest, CPU cores unlocked)
- **VCN:** Van Gogh variant (0x163f, product_id=0x1638)
- **Status:** Isolation gate ACTIVE (MMIO clamped at 0xffffffff)
- **PSU:** ESPHome relay @ 10.0.0.78 (`BC250 PSU PS_ON` switch)

### Board Recovery
If board hangs during testing:
```bash
curl -X POST http://10.0.0.78/api/switch/BC250%20PSU%20PS_ON/turn_off -d ''
# Wait 10s
curl -X POST http://10.0.0.78/api/switch/BC250%20PSU%20PS_ON/turn_on -d ''
```

## Community References

- **bc250-smu-unlock**: github.com/rw-r-r-0644/bc250-smu-unlock (SMU exploit library)
- **bc250-vcn-enable**: github.com/daveconde/bc250-vcn-enable (Reference implementation; independently reaches the same "register file clamped at root" wall)
- **bc250-vcn-linux-research**: github.com/m2jgh8tg7r-bot/bc250-vcn-linux-research (Linux enablement side — firmware/ring/doorbell staging)
- **Van Gogh SMU**: Linux kernel amd/pm code (SMU register reference)
- **recon**: github.com/cachenetics/recon (BC-250-specific PSP/SMU firmware analysis toolkit — used for the SVC dispatch table + SEC_GASKET extraction in the 09-14 report)

## Next Steps

1. **Firmware Analysis (Ghidra)**
   - Target: `firmware/vangogh_smu_full.bin`
   - Focus: `FUN_00023b14` (PGFSM state machine at 0x23744)
   - Goal: Identify island isolation gate unlock trigger
   - See: `research/GHIDRA_ANALYSIS_GUIDE.md`

2. **Isolation Gate Unlock Testing**
   - Test register write to 0x0900c004 (cold-reset candidate)
   - Test MMIO access via direct kernel mapping
   - Test PSP firmware loading sequence

3. **VCN Bring-Up (If Gate Unlocked)**
   - Load VCN firmware via PSP
   - Enable VCN in kernel driver (amdgpu)
   - Test video decode operations

## Usage & Contributing

This project is licensed under **GPLv3**. Contributions welcome.

### Report Issues
- Hardware failures / board bricks (with recovery steps)
- Firmware analysis findings
- Alternative isolation gate unlock sequences
- Cross-ASIC compatibility (Picasso, Rembrandt, Mendocino)

### Testing Requirements
- Real BC-250 hardware (or compatible Van Gogh GPU)
- SMU exploit access (bc250-smu-unlock library)
- Documentation of test environment & results

## Citation

If you use this research, cite:

```
BC-250 VCN Enablement Research
Shalasere
September 2026
https://github.com/shalasere/bc250-vcn
```

## License

GNU General Public License v3.0 - See LICENSE file.

---

**Status**: Research in progress. Hardware testing complete. Awaiting firmware analysis to identify isolation gate unlock mechanism.
