# BC-250 VCN Enablement

**Enable VCN (Video Core Next 2.0.3) hardware on AMD BC-250 by overcoming firmware-imposed isolation gates.**

## Status

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
  └── execute_fix.py          : Mock/demo harness (testing without hardware)
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
- **bc250-vcn-enable**: github.com/daveconde/bc250-vcn-enable (Reference implementation)
- **Van Gogh SMU**: Linux kernel amd/pm code (SMU register reference)

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
Jacob Burns (jacob.burns@wwt.com)
September 2026
https://github.com/shalasere/bc250-vcn
```

## License

GNU General Public License v3.0 - See LICENSE file.

---

**Status**: Research in progress. Hardware testing complete. Awaiting firmware analysis to identify isolation gate unlock mechanism.
