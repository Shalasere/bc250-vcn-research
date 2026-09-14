# Live SMU Probe Session (2026-09-13)

Real hardware SMU probing on BC-250 at 10.0.0.104 via bc250_smu library.
Objective: test whether any user-accessible SMU command can activate VCN clocks
(specifically move VCLK from 0 to nonzero).

## Findings at a Glance

**VCLK is confirmed 0 in live gpu_metrics (offset 72).** DCLK reads 1111 (sentinel).
No SMU command in the community's decoded handler table moves VCLK off zero.

## Metric Offsets Identified

By parsing `/sys/class/drm/card1/device/gpu_metrics` (128-byte truncated struct):

| Offset | Value | Interpretation |
|--------|-------|----------------|
| 66 | 1254 | current SOCCLK MHz (matches pp_dpm_socclk) |
| 68 | 1750 | current FCLK MHz |
| 70 | 1750 | current MCLK MHz |
| **72** | **0** | **current VCLK MHz** ← VCN video clock is OFF |
| **74** | **1111** | **current DCLK MHz** ← matches thelamer's "DCLK=1111" — likely sentinel |
| 76 | 12 | active WGP count |

These reproduce thelamer's stock telemetry exactly.

## SMU Feature Bitmap (0xdd602c7d)

Enabled DPM features (via Q3 msg 0x35 to avoid amdgpu contention on Q0):
- DPM_GFXCLK (bit 0), DPM_FCLK (bit 2), DPM_MP1CLK (bit 3)
- **DPM_VCLK (bit 4)** ← ON
- **DPM_DCLK (bit 5)** ← ON
- DPM_LCLK (bit 6), DS_SOCCLK, DS_FCLK, DS_MP0CLK, DF_CSTATES, GFX_PACE,
  IH_OOB, ATHUB_PG, FCLK_DSTATE, CSTATE_BOOST, bit 30, bit 31

DPM_VCLK and DPM_DCLK are already enabled — this disproves the "enable feature
bit" hypothesis.

## Clock DPM Tables (Populated but Unused)

Read via Q3 msg 0x38/0x39/0x3A `get_*_clock_assigned_to_state`:

| Msg | Interpretation | idx 0 | idx 1 | idx 2 | idx 3 |
|-----|---------------|-------|-------|-------|-------|
| 0x38 | SCLK p-states MHz | 250 | 250 | 750 | 1200 |
| 0x39 | VCLK p-states MHz | 225 | 225 | 425 | **875** |
| 0x3A | DCLK p-states MHz | 112 | 112 | 106 | 109 |

VCN clock DPM tables ARE populated. The SMU knows about VCLK/DCLK frequencies
up to 875/109 MHz. Nothing is requesting them.

## Perf Profile Enumeration

Via Q3 msg 0x1E `set_PerfProfileIndex`:

| Index | Status | Notes |
|-------|--------|-------|
| 0 | OK (0x01) | BOOTUP_DEFAULT (currently active) |
| 1 | OK | 3D_FULL_SCREEN |
| 2 | OK | POWER_SAVING |
| 3 | OK | **VIDEO** — no effect on VCLK/DCLK |
| 4-6 | FAILED (0xFF) | Not supported on Cyan Skillfish |

Only 4 profiles are valid. Setting VIDEO (3) does NOT wake VCN.

## Set-Clock Message Enumeration

Via Q3 msg 0x1D `_q3_0x1d_set_soc_clock_for_index`:

| arg (encoded) | Interpretation | Status | VCLK Effect |
|---------------|----------------|--------|-------------|
| 0x00040186 | type=4, freq=390 | OK | none |
| 0x00050186 | type=5, freq=390 | OK | none |
| 0x00040000 | type=4, freq=0 | OK | none |
| 0x000A0186 | type=10, freq=390 | OK | none |
| 0x000B0186 | type=11, freq=390 | OK | none |
| 0x00160186 | type=0x16, freq=390 | FAILED | — |
| 0x00170186 | type=0x17, freq=390 | FAILED | — |

Clock types 0-11 accepted, higher rejected. Setting SOC clocks (including
what should be VCLK/DCLK indices) accepted OK — but VCLK stayed 0.

Via `q3_0x25_set_oc_clk(core_id, freq_mhz)`:

| core_id | Status | Notes |
|---------|--------|-------|
| 0-5 | OK | Valid CPU cores |
| 0xFF | OK | All cores |
| 0x0E, 0x0F, 0x10, 0x1A | FAILED | Not valid indices |

`set_oc_clk` is CPU-only.

## UVD IP Discovery Confirmed

`/sys/bus/pci/devices/0000:01:00.0/ip_discovery/die/0/UVD/0/`:
- hw_id: 12 (matches VCN)
- major.minor.revision: 2.0.3 (matches VCN 2.0.3)
- harvest: 0x0 (not harvested)
- base_addr: 0x7800, 0x7E00, 0x2403000
- num_instance: 0

IP discovery table knows about VCN. amdgpu's Cyan Skillfish path uses
hardcoded `cyan_skillfish_reg_base_init()` and never registers it.

## Unnamed Q3 Handlers (Community VCN Candidates)

| Msg | Status | arg_out | Notes |
|-----|--------|---------|-------|
| 0x18 | OK | 0 | Returns 0, no observable effect |
| 0x19 | OK | 0 | Returns 0, no observable effect |
| 0x1A | OK | 0 | Returns 0, no observable effect |
| 0x1B | **0x00 (NO DONE STATE)** | — | **DANGEROUS — jams SMU mailbox** |

**Q3 msg 0x1B is a hazard.** It never writes a done status; the SMU state
degrades over time (particularly in conjunction with amdgpu polling),
requiring PSU cold-cycle recovery.

## amdgpu-Side Signals

- `pp_dpm_vclk` and `pp_dpm_dclk` sysfs: **MISSING** (kernel driver never
  registered them for Cyan Skillfish)
- `pp_dpm_dcefclk`: empty string (display clock DPM absent)
- `pp_power_profile_mode`: **MISSING**
- `pp_num_states`: only 1 (default)
- dmesg errors: "Unsupported clock type" when amdgpu tries certain queries
- No VCN/UVD entries in dmesg at all

## Mailbox Collision Hazard (Documented)

Running SMU probes on Queue 0 concurrent with amdgpu's polling of
`TransferTableSmu2Dram` (msg 6) and `GetEnabledSmuFeatures` (msg 0x3D)
jams the mailbox with "SMU: I'm not done with your previous command"
errors. State does not self-recover; requires PSU cold-cycle + fsck boot.

**Mitigation:** Use Queue 3 exclusively for probes. Q3 msg 0x35 replicates
GetEnabledSmuFeatures without touching Q0. Never send Q3 msg 0x1B.

## Conclusion

**The SMU firmware genuinely has no user-accessible pathway to activate VCN clocks.**

The infrastructure exists (feature bits enabled, DPM tables populated, IP
discovery listing UVD 2.0.3, base addresses assigned) but the activation
trigger is absent from every mailbox handler the community has decoded.

VCN activation almost certainly requires either:
1. **Direct SMU firmware execution** via the queue-overflow exploit
   (bc250-smu-unlock) to call the internal `FUN_00023b14(6, 1)` function
2. **A patched amdgpu driver** that registers VCN as a valid IP block AND
   requests VCLK/DCLK via SMU protocols the driver understands
3. **Bootloader-level provisioning changes** (untested; would require BIOS
   modification and outer signature regeneration — not currently feasible)

Consistent with the 2026-09-11 community report: "SMU has zero VCN handlers"
is correct at the message-level API. The clocks exist as DPM state, but
nothing user-accessible requests them.

---

**Recorded:** 2026-09-13
**Probe method:** bc250_smu 0.x, allow_queue0=True, use_flock=True, Q3-only
**Board state:** healthy throughout (excluding Q3 msg 0x1B hazard which triggered
  wedges in prior sessions — now blacklisted)
