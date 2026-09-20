# TOCTOU Analysis — VCN Enablement Gates (2026-09-20)

## Summary

Systematic Time-of-Check-Time-of-Use analysis across all 6 gates in the BC-250 VCN enablement chain. **No exploitable race condition exists from software at runtime.**

The only gate with a meaningful time window (Gate 2: permission table population at boot vs query at runtime) was investigated through three independent vectors. All three are closed: CCP queues are not host-exposed, PSP SRAM has no SMN window, and no known CVE provides a host→PSP SRAM write primitive.

## Boot Chain (temporal order)

```
Boot ROM → PSP_BL → TOS → KDB load → ABL0-4 (APCB parse, DF config) → x86 release → UEFI → OS → amdgpu → LOAD_IP_FW
```

## Gate Analysis

### Gate 1: KDB Signature Verification → Entry Consumption

| Aspect | Detail |
|--------|--------|
| **Check** | Boot ROM RSA-4096 verifies KDB (ARK signature) |
| **Use** | TOS parses verified KDB entries → populates pool+0x700 permission table |
| **Medium** | SPI flash → copied to PSP SRAM → verified + parsed from SRAM copy |
| **Window** | None — verify + parse operate on same SRAM copy |
| **Host access** | Host CPU is in reset |
| **Verdict** | **DEAD** |

### Gate 2: Permission Table Population → Ucode Authorization Query

| Aspect | Detail |
|--------|--------|
| **Check** | Table populated at boot from KDB (one-time write to pool+0x700..+0xF00) |
| **Use** | Queried at runtime when amdgpu submits LOAD_IP_FW for VCN (0x37) |
| **Medium** | PSP SRAM — ARM address space internal to PSP |
| **Window** | **Minutes** — from boot completion to driver load |
| **Host access** | PSP SRAM unreachable (see investigation below) |
| **Verdict** | **DEAD** |

#### Gate 2 Investigation: CCP MEMTYPE_LOCAL (board-tested)

CCP v5 PASSTHROUGH descriptors support a 2-bit `mem_type` field:

| Value | Name | Target |
|-------|------|--------|
| 0 | MEMTYPE_SYSTEM | Host DRAM |
| 1 | MEMTYPE_SB | CCP Local Storage Blocks |
| **2** | **MEMTYPE_LOCAL** | **PSP SRAM** |

If host-submitted CCP descriptors could use `mem_type=2`, we could DMA directly into PSP SRAM at pool+0x700 to inject a fake ucode permission entry.

**Board test result**: CCP command queue registers are **completely invisible** from the host on BC-250. Full 1MB BAR2 scan found only PSP mailbox/status registers (0x10000+) and TRNG output (0x000C). The entire CCP region (0x0000-0x6000, where queue registers should be at BAR2+0x1000 per queue) reads 0xFFFFFFFF and is not writable.

```
BAR2 live regions (15 total, ~100 bytes):
  0x0000C: TRNG output (changing = PSP alive)
  0x10004: PSP_CAPABILITIES (0x40000c25)
  0x1005C: PSP_VERSION (0x02011c00)
  0x10544-0x10578: PSP mailbox registers
  0x109E8-0x10A6C: SEV zone
```

BAR5 (8KB): only scratch/doorbell registers at 0x0000-0x0018, no CCP queues.

Scripts: `code/toctou-analysis/ccp_sram_probe.py`, `code/toctou-analysis/ccp_bar_scan.py`

#### Gate 2 Investigation: PSP SRAM via SMN

PSP SRAM is architecturally invisible via SMN on Zen2/Zen3. No index/data window register pair exists (unlike SMU, which has SMC_IND_INDEX/DATA). The MP0 SMN range (0x03810000+) only exposes mailbox registers (C2PMSG_xx). This is a deliberate security boundary confirmed by Linux kernel source analysis.

#### Gate 2 Investigation: Known CVEs

| CVE | What it does | Host→PSP SRAM? |
|-----|-------------|----------------|
| CVE-2023-31316 | VCN FW integrity during power save/restore | No — *requires* TMR bypass as precondition |
| CVE-2023-31315 (Sinkclose) | Ring 0 → SMM escalation | No — targets SMRAM, not PSP SRAM |
| CVE-2021-46757 | Malicious TA reads/writes ASP kernel | No — requires TA running on PSP |
| PSPReverse glitch | SVI2 voltage fault → PSP code exec | **Yes** — but physical, boot-time only |

### Gate 3: APCB Checksum → Token Parsing

| Aspect | Detail |
|--------|--------|
| **Check** | Byte-sum checksum verified by PSP_BL or ABL |
| **Use** | ABL1 parses DFG/CBSG tokens to configure DF fabric |
| **Medium** | PSP SRAM at 0x7A000 |
| **Window** | Sequential on PSP ARM core during ABL execution |
| **Host access** | x86 in reset or just starting UEFI |
| **Verdict** | **DEAD** |

### Gate 4: DF Fabric Configuration → DF Lock

| Aspect | Detail |
|--------|--------|
| **Check** | ABL writes DF isolation registers based on APCB tokens |
| **Lock** | PSP sends MboxCmd 0x1B to lock DF config |
| **Medium** | DF hardware registers (0x06900900, 0x50D6C) |
| **Window** | Both pre-x86 |
| **Host access** | DF isolation registers not host-writable (all 5 write vehicles tested, dead) |
| **Verdict** | **DEAD x 2** |

### Gate 5: PSP Ring Submission → Processing

| Aspect | Detail |
|--------|--------|
| **Check** | amdgpu writes LOAD_IP_FW to ring |
| **Use** | PSP reads ring, checks permission table |
| **Medium** | DMA ring buffer in host DRAM |
| **Window** | Microseconds |
| **Host access** | We control the ring, but check is server-side |
| **Verdict** | **DEAD** |

### Gate 6: Runtime Flash Modification → Warm Reboot

| Aspect | Detail |
|--------|--------|
| **Mechanism** | Modify KDB in SPI flash via FCH controller, reboot |
| **Blocker** | PSP re-boots and RSA-verifies KDB on cold boot |
| **Note** | Not true TOCTOU — same as CH347 flash approach |
| **Verdict** | **DEAD** (RSA-gated) |

## Conclusion

The PSP security boundary is well-enforced on this PS5-derived silicon. No runtime software path can modify the VCN ucode permission table at pool+0x700. All remaining VCN enablement paths require taking the board offline:

1. **APCB Variant G flash** — Robin5.00 DFG+CBSG transplant (built, verified, pending flash)
2. **Voltage glitch** — PSPReverse SVI2 attack (proven on Zen2, needs Teensy ~$24)
