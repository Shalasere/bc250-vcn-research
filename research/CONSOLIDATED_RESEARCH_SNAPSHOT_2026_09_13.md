# BC-250 VCN Enablement: Consolidated Research Snapshot (2026-09-13)

> **Purpose:** Comprehensive snapshot consolidating all findings from thelamer/bc250-vcn, bc250-vcn-research, and contributor research. Durable reference for understanding the current state and next steps.
>
> **Scope:** VCN 2.0.3 ("Cyan Skillfish") power-on, firmware authentication, execution blockers, and known dead ends.

---

## Executive Summary: State of Play

| Aspect | Status | Evidence |
|--------|--------|----------|
| **Silicon Present** | ✅ Yes, not harvested | IP discovery confirms VCN 2.0.3, harvest=0 |
| **Power Domain** | ✅ Can be switched ON | `FUN_00023b14(6, 1)` works, domain 6 acknowledges |
| **Firmware Placement** | ✅ Possible via direct-load | Bypasses PSP auth, reaches `vcn_v2_0_hw_init()` |
| **Firmware Authentication** | ⚠️ PSP rejects by default | Missing KDB usage-6 key; works via transient interposer injection |
| **MMIO Access** | ❌ Still gated/clamped | Reads 0xffffffff or hangs board |
| **VCPU Execution** | ❌ Never runs | PC=0x00000000, no instruction fetch |
| **Hardware Harvest Latch** | ❌ Immutable | CC_UVD_HARVESTING @ 0x1f81c reads 3, stays 3 even via PSP write |

**Bottom Line:** VCN silicon is fully functional and provably accessible from **PSP context** (proven via interposer experiments). Multiple independent gates prevent access from **host context**. At least three separate blockers exist at different architectural layers.

---

## The Gate Hierarchy: Three Independent Blockers

### Gate 1: PSP Staging-Slot Walker (Software, Firmware-Level)

**Location:** PSP bootloader `FUN_0000a030` @ 0xa030  
**Mechanism:** `svc #0x87` at PSP 0xa06e checks: `return ((u8)0x6007 == 0)`  
**Gate Logic:**
```
if (byte_at_PSP_0x6007 == 0) {
    ACCEPT firmware load (short-circuit)
} else if (staging_row_id == 13) {
    ACCEPT firmware load
} else {
    RETURN 0x80000205 (ITEM_NOT_FOUND)
}
```

**BC-250 State:** Byte @ 0x6007 = `0`, VCN staging row id = `0x22` (34) not 13 → both conditions fail  
**Impact:** PSP rejects VCN firmware via normal `LOAD_IP_FW` driver path  
**Workaround:** Direct-load firmware into VCN buffer, bypassing PSP  
**Missing Primitive:** PSP kernel-RAM write to address 0x6007 from host context

**Status:** Identified, root cause clear, no host-context primitive yet

---

### Gate 2: KDB Usage-6 Signing Key (Firmware Authentication)

**Location:** PSP Key Database (KDB) in BIOS  
**Issue:** BC-250 KDB is missing the usage-6 key that firmware type 13 (VCN) requires  
**Reference:** Steam Deck TOS KDB contains:
- Usage-6 key (Cezanne/Navi): `c37290c310e64a62b027c56695492368`
- Usage-6 key (Van Gogh): `70ec3e2d8a694792ac7969ff8ac9caca`

**BC-250 KDB:** Only has usages 10, 17, 44 — missing 6  
**Result:** PSP authentication fails with no matching key

**Workaround Tested:**
- ❌ Persistent KDB edit: Appending usage-6 key causes no-POST (KDB signature check fails)
- ✅ Transient interposer injection: Injects usage-6 record into runtime KDB via Pico SPI MITM → firmware authenticates cleanly, status=0, valid TMR address

**Firmware Tested & Authenticated:**
- Navi10 type-13 with Cezanne/Navi usage-6 key → ✅ status zero
- Van Gogh type-13 with Van Gogh usage-6 key → ✅ status zero

**Status:** Root cause identified, transient workaround proven, persistent solution blocked by KDB signature

---

### Gate 3: Hardware Harvest Latch (Hardware-Level, Likely Unfixable)

**Register:** `CC_UVD_HARVESTING` @ MMIO 0x1f81c  
**Current Value:** `0x00000003`  
**Access:** Via PSP secure read/write interface

**Attempted Unlock:**
```
PSP secure write(0x1f81c, 0x00000000)
Result: Operation acknowledged as successful
Immediate PSP readback: 0x00000003 (unchanged)
Independent host readback: 0x00000003 (unchanged)
```

**Finding:** Write is accepted but value never changes. Consistent with fuse-style latch (hardware read-only).

**Firmware Involvement:** Full register audit of borrowed Navi10/Renoir firmware blob (405 KB) found:
- 33 named VCN registers referenced
- 66 unresolved address-shaped values
- **0x1f81c is NOT among the addresses the firmware touches**
- 13 overlapping registers match PS5 init sequence perfectly (ABI correct)

**Conclusion:** Firmware doesn't clear this latch, and neither can host or PSP. This is likely a hardware-level harvest control that requires either:
- Silicon revision/respinning
- Fuse override (unknown method)
- Or it's an incorrect assumption about what 0x1f81c controls

**Status:** Immutable, probably unfixable in software

---

## What Works: Proven in PSP Context

### Interposer-Based PSP Power-Up (Reproducible)

**Setup:** Physical Pico2 SPI MITM on J4004 header + hybrid P3/P5 BIOS + PSP hooks  
**Sequence Executed:**
1. Load VCN firmware (with transient KDB injection)
2. Run PGFSM power sequence (`FUN_00023b14(6, 1)`)
3. Run clock/reset sequence (slots 0x16/0x17/0x18 via `FUN_00023744`)

**Results:**
```
UVD_VERSION:
  Before hook: 0xDEADBEEF (unpowered sentinel)
  After hook:  0x0002001B (real VCN 2.0.3 version) ✅

PGFSM_STATUS:     0x00200000 ✅
POWER_STATUS:     0x00000801 ✅
Register aperture: EXPOSED ✅
```

**Conclusion:** VCN 2.0.3 silicon is **fully functional and accessible**. The gates are firmware/configuration, not silicon-level.

**Current Blocker:** VCPU still doesn't execute (PC=0x00000000). Firmware is authenticated and placed, but something prevents code execution.

---

## What Doesn't Work: Dead Ends (Don't Repeat)

### ❌ PSP Path for Firmware

| Attempt | Result | Why |
|---------|--------|-----|
| Type 13 (VCN) via PSP | `0xffff0008` (ITEM_NOT_FOUND) | PSP 0x6007 gate rejects it |
| Type 64 (alternative) | `0x00000000` (TEE_SUCCESS) | No-op, doesn't power VCN |
| AMD-signed TAs | Load successfully but no-op | Wrong component type |

**Verdict:** PSP path is **dead end for VCN firmware**. Direct-load is the only working host-side approach.

### ❌ Direct SMU Mailbox Messages

| Message | Queue | Result | Why |
|---------|-------|--------|-----|
| 0x08 (PowerUpVcn) | 0/1/3 | No-op or wrong domain | Doesn't exist in SMU 11.8 Xtensa |
| 0x09 (PowerDownVcn) | 0/1/3 | DRAM/MC related | Not VCN on this SMU version |

**Verdict:** Full Ghidra decompile shows **zero VCN-named messages in any queue**. Stop looking for a dedicated VCN message. The working approach uses SMU **internal functions**, not mailbox messages.

### ❌ Direct MMIO Access (Hangs Board)

| Method | Result |
|--------|--------|
| BAR5 direct reads/writes | Hard hang |
| UMR (AMD GPU monitor) | Hard hang |
| Kernel SMN via debugfs | Hard hang |

**Verdict:** Any direct MMIO access to VCN registers causes board hang. Access must go through SMU or PSP context.

### ❌ BIOS Setup / IFR Options

**Finding:** No VCN enable option exists in BC-250 BIOS setup screens. Not a user-configurable feature.

---

## SMU Architecture: Key Details

### SMU 11.8 Internals

| Property | Value |
|----------|-------|
| **Processor** | Xtensa (RISC ISA) |
| **Firmware** | robin_1, version 88.6.0 |
| **Queues** | 7 total (Q0-Q6), Q1-Q4 host-accessible |
| **Host Interface** | PCI config 0xB8 (queue) / 0xBC (message) |
| **VCN Domain** | Domain 6 (VCLK/DCLK + unknown clock) |

### Working Primitives

| Primitive | Queue | Message | Effect | Status |
|-----------|-------|---------|--------|--------|
| Power domain 6 | Internal | `FUN_00023b14(6, 1)` | Powers on VCN, VCLK/DCLK enabled | ✅ Proven |
| Arbitrary SMN write | Q3 | `0x98` arg | Write 0x00FF to any SMN address | ✅ Proven (CPU unlock) |
| Clock slot program | Internal | `FUN_00023744` + `FUN_0002362c` | Programs slots 0x16/0x17/0x18 | ✅ In PSP context |

### Unused/Blocked

| Path | Queue | Note |
|------|-------|------|
| VCN firmware load via PSP | PSP path | Gated by 0x6007 + KDB key |
| Direct VCN MMIO | Host | Hangs; must route through SMU/PSP |

---

## Firmware Architecture

### Firmware Types & Authentication

| Type | Purpose | Example | KDB Usage | BC-250 Status |
|------|---------|---------|-----------|---------------|
| 10 | PMFW (Power Mgmt) | Xtensa robin_1 | Usage 44 | ✅ Present |
| 13 | VCN firmware | Navi10/Van Gogh | Usage 6 | ❌ Missing |
| 64 | SEV-SNP ABL | Security | Varies | ✅ Present |

### Firmware Placement

| Stage | Method | Status | Notes |
|-------|--------|--------|-------|
| PSP path (normal) | LOAD_IP_FW driver call | ❌ Rejected | Blocked by 0x6007 gate, KDB key missing |
| Direct-load workaround | Write to VCN buffer directly | ✅ Works | Bypasses PSP, reaches `vcn_v2_0_hw_init()` |
| Interposer injection | Transient KDB injection | ✅ Works | Physical access required, authentication succeeds |

**Current Issue:** Firmware is placed and authenticated, but VCPU never executes (PC=0x00000000).

---

## Clocking: VCLK/DCLK Status

### Before Power-Up

```
VCLK: 0x0000 (disabled)
DCLK: 1111 (not 0, but check actual freq)
Status: VCN powered down
```

### After `FUN_00023b14(6, 1)` (PSP Context)

```
VCLK: enabled (non-zero)
DCLK: enabled (non-zero)
PGFSM_STATUS: 0x00200000
Status: VCN powered up ✅
```

### Host Context Equivalent

Target: Replicate clock-slot programming (`FUN_00023744` + `FUN_0002362c`) for slots 0x16/0x17/0x18

**Open:** Exact register addresses and bit patterns not yet extracted from Ghidra decompile

---

## Platform Comparisons: Why VCN Works Elsewhere

### Steam Deck (Works)

- **VCN:** Van Gogh variant (same as BC-250)
- **BIOS:** PSP 0x6007 = non-zero (walker short-circuits)
- **KDB:** Usage-6 key present
- **Result:** ✅ VCN working, video playback functional

### Renoir APU (Reference)

- **VCN:** Renoir variant (similar to Van Gogh)
- **Reset/Clock Sequence:** Documented in AMD amdgpu driver (`vcn_v2_0_start()`)
- **DPM Callback:** `dpm_set_vcn_enable` present and called
- **Result:** ✅ VCN working

### BC-250 (Broken)

- **VCN:** Van Gogh variant silicon
- **BIOS:** PSP 0x6007 = 0 (walker rejects it)
- **KDB:** Usage-6 key absent
- **DPM Callback:** Missing `dpm_set_vcn_enable`
- **Result:** ❌ All three gates block access

---

## Next Steps by Priority

### Phase 1: Root Cause Confirmation (0 Risk, Passive)

1. **Gate 3 investigation:** Is 0x1f81c truly unfixable, or is it misunderstood?
   - Check PS5 VCN init sequence for harvest latch references
   - Explore whether the register is fuse-backed or cacheable
   - Review AMD firmware commits (RescueMei, AMDVLK) for 0x1f81c usage

2. **Clock slot programming:** Extract exact addresses/patterns from Ghidra
   - Slots 0x16/0x17/0x18 register offsets
   - `FUN_0002362c` (soc_clk_program_slot) implementation
   - Reproduce from host context (without PSP hook)

3. **KDB signature analysis:** Can a persistent KDB edit be made without breaking PSP verification?
   - Understand KDB checksumming/signing
   - Explore whether a compromised checksum is detectable at runtime

### Phase 2: Mitigation Testing (Low Risk, Live Hardware)

4. **SMU Queue 3 msg 0x98 tests:** Probe register writes to clock/gate addresses
   - Use existing arbitrary SMN write primitive
   - Target clock-gate addresses identified in step 2
   - Monitor VCLK/DCLK for change

5. **PSP 0x6007 write primitive:** Develop host-context write to PSP kernel RAM
   - Known blocker: all existing paths wedge at 0x6007
   - Potential routes: SMU callback, PSP doorbell, firmware hook

### Phase 3: Long-Term Path (Requires Physical Access)

6. **Interposer-based solution:** Reproduce P's PSP hook setup
   - Pico2 SPI MITM on J4004 header
   - Hybrid P3/P5 BIOS + PSP hooks
   - Transient KDB injection at boot

---

## Tool Ecosystem: What Works, What's Lacking

### Reverse Engineering Tools (Good)

| Tool | Purpose | Status | Relevant Files |
|------|---------|--------|-----------------|
| **Ghidra** (with SMU extensions) | SMU Xtensa decompile | ✅ Complete | `FUN_00023b14`, `FUN_00023744`, `FUN_0002362c` |
| **PSPEmu** (BC-250 fork) | PSP ARM emulation | ✅ Works for PSP ARM code | Boot sequence, key database |
| **recon** toolkit | SMU/firmware static analysis | ✅ Available | Register finding, boot flow analysis |
| **Binary Ninja** (PSP loader) | PSP firmware disassembly | ✅ Available | KDB structure, staging-slot walker |
| **UMR** (AMD GPU monitor) | Register inspection | ✅ Works for readable regs | Hangs on VCN MMIO (0x1000+) |

### Reverse Engineering Tools (Gaps)

| Tool | Needed For | Status | Workaround |
|------|-----------|--------|-----------|
| **VCN Xtensa emulator** | Dynamic trace of VCN firmware | ❌ Doesn't exist | Use PSP context + hardware to infer |
| **PSP kernel-RAM writer** | Fix 0x6007 from host | ❌ No primitive exists | Interposer or firmware hook |
| **KDB re-signer** | Persistent KDB edit | ❌ No private key | Accept transient injection limitation |

### External Tools (Used in Research)

| Name | Purpose | Source |
|------|---------|--------|
| **codex** | Firmware structure comparison | Internal tool (cited without upstream) |
| **UMR** | Register read/write | AMD amdgpu utilities |
| **Pico2** (SPI MITM) | Interposer SPI capture | Raspberry Pi Pico with level shifter |

---

## External Resources: Linked Projects & References

### BC-250 Specific (Most Relevant)

**SMU Reverse Engineering:**
- [`bc250-collective/amd_smu_reverse_engineering`](https://github.com/bc250-collective/amd_smu_reverse_engineering) — Full Ghidra decompile of BC-250 SMU (Xtensa). All 7 queue tables. Source of all `FUN_*` addresses.

**SMU Access & Exploitation:**
- [`rw-r-r-0644/bc250-smu-unlock`](https://github.com/rw-r-r-0644/bc250-smu-unlock) — Arbitrary SMU r/w + code execution. Testing/access mechanism.
- [`rw-r-r-0644/bc250-core-unlock`](https://github.com/rw-r-r-0644/bc250-core-unlock) — CPU 6c→8c unlock, reveals Queue 3 msg 0x98 arbitrary SMN write.
- [`bc250-collective/bc250_smu_oc`](https://github.com/bc250-collective/bc250_smu_oc) — Userspace OC tool using Queue 3 via PCI 0xB8/0xBC.
- [`RescueMei/BC250-DXE-SMU-Core-Unlock`](https://github.com/RescueMei/BC250-DXE-SMU-Core-Unlock) — Alternative core-unlock, same 0x98 primitive.

**SMU Driver (Potential):**
- [`leogx9r/ryzen_smu`](https://github.com/leogx9r/ryzen_smu) ([GitLab](https://gitlab.com/leogx9r/ryzen_smu)) — SMU access kernel driver. **Lacks Cyan Skillfish support** — would need integration.

**SMU Handler Reference:**
- [`rpf16rj/bc250-steamos-real-toolkit`](https://github.com/rpf16rj/bc250-steamos-real-toolkit) — SMU-HANDLERS.md: Decoded Q0/Q2/Q3 handlers, feature framework (64 bits), Queue 2 mailbox addrs.

### BIOS / Firmware / Docs

| Link | Why It Matters |
|------|---|
| [`elektricm/amd-bc250-docs`](https://elektricm.github.io/amd-bc250-docs/bios/flashing/) | BIOS variants, flashing, verified hashes |
| [`katzzero/bc250-unofficial-community-guide`](https://github.com/katzzero/bc250-unofficial-community-guide) | Comprehensive BIOS/firmware guide |
| [`MrrZed0/bc-250-bios`](https://github.com/MrrZed0/bc-250-bios) | BIOS resources and variants |
| [`amd/firmware_binaries/v2000a`](https://github.com/amd/firmware_binaries/tree/main/v2000a) | Closest relative APU vBIOS/PSP — check VCN power-up chain |

### AMD SMU / PSP / Firmware Reference

| Link | Why It Matters |
|------|---|
| [`smu_v11_8_pmfw.h`](https://codebrowser.dev/linux/linux/drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if/smu_v11_8_pmfw.h.html) (Codeblocks) | All 64 SMU 11.8 feature bits (FEATURE_DS_SMNCLK_BIT=14, etc.) |
| [Dayzerosec: Reversing the AMD PSP (2023)](https://dayzerosec.com/blog/2023/04/17/reversing-the-amd-secure-processor-psp.html) | PSP SMN/Syshub slot mechanism, ABL boot order |
| [`PSPReverse`](https://github.com/PSPReverse) / [`AMD-SP-Loader`](https://github.com/dayzerosec/AMD-SP-Loader) | PSP emulator, headers, Binary Ninja loader |
| [Buhren — BlackHat USA 2020 PDF](https://i.blackhat.com/USA-20/Wednesday/us-20-Buhren-All-You-Ever-Wanted-To-Know-About-The-AMD-Platform-Security-Processor-And-Were-Afraid-To-Emulate.pdf) | PSP internals, SuperIO/UART, emulation challenges |
| [Coreboot PSP Integration](https://doc.coreboot.org/soc/amd/psp_integration.html) | FET/directory format, bootloader syscalls |
| [bl_syscall_public.h](https://github.com/sameershaik/coreboot_beagle-xM/blob/ab8cc142a727c917aa58bd3ff1e3097332ee2610/src/vendorcode/amd/fsp/cezanne/include/bl_uapp/bl_syscall_public.h) | PSP syscall ABIs |
| [bl_errorcodes.h](https://review.coreboot.org/plugins/gitiles/amd_blobs/+/53c000991a5e896bb107e816ff6e422d5c25d3c7/picasso/PSP/bl_errorcodes.h.txt) | PSP POST/error codes (0xffff0008 = ITEM_NOT_FOUND) |
| [ARM Cortex-A5 TRM](https://documentation-service.arm.com/static/5e8e2aacfd977155116a6e48) | PSP CPU core (ARM) specification |

### Linux Kernel References

| Link | Why It Matters |
|------|---|
| [`drivers/gpu/drm/amd/pm/swsmu/...`](https://github.com/torvalds/linux/tree/master/drivers/gpu/drm/amd/pm/swsmu) (Linux kernel) | SMU v11.8 driver code, feature bits, DPM callbacks |
| [`drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c`](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c) | VCN 2.0 driver init (reference: dpm_set_vcn_enable, reset sequence) |
| [Linux VCN 2.0 init flow](https://github.com/torvalds/linux/blob/master/drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c#L292) | `vcn_v2_0_start()` — clock gating, reset, power sequencing |

### Related Projects (Workarounds/Alternatives)

| Link | Relevance |
|------|-----------|
| [`bc250-vcn-driver`](https://github.com/thelamer/bc250-vcn-driver) (if available) | Compute-shader VA-API workaround; H.264 encoding via Vulkan CUs (ships today) |
| [`daveconde/bc250-vcn-enable`](https://github.com/daveconde/bc250-vcn-enable) | VCN research from another angle |

---

## Known Hardware Constraints

### S3 Sleep / Resume

**Finding:** S3 suspend is **impossible on BC-250 hardware**.
- GDDR6 memory doesn't support self-refresh on this SKU
- PSU cannot switch VRMs to standby rail
- This is **not fixable in software**

### Kexec

**Finding:** Full-power kexec (without S3) is **feasible**.

### Other SKUs / Variants

| SKU | VCN Status | Notes |
|-----|-----------|-------|
| Steam Deck | ✅ Working | Van Gogh variant, PSP 0x6007 non-zero, KDB key present |
| Renoir APU | ✅ Working | dpm_set_vcn_enable callback present |
| BC-250 | ❌ Multiple gates | Three blockers at different layers |

---

## Summary: What We Know & What's Missing

### Conclusively Proven

✅ VCN 2.0.3 silicon is present, not harvested  
✅ Power domain 6 can be switched on (verified `FUN_00023b14(6, 1)`)  
✅ Firmware can be placed in VCN buffer (direct-load bypass)  
✅ Firmware can be authenticated when KDB usage-6 key is injected  
✅ From PSP context, the full bring-up sequence works  
✅ Queue 3 msg 0x98 provides arbitrary SMN write primitive  

### Still Blocked (Host Context)

❌ PSP 0x6007 gate: No host-context write primitive to PSP RAM  
❌ Hardware harvest latch: Appears immutable, possibly fuse-level  
❌ VCPU execution: Firmware authenticated but PC never leaves 0x00000000  

### Not Yet Understood

❓ Why VCPU doesn't execute despite successful firmware placement + authentication  
❓ Whether 0x1f81c (harvest latch) is truly hardware-locked or misunderstood  
❓ Exact clock-slot programming (0x16/0x17/0x18) register patterns for host context  

---

## Recommended Reading Order

For someone starting fresh:

1. **This document (CONSOLIDATED_RESEARCH_SNAPSHOT)** — Full overview
2. **`COMMUNITY_REPORT_2026_09_11.md`** — Latest blocker status (harvest latch, KDB, PSP gate)
3. **`COMMUNITY_REPORT_2026_09_09.md`** — How the 0x6007 gate was discovered
4. **`COMMUNITY_REPORT_2026_09_06.md`** — Original SMU/power-on breakthrough
5. **thelamer/bc250-vcn README** — Working notes, Ghidra findings, open threads

For active debugging:

1. **Ghidra decompile** (`amd_smu_reverse_engineering` repo) — Extract `FUN_00023744`, `FUN_0002362c`
2. **recon toolkit** — Firmware static analysis
3. **PSPEmu BC-250 fork** — Emulate boot sequence, KDB inspection
4. **PSPReverse/AMD-SP-Loader** — Binary Ninja loaders for PSP blobs

---

## Attribution

Research consolidated from:
- **thelamer/bc250-vcn** — Initial status, open threads, tool ecosystem
- **bc250-vcn-research** — Contributors P (interposer-route), R (PSP static analysis)
- **bc250-collective** — SMU reverse engineering, core unlock
- **Community tools** — Ghidra, PSPEmu, recon, Binary Ninja extensions

---

**Document Generated:** 2026-09-13  
**Last Updated:** 2026-09-13  
**Scope:** VCN 2.0.3 on AMD BC-250 "Cyan Skillfish"  
**Status:** Comprehensive snapshot (comprehensive but not exhaustive—ongoing research)
