# BC-250 VCN Enablement: Integrated Research Summary (2026-09-13)

> **Final comprehensive synthesis:** Consolidates thelamer findings, bc250-vcn-research (Sept 6-11), agent research (Sept 13), and identifies actionable next steps.

---

## Current State: Three Independent Gates Block Execution

| Gate | Layer | Status | Cause |
|------|-------|--------|-------|
| **Gate 1: PSP 0x6007 (Staging-Slot Walker)** | Firmware/PSP | Known, unsolved | One byte gates LOAD_IP_FW acceptance; no host-context write primitive |
| **Gate 2: KDB Usage-6 Key** | Firmware auth | **Solved (transient)** | Missing key works around via Pico interposer; authenticated cleanly |
| **Gate 3: Hardware Harvest Latch** | Hardware | Immutable | Register 0x1f81c reads 3, stays 3; fuse-level or unfixable |
| **Gate 4: Clock/Reset/Isolation (Second Gate)** | Hardware | **Active blocker NOW** | Soft reset not released, isolation gates not cleared, VCLK/DCLK not enabled |

**All four gates are INDEPENDENT.** Solving one doesn't solve the others.

---

## What's Working vs. Broken

### ✅ PROVEN WORKING

**From PSP-context experiments (physical interposer, Sept 9-11):**
- ✅ VCN 2.0.3 silicon present (harvest = 0)
- ✅ Domain 6 power activation via `FUN_00023b14(6, 1)` — SMU responds, domain acknowledges
- ✅ Firmware placement (direct-load bypasses PSP)
- ✅ Firmware authentication (transient KDB injection solves missing usage-6 key)
- ✅ MMIO aperture exposure — UVD_VERSION = 0x0002001B readable
- ✅ PGFSM state transitions — register writes accepted
- ✅ Cache/MMHUB setup — GPU complex responds correctly

**From host-side SMU access (proven):**
- ✅ Queue 3 msg 0x98 (arbitrary SMN write 0xFF) — works reliably in always-on domains
- ✅ SMU mailbox transport — no collisions with GPU governor
- ✅ PCI 0xB8/0xBC SMN access — functional, no auth required

### ❌ BLOCKED

**From host context (Sept 6 testing + hardware constraints):**
- ❌ Direct MMIO access to VCN registers → hard hang (unmapped SMN frame)
- ❌ Clock/reset/isolation registers remain asserted despite power-on
- ❌ VCPU never executes (PC stays at 0x00000000)
- ❌ Ring test hangs (decode ring not ready)

**From PSP path (confirmed insufficient):**
- ❌ PSP 0x6007 gate blocks firmware load via normal driver
- ❌ Direct register writes to VCN clocks hang (clock sub-block unpowered at L1 layer)

---

## The "Second Gate" (CURRENT BLOCKER)

**Root cause:** After SMU powers domain 6, a **second hardware gate** remains asserted at the L1 (clock/reset) layer.

**What this gate controls:**
1. **Soft Reset Release** — `mmVCN_SOFT_RESET` bit 0 (1 = held, 0 = released)
2. **Isolation Gate Clearing** — `mmVCN_CLOCK_GATING_DELAY` (0 = disables gating)
3. **Clock Enable** — VCLK/DCLK frequency/gating (SMU domain change alone insufficient)
4. **PGFSM Handshake** — if PGFSM is used, may not complete without clock enablement

**Why it hasn't been cleared:**
- BC-250 has **no `dpm_set_vcn_enable` callback** in amdgpu driver (deliberately omitted, VCN not public API)
- SMU firmware has **zero VCN code** — no handlers, no clock programming
- Direct MMIO hangs — can't write these registers from host context
- SMU 0x98 primitive only works in **always-on domains** — clock sub-block is unpowered

**Diagnostic needed:** Register state before/after `FUN_00023b14(6,1)` to identify which bits change and which are still asserted.

---

## Register Reference: What Needs Clearing

**From Linux amdgpu driver comparison (Renoir reference):**

| Register | Address | Purpose | Need to Clear |
|----------|---------|---------|----------------|
| `mmVCN_SOFT_RESET` | 0x401C | Soft reset assertion | Clear bit 0 (write 0x00000000) |
| `mmVCN_CLOCK_GATING_DELAY` | 0x401E | Clock gating delay / isolation | Clear all bits (write 0x00000000) |
| `mmVCN_PGFSM_CONFIG` | 0x0E90 | PGFSM enable (if used) | Check/set appropriate state |
| `mmVCN_PGFSM_STATUS` | 0x0E94 | Power state readback | Poll for handshake |
| `mmVCN_DCFE_CTRL` | 0x4000-0x4010 | Decoder frontend config | Initialize (domain-dependent) |

**Renoir sequence (reference, may differ on BC-250):**
```
1. Assert soft reset:   WRITE(mmVCN_SOFT_RESET, 0x00000000)
2. Clear isolation:     WRITE(mmVCN_CLOCK_GATING_DELAY, 0x00000000)
3. Enable clocks:       (handled by SMU domain activation)
4. Release soft reset:  WRITE(mmVCN_SOFT_RESET, 0xFFFFFFFF) [or specific pattern]
5. Wait/poll:           READ(mmVCN_PGFSM_STATUS) until stable
```

**BC-250 issue:** These writes hang from host context. Need SMU pathway or prior L1 enable.

---

## The L1 Power-Enable Mystery

**Missing piece identified by agent analysis:**

VCN clock registers (`0x5c1xx`, `0x401xx`) are in an **unpowered sub-block**.
Direct access hangs the board.

**Hypothesis:** There's an **always-on domain register** that gates the L1 (clock layer) power to VCN, similar to how domain 6 itself is enabled.

**Search for it:**
1. Extract BC-250 SMU firmware from BIOS
2. Run `smu_function_helper.py` to discover all functions
3. Trace `FUN_00024764` (power-down) → may reveal the L1 gating register
4. Cross-reference Van Gogh SMU firmware (if available) for comparison
5. Test candidate register via SMU 0x98 (if in always-on domain)

**If found:** Single `0x98` write to that register might wake the L1 layer, allowing subsequent clock register writes.

---

## Parallel Research Paths (Ready to Execute)

### Path 1: SMU Function Discovery (0 Risk, Passive)
**Time:** 30 minutes  
**Tools:** Ghidra + smu_function_helper.py  
**Goal:** Discover FUN_00023b14, FUN_00023744, FUN_0002362c, FUN_00024764

**Steps:**
1. Extract SMU firmware from user's BIOS (PSPTool)
2. Open in Ghidra with Xtensa-LE architecture
3. Run smu_function_helper.py → generates complete function list
4. Locate and trace teardown path to identify L1 enable register

**Success metric:** Confirm all four power-related functions; identify L1 enable register address

### Path 2: Register State Diff (Low Risk, Live Hardware)
**Time:** 1 hour  
**Tools:** SMU 0x98 writes, careful register reading  
**Goal:** Identify which gate is still asserted post-power-on

**Steps:**
1. Read VCN control registers pre-power-on (SMU 0x98 if in readable domain, else boot script)
2. Execute `FUN_00023b14(6, 1)` (SMU internal function via exploit/hook)
3. Read same registers post-power-on
4. Diff output to see which bits transitioned

**Registers to diff:**
- `mmVCN_SOFT_RESET`, `mmVCN_CLOCK_GATING_DELAY`
- `mmVCN_PGFSM_CONFIG`, `mmVCN_PGFSM_STATUS`
- `mmVCN_DCFE_CTRL` (if addressable)

**Success metric:** Identify which gate (soft reset, isolation, or PGFSM) is still asserted

### Path 3: Van Gogh Cross-Reference (Medium Risk, Static Analysis)
**Time:** 2 hours  
**Tools:** Ghidra, PSPReverse tools, kernel sources  
**Goal:** Compare working VCN platform clock sequence to BC-250 pattern

**Steps:**
1. Extract Van Gogh SMU firmware (public in amd/firmware_binaries)
2. Ghidra analysis of Van Gogh clock slot programming (SMU 13.x)
3. Cross-reference with Linux `smu_v13_0_vcn_enable()` kernel driver code
4. Map Renoir register offsets (`0x401C`, `0x401E`) to Van Gogh equivalent
5. Identify if BC-250 uses same register offsets (likely yes, same VCN 2.0.3 IP)

**Success metric:** Confirm register offsets and sequence apply to BC-250

### Path 4: SMU Arbitrary Code Execution (High Risk, Requires Expertise)
**Time:** 4+ hours  
**Tools:** bc250-smu-unlock (if code-exec variant available)  
**Goal:** Bypass firmware limitation by running custom SMU code

**Approach:** If SMU arbitrary code execution exists in the community toolkit, write custom SMU handler to:
1. Enable L1 power to VCN clock sub-block
2. Program clock slots 0x16/0x17/0x18
3. Clear soft reset + isolation gates
4. Return control to host

**Risk:** Requires intimate SMU firmware knowledge; wrong code can hang/crash board

**Status:** rw-r-r-0644 reportedly has this capability; verify before attempting

---

## Integration Path Forward

### Phase 1: Diagnosis (This Week)
**Execute Path 1 (function discovery) + Path 2 (register diff) in parallel**
- Discover all VCN functions in SMU firmware
- Identify which gate is still asserted after power-on
- **Gate #4 isolation level** → determines whether simple register writes suffice

### Phase 2: Mitigation (If Gate #4 Is Soft-Reset/Isolation Only)
**If register diff shows only soft reset or isolation gates asserted:**
- Attempt Renoir sequence via SMU 0x98 writes to clock-sub-block enable register
- If found, test releasing soft reset + clearing isolation
- Risk: Low (register writes in always-on domain, same primitive as CPU unlock)

### Phase 3: Complex Solutions (If Gate #4 Is PGFSM/Unpowered)
**If L1 enable register not found or clock sub-block truly unpowered:**
- Execute Path 4 (SMU arbitrary code execution)
- Or pursue Pico interposer route for transient SMU hook (permanent solution)
- Risk: High (requires firmware knowledge)

---

## Key Equations & Dependencies

### VCN Bring-Up Dependencies

```
Silicon functional (proven) 
  ✅ via PSP-context experiments

Domain 6 power-on (achieved)
  ✓ FUN_00023b14(6, 1) works
  ✓ SMU acknowledges transition
  ✗ But doesn't clear Gate #4

Gate #4 clearance (BLOCKING CURRENT PATH)
  Depends on: L1 enable register discovery (unknown address)
  OR: SMU arbitrary code execution (complex)
  OR: PGFSM handshake (if used, requires clock enablement)

Clock enablement (downstream)
  Depends on: Gate #4 clearance

Firmware execution (final)
  Depends on: Clock enablement + all gates cleared
```

### What We Know vs. Don't Know

| Element | Known? | Source |
|---------|--------|--------|
| VCN is present | ✅ Yes | IP discovery, harvest=0 |
| Domain 6 power path | ✅ Yes | FUN_00023b14(6,1) proven |
| Clock register addresses | ✅ Yes | Renoir reference, driver code |
| L1 enable register address | ❌ **NO** | Still missing |
| Exact reset/isolation sequence | ⚠️ Partial | Renoir reference, may differ |
| PGFSM usage on BC-250 | ❌ Unknown | Need register diff |
| Clock slot programming (0x16-18) | ❌ Unknown | Need FUN_00023744 analysis |

---

## Recommended Resources to Access Now

**Immediate (free, public):**
1. Linux amdgpu kernel: `drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c` — VCN 2.0 reference init
2. AMD SMU headers: `smu_v11_8_pmfw.h` — All feature bits, feature framework
3. AMD firmware_binaries: Van Gogh SMU firmware (comparison reference)
4. Coreboot PSP docs: PSP FET/directory structure, boot flow

**Secondary (community):**
1. bc250-collective/amd_smu_reverse_engineering — Ghidra database + scripts
2. PSPReverse/PSPEmu — PSP firmware emulation, KDB inspection
3. rw-r-r-0644 projects — SMU access primitives, exploit documentation

**Tertiary (if pursuing SMU code execution):**
1. bc250-smu-unlock (if arbitrary code execution variant published)
2. Xtensa ISA reference manuals (for SMU firmware writing)

---

## Executive Summary

**Current blocker:** Gate #4 (clock/reset/isolation layer) remains asserted despite SMU power-on.

**Missing link:** L1 power-enable register address (if it exists in always-on domain).

**Path to unlock:**
1. Discover SMU functions + identify L1 register (Path 1)
2. Verify gate state with register diff (Path 2)
3. If L1 register found: Single 0x98 write to enable it, then Renoir sequence
4. If not found: Pursue SMU arbitrary code execution or Pico interposer

**Effort estimate:** 
- Paths 1-3: 3-4 hours (discoverable, low risk)
- Path 4: 6+ hours (complex, high risk)

**Probability of success:** High if L1 register exists in always-on domain; lower if Gate #4 is PGFSM-dependent or truly unpowered.

---

**Document generated:** 2026-09-13  
**Based on:** 5 parallel agent research sessions synthesized  
**Status:** Actionable research roadmap ready for next phase
