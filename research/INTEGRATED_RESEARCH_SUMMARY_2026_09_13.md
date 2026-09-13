# BC-250 VCN Enablement: Integrated Research Summary (2026-09-13)

> **Final comprehensive synthesis:** Consolidates thelamer findings, bc250-vcn-research (Sept 6-11), agent research (Sept 13), and identifies actionable next steps.

---

## Current State: Three Sequential Gates Form a Pipeline

**CORRECTED from community cross-reference:** Gates are **dependent stages**, not independent blockers. Each must clear sequentially.

| Stage | Layer | Status | Blocker | Notes |
|-------|-------|--------|---------|-------|
| **Stage 1: PSP 0x6007 (Staging-Slot Walker)** | Firmware/PSP | Blocked | Host context has no write primitive | One byte gates LOAD_IP_FW acceptance |
| **Stage 2: KDB Usage-6 Key** | Firmware auth | **Solved (transient)** | — | Missing key worked around via Pico interposer; firmware authenticates cleanly |
| **Stage 3: Hardware Harvest Latch (0x1f81c)** | Hardware | **Current blocker** | Software-locked (not fuse-level) | PSP secure write fails; bootloader & SMU RPC paths untested |

**Pipeline dependency:** Stage 1 → Stage 2 → Stage 3. Must clear each sequentially to reach execution.

**Key correction:** Register 0x1f81c immutability is **proven only to one specific write path (PSP secure write)**. Other paths (bootloader, SMU RPC, alternate PSP code) remain unexplored.

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
  - **Caveat:** Source of 0x98 message ID needs verification (not documented in community reports; may be parallel research or firmware variant)
- ✅ SMU mailbox transport — no collisions with GPU governor
- ✅ PCI 0xB8/0xBC SMN access — functional, no auth required

### ❌ BLOCKED

**Stage 1 (PSP 0x6007):**
- ❌ Blocks firmware load via normal driver
- ❌ No host-context write primitive known

**Stage 3 (0x1f81c harvest latch) — CRITICAL HAZARD:**
- ⚠️ **Host-side read of 0x1f81c causes PHYSICAL BOARD HANG** (requires PSU power-cycle to recover)
- Safe workaround: Read 0x1f81c only from PSP context (returns successfully without hanging)
- ❌ PSP secure write fails (value stays 3)
- ❌ Register immutability proven only to this one write path; other paths untested

**Downstream (after stages 1-3 clear):**
- Clock/reset/isolation gates remain asserted
- VCPU never executes (PC stays at 0x00000000)
- Ring test hangs (decode ring not ready)

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
- SMU firmware has **VCN handlers (0x19, 0x1A)** but they are either:
  - Non-functional stubs that acknowledge but don't execute, OR
  - Missing prerequisites to operate (direct function call at 0x1EE90 hangs the SMU)
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

## Priority: Clear Stage 3 (0x1f81c Harvest Latch)

**Current blocker:** Register 0x1f81c controls VCN execution permission. Proven immutable via PSP secure write; other paths untested.

**Tested:**
- ❌ PSP secure write (fails, value stays 3)

**Untested write paths (high priority):**
1. **Bootloader-level access** — May have privilege to clear latch at boot time
2. **SMU RPC mechanism** — Possible SMU-side register write path
3. **Alternate PSP code paths** — Different PSP firmware entry points or debug modes

**After Stage 3 clears:** VCN clock sub-block may need L1 power-enable (unknown register address). This will require register state diff post-power-on to identify.

**Search for it:**
1. Extract BC-250 SMU firmware from BIOS
2. Run `smu_function_helper.py` to discover all functions
3. Trace `FUN_00024764` (power-down) → may reveal the L1 gating register
4. Cross-reference Van Gogh SMU firmware (if available) for comparison
5. Test candidate register via SMU 0x98 (if in always-on domain)

**If found:** Single `0x98` write to that register might wake the L1 layer, allowing subsequent clock register writes.

---

## Priority Research Paths

### HIGHEST PRIORITY: Discover Write Path to Clear 0x1f81c

**0x1f81c immutability is proven only to PSP secure write.** Other paths untested.

#### Path 1: Bootloader Analysis (0 Risk, Static)
**Time:** 1-2 hours  
**Goal:** Determine whether bootloader has authority to clear harvest latch
**Method:**
1. Extract BIOS → extract bootloader blob (PSPTool)
2. Disassemble with Ghidra (ARM or Xtensa depending on stage)
3. Search for writes to 0x1f81c or harvest-related code
4. Document if bootloader has clear authority

**Success:** Identifies bootloader write path (if exists)

#### Path 2: SMU RPC Exploration (Low Risk, Hardware)
**Time:** 2-3 hours  
**Goal:** Test whether SMU has a register-write path to 0x1f81c
**Method:**
1. Reverse-engineer SMU function `FUN_00024764` (teardown, touches slots 0x16/0x17/0x18)
2. Identify if it references or clears 0x1f81c
3. Test SMU-side power-down to see if harvest latch state changes

**Success:** Identifies SMU authority / function path

#### Path 3: PSP Debug Mode (Medium Risk, Hardware)
**Time:** 2-4 hours  
**Goal:** Test if PSP has alternate code paths (debug, production, attestation) that can write 0x1f81c
**Method:**
1. Document all PSP entry points in firmware (FET)
2. Identify any marked for debug/development
3. Test write via alternate entry point if available

**Success:** Discovers alternate PSP write path

---

### SECONDARY: SMU & Clock Analysis (for after Stage 3 clears)

#### Path 4: SMU Function Discovery (0 Risk, Passive)
**Time:** 30 minutes  
**Tools:** Ghidra + smu_function_helper.py  
**Goal:** Discover all VCN-related SMU functions

**Steps:**
1. Extract SMU firmware from BIOS
2. Open in Ghidra with Xtensa-LE
3. Run smu_function_helper.py
4. Trace `FUN_00024764` → `FUN_00023744` → `FUN_0002362c` chain

**Success metric:** Map all power-related functions; understand clock slot programming

#### Path 5: Register State Diff (Low Risk, Live Hardware)
**Time:** 1 hour  
**Goal:** After Stage 3 clears, identify which clock gates remain asserted

**Steps:**
1. Read control registers pre-power-on
2. Execute `FUN_00023b14(6, 1)` 
3. Read same registers post-power-on
4. Diff to identify which bits need clearing

**Registers:** `mmVCN_SOFT_RESET`, `mmVCN_CLOCK_GATING_DELAY`, `mmVCN_PGFSM_*`

**Success metric:** Identify next gate (soft reset vs isolation vs PGFSM)

#### Path 6: Van Gogh Cross-Reference (Medium Risk, Static)
**Time:** 2 hours  
**Goal:** Verify clock sequence against working platform

**Steps:**
1. Extract Van Gogh SMU firmware
2. Compare `smu_v13_0_vcn_enable()` kernel code (Linux)
3. Map Renoir register offsets to BC-250

**Success metric:** Confirm register offsets and sequence apply

---

## Integration Path Forward

### Phase 1: Unlock Stage 3 (0x1f81c Harvest Latch) — CRITICAL
**Execute Paths 1-3 in parallel (bootloader, SMU RPC, PSP debug modes)**
- Goal: Find **any** write path to clear 0x1f81c
- Expected outcome: Bootloader authority (highest probability) or SMU RPC
- Timeline: 2-4 days with parallel exploration
- **Blocker until Stage 3 clears:** Nothing downstream can execute

### Phase 2: Diagnosis After Stage 3 Clears
**Execute Path 5 (register state diff) + Path 4 (SMU function discovery)**
- Run register diff to identify which clock gates are asserted
- Discover all VCN functions in SMU firmware
- **Outcome:** Determines whether simple register writes suffice or complex SMU code needed

### Phase 3: Mitigation (Clock/Reset/Isolation Gates)
**If register diff shows soft reset or isolation gates asserted:**
- Attempt Renoir register sequence via SMU 0x98 writes
- May need L1 power-enable register discovery (unknown address)
- Risk: Low to medium (register writes in always-on domain)

**If clock sub-block remains unpowered after Stage 3:**
- Execute Path 6 (Van Gogh cross-reference) to verify register locations
- Or pursue SMU arbitrary code execution (high risk, requires firmware expertise)
- Or Pico interposer route for persistent SMU hook

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

| Element | Known? | Notes | Priority |
|---------|--------|-------|----------|
| VCN is present | ✅ Yes | IP discovery, harvest=0 | — |
| Domain 6 power path | ✅ Yes | FUN_00023b14(6,1) proven | — |
| 0x1f81c immutability | ⚠️ Partial | PSP secure write fails; other paths untested | **CRITICAL** |
| 0x1f81c write authority | ❌ Unknown | Bootloader? SMU? Alternate PSP? | **HIGHEST** |
| Clock register addresses | ✅ Yes | Renoir reference, driver code | Secondary |
| L1 enable register address | ❌ Unknown | May not exist; only needed if Stage 3 clears | Secondary |
| Exact reset/isolation sequence | ⚠️ Partial | Renoir reference, may differ | Secondary |
| PGFSM usage on BC-250 | ❌ Unknown | Need register diff after Stage 3 clears | Secondary |
| Clock slot programming (0x16-18) | ❌ Unknown | Need FUN_00023744 analysis | Secondary |

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
