# BC-250 VCN Enablement: Update Report (2026-09-09)

> **Update to `COMMUNITY_REPORT_2026_09_06.md`.** Three days after the last
> report, a different researcher independently ran the exact two tests it
> proposed (Hypothesis A + Hypothesis B) and produced a decisive result. This
> report records what changed and what the current-best blocker actually is.
>
> Contributor letters in this document (single-letter aliases, consistent
> within this doc only): **P** = the interposer-route researcher; **R** = the
> PSP static analyst. Tool names (`recon`, `PSPEmu`) are cited without their
> upstream account.

## Status: Root Blocker Is Not What We Thought

**TL;DR:** The 2026-09-06 report proposed four hypotheses (A, B, C, D). The
two highest-likelihood ones (A + B) were subsequently implemented and tested.
**Neither, alone or combined, is sufficient from host-side software.** The
same sequence executed from **PSP context** does work — proving the silicon
itself is fully functional. The actual binding blocker turns out to be closer
to Hypothesis D than the report weighted it: a **single-byte PSP boot-config
value** gates the entire `LOAD_IP_FW` path for VCN firmware.

---

## What Was Actually Proven Since 2026-09-06

### 1. Hypothesis A (Multi-Cycle PGFSM) — Insufficient Alone
```
Test:        Full PGFSM state machine replay, with polling, with slot
             reprogramming — the exact firmware behavior FUN_00023b14
             does that the host --direct-load didn't.
Executed:    By P, integrated into a patched amdgpu with BC250-* telemetry
Result:      Executed cleanly. Registers accepted the writes. But the VCN
             VCPU still fetches zero instructions. PC stays at 0x00000000
             through 10 reset attempts. decode ring test result=-110.
Conclusion:  Doing what the firmware does, from host context, is not enough.
             Something below the SMU sequencer is still refusing to route.
```

### 2. Hypothesis B (Cold-Reset Register 0x0900c004) — Insufficient Alone
```
Test:        Write 0x0900c004 = 1 to release VCN cold reset. Readback to
             confirm the write took.
Executed:    By P as part of a "TYPE13 replay" sequence of 8 register
             writes (0x0900c004, 0x0001f8a4/c4/c8/cc/d0/d4, 0x00020160)
             with readbacks. All accepted; all readbacks match writes
             EXCEPT the last (VCPU_CNTL 0x0ff20400 written, 0x0ff20000
             read back — the clock-gating enable bit doesn't stick).
Result:      Still hangs the same way. VCPU never runs.
Conclusion:  The cold-reset release IS necessary, but not sufficient. The
             fabric that would honor the clock-gating enable bit isn't
             actually clocking VCN, so the write partially takes effect
             but has no downstream consequence.
```

### 3. A + B Combined From PSP Context — WORKS
```
Test:        Same PGFSM sequence + cold-reset release, executed from
             inside a PSP hook (not from host amdgpu context).
Executed:    By P using a physical interposer on the J4004 header +
             hybrid P3/P5 BIOS + PSP hooks.
Result:      UVD_VERSION:
               Before hook:  0xDEADBEEF  (the "unpowered" sentinel)
               After hook:   0x0002001B  (the real VCN 2.0.3 version)
             PGFSM_STATUS:   0x00200000
             POWER_STATUS:   0x00000801
Conclusion:  The VCN 2.0.3 silicon is FULLY FUNCTIONAL. It can be
             powered up and its real register aperture exposed. What
             was walled from host-side was walled to the master, not
             to the operation.
```

---

## The Actual Binding Blocker

Static analysis of the PSP firmware (by R) has pinpointed the exact
instruction that blocks VCN's own firmware from loading via the standard
`LOAD_IP_FW` path (host command 6, fw_type 13):

- **Function:** `FUN_0000a030` at PSP address `0xa030` — the fw staging-slot walker
- **Instruction:** `svc #0x87` at PSP address `0xa06e`
- **Semantics:** `return ((u8)0x6007 == 0)` — a bare one-byte flag query
  against PSP kernel RAM at address `0x6007`
- **Walker acceptance:** `if (svc_0x87() == 0) ACCEPT; else if (row+0x8 == 13) ACCEPT; else ERROR 0x80000205`

On a working reference platform (Steam Deck), the byte at `0x6007` is
non-zero → svc returns 0 → walker accepts short-circuit → VCN firmware
loads cleanly.

On BC-250:
- Byte at `0x6007` is `0`
- The VCN-named staging row is registered with id `0x22` (34) instead of `13`
- Both walker conditions fail → returns `0x80000205` (ITEM_NOT_FOUND family)
- No VCN firmware ever loads via the driver path

The differentiation between VCN-enabled and VCN-disabled platforms at this
gate is **one byte of PSP boot config.** Not a fuse. Not a fabric lock. Not
a fundamental silicon block. One byte.

**Minimal exploit payload:** `strb any_nonzero, [0x6007]` from PSP kernel
context. Satisfies the walker regardless of the wrong row id.

**Missing primitive:** a PSP kernel-RAM write. All known host transports
wedge when reaching for that address.

---

## Revised Hypothesis Ranking

| # | Hypothesis (from 2026-09-06 report) | 2026-09-06 rating | 2026-09-09 verdict |
|---|-------------------------------------|-------------------|--------------------|
| A | Multi-cycle PGFSM state machine | HIGH | **Necessary, not sufficient.** From host context alone, doesn't produce working VCN. Firmware DOES do this; that observation was correct. |
| B | Cold-reset register 0x0900c004 | VERY HIGH | **Necessary, not sufficient.** Was worth trying; contributes to power-up but doesn't lift the aperture on its own. |
| C | Unknown isolation gate register | MEDIUM | Now less relevant. Nothing outside the observed set has surfaced during PSP-context experiments. |
| D | PSP-side isolation gate (out of scope) | LOW | **This turned out to be closer to correct than the ranking suggested.** The gate is PSP-side but the mechanism isn't "the PSP enforces a fabric lock" — it's "the PSP walker rejects the VCN staging row because one boot-config byte is wrong." |

Nothing about the 2026-09-06 report was wrong per se — the SMU-side proof
work stands, the sequencer state changes were real, the aperture-clamp
observation was real. What changed is that the "root gate BETWEEN SMU
sequencer and register file" turned out to require **a fourth register
master (PSP context) that wasn't in the tested set**, plus a **one-byte
config change** to make the driver-clean load path work.

---

## Current State of the Art

### Near-Term Shippable Result — Compute-Shader Video Acceleration
A completely separate approach ships working video encoding **today**,
without depending on VCN unlock:

- **What:** A VA-API driver that implements H.264 encoding via Vulkan
  compute shaders on the BC-250's RDNA 2 CUs, bypassing VCN silicon
  entirely.
- **Performance:** 1440p60 real-time in extended form. This is materially
  better than Sunshine's built-in software mode (which struggles at
  1080p30 on the same CPU).
- **Where:** Search for the `bc250-vcn-driver` project. The
  `approach1-compute-encoder` directory is the working path.
- **Codec limits:** H.264 Baseline (CAVLC). No CABAC, no HEVC, no AV1.
  These are fundamental parallelism limits of the codecs, not of the
  approach.
- **Recommended for:** anyone who wants game streaming to Sunshine /
  Moonlight / Steam Link / OBS today.

### Long-Term Path — Real VCN Unlock via PSP Route
- **Interposer-based BIOS mod (P):** Physical access to J4004 header
  with one lifted arm on the SPI chip. Hybrid P3/P5 BIOS + PSP hooks.
  Demonstrated `UVD_VERSION = 0x0002001B`. Currently blocked by a
  GFX-side KIQ ring init regression in the modified BIOS.
- **Static-analysis path (R):** Identified the exact 1-byte gate. The
  remaining research task is a PSP kernel-RAM write primitive to
  address `0x6007`. All known host transports currently wedge when
  reaching for it.
- **PSP tooling:** A `recon` firmware analysis toolkit and a `PSPEmu`
  fork with BC-250 extensions (FIQ delivery, host doorbell, memory
  watch, SMN aperture emulation) are now the current state of the art
  for BC-250 PSP work. Independent from this repo.

### Hardware Constraints That Bound Any Success
- **S3 suspend is impossible on this board** — GDDR6 self-refresh not
  supported by the SKU, and the PSU cannot switch VRMs to a standby
  rail. This is hardware, not firmware. Sleep/wake is not solvable
  regardless of VCN status.
- **Full-power kexec remains feasible.**

### Windows / MacOS
- Independent researcher working on PID rename (13FE → 13E9 → Navi Lite
  driver family). Test-signed rename installs but yields error 43 at
  the PEI enumeration layer. Work in progress.

---

## What Changed for Future Testers

### Do This
- **If you want video acceleration today:** try the compute-shader VA-API
  driver. Report bugs upstream.
- **If you're doing PSP-side RE:** start from the `recon` toolkit and the
  `PSPEmu` BC-250 fork. This repo's SMU-side artifacts are still valid
  reference material but do not lead the field for PSP work.
- **If you have physical access to J4004:** the interposer path is
  reproducible in principle from P's write-up (when P publishes the
  full flow). Coordinate before duplicating hardware setup.

### Don't Do This
- Don't re-run Test #1 (Cold-Reset) or Test #2 (State Machine) from the
  2026-09-06 report expecting them to unlock VCN from host context.
  P has already done both and the result is the log line
  `decode ring test result=-110`. They contribute to understanding but
  do not, alone or combined, produce working VCN.

---

## What This Repo Remains Authoritative For

- Board-verified evidence that VCN 2.0.3 silicon is present, not
  fuse-harvested (`ip_discovery` with `harvest=0x0`)
- L0/L1 wall verification from **three** external SMN masters (the
  fourth master — PSP context — was out of scope and is where the
  broader-scope work has now succeeded)
- `robin_1` vs Van Gogh SMU message-table diff (VCN messages absent on
  `robin_1`)
- The two-address-view model (`mm = smn + 0x01100000`)
- VCN clock register map (SMN-offset form)
- DFS divider encoding (board-verified on gfx clocks)
- `0x50d6c` bits[12:11] semantics (via `FUN_0002bf30` Van Gogh disasm)
- The 25-iteration exhaustion log

None of the above is invalidated. What's invalidated is the closing verdict
scope: not "impossible" but "not achievable by host-side software on a
stock board." The broader scope (physical interposer + PSP context) exists
and has produced working VCN register reads.

---

## Files Ready for Community

- `research/COMMUNITY_REPORT_2026_09_06.md` — the previous report (now marked
  updated at its top); the SMU-side proof work in it remains valid
- `research/EXHAUSTION_LOG.md` — the full 25-iteration history that led up
  to it; still useful reference for how the SMU-side conclusions were reached
- `research/GHIDRA_ANALYSIS_GUIDE.md` — decompilation walkthrough for anyone
  wanting to independently verify the `FUN_00023b14` static analysis; note
  that the follow-up question the guide poses (which hypothesis is correct)
  has been substantially answered by this update

---

## Conclusion

**Three days ago the report said "not impossible, and here are four
hypotheses." Three days later, two of those hypotheses were tested by
another researcher, both were shown insufficient from host-side, and both
turned out to work from PSP context.** The silicon is functional. The
mechanism is understood down to a single byte of PSP boot config. The
remaining research task is a specific write primitive to a specific
address.

Meanwhile, a parallel effort produced working 1440p60 video encode via
GPU compute shaders that doesn't need any of this to be solved. That's
the immediate community win. VCN unlock is a longer game — closer than
we thought, but still gated on PSP-side work.

---

**Reported:** 2026-09-09  
**Next milestone:** a PSP kernel-RAM write primitive to `0x6007`; or a
BIOS-side fix to the GFX-KIQ regression in P's current build  
**Status:** Silicon proven functional; blocking mechanism identified; near-term
video-acceleration alternative shipping

---

## Addendum: Direct SMU message probe on stock robin_1 (2026-09-09, later)

After publishing the above, this repo's author ran a direct SMU probe on their
own stock BC-250 board (BIOS P3.00, SMU robin_1 v0.58.6.0) using the
`bc250-smu-unlock` mailbox API. Two findings that **partially contradict this
repo's earlier work**, followed by a "not the missing lever" negative result.

### Finding: Q3 handlers 0x19 and 0x1A DO exist on robin_1

`BC250_VCN_FINDINGS.md` earlier stated the robin_1 SMU has "zero VCN / VCLK /
DCLK / PowerUpVcn / JPEG" messages in its 338-message table. Direct probe:

```
Q0 msg 0x02 GetSmuVersion        -> status=0x01(OK) arg0=0x00580600  (v0.58.6.0)
Q0 msg 0x3D GetEnabledFeatures   -> status=0x01(OK) arg0=0xDD602C7D
Q3 msg 0x18 (safety)             -> status=0x01(OK) arg0=0x00000000
Q3 msg 0x19 (claim: PowerUpVcn)  -> status=0x01(OK) arg0=0x00000001
Q3 msg 0x19 arg=0                -> status=0x01(OK) arg0=0x00000000
Q3 msg 0x1A (claim: PowerDownVcn)-> status=0x01(OK) arg0=0x00000000
```

Status codes: `0x01=OK, 0xFE=UNKNOWN_CMD, 0xFF=FAILED`. All three Q3 messages
returned `OK`, not `UNKNOWN_CMD`. **The handlers exist.** This repo's earlier
message-table enumeration missed them.

The GetEnabledFeatures bitmask `0xDD602C7D` has bit 11 (VCN DPM per the
community's convention) SET.

### Finding: msg 0x19 arg=1 does not power up VCN by itself

Second probe, with strict "no VCN MMIO access" discipline (previous probe
hung the board, requiring physical power-cycle). Read the safe/documented
SMN registers before and after `Q3 msg 0x19 arg=1`, and inspect the
kernel's own PM view.

```
                                Before        After
  0x0050d6c (DF fabric-present)  0x000000F0   0x000000F0   (unchanged)
  0x0116f200 (clock-IP enable)   0x00000000   0x00000000   (unchanged)
  0x0115a820 (gfx clock sanity)  0x48140880   0x48140880   (unchanged)
  Features mask (Q0 0x3D)        0xDD602C7D   0xDD602C7D   (unchanged)
  amdgpu_pm_info VCN state       —            "Powered down"
```

**Nothing visible changed.** The handler exists and returns OK, but the DF
fabric-present bit stays `0xf0`, the clock-IP enable stays 0, the feature
mask is untouched, and the kernel driver still reports VCN as powered down.

### What this means

- The community claim "0x19 = PowerUpVcn (Xtensa addr 0x1E5B0)" is either
  wrong about what 0x19 does, or the handler is a stub that acknowledges
  the message without executing the tile power sequence.
- **Sending msg 0x19 alone is NOT the missing lever.** Anyone running
  `bc250-smu-unlock` today can send it and observe the same no-op result.
- The board-wedge that followed the previous probe was almost certainly
  caused by the SEQUENCE of `0x19 arg=1` then `0x19 arg=0` then `0x1A`,
  not by `0x19 arg=1` in isolation.
- The right next step is not another blind message probe. It's finding
  which SMU function actually performs the tile-power sequence
  (`power_gate_tile(3)`/`(4)` at Xtensa 0x1EE90 per the VCPU-state
  analysis), and calling THAT via the code-execution primitive rather than
  the standard mailbox.

### Correction to publish

The 2026-08 `BC250_VCN_FINDINGS.md` claim of "zero VCN messages in the
robin_1 message table" needs correction: at minimum handlers at Q3 0x19
and Q3 0x1A exist and return OK. Whether they *do* anything is a separate
question the observation above tentatively answers "no, not on their own."

### Second probe: unlock + patch + direct SRAM 0xCCB8 read (2026-09-09)

Same board, second probe. This one ran `unlock.py` and `patcher.py` to
gain arbitrary SMU-local memory access, then read PSP-side data
directly. Two findings, then a self-inflicted SMU wedge.

**Exploit chain works cleanly on stock robin_1 (BIOS P3.00).** Unlock
succeeded (`dbg unlocked; SMU still alive (this was a triumph..)`),
patcher applied all 60 patch sites cleanly (none previously applied).

**Direct read of SRAM address 0xCCB8 (the community-cited "feature mask"
address, per the VCPU-STATE-LOADING analysis).**

```
  SRAM 0xCCB4..0xCCC0 = f0730200 243c0200 d8de0100
  SRAM 0xCCB8 (u32)   = 0x00023C24
    bit 11 (VCN DPM)  = 1  (SET)
```

Compare to what other sources report:
- Community VCPU-STATE-LOADING analysis: "feature mask at SRAM 0xCCB8
  reads 0x00000000 (all features disabled, firewalled from host write)"
- Q0 msg 0x3D `GetEnabledFeatures`: `0xDD602C7D` (bit 11 SET)
- Direct SRAM 0xCCB8: `0x00023C24` (bit 11 SET)

**All three sources disagree on the numeric value, but two of three agree
that bit 11 (VCN DPM) is SET on stock robin_1.** The community's claim
that VCN DPM is disabled and therefore `power_gate_tile(3)/(4)` are
never called is FALSIFIED by direct SRAM readback on this board. The
"unpowered VCN tile due to feature gate" theory needs revisiting — the
feature mask says the feature IS enabled.

This does not automatically mean `vcn_power_sequence()` at Xtensa
0x1EE90 was ever actually called during boot — it just removes one of
the community's hypothesized reasons for why it wouldn't have been.

### Wedge (session author's error, for the record)

Before attempting `smu.call(0x1EE90)` (the target of the run), the
script also ran a "sanity" call: `smu.call(0x23744, 0x99)` intending to
invoke `FN_CLK_DOMAIN_UNGATE` with a "harmless unknown" clock slot
0x99. **This wedged the SMU** — 0x99 is not a valid slot, and the
function does not validate its argument. Post-wedge, the target call
never ran.

Lesson: `rpc_demo.py` uses slots 0x16/0x17/0x18 for a reason. Do not
invent arg values for these SMU internal functions without RE of the
handler.

Recovery: physical PSU unplug. ATX relay cycle alone did NOT recover.
5VSB rail keeps some SMU state alive across a soft power-off.

### Net for a community reader

- The community's stated blocker for VCN tile power (feature mask =
  0 at SRAM 0xCCB8) is not what the actual SRAM says on this board.
  If you're going down that path, verify on your own board first.
- The unlock + patcher chain works cleanly on stock robin_1 with
  BIOS P3.00 — good baseline for anyone attempting SMU-level VCN work.
- `FN_CLK_DOMAIN_UNGATE (0x23744)` does not validate arg. Don't call
  it with untested slot values.
- The target call `smu.call(0x1EE90)` was not exercised in this
  session because of the self-inflicted wedge. That test is still
  pending.
