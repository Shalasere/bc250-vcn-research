# BC-250 VCN Enablement: Update Report (2026-09-11)

> **Update to `COMMUNITY_REPORT_2026_09_09.md`.** Two days after that report,
> the same interposer-route researcher ran a register-level audit of the
> borrowed Navi10/Renoir firmware and, separately, a live probe of the
> harvest-fuse register the audit flagged as missing from the firmware's own
> code paths. A second contributor's question prompted the probe. This report
> also folds in a KDB (key database) authentication gap that the same
> researcher found and worked around — successfully, but without producing a
> running VCPU.
>
> Contributor letters (single-letter aliases, consistent with the 09-09
> report and kept stable across both): **P** = the interposer-route
> researcher; **R** = the PSP static analyst. Tool names (`codex`, `PSPEmu`,
> `recon`) are cited without their upstream account, same convention as
> before.

## Status: Two More Gates Characterized, VCPU Still Silent

**TL;DR:** P completed a register-level audit of the borrowed Navi10/Renoir
VCN firmware and found no evidence the firmware itself can clear BC-250's
harvest latch — the relevant register isn't referenced anywhere in the
blob. A live probe then confirmed that latch, `CC_UVD_HARVESTING` at MMIO
`0x1f81c`, reads `3` and **stays `3` through a PSP secure write of zero**,
verified by both a PSP-side readback and an independent host-side readback.
Separately, P identified and worked around a second, distinct gate: BC-250's
PSP key database (KDB) is missing the usage-6 VCN signing key that Steam
Deck has. A **transient** injection of that key via the Pico interposer (not
a persistent flash edit, which caused a no-POST) let the PSP cleanly
authenticate both the Navi10 firmware and, separately, the Van Gogh
(Steam Deck) firmware — status zero, valid TMR address, in both cases.
**The VCPU still never executes.** Fixing authentication did not fix the
harvest latch. These are two separate, independently-confirmed blockers,
not one.

---

## What Was Actually Proven Since 2026-09-09

### 1. Firmware Register Audit — No Internal Path Around the Harvest Latch
```
Scope:       Full register audit of the borrowed Navi10/Renoir VCN
             firmware blob (405,696 bytes — Navi10 and Renoir are
             byte-identical here; the files differ by one outer-header
             byte distinguishing VCN 2.0 vs 2.2).
Executed:    By P.
Result:      33 named VCN registers + 66 unresolved address-shaped values
             found in the blob. 13 of the named registers overlap the PS5
             init sequence, and every overlapping address agrees with the
             PS5 reference — no ABI mismatch between the borrowed firmware
             and BC-250's silicon.
Finding:     The harvest register, 0x1f81c, is NOT among the addresses the
             firmware touches.
Conclusion:  The firmware's register ABI is correct (strengthens the case
             that borrowing Navi10 firmware is the right approach), but it
             gives "no apparent way around the BC-250's latched
             UVD_DISABLE" (P's own words) — because the firmware never
             tries to touch that register at all. Whatever clears the
             harvest latch, it isn't something this firmware blob does on
             its own.
```

**Tooling limitation noted by P:** `PSPEmu` cannot dynamically trace this
blob — it emulates PSP ARM firmware, and this blob runs on the VCN VCPU
(Xtensa), a different processor. A real dynamic trace of this firmware
would need a VCN-specific emulator/disassembler, or a working-hardware
trace. This is a gap in current tooling, not a dead end — noted here so
nobody assumes `PSPEmu` already covers it.

### 2. Live Probe: `CC_UVD_HARVESTING` Confirmed Immutable via PSP Secure Write
```
Prompted by: R asking whether anyone had actually read the register's live
             value on hardware, rather than inferring it from the firmware
             audit alone.
Test:        Read/write CC_UVD_HARVESTING at MMIO 0x1f81c on a live BC-250
             (PCI 01:00.0), via an SSH-driven kernel probe.
Executed:    By P.
Result:      PSP secure read:              0x00000003
             PSP secure write of zero:     reported success
             Immediate PSP readback:       0x00000003
             Independent host readback:    0x00000003
Conclusion:  The write is acknowledged as successful by the PSP, but the
             value never actually changes — checked twice, from two
             different read paths. This is consistent with a fuse-style
             latch: the PSP's own secure-write path either silently
             no-ops against this address or the underlying store is
             genuinely write-protected below the PSP's own authority.
             Either way, this is not the same blocker as the 0x6007
             staging-slot-walker byte reported on 09-09 (see below).
```

### 3. KDB Usage-6 Key Gap — Found, Worked Around, Doesn't Fix the VCPU
```
Test:        Compare BC-250's PSP key database (KDB) against Steam Deck's.
Executed:    By P, comparing loading behavior against the Deck's TOS KDB
             (assisted by `codex` for structural comparison — tool cited,
             not a contributor).
Finding:     BC-250's TOS KDB contains only usages 10, 17, and 44. Steam
             Deck's TOS KDB has an authentic usage-6 key
             (c37290c310e64a62b027c56695492368) that BC-250 lacks. Firmware
             type 13 (VCN) maps to KDB usage 6 — so without that key
             record, the VCN firmware-load path has no matching signing
             key to authenticate against.
Attempt 1:   Appended the authentic usage-6 key record to the persistent
             flash KDB, updated its length fields and directory checksum.
             Could NOT regenerate the KDB's outer RSA signature (no
             private key access, as expected).
Result 1:    No-POST — immediate shutdown on power-on. Consistent with a
             signature or other early integrity check catching the
             tampered KDB, though the test can't distinguish exactly which
             check fired.
Attempt 2:   Avoided the persistent edit entirely. Injected the usage-6
             record TRANSIENTLY into the runtime KDB via the Pico
             interposer, leaving the flash image untouched.
Result 2:    P5 authenticated cleanly — status zero, valid TMR address —
             for the Navi10 type-13 firmware using the appended
             Cezanne/Navi usage-6 key. Repeated with the Steam Deck's own
             usage-6 key (70ec3e2d8a694792ac7969ff8ac9caca) against the
             matching Van Gogh type-13 firmware: also authenticated
             cleanly, status zero, valid TMR.
Conclusion:  The missing usage-6 key fully explains the original
             authentication failure for BOTH firmware candidates — this is
             a real, reproducible fix for that specific problem. But
             **neither authenticated firmware made the VCPU execute.**
             The remaining blocker is downstream of authentication:
             CC_UVD_HARVESTING at 0x1f81c stays 3, and (per Finding #2) not
             even a successful PSP secure write can move it.
```

---

## How This Fits the 09-09 Picture

The 09-09 report narrowed the binding blocker to a single PSP boot-config
byte at `0x6007`, gating the staging-slot walker's acceptance of the
`LOAD_IP_FW` command for fw_type 13. That finding is **not contradicted** by
this update — it's a different, earlier stage of the same pipeline. As best
understood now, there are at least three independent checks between "PSP
receives a VCN firmware-load request" and "VCPU actually runs code":

| Stage | Gate | Status as of this report |
|---|---|---|
| 1. Request acceptance | Staging-slot walker (`svc #0x87`, byte at PSP `0x6007`) | Reported 09-09: satisfiable by any non-zero write to `0x6007`, but no PSP kernel-RAM write primitive exists yet from host context |
| 2. Cryptographic authentication | KDB usage-6 signing key | **New, and separately solved**: transient KDB injection via physical interposer authenticates cleanly for both Navi10 and Van Gogh firmware |
| 3. Hardware harvest latch | `CC_UVD_HARVESTING` at `0x1f81c` | **New**: confirmed immutable via PSP secure write; no firmware code path touches it either |

Getting past stage 2 (this report) did not require solving stage 1 the same
way, because the KDB work was done via interposer, which sidesteps the
staging-slot walker's normal host-side path entirely. What this update
mainly changes is the **closing verdict for "what's left"**: it's no longer
just "one byte at 0x6007." Even with authentication clean, stage 3 is a
distinct, so-far-unmovable latch. Whether stage 3 is a real fuse, an
SMU-side lock, or something the PSP itself can clear through a path nobody
has found yet is still open.

---

## What This Repo Remains Authoritative For

Everything the 09-09 report listed as authoritative still stands. Added by
this update:
- Firmware-level confirmation (register audit) that the borrowed
  Navi10/Renoir VCN blob has no internal path to touch `0x1f81c`
- Live, twice-verified confirmation that `CC_UVD_HARVESTING` does not
  respond to a PSP secure write
- A working, reproducible method (transient KDB injection via physical
  interposer) for authenticating either Navi10 or Van Gogh type-13 VCN
  firmware against BC-250's PSP — useful to anyone continuing this line of
  work, so it doesn't need to be re-derived
- Confirmation that authentication succeeding is **not** sufficient — save
  effort by not treating "get authentication to pass" as the finish line

## What Changed for Future Testers

### Do This
- If continuing the interposer/KDB route: the transient-injection method
  works cleanly for both firmware candidates. Don't attempt a persistent
  flash KDB edit without a way to regenerate the outer RSA signature — it
  no-POSTs.
- If you have independent hardware access: an independent re-read of
  `CC_UVD_HARVESTING` on a different board would help rule out a
  board-specific fault versus a universal latch.

### Don't Do This
- Don't assume solving the `0x6007` walker byte (09-09) or the KDB key gap
  (this report) gets you a running VCPU on its own. Both are real,
  reproducible fixes for their specific problem, and neither is sufficient
  alone.
- Don't persistently modify the flash KDB without first solving outer
  signature regeneration — it's a confirmed no-POST.

### Hardware-risk note
Physical interposer work on this board carries real risk to the target
chip: this cycle's session lost a chip's CS pin during a routine interposer
lift (lifted fully rather than partially), plus incidental damage to an
adjacent filter pad. Neither is BC-250-specific, but worth restating for
anyone about to attempt physical modification: plan for the possibility of
losing the chip and have replacements sourced before starting.

---

## Files Ready for Community

- `research/COMMUNITY_REPORT_2026_09_09.md` — the previous update (now
  marked pointing forward to this one); its PSP-context findings and the
  `0x6007` walker analysis remain valid
- `research/COMMUNITY_REPORT_2026_09_06.md` — original SMU-side proof work,
  still valid as historical foundation
- `research/EXHAUSTION_LOG.md` — full iteration history

---

## Conclusion

**Authentication is no longer the blocker — for either firmware candidate,
it can be made to pass cleanly via a transient KDB key injection.** What
remains is a hardware-level harvest latch (`CC_UVD_HARVESTING = 3`) that
resists a PSP secure write, and which the firmware itself has no code path
to touch. That's a narrower, more specific problem than "authentication
fails," but it's not yet a solved one. The `0x6007` boundary-walker finding
from 09-09 and the KDB gap in this report look, at this point, like two
gates in a pipeline that both needed solving to get this far — with the
harvest latch as a third, currently-unsolved gate sitting downstream of
both.

---

**Reported:** 2026-09-11
**Next milestone:** find any write path — PSP-side or otherwise — that can
actually move `CC_UVD_HARVESTING` off `3`; alternatively, confirm on a
second board that the latch is universal rather than a fault on this one
**Status:** Authentication solved (two independent methods); hardware
harvest latch confirmed immutable via the one write path tried so far

---

## Addendum: `ip_discovery`'s "not harvested" verdict is not measuring what
## we thought, plus a confirmed hang on a plain register read (2026-09-11, later)

Same day, this repo's author checked two things directly on a stock board
(cross-referencing assisted by Claude for the static-analysis and
source-citation work — tool cited, not a contributor, same convention as
`codex` above).

### 1. Every single `harvest` field in `ip_discovery` reads `0x0` — not just VCN's

`EXHAUSTION_LOG.md` Iter #2 (2026-08-04) rules out the fuse-harvest
hypothesis on the strength of `ip_discovery` reporting `harvest=0x0` for
VCN (HWID 12). Every report since has cited this as settled.

Direct read on a stock BC-250 (`/sys/bus/pci/devices/0000:01:00.0/ip_discovery/die/0/*/*/harvest`):
**every single HWID in the table reads `0x0`** — VCN included (confirmed
major.minor.rev = `2.0.3`, matching "VCN 2.0.3" as used throughout this
project), with zero exceptions across ~35 entries. A table that reports
literally nothing as harvested, on a die that is demonstrably cut down in
other ways, is a red flag that the field itself isn't measuring anything on
this platform.

It isn't. The `cachenetics/recon` toolkit's static analysis of
`amdgpu_discovery.c` (its `discovery-harvest-audit.json`, dated 2026-05-21 —
predating this project's Discord thread) identifies the mechanism: BC-250
(the mining-card variant, PCI dev `0x13FE`) takes a **different code path**
than the PS5-devkit-like `CYAN_SKILLFISH2` variant. BC-250's path calls a
hardcoded `cyan_skillfish_reg_base_init()` and **never calls
`amdgpu_discovery_harvest_ip()` at all** — so `harvest_ip_mask` simply stays
at its zero-initialized default. It was never a live readout to begin with,
on this code path. We independently found real, upstream amd-gfx
mailing-list patch series titled "add support for cyan skillfish without IP
discovery" and "add ip offset support for cyan skillfish" (mail-archive.com
— a legitimate, canonical list mirror) that corroborate this two-path
split exists; we have not personally traced every cited line number in
`amdgpu_discovery.c`, so treat the exact line citations as recon's, not
independently confirmed by us line-for-line.

**This does not overturn "VCN is present and not IP-block-gated."** The
same recon data shows BC-250's actual harvest-equivalent mechanism —
omission from the hardcoded 13-IP-block table in
`cyan_skillfish_reg_init.c` — does NOT omit VCN/UVD either; it's one of the
IP blocks explicitly wired up. So the conclusion "VCN isn't blocked at the
IP-block level" still holds, just via different reasoning than Iter #2
gave. **What it does overturn is treating `ip_discovery`'s harvest field as
evidence about anything on BC-250** — good for Iter #2's actual subject
(VCN specifically), misleading if anyone extends the same "check
`ip_discovery`" method to a different IP block on this platform in the
future.

**What remains genuinely unexplained:** `CC_UVD_HARVESTING` at `0x1f81c`
is referenced by *neither* driver mechanism discussed here — not the
discovery-table path, not the hardcoded reg-base-init path. Nothing in
mainline amdgpu reads or acts on it for this chip. Its live value (`3`,
immutable per the finding earlier in this report) is a real hardware/fuse-
style signal that exists completely outside what the driver's own
IP-presence logic checks. That gap — a register the driver never looks at,
that nonetheless reads a fixed nonzero value — is still the open question.

### 2. A plain, read-only MMIO read of this same register hard-hung a stock board

Separately (not part of the same session as the audit above), a
completely standard, unmodified board — stock Fedora-based OS, stock
upstream `amdgpu.ko`, no interposer, no patched kernel, no PSP hooks — was
asked to read `CC_UVD_HARVESTING` at `0x1f81c` through the **mainline
kernel's own read-only debugfs register interface**
(`/sys/kernel/debug/dri/<minor>/amdgpu_regs`, a facility AMD's own driver
developers use for register debugging — not exploit tooling, not a write,
just a 4-byte read at a byte offset).

The read never returned. Within seconds, the board dropped off the network
entirely — SSH refused new connections, and ICMP came back
"destination host unreachable" from the router, meaning the NIC itself
was gone, not just the SSH daemon. A full physical power cycle (AC off,
not just a soft reset) was required to recover; the board came back up
clean with no lasting damage once power was restored (in this instance a
loose PSU connector added to the downtime, unrelated to the register read
itself).

This is a stronger result than the community's "experimental enable;
register access may hang" dmesg warning implies — that warning was written
for a *patched* kernel doing PSP-context probing. Here, the exact same
class of hang happened through completely stock tooling with **zero
third-party code involved**. **Treat `CC_UVD_HARVESTING` / `0x1f81c` as
unsafe to read at all from host context, on any kernel, until someone
understands why the read itself stalls the fabric** — this is now the
second independent report of this exact failure mode (the first being the
Discord thread's own "register access may hang" note), and the first with
a full reproduction and recovery procedure documented.

**For anyone continuing this:** if you need this register's value, get it
from PSP-context reads only (as the KDB/authentication work above already
does safely), never from a plain host MMIO read.
