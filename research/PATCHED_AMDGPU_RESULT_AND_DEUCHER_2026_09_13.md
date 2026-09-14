# Patched amdgpu.ko Test + Deucher Statement (2026-09-13 late session)

Two decisive pieces of information landed in the same session that together
reframe the BC-250 VCN problem from "unlock a gate" to "architectural
infrastructure absent."

## 1. Patched amdgpu.ko Test — Definitive Failure Mode

A pre-built patched `amdgpu.ko` was found on the BC-250 at
`/var/lib/vcn-patch/amdgpu.ko` (dated 2026-09-07), with a matching modprobe.d
install rule and blacklist file. The patch's intent (from
`/etc/modprobe.d/amdgpu-vcn-patch.conf` comment): register the VCN 2.0.3 and
JPEG 2.0 IP blocks that stock amdgpu skips for Cyan Skillfish's
`IP_VERSION(2,0,3)` case (currently `break;`).

### Test setup
- Enabled `amdgpu-vcn-patch.service`
- Added kernel arg `modprobe.blacklist=amdgpu` via `rpm-ostree kargs`
- Rebooted so stock module wouldn't load first
- Manually insmod'd `/var/lib/vcn-patch/amdgpu.ko`

### Result

The patch works correctly at the IP-block registration level:

```
amdgpu: detected ip block number 8 <vcn_v2_0>    ← NEW: VCN now registered
amdgpu: detected ip block number 9 <jpeg_v2_0>   ← NEW: JPEG now registered
```

**But immediately after that:**

```
amdgpu 0000:01:00.0: Direct firmware load for amdgpu/vcn_2_0_3.bin failed with error -2
amdgpu 0000:01:00.0: amdgpu: early_init of IP block <vcn_v2_0> failed -19
amdgpu 0000:01:00.0: amdgpu: Fatal error during GPU init
amdgpu 0000:01:00.0: amdgpu: amdgpu: finishing device.
```

Error -2 = ENOENT (file not found). The kernel searched `/lib/firmware/amdgpu/vcn_2_0_3.bin` and it doesn't exist on the system.

Even if the file were provided from a borrowed Navi10/Renoir source (as the community's interposer work did), the PSP would refuse to authenticate it — see next section.

The failure is **not a bug in the patch** — the patch does exactly what its comment says. The failure is that **the rest of the BC-250 firmware stack doesn't support VCN.**

## 2. Alex Deucher (AMD) Statement — amd-gfx Mailing List

An amd-gfx list post from Alex Deucher (upstream amdgpu maintainer at AMD)
provides the authoritative architectural context:

- **SMU 11.8 PMFW on BC-250 has no VCN power management** (matches this
  session's own SMU handler-table decoding: zero VCN messages, no VCN tick
  handler, no VCN clock domains in the DFS tables)
- **VBIOS lacks VCN entries** (matches Iter #1 finding: no
  UVD/VCN/VCE/JPEG/Media strings in stock or modded BIOS)
- **PSP does not have signed VCN ucode for this SKU** (matches Sept 11
  community report: type-13 (VCN) firmware load returns `ITEM_NOT_FOUND`
  and requires a borrowed usage-6 KDB key + firmware to even attempt auth)

Deucher's framing: **VCN was never part of the BC-250 product definition.**
This is architectural absence, not a signature-defeat or unlock problem.

Source: https://ratatoskr.run/amd-gfx/2026/07/17347454/t

## 3. Synthesis — What the Wall Actually Is

The four converging pieces of evidence:

| Evidence | Layer | What it says |
|----------|-------|--------------|
| Patched amdgpu ENOENT for `vcn_2_0_3.bin` | Firmware image | No VCN firmware is packaged for this SKU |
| Community: type-13 fw load returns `ITEM_NOT_FOUND` on stock | PSP | No signed VCN ucode in the PSP's KDB |
| Community: KDB usage-6 key missing, injected via interposer | PSP auth | Even borrowed firmware needs added signing keys |
| Community: SMU has 0 VCN messages in 338-entry table | SMU firmware | No power/clock management code for VCN |
| Iter #1: Zero VCN strings in stock or modded BIOS | VBIOS | No init tables for VCN |
| Deucher: "never part of product definition" | Architecture | The above are all deliberate omissions |

VCN 2.0.3 silicon is present on the die (proven by IP discovery). Everything
above the silicon is missing. Making VCN work would require adding
infrastructure at **every one of these layers**:

1. Add VCN firmware image to `/lib/firmware/amdgpu/` (technically trivial —
   borrow `vcn_2_0_3.bin` from a Renoir/Van Gogh source)
2. Sign the borrowed VCN firmware with keys the BC-250 PSP trusts, OR add
   the signing keys to BC-250's PSP KDB (community's Sept 11 interposer
   work achieves this transiently)
3. Add VCN power/clock code to the SMU firmware — requires modifying the
   signed SMU image, which the PSP refuses to load if modified
4. Add VCN init tables to VBIOS

Layers 2 and 3 are gated by signature verification the community's project
scope explicitly excludes bypassing.

## 4. Verdict

**The BC-250 VCN activation problem is NOT solvable within the project's
constraints** (don't brick, don't defeat signatures, work with existing
infrastructure). The wall is not one gate but a complete absence of
provisioning at multiple firmware layers, each independently signed and
locked.

The community's Sept 2026 work is real progress on individual layers
(understanding the KDB gap, achieving SMU code execution via the Q2
queue-overflow exploit, transiently clearing the 0x1f81c latch investigation)
but no combination of accessible techniques can produce a running VCN VCPU
because required infrastructure fundamentally doesn't exist.

## 5. What Remains as Legitimate Paths (Outside This Project's Scope)

1. **PSP fault-injection modchip** (Somnacin/PicoModchip family) to defeat
   signature verification and allow modified SMU firmware with ported VCN
   code — has real brick risk, explicitly out of scope
2. **Full SMU RE + port of Van Gogh's VCN power code into a modified robin
   SMU firmware** — technically bounded but requires (1)
3. **Vulkan compute-shader video decode/encode as a stopgap** — already
   being pursued by other community members (simpmix, Shalasere)

## 6. Board State After Test

Test executed cleanly. Recovery:
- Unloaded failed patched module
- Reverted `modprobe.blacklist=amdgpu` via `rpm-ostree kargs --delete`
- Disabled `amdgpu-vcn-patch.service`
- Rebooted
- Stock amdgpu loaded normally, display working

The pre-built patched `amdgpu.ko` at `/var/lib/vcn-patch/` was left in place
in case someone wants to add the missing firmware file and re-test (though
per section 2 above, that path leads to a PSP auth failure).

---

**Recorded:** 2026-09-13 late session
**Board:** BC-250 @ 10.0.0.104, Bazzite-Deck OSTree deployment,
kernel 6.17.7-ba29.fc43.x86_64
