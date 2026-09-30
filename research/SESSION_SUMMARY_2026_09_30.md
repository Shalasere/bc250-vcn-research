# Session Summary 2026-09-29 / 2026-09-30

> **⚠️ Read `research/CORRECTIONS_2026_09_30.md` alongside this doc.** Post-writeup validation caught two issues: (a) the VCN firmware filename is `vcn_2_0_3.bin`, not `cyan_skillfish2_vcn.bin` (all inline references have been corrected); (b) the "Q0 == Q3 same mailbox" claim below is a terminology conflict — the mailbox at SMN 0x3B10A20/A80/A88 is NOT the amdgpu driver's Q0 (which uses MP1_SMN_C2PMSG_66/82/90). The functional finding — that the msg-ID handler table observed via 0x3B10A20 is the same table the community's Q3 catalog references — remains correct.

**Two-day session updating the enablement picture. Two independent tracks pursued: (1) driver-side firmware provisioning that sidesteps the PSP `LOAD_IP_FW` wall; (2) SMU-mailbox-side probing that confirms the "secure_access" block hypothesis with direct evidence.**

Neither track ends with a working VCN pipeline. Together they close out the software-only exploration for this specific board: the **PSP fw-load wall is genuinely bypassable** (proven end-to-end), but a **second wall — the SMU-side PowerUpVcn PREREQ lock — remains standing**, and that wall's unlock lives at BIOS-init time in a msg sequence we haven't extracted.

## TL;DR

1. **Direct-load driver-side capability is proven.** `amdgpu.ko` (patched) enumerates VCN 2.0 in the IP-block list, allocates a driver-managed BO, `memcpy`'s the 405,696-byte `vcn_2_0_3.bin` into the BO at `AMDGPU_UVD_FIRMWARE_OFFSET`, programs LMI VCPU_CACHE_64BIT_BAR to point at that BO, and never invokes `PSP LOAD_IP_FW(VCN)`. The `TEE_ERROR_ITEM_NOT_FOUND` wall is never hit because the PSP call is never made. Board loads amdgpu fully with this patch + `vcn_direct=1` (see caveats below).
2. **The SMU firmware DOES contain PowerUpVcn handlers.** Msg IDs 0x2A and 0x2B (PowerUpVcn on other AMD SMU variants) return `RESP=0xFD REJECTED_PREREQ` — not `0xFE UNKNOWN_CMD`. This upgrades the community's "secure_access block seems accessible if some flag is passed to SMU at boot from BIOS" hypothesis to confirmed fact: **the code is present, gated by an unmet prerequisite**.
3. **Same msg-ID handler table observed via two SMN mailbox address pairs.** Msgs 0x3E–0x50 sent to the SMU via SMN mailbox at 0x3B10A20/A80/A88 returned the same clock values (100/1200/1254/3500/1500 MHz, byte-exact) that prior community work documented for what they called the "Q3" mailbox. *(Terminology fix: the mailbox at SMN 0x3B10A20 is NOT the amdgpu driver's Q0, which uses `MP1_SMN_C2PMSG_66/82/90` — see `research/CORRECTIONS_2026_09_30.md`.)*
4. **The wedge that appeared to happen at `dm_hw_init` is actually caused by drm_sched ring registration.** Bisected via a series of `vcn_direct=N` gating variants. `amdgpu_ring_init` for `vcn_dec` / `vcn_enc[0,1]` deadlocks post-init when the underlying hardware isn't running. Everything else in `vcn_v2_0_sw_init` (BO alloc, fw load, IRQ registration, fw_shared setup) is safe. Netconsole UDP drops during dm's WARN cascade misled earlier interpretation.

## The direct-load track

The prior work in this repo (through 2026-09-20) concluded that runtime software-only paths were exhausted at the PSP wall — PSP would refuse to LOAD_IP_FW(VCN) with `0xFFFF0008 TEE_ERROR_ITEM_NOT_FOUND`, and no runtime TOCTOU path lets us modify the permission table.

**We took a different question**: instead of trying to make PSP load VCN firmware, what if the driver never asks PSP to do it, and does the load itself?

The upstream `amdgpu` driver has an `AMDGPU_FW_LOAD_DIRECT` code path (used on SoCs where PSP doesn't handle VCN fw). `vcn_v2_0_mc_resume` has a live `else` branch that programs the LMI VCPU cache windows to point at a driver-allocated BO instead of the PSP TMR. That code already exists in the tree — it just never runs on cyan_skillfish because the default `load_type` is `AMDGPU_FW_LOAD_PSP`.

**What we did**:
- Added a module param `amdgpu.vcn_direct=<int>` (default 0). When set to 1:
  - Grow the VCN VCPU BO to hold the firmware (`bo_size += ucode_size + 8`, page-aligned).
  - After `amdgpu_bo_create_kernel`, `memcpy` the firmware bytes from `adev->vcn.inst[i].fw->data + ucode_offset` to `cpu_addr + AMDGPU_UVD_FIRMWARE_OFFSET`.
  - In `amdgpu_vcn_setup_ucode`, early-return without registering VCN with the PSP autoload list.
  - In `vcn_v2_0_mc_resume`, take the `!PSP` LMI-direct branch so the LMI VCPU cache windows point at our BO's GPU address.
- Added the missing `amdgpu_device_ip_block_add(adev, &vcn_v2_0_ip_block)` in `amdgpu_discovery.c` for `case IP_VERSION(2, 0, 3)` (stock upstream leaves this as an empty `break;`, so VCN never enumerates on BC-250 without this hunk).

**What worked end-to-end** (netconsole-captured):
```
[VCN instance 0] Found VCN firmware Version ENC: 1.24 DEC: 8 VEP: 0 Revision: 13
VCN-DIRECT: copy fw inst=0 bytes=405696 src_off=256 dst_off=256 bo_size=1069056
VCN-DIRECT: fw copy complete
VCN-PROBE: skip PSP ucode registration for VCN inst 0
reserve 0x400000 from 0xf41f800000 for PSP TMR
smu fw version = 0x00580600 (88.6.0)
SMU is initialized successfully!
Display Core v3.2.384 initialized on DCN 2.0.1
kiq ring mec 2 pipe 1 q 0
...
Initialized amdgpu 3.64.0 for 0000:01:00.0 on minor 1
```

`/dev/dri/card1` and `/dev/dri/renderD128` present. `lsmod | grep amdgpu` shows 7 refs. Board stable.

**What still doesn't work**: the hardware never actually decodes anything. When we try to program VCN registers (`vcn_v2_0_start` → `vcn_v2_0_mc_resume` → LMI programming → VCPU release from reset), the VCN MMIO aperture appears to be clock-gated. Reads hang the data fabric. This is the second wall, discussed next.

## The SMU-side track: PowerUpVcn is present but PREREQ-locked

Prior work in this repo (via the `bc250-smu-unlock` queue-overflow exploit + `daveconde/bc250-vcn-enable`'s Q3 probing) reported that:

- The cyan_skillfish PPT ships only 11 documented msgs. None are `PowerUpVcn`.
- Direct `PowerUpVcn` msg IDs from other AMD SMU variants (0x09 Van Gogh, 0x2A smu_v11_0_7, 0x2B smu_v11_0) return varying results.
- A "secure_access" block (msgs 0x27, 0x2A, 0x2C-0x2F, 0x71/0x72 per community's `api_q3.py`) all return `PREREQ` — the note says "seems accessible if some flag is passed to SMU at boot from BIOS".

**We reproduced the sweep from Q0 via SMN and got direct evidence**:

- Baseline mailbox works: `TestMessage(0x01, arg=0xdeadbeef)` returns `resp=0x01, arg0=0xdeadbef0` (echo+1). `GetSmuVersion(0x02)` returns `arg0=0x00580600` (matches known 88.6.0).
- `PowerUpVcn(0x09)` — Van Gogh mapping — returns `resp=0xFE UNKNOWN_CMD`. **Not in this SMU firmware.**
- `PowerUpVcn(0x2A)` — smu_v11_0_7 mapping — returns `resp=0xFD REJECTED_PREREQ`. **Handler IS present in this SMU firmware, but locked.**
- `PowerUpVcn(0x2B)` — smu_v11_0 mapping — returns `resp=0xFD REJECTED_PREREQ`. **Same.**
- `GetEnabledSmuFeatures(0x3D)` returns `arg0=0x00000000` — SMU reports zero features enabled (which contradicts `amdgpu_pm_info`'s `0xffff...` stub — that's an unimplemented-sensor default, not real data).

**Confirmed**: the SMU firmware ships PowerUpVcn code at msg 0x2A/0x2B. It's not missing — it's gated. The community's guess about a BIOS-init flag is correct in spirit: **there's a prerequisite that the SBIOS/AGESA sets at boot, and this specific board's BIOS doesn't set it**. Boards where the community's "leaked script → garbage VCN frames" works must have a BIOS that does the unlock.

## Attempts to trigger the unlock (all unsuccessful)

- `EnableSmuFeatures(0x3C)` with args `0xFFFFFFFF`, `0x800` (FEATURE_VCN_DPM_BIT), `0x1`, `0x0000FFFF` — every attempt: `0x2A` still returns PREREQ.
- Various args (0/1/0xFF/hi-bit) sent directly to msg 0x2A — no change.
- Context msgs (`SetDriverTableVMID`, `SetCoreEnableMask`, `QueryActiveWgp`, `TransferTable`, `GetGfxFrequency`) followed by re-attempt of 0x2A — no change.
- Direct SMN writes to `PGFSM_CTRL @ 0x6d0f8` (VCN power gate control) with values `0x03` / `0xdeadbeef` — silently ignored. Register is host-write-locked (SMN fabric protects SMU-owned resources; only the SMU mailbox itself is host-writable).

## SMN 0x5d928 UVD-disable fuse observation

An interesting side finding: SMN address `0x5d928` — flagged externally as the UVD-disable fuse — reads as `0x000010C6` on this board. Bit 1 is set. AMD's own `vcn_1_0_sh_mask.h` defines `CC_UVD_HARVESTING__UVD_DISABLE__SHIFT = 0x1` (bit 1 mask `0x00000002L`) — same bit position.

If `0x5d928` is the SMN mirror of `CC_UVD_HARVESTING` (or a fuse-array shadow of the same fuse), then **this specific board might have the UVD_DISABLE fuse actually set**. That would neatly explain everything:
- Why the SMU firmware doesn't ship PowerUpVcn in its "normal" msg map (the msg exists at 0x2A but is PREREQ-locked, and the PREREQ is likely the fuse readback)
- Why the community's leaked script produces "garbage VCN frames" on OTHER boards (their fuse is CLEAR)
- Why every unlock attempt from software fails

Register `0x5d928` is definitively write-locked from host — attempts to change it are silently discarded. The neighboring `0x5d930` reads the same `0x10C6` value (mirror or paired JPEG fuse). Whether the register is true OTP or SMU-protected is inconclusive from probing alone.

**Bit-1-is-UVD_DISABLE is not proven for this specific SMN offset** — the interpretation is inferred from the standard AMD naming convention, and the register being write-locked is consistent with either interpretation. A cross-check with another BC-250 (with known working VCN) would resolve it.

## Q0 == Q3 discovery

The community's `api_q3.py` and this repo's prior work refer to a "Q3 mailbox" with msg IDs distinct from the driver's official Q0 map. The distinction is real at the transport level (different SMN address pairs for cmd/resp/arg), but **the underlying SMU firmware has one msg-ID space**. Msgs 0x40..0x46 sent via the Q0 mailbox return the same clock values (100/1200/1254/3500/1500 MHz) that prior work documented for the Q3 mailbox. Msgs 0x2A/0x2B return the same PREREQ code from either transport.

Practical consequence: any exploration or unlock attempt can use either transport interchangeably. The msg ID map is one table.

## What this leaves for the next attempt

- **BIOS static analysis** of the board's own ROM (`our_rom_backup.bin` or equivalent) to find AGESA / ABL / DXE code that writes to SMN `0x3B10A20` (SMU cmd register). The specific msg IDs written at boot are the unlock sequence. Once extracted, replay from Linux via SMN.
- **Cross-reference** the extracted sequence against thomas's BIOS-modded board (community-reported to see VCN registers responsive), if their BIOS dump becomes available.
- **Direct-load code itself** is complete and ready to use IF the SMU-side unlock is ever solved. It removes one of the two walls; nothing more needs to happen at the driver level to hand VCPU firmware.

## Session artifacts

- Direct-load driver patches: see `code/direct-load/` for the source files and `PATCHES.md` explaining how to apply them to `linux-cachyos-bc250` v7.2.7 to get the working `vcn_direct=1` module.
- WSL cross-build recipe: `code/direct-load/wsl-build.sh` — 65-second `amdgpu.ko` builds vs 10+ min on-board. Uses clang-20 + `libsframe.so.3`/`pahole` 1.32 rsync'd from the board (Ubuntu 24.04's own binutils 2.42 + pahole 1.25 are too old for CachyOS 7.2.7's build requirements).
- SMU-side probe scripts (Q0-mailbox SMN sends, msg 0x2A/0x2B PREREQ evidence): `code/smu-mailbox-probe/` — regenerated clean from scratch (do not reference tools under `/home/user/`).

## Reproducing the direct-load result (short version)

Requires: a BC-250 running `linux-cachyos-bc250` 7.2.7, kernel-devel headers, a WSL/Linux build host with clang 20, and a Pi-with-netconsole listener for probing.

1. Clone `aur/linux-cachyos-bc250`, apply patches from `code/direct-load/patches/` on top of the shipped 18 board-specific patches.
2. Build `amdgpu.ko` out-of-tree (`make -C /lib/modules/$(uname -r)/build M=<amdgpu-dir> LLVM=1 modules`).
3. Set up a boot-entry with `modprobe.blacklist=amdgpu ignore_loglevel`, arm one-shot via `bootctl set-oneshot`, reboot.
4. After boot (no amdgpu): `modprobe drm_kms_helper drm_client_lib drm_display_helper drm_ttm_helper amdxcp ttm gpu-sched drm_exec i2c-algo-bit video drm_suballoc_helper drm_buddy cec drm_panel_backlight_quirks && insmod <path>/amdgpu.ko vcn_direct=1`.
5. Observe `dmesg` for `VCN-DIRECT: copy fw`, `VCN-DIRECT: fw copy complete`, `Initialized amdgpu 3.64.0`.

The `vcn_direct=6` variant (skip drm_sched `amdgpu_ring_init` for VCN rings) is the reliably-loading configuration. `vcn_direct=1` also loads on a clean patch tree — the earlier "dm_hw_init wedge" turned out to be netconsole UDP-loss during a WARN cascade, actual hang was at later VCN hw_init trying to touch clock-gated MMIO. See `code/direct-load/PATCHES.md` for the full option map.
