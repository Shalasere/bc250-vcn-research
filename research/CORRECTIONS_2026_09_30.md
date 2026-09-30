# Corrections & Enhancements — post-writeup validation pass

Ran a deeper re-validation of the 2026-09-30 writeup a few hours after the initial push. Findings below are additions/corrections that supersede specific claims. Everything else in `SESSION_SUMMARY_2026_09_30.md` remains accurate as validated.

## Correction 1: The VCN firmware filename is `vcn_2_0_3.bin`, not `cyan_skillfish2_vcn.bin`

The original writeup said the driver loads `cyan_skillfish2_vcn.bin`. That's **wrong**. Verified by reading the driver's actual naming logic in `amdgpu_ucode.c` (`amdgpu_ucode_ip_version_decode` for `UVD_HWIP`):
- `amdgpu_ucode_legacy_naming` for `UVD_HWIP` has **no case for cyan_skillfish** (unlike for GC / SDMA blocks, which do return `cyan_skillfish2` / `cyan_skillfish2_sdma` respectively).
- Falls through to the generic path: `snprintf(ucode_prefix, "vcn_%u_%u_%u", maj, min, rev)`.
- For VCN 2.0.3 that produces `vcn_2_0_3`, and the driver requests `amdgpu/vcn_2_0_3.bin`.

Verified on the running board: `/lib/firmware/amdgpu/vcn_2_0_3.bin` exists, 405,952 bytes (uncompressed, not `.bin.zst`). Our probe log's `VCN-DIRECT: copy fw inst=0 bytes=405696` matches this (the 405,952 file has a 256-byte `common_firmware_header`; `ucode_size_bytes` in the header reads 405,696 = 0x000630C0).

## Correction 2: `vcn_2_0_3.bin` is not in standard `linux-firmware`

The `linux-firmware` package (version 1:20260916-1 on this board) contains the cyan_skillfish2 family for GC and SDMA — `cyan_skillfish2_{ce,me,mec,mec2,pfp,rlc,sdma,sdma1}.bin.zst` — but **no VCN**. It also has `vcn_3_1_2.bin.zst`, `vcn_4_0_0` through `vcn_4_0_6`, `vcn_5_0_0`, etc., but **no `vcn_2_0_x`**.

The `vcn_2_0_3.bin` file on this board is manually placed (`pacman -Qo` reports "No package owns"). Anyone reproducing the direct-load setup will need to source this file independently — it's not shipped by any upstream package.

Where the file originally came from is unclear. Given the header magic and size, it's a genuine AMD VCN firmware image; possibly extracted from another AMD platform's driver / bundle. Community input on the canonical source would be useful.

## Correction 3: The "Q0 == Q3 same mailbox" claim is misleading

The original writeup said "Q0 and Q3 mailboxes are the same underlying SMU mailbox." That conflates two different labels:

- **The `amdgpu` driver's Q0** uses SMN offsets `mmMP1_SMN_C2PMSG_66/82/90` (relative offsets 0x282/0x292/0x29a dwords within the MP1 base). This is what `smu_v11_0_send_msg` calls.
- **The mailbox at SMN `0x3B10A20/A80/A88`** (which I called "Q0" in the writeup, matching the leaked-script terminology) is a **different pair of SMN addresses**. Whether it's a distinct mailbox, or the same mailbox aliased through a different SMN path, isn't fully resolved by the probing we did.

What IS true, and is the actionable finding: the mailbox at `0x3B10A20/A80/A88` accepts msg IDs beyond the driver's documented 22-msg map. Msgs 0x40–0x46 return the same clock values (100 / 1200 / 1254 / 3500 / 1500 / 0 / 3) that prior work (via what the community calls the "Q3" mailbox at SMN pair we didn't independently confirm) documented for those msg IDs. So the msg-ID space observed via this SMN pair and the community's "Q3" msg-ID space are the same handler table — either literally one mailbox with two SMN aliases, or two mailboxes wired to the same firmware dispatch.

Practical consequence unchanged: the mailbox at `0x3B10A20/A80/A88` is a working handle for any msg-ID we want to probe, and its handler responses are consistent with prior community work.

## Enhancement: extended fuse-region layout

Original writeup mentioned SMN `0x5d928 = 0x10C6` and `0x5d930 = 0x10C6` (mirror). A wider sweep (0x5d900–0x5d940) turned up a **third** occurrence:

| SMN | Value |
|---|---|
| 0x5d900–0x5d920 | 0x00000000 (all zeros, 33 bytes of padding) |
| 0x5d924 | 0x00000007 (3-bit mask — possibly a different-block HARVESTING register) |
| **0x5d928** | **0x000010C6** (UVD-disable fuse per user's tip; bit 1 set matches `CC_UVD_HARVESTING__UVD_DISABLE__SHIFT=0x1`) |
| 0x5d92C | 0x00000000 |
| **0x5d930** | **0x000010C6** (mirror) |
| 0x5d934, 0x5d938 | 0x00000000 |
| **0x5d93C** | **0x000010C6** (third mirror) |
| 0x5d940 | 0x00000000 |

Three copies at 0x5d928 / 0x5d930 / 0x5d93C, all identical. All three are host-write-locked (write attempts silently discarded, per the earlier write-battery test).

## Cross-check: prior repo history's `CC_UVD_HARVESTING = 3` is consistent

The 2026-09-11 report in this repo (`research/COMMUNITY_REPORT_2026_09_11.md`) recorded `CC_UVD_HARVESTING at 0x1f81c reads 3 and stays 3 through a PSP secure write`. Value 0x3 = binary 011 — **bit 1 is set there too**. So the fuse-disable inference has two independent runtime measurements on this same board pointing at the same bit:

- VCN MMIO `CC_UVD_HARVESTING` (0x1f81c) = 0x3 → bit 1 (UVD_DISABLE per AMD's mask def) set. [2026-09-11]
- SMN 0x5d928 (fuse mirror per external tip) = 0x10C6 → bit 1 set. [2026-09-30]

Two paths, two measurements, both consistent with **UVD_DISABLE set on this specific board's silicon**. The unlock for msg `0x2A/0x2B PowerUpVcn` (PREREQ) may itself be gated on this fuse state — which would mean the SMU firmware never intends to unlock VCN on boards where the fuse says disabled, regardless of BIOS-side msg sequences.

If that's right, the BIOS-msg-sequence unlock discussed in `SESSION_SUMMARY_2026_09_30.md` may only exist on boards where the fuse is CLEAR — which would be the boards where the community's leaked script actually produces frames.

## Confirmed unchanged (re-validated 2026-09-30 post-push)

Every specific runtime value in the writeup was re-read at least once and matches:

| Claim | Re-verified |
|---|---|
| `GetSmuVersion(0x02)` returns `arg0=0x00580600` | ✓ (still SMU 88.6.0) |
| `PowerUpVcn(0x2A)` returns `resp=0xFD REJECTED_PREREQ` | ✓ |
| `PowerUpVcn(0x2B)` returns `resp=0xFD REJECTED_PREREQ` | ✓ |
| `PowerUpVcn(0x09)` returns `resp=0xFE UNKNOWN_CMD` (Van Gogh mapping absent) | ✓ |
| `TestMessage(0x01, arg=0xdeadbeef)` returns `arg0=0xdeadbef0` (echo+1) | ✓ |
| SMN 0x5d928 = 0x10C6, SMN 0x6d0f8 (PGFSM_CTRL) = 0x2 | ✓ |
| msgs 0x40-0x46 return clocks 100/1200/1254/3500/1500/0/3 (MHz where applicable) | ✓ byte-exact |
| BO sizing math: 128 KB stack + 512 KB context = 640 KB baseline; +ucode → 1069056 bytes | ✓ (verified against `AMDGPU_VCN_STACK_SIZE`/`_CONTEXT_SIZE` constants in `amdgpu_vcn.h`) |
| Discovery hunk targets `IP_VERSION(2, 0, 3)` and adds `vcn_v2_0_ip_block` | ✓ applies cleanly to pristine 7.2.7 via `patch --dry-run -p1` |
| Direct-load code path is guarded on `amdgpu_vcn_direct`; `!amdgpu_vcn_direct && load_type == PSP` guard present in vcn_v2_0.c (3 occurrences: mc_resume, mc_resume_dpg_mode, hw_init) | ✓ |
