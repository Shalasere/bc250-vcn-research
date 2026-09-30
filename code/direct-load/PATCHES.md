# Direct-load VCN patches for `linux-cachyos-bc250` v7.2.7

Adds a driver-side path to load VCN 2.0 firmware directly (no PSP `LOAD_IP_FW` call), which sidesteps the BC-250's `TEE_ERROR_ITEM_NOT_FOUND` wall for VCN firmware.

## What this does NOT do

This patch series **does not** enable VCN decode/encode on BC-250. It removes the driver-side wall (PSP fw-load fails) and lets `amdgpu` load fully with VCN in the IP block list. The **VCN hardware** still doesn't respond because SMU has not powered up the VCN clock domain (the `PowerUpVcn` handler at SMU msg `0x2A` is present but returns `REJECTED_PREREQ`). Without SMU-side unlock, any attempt to program VCN MMIO from Linux hangs the data fabric.

Use these patches as one of two building blocks — the other being an SMU-side unlock sequence, which as of 2026-09-30 has not been discovered from software.

## Requirements

- `linux-cachyos-bc250` sources at the shipped v7.2.7 (or compatible). AUR: `git clone https://aur.archlinux.org/linux-cachyos-bc250.git`.
- Board-specific patches from `patches/linux-cachyos-rc/` (18 shipped patches — apply first).
- Then apply the changes below.

## The changes

Five source files touched, plus one small `amdgpu_discovery.c` hunk.

1. **`drivers/gpu/drm/amd/amdgpu/amdgpu_drv.c`** — adds `MODULE_PARM_DESC` and `module_param_named` for a new `vcn_direct` module parameter (`int`, default `0`). Documented values:
   - `0` — off (default). Driver behaves as stock.
   - `1` — driver-side direct-load enabled. `bo_size` bumped, `memcpy` copies fw into BO, LMI programmed to point at BO, `amdgpu_vcn_setup_ucode` early-returns to skip PSP autoload registration.
   - `2` — `vcn_v2_0` `early_init`/`sw_init`/`hw_init` all no-op (VCN block enumerated but zero state written). Debug/isolation mode.
   - `3` — `early_init` normal; `sw_init` + `hw_init` no-op. Debug/isolation mode.
   - `5` — `sw_init` normal (with direct-load memcpy); `hw_init` no-op. Debug/isolation mode.
   - `6` — as `5` but also skip `amdgpu_ring_init` for `vcn_dec` / `vcn_enc[0,1]`. **This is the reliably-loading configuration.** Skips drm_sched registration for VCN rings (which deadlocks post-init if VCN hw isn't running).
   - `7` — as `6` but hw_init calls `vcn_v2_0_start` unmodified. Crashes on uninit ring state — do not use.
   - `8` — as `6` but hw_init calls `vcn_v2_0_start` and it early-returns after VCPU release + master interrupt enable (before RB register programming). Attempts to boot VCPU. Currently hangs on VCN MMIO because clock domain isn't up — see caveats above.

2. **`drivers/gpu/drm/amd/amdgpu/amdgpu.h`** — one line: `extern int amdgpu_vcn_direct;`.

3. **`drivers/gpu/drm/amd/amdgpu/amdgpu_vcn.c`**:
   - `bo_size` condition extended: `if (amdgpu_vcn_direct || load_type != PSP)` — so BO grows when direct-load requested.
   - After BO allocation and before `fw_shared` setup, memcpy the fw bytes when `vcn_direct` is set:
     ```c
     if (amdgpu_vcn_direct) {
         const struct common_firmware_header *hdr_dl = ...;
         unsigned int ucode_bytes = le32_to_cpu(hdr_dl->ucode_size_bytes);
         unsigned int ucode_offset = le32_to_cpu(hdr_dl->ucode_array_offset_bytes);
         dev_info(adev->dev, "VCN-DIRECT: copy fw inst=%d bytes=%u src_off=%u dst_off=%u bo_size=%lu\n", ...);
         memcpy((char *)cpu_addr + AMDGPU_UVD_FIRMWARE_OFFSET,
                fw->data + ucode_offset, ucode_bytes);
         dev_info(adev->dev, "VCN-DIRECT: fw copy complete\n");
     }
     ```
   - `amdgpu_vcn_setup_ucode` unconditional early-return with a `VCN-PROBE: skip PSP ucode registration` log line. Prevents VCN from being added to the PSP autoload list.
   - Include added: `#include "amdgpu_uvd.h"` for `AMDGPU_UVD_FIRMWARE_OFFSET`.

4. **`drivers/gpu/drm/amd/amdgpu/vcn_v2_0.c`**:
   - `mc_resume` condition changed from `if (adev->firmware.load_type == AMDGPU_FW_LOAD_PSP)` to `if (!amdgpu_vcn_direct && adev->firmware.load_type == AMDGPU_FW_LOAD_PSP)` — so `vcn_direct=1` takes the `!PSP` LMI-direct branch that programs `mmUVD_LMI_VCPU_CACHE_64BIT_BAR_{LOW,HIGH}` to `adev->vcn.inst[i].gpu_addr + offset` (our BO's GPU address) instead of the PSP TMR address.
   - Same guard added to `mc_resume_dpg_mode`'s equivalent branch.
   - `hw_init` gains logic to handle `vcn_direct != 0` — full `start()` runs when direct-load is on, otherwise stock behavior. For debug values 2/3/5/6/7/8 (introduced during bisection), see the module-param doc above.
   - `sw_init` skip-guards for `amdgpu_ring_init` calls when `vcn_direct >= 6` (drm_sched registration causes post-init deadlock if VCN hw isn't running).

5. **`drivers/gpu/drm/amd/amdgpu/amdgpu_discovery.c`** — single hunk. Change:
   ```c
   case IP_VERSION(2, 0, 3):
       break;
   ```
   to:
   ```c
   case IP_VERSION(2, 0, 3):
       amdgpu_device_ip_block_add(adev, &vcn_v2_0_ip_block);
       break;
   ```
   Without this, VCN is never enumerated on BC-250 (upstream's stock behavior for this SoC).

6. **`drivers/gpu/drm/amd/amdgpu/amdgpu_trace.h`** — one line changed to make out-of-tree module builds resolve the tracepoint header path:
   ```c
   #define TRACE_INCLUDE_PATH .
   ```
   (was `../../drivers/gpu/drm/amd/amdgpu`). Required for `make M=` builds against installed kernel-devel.

## Files in this directory

- `amdgpu_drv.c` — full modified file with the direct-load param
- `amdgpu.h` — the one-line addition
- `amdgpu_vcn.c` — full modified file
- `vcn_v2_0.c` — full modified file with mc_resume/hw_init/sw_init changes
- `amdgpu_discovery.hunk.patch` — the single 5-line unified diff for the discovery hunk
- `amdgpu_trace.h.hunk.patch` — the trace.h one-line change
- `wsl-build.sh` — WSL cross-build script (see below)

## Applying

```bash
# On WSL/Linux build host with the linux-cachyos-bc250 checkout at $KTREE
cd $KTREE/drivers/gpu/drm/amd/amdgpu
cp <this-dir>/amdgpu_drv.c amdgpu_drv.c
cp <this-dir>/amdgpu.h amdgpu.h
cp <this-dir>/amdgpu_vcn.c amdgpu_vcn.c
cp <this-dir>/vcn_v2_0.c vcn_v2_0.c
cp <this-dir>/amdgpu_trace.h amdgpu_trace.h
patch -p3 < <this-dir>/amdgpu_discovery.hunk.patch

# Then build (either on board or via WSL cross-build — see wsl-build.sh)
```

## Reproducing the working baseline (`vcn_direct=6`)

```bash
# On the BC-250 (after installing/copying the built amdgpu.ko somewhere accessible):
# 1) Configure a one-shot boot entry that blacklists amdgpu:
sudo cp /boot/loader/entries/bc250.conf /boot/loader/entries/bc250-noamdgpu.conf
sudo sed -i 's|^options .*|& modprobe.blacklist=amdgpu ignore_loglevel|' /boot/loader/entries/bc250-noamdgpu.conf
sudo sed -i 's|^title .*|title CachyOS BC-250 NOAMDGPU (oneshot)|' /boot/loader/entries/bc250-noamdgpu.conf
sudo bootctl set-oneshot bc250-noamdgpu.conf
sudo systemctl reboot

# 2) After board comes back (no amdgpu), load deps and our module:
for d in drm_kms_helper drm_client_lib drm_display_helper drm_ttm_helper amdxcp ttm \
         gpu-sched drm_exec i2c-algo-bit video drm_suballoc_helper drm_buddy cec \
         drm_panel_backlight_quirks; do sudo modprobe $d; done
sudo insmod /path/to/amdgpu.ko vcn_direct=6

# 3) Verify
lsmod | grep '^amdgpu'
ls -la /dev/dri/
sudo cat /sys/kernel/debug/dri/*/amdgpu_firmware_info | head -30
```

Expected: `amdgpu` loaded with 7 refs, `/dev/dri/card1` and `/dev/dri/renderD128` present, `firmware_info` shows VCE/UVD/VCN all `0x00000000` (unloaded via PSP — expected), MEC/MEC2/RLC/SDMA/SMC loaded via PSP normally.
