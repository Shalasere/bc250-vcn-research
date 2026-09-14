# BC-250 vs Subor Z+ PSP Directory Diff — HARDWARE_IP_CONFIG + IPDS Table (2026-09-14)

**Corrected 2026-09-14 (same day) after kernel-source cross-reference:** the
initial "smoking gun" reading was WRONG. The IPDS table in BC-250's
HARDWARE_IP_CONFIG explicitly declares VCN 2.0.3 as PRESENT and NOT
HARVESTED. HARDWARE_IP_CONFIG is not the veto mechanism. Details below.

First direct comparison of BC-250's PSP directory against the closest known
sibling silicon: **Subor Z+ (aka "Fireflight")**, a Chinese console using
what appears to be the same Cyan-Skillfish-family die. Both BIOS ROMs sourced
locally; psptool 3.6.

**Subor Z+ BIOS:** DA220103 (2018/2021 build)
`AGESA!V9 FireflightPI-FPX 0.0.1.0`
9,482,784 bytes.

**BC-250 BIOS:** stock 3.00
`AGESA!V9 RBNBDK-BL5 46.1.2.211126`
16,777,216 bytes.

## PSP L1 Directory Diff

| Entry Type | BC-250 (3.00) | Subor Z+ (DA220103) |
|---|---|---|
| AMD_PUBLIC_KEY (0x00) | (in L2/omitted) | YES |
| PSP_FW_BOOT_LOADER (0x01) | (in L2/omitted) | YES |
| PSP_FW_TRUSTED_OS (0x02) | YES | YES |
| PSP_NV_DATA (0x04) | (in L2/omitted) | YES |
| SMU_OFFCHIP_FW (0x08) | YES | YES |
| SEC_DBG_PUBLIC_KEY (0x09) | YES | YES |
| SOFT_FUSE_CHAIN_01 (0x0b) | (L2?) | YES (soft_fuse 0x1) |
| SMU_OFF_CHIP_FW_2 (0x12) | YES | YES |
| DEBUG_UNLOCK (0x13) | YES | YES |
| **HARDWARE_IP_CONFIG (0x20)** | **YES (0x650 bytes)** | **NO** |
| WRAPPED_IKEK (0x21) | (in L2/omitted) | YES |
| TOKEN_UNLOCK (0x22) | (in L2/omitted) | YES |
| SEC_GASKET (0x24) | YES | NO |
| DRIVER_ENTRIES (0x28) | YES | YES |
| ABL0-4 (0x30-0x34) | YES | YES |
| FW_XHCI (0x44) | YES | NO |
| TOS_SECURITY_POLICY (0x45) | YES | NO |
| UMC_FW (0x4f) | YES | NO |
| BL_PUBLIC_KEY (0x50) | YES | NO |
| TOS_PUBLIC_KEY (0x51) | YES | NO |

BC-250's L1 psptool run threw a ParseError on one entry and only fully walked
one $PSP directory; the raw ROM contains 6× `$PSP` and 5× `2PSP` magics,
implying additional L2 directories not shown here.

## HARDWARE_IP_CONFIG (type 0x20) — structure and full IP Discovery decode

### Payload layout

```
Offset  Size    Content
0x000   0x100   PSP entry header (RSA signature, $PS1 magic, GUID
                {2E4C7B53-70F4-4AFB-9ECE-D5D78D04A505}, size fields)
0x100   0x03c   Container header
                +0: 07 14 21 28   build stamp
                +8: ac 50 4c 04   0x044C50AC magic/ptr
                +c: 3c 00 dc 48   pointer field
                +10: 24 03 00 00  0x324 = IPDS section size
0x13c   0x324   IPDS section (see below)
0x510   0x100   trailing signature/hash
```

### IPDS section layout (offset 0x13c-0x460 of payload)

```
+0x000  "IPDS" magic
+0x004  02 00                    version 2
+0x006  24 03                    section size 0x324
+0x008  db 91 ed 60              timestamp 0x60ED91DB (2021-07-12 UTC)
+0x00c  01 00 00 00              flags/version
+0x010  8c 00 00 00              record area size hint 0x8c
+0x014  ... 0x40 bytes zero padding ...
+0x054  IP block records (variable length, ~37 records)
+0x324  "GC" subsection (Graphics Core config)
+0x388  "HARV" subsection (Harvesting - all zeros in stock BC-250)
+0x410  trailing signature
```

### IP block record format (v1 per kernel `discovery.h`)

```c
struct ip {
    uint16_t hw_id;
    uint8_t  number_instance;
    uint8_t  num_base_address;
    uint8_t  major;
    uint8_t  minor;
    uint8_t  revision;
    uint8_t  harvest:4;         /* + 4 reserved bits */
    uint32_t base_address[num_base_address];
};
```

Record size = 8 + 4 × num_base_address bytes.
Authoritative source: `drivers/gpu/drm/amd/include/discovery.h` +
`drivers/gpu/drm/amd/include/soc15_hw_ip.h` in the Linux kernel mainline.

### Complete BC-250 IPDS decode (37 records)

| offset (IPDS) | hw_id | Name | inst | nba | version | harvest | bases |
|--:|--:|---|--:|--:|--:|--:|---|
| 0x054 | 0x0e | ACP | 0 | 2 | 4.0.0 | 0 | 0x00480000, 0x02403800 |
| 0x064 | 0x23 | ATHUB | 0 | 2 | 2.0.3 | 0 | 0x00000c00, 0x02408c00 |
| 0x074 | 0x06 | CLKA | 0 | 2 | 11.0.1 | 0 | 0x00016c00, 0x02401800 |
| 0x084 | 0x06 | CLKA | 1 | 2 | 11.0.1 | 0 | 0x00016e00, 0x02401c00 |
| 0x094 | 0x06 | CLKA | 2 | 2 | 11.0.1 | 0 | 0x00017000, 0x02402000 |
| 0x0a4 | 0x2f | CLKB | 0 | 2 | 11.0.1 | 0 | 0x00017e00, 0x0240bc00 |
| 0x0b4 | 0x24 | DBGU_NBIO | 0 | 1 | 3.0.0 | 0 | 0x000001c0 |
| 0x0c0 | 0x2e | DF | 0 | 2 | 3.5.0 | 0 | 0x00007000, 0x0240b800 |
| 0x0d0 | 0x25 | DFX | 0 | 2 | 2.0.0 | 0 | 0x00000580, 0x02409400 |
| 0x0e0 | 0x31 | DFX_DAP | 0 | 3 | 2.0.0 | 0 | 0x000005a0, 0x00b80000, 0x0240c400 |
| 0x0f4 | 0x110 | DIO | 0 | 1 | 127.127.63 | 0 | 0x02404000 |
| 0x100 | 0x10f | DMU | 0 | 5 | 2.0.3 | 0 | 0x12, 0xc0, 0x34c0, 0x9000, 0x02403c00 |
| 0x11c | 0x05 | FUSE | 0 | 2 | 11.0.1 | 0 | 0x00017400, 0x02401400 |
| 0x12c | 0x0b | GC | 0 | 3 | 10.1.3 | 0 | 0x00001260, 0x0000a000, 0x02402c00 |
| 0x140 | 0x112 | DAZ | 0 | 2 | 127.127.63 | 0 | 0x004c0000, 0x02404800 |
| 0x150 | 0x29 | HDP | 0 | 2 | 5.0.1 | 0 | 0x00000f20, 0x0240a400 |
| 0x160 | 0x22 | MMHUB | 0 | 2 | 2.0.3 | 0 | 0x0001a000, 0x02408800 |
| 0x170 | 0xff | MP0 (PSP) | 0 | 5 | 11.0.8 | 0 | 0x00016000, 0x00dc0000, 0x00e00000, 0x00e40000, 0x0243fc00 |
| 0x18c | 0x01 | MP1 (SMU) | 0 | 5 | 11.0.8 | 0 | 0x00016000, 0x00dc0000, 0x00e00000, 0x00e40000, 0x0243fc00 |
| 0x1a8 | 0x00 | (L1IMU?) | 0 | 5 | 11.0.1 | 0 | 0x0001b800, 0x01440000, 0x01480000, 0x014c0000, 0x02411000 |
| 0x1c4 | 0x00 | (L1IMU?) | 1 | 5 | 11.0.1 | 0 | 0x0001ba00, 0x01500000, 0x01540000, 0x01580000, 0x02411400 |
| 0x1e0 | 0x6c | NBIF | 0 | 6 | 2.1.1 | 0 | 0x00000000, 0x14, 0xd20, 0x00010400, 0x0241b000, 0x04040000 |
| 0x200 | 0x28 | OSSSYS (IH) | 0 | 2 | 5.0.1 | 0 | 0x000010a0, 0x0240a000 |
| 0x210 | 0x46 | PCIE | 0 | 2 | 4.2.0 | 0 | 0x02411800, 0x04440000 |
| 0x220 | 0x50 | PCS | 0 | 2 | 3.6.0 | 0 | 0x02414000, 0x04680000 |
| 0x230 | 0x2a | SDMA0 | 0 | 3 | 5.0.1 | 0 | 0x00001260, 0x0000a000, 0x02402c00 |
| 0x244 | 0x2b | SDMA1 | 0 | 3 | 5.0.1 | 0 | 0x00001260, 0x0000a000, 0x02402c00 |
| 0x258 | 0x04 | SMUIO | 0 | 4 | 11.0.8 | 0 | 0x00016800, 0x00016a00, 0x00440000, 0x02401000 |
| 0x270 | 0x80 | SYSTEMHUB | 0 | 3 | 2.1.0 | 0 | 0x00000ea0, 0x00500000, 0x02420000 |
| 0x284 | 0x03 | THM | 0 | 2 | 11.0.1 | 0 | 0x00016600, 0x02400c00 |
| 0x294 | 0x96 | UMC | 0 | 2 | 8.1.1 | 0 | 0x00014000, 0x02425800 |
| 0x2a4 | 0x96 | UMC | 1 | 2 | 8.1.1 | 0 | 0x00054000, 0x02425c00 |
| 0x2b4 | 0xaa | USB | 0 | 2 | 4.5.0 | 0 | 0x0242a800, 0x05b00000 |
| 0x2c4 | 0xaa | USB | 1 | 2 | 4.5.0 | 0 | 0x0242ac00, 0x05b80000 |
| **0x2d4** | **0x0c** | **VCN (=UVD_HWID)** | **0** | **3** | **2.0.3** | **0** | **0x00007800, 0x00007E00, 0x02403000** |
| 0x2e8 | 0x2d | DBGU_IO | 0 | 1 | 3.0.0 | 0 | 0x000001e0 |
| 0x2f4 | 0x1c | L2IMU (IOMMU L2) | 0 | 5 | 0.0.0 | 0 | 0x00007dc0, 0x00900000, 0x02407000, 0x04fc0000, 0x055c0000 |
| 0x310 | 0x18 | IOHC (IO Hub) | 0 | 3 | 0.0.0 | 0 | 0x00010000, 0x02406000, 0x04ec0000 |

### The VCN record

```
Offset IPDS+0x2d4 (ROM 0x981d10):
  hw_id            = 0x000c (VCN, per kernel #define VCN_HWID UVD_HWID)
  number_instance  = 0
  num_base_address = 3
  major.minor.rev  = 2.0.3   ← EXACT match to BC-250 silicon
  harvest          = 0x0     ← NOT harvested
  base[0]          = 0x00007800  (MMIO aperture)
  base[1]          = 0x00007E00  (MMIO aperture)
  base[2]          = 0x02403000  (fabric slice)
```

**BC-250's PSP IP Discovery table explicitly declares VCN 2.0.3 as PRESENT
and NOT HARVESTED, with valid base addresses.** The IP Discovery
mechanism is NOT what disables VCN on this board.

## Corrected Interpretation

The initial "smoking gun" reading — that BC-250's presence of HARDWARE_IP_CONFIG
vs Subor Z+'s absence explained the VCN disable — is FALSE. IPDS is a hardware
INVENTORY table (which IPs exist and where they live in the address space),
not an enable/disable authority. All 37 records in BC-250's IPDS have
harvest=0. The HARV subsection at IPDS+0x388 is also all zeros. There is no
per-IP disable field being asserted here.

Subor Z+ ships no HARDWARE_IP_CONFIG entry, which just means its amdgpu
falls back to built-in per-SoC IP tables in `amdgpu_discovery.c`. Not a
disable difference.

## What WAS Learned (still novel)

1. **Independent silicon-level confirmation of VCN presence.** The PSP's own
   signed IP Discovery declares VCN 2.0.3 with harvest=0 on BC-250. This
   corroborates iter#13/iter#15's community finding "silicon has VCN, it's
   not fuse-harvested" from a completely independent source — the AMD signed
   PSP data itself.

2. **Exact VCN register-aperture base addresses:**
   - MMIO `0x7800`, `0x7E00`
   - SMN fabric `0x02403000`
   These are what any working VCN driver would use as base addresses. Useful
   for future patched-driver work.

3. **LIVE CONFIRMATION (post-session insmod test): the amdgpu_discovery blob
   read from /sys/kernel/debug/dri/0000:01:00.0/amdgpu_discovery is
   BYTE-FOR-BYTE IDENTICAL to the ROM's IPDS section.** PSP delivers the
   IP Discovery unchanged from the signed ROM template — no runtime harvest
   injection, no soft-fuse-based masking, no PSP synthesis. What amdgpu
   sees at runtime is exactly what's in the SPI flash. This CLOSES a
   potential source of uncertainty about whether PSP might apply harvest at
   runtime — it does not.

   Test method: loaded stock amdgpu.ko via `insmod` (bypasses the cmdline
   `modprobe.blacklist=amdgpu`), read amdgpu_discovery via `base64 -w0`,
   decoded and byte-compared against `BC250_3.00.ROM[0x981a3c:0x981d60]`.
   All 0x324 bytes identical. Live VCN record parsed exactly matches:
   `hw_id=0x000c, inst=0, num_ba=3, ver=2.0.3, harvest=0x0,
   bases=[0x7800, 0x7e00, 0x2403000]`.

4. **RETRACTED: initial claim that "SDMA1 is a parallel case to VCN".**
   SDMA1 (hw_id 0x2b) IS exposed at runtime. Stock amdgpu dmesg shows
   `ring sdma1 uses VM inv eng 13 on hub 0` — SDMA1's IP block is
   registered and functioning. It is NOT a parallel case to VCN. VCN is
   unique in being declared-present-in-IPDS but not registered by amdgpu,
   because the stock driver has a `case IP_VERSION(2, 0, 3): break;` in
   `amdgpu_discovery.c` that deliberately skips VCN 2.0.3.

4. **Two hw_id=0 records with 5 base addresses each** at IPDS+0x1a8 and
   +0x1c4. These are almost certainly L1IMU (IOMMU L1) instances — the
   kernel enum has L1IMU_HWID codes in 0x32-0x41 range that don't appear
   here, and these two records' base addresses (0x1440000/0x1480000/0x14c0000
   for inst 0; 0x1500000/0x1540000/0x1580000 for inst 1) are IOMMU-typical
   ranges. Cyan-Skillfish-specific encoding not in mainline kernel.

5. **DIO (0x110) and DAZ (0x112) have version 127.127.63** — sentinel/
   placeholder values (all bits set). Display blocks are declared but their
   version info is stubbed.

6. **The first BC-250 vs Subor Z+ PSP directory comparison** in any public
   record.

## What This RULES OUT

- HARDWARE_IP_CONFIG modification as a VCN-enable path
- Per-IP-record harvest byte as a VCN-enable target (already 0)
- HARV subsection modification as a VCN-enable target (already all-zero)
- Rukkus's model's "KDB usage-6 entry" theory as being the exclusive cause
  (Subor Z+ doesn't have a KDB entry either)

## Restated Veto Mechanism (per prior iter#15 + this session's data)

VCN is declared present at the IP Discovery layer. The disable mechanisms
that remain to be defeated:

1. **DF fabric present bit** (SMN `0x50d6c` bits[12:11]=0) — set by signed
   ABL at boot, locked by MboxBiosCmd 0x1B at PciEnumerationComplete.
   `FABRICKED`-style skip of 0x1B is the one in-scope lever identified in
   iter#20.

2. **CC_UVD_HARVESTING** (SMN `0x1f81c`) — reads 0x3 on hardware. Not
   writable via SMU authority (proven this session) or PSP secure write.
   Origin: signed PSP_BL boot code, not in IPDS.

3. **PSP `load_ip_fw` for VCN type 13** returns ITEM_NOT_FOUND because no
   VCN firmware entry exists in the PSP directory. Community's Sept 11
   remediation was firmware substitution; earlier session attempt via
   green_sardine_vcn.bin.xz hung the board on driver load.

The IPDS record for VCN with correct version and base addresses is the
FOUNDATION amdgpu would use to attach VCN — but even with amdgpu's stock
BC-250 case gated open, the actual power/clock/routing gates below IP
Discovery remain closed.

## Files

- BC-250 ROM: `bc250-research/firmware/BC250_3.00.ROM`
- Subor Z+ ROM: (session scratchpad)
- IPDS extractor script: (session scratchpad `reparse_ipds_correct.py`)
- BC-250 psptool output: (session scratchpad)
- Subor Z+ psptool output: (session scratchpad)

**Recorded:** 2026-09-14 (initial version + same-day correction after
kernel-source cross-reference)
