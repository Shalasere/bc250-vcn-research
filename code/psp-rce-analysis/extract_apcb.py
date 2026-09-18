#!/usr/bin/env python3
"""Extract and analyze APCB data from the live BC-250 firmware.
APCB is at flash offset 0xAB1000, unsigned, checksum-only.
"""
import struct
import os

# Use the live dump first, then check internal BIOS too
LIVE_FW = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\BC250_live.bin"
INTERNAL_FW = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_p300\rom\P3.00.AMD\P3.00.AMD\P3.00.AMD.FD"
OUT_DIR = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware"

APCB_FLASH_OFFSET = 0xAB1000

# APCB header structure (from AGESA APCB spec):
# +0x00: 4 bytes "APCB" magic
# +0x04: 2 bytes version
# +0x06: 2 bytes header size
# +0x08: 4 bytes total size
# +0x0C: 4 bytes unique_apcb_instance (checksum is in the group headers)
# +0x10: 1 byte checksum byte
# ... more fields

for label, fw_path in [("LIVE", LIVE_FW), ("INTERNAL", INTERNAL_FW)]:
    if not os.path.exists(fw_path):
        print("{}: File not found: {}".format(label, fw_path))
        continue

    fw_size = os.path.getsize(fw_path)
    if APCB_FLASH_OFFSET >= fw_size:
        print("{}: APCB offset 0x{:X} beyond file size 0x{:X}".format(
            label, APCB_FLASH_OFFSET, fw_size))
        continue

    with open(fw_path, "rb") as f:
        f.seek(APCB_FLASH_OFFSET)
        # Read generous amount — APCB can be large
        apcb_raw = f.read(0x10000)  # 64KB should be enough

    print("=== {} APCB at flash 0x{:06X} ===".format(label, APCB_FLASH_OFFSET))
    print("First 64 bytes: {}".format(apcb_raw[:64].hex()))

    magic = apcb_raw[:4]
    print("Magic: {} (0x{:08X})".format(
        magic.decode("ascii", errors="replace"),
        struct.unpack_from("<I", apcb_raw, 0)[0]))

    if magic != b"APCB":
        # Try scanning nearby
        print("No APCB magic at offset, scanning +/- 0x1000...")
        found = False
        for delta in range(-0x1000, 0x1000, 4):
            off = APCB_FLASH_OFFSET + delta
            if off < 0 or off >= fw_size - 4:
                continue
            with open(fw_path, "rb") as f:
                f.seek(off)
                test = f.read(4)
            if test == b"APCB":
                print("  Found APCB at flash 0x{:06X} (delta {:+d})".format(off, delta))
                with open(fw_path, "rb") as f:
                    f.seek(off)
                    apcb_raw = f.read(0x10000)
                magic = apcb_raw[:4]
                APCB_FLASH_OFFSET = off
                found = True
                break
        if not found:
            # Check PSP directory for APCB entry (type 0x60)
            print("  Scanning PSP directory for type 0x60 (APCB_DATA)...")
            with open(fw_path, "rb") as f:
                f.seek(0x8E0000)
                psp_hdr = f.read(16)
            if psp_hdr[:4] == b"$PSP":
                num_entries = struct.unpack_from("<I", psp_hdr, 8)[0]
                with open(fw_path, "rb") as f:
                    f.seek(0x8E0000 + 16)
                    entries = f.read(min(num_entries, 64) * 16)
                for i in range(min(num_entries, 64)):
                    off = i * 16
                    w0 = struct.unpack_from("<I", entries, off)[0]
                    etype = w0 & 0xFF
                    if etype == 0x60:
                        esize = struct.unpack_from("<I", entries, off + 4)[0]
                        eaddr = struct.unpack_from("<I", entries, off + 8)[0]
                        if eaddr >= 0xFF000000:
                            fa = eaddr & 0x00FFFFFF
                        else:
                            fa = eaddr
                        print("  PSP dir entry #{}: APCB_DATA, size={}, flash 0x{:06X}".format(
                            i, esize, fa))
            continue

    if magic == b"APCB":
        # Parse APCB header
        version = struct.unpack_from("<H", apcb_raw, 4)[0]
        hdr_size = struct.unpack_from("<H", apcb_raw, 6)[0]
        total_size = struct.unpack_from("<I", apcb_raw, 8)[0]
        unique_id = struct.unpack_from("<I", apcb_raw, 12)[0]
        checksum = apcb_raw[16]

        print("  Version: 0x{:04X}".format(version))
        print("  Header size: {} bytes".format(hdr_size))
        print("  Total size: {} bytes (0x{:X})".format(total_size, total_size))
        print("  Unique ID: 0x{:08X}".format(unique_id))
        print("  Checksum byte: 0x{:02X}".format(checksum))

        # Verify checksum (8-bit additive over total_size bytes)
        if total_size <= len(apcb_raw):
            apcb_data = apcb_raw[:total_size]
            cksum = sum(apcb_data) & 0xFF
            print("  Computed checksum: 0x{:02X} ({})".format(
                cksum, "VALID" if cksum == 0 else "INVALID - sum should be 0"))

            # Save the full APCB
            out_path = os.path.join(OUT_DIR, "{}_apcb.bin".format(label.lower()))
            with open(out_path, "wb") as f:
                f.write(apcb_data)
            print("  Saved to: {} ({} bytes)".format(out_path, len(apcb_data)))

            # Parse group headers
            print("\n  === APCB Groups ===")
            off = hdr_size
            group_num = 0
            while off < total_size - 16:
                # Group header: 4 bytes sig, 2 bytes group_id, 2 bytes type_id, etc
                group_sig = struct.unpack_from("<I", apcb_data, off)[0]
                if group_sig == 0xFFFFFFFF or group_sig == 0:
                    print("  End of groups at offset 0x{:X}".format(off))
                    break

                group_id = struct.unpack_from("<H", apcb_data, off + 4)[0]
                type_id = struct.unpack_from("<H", apcb_data, off + 6)[0]
                group_size = struct.unpack_from("<I", apcb_data, off + 8)[0]

                print("  Group {:2d} @ +0x{:04X}: sig=0x{:08X} group=0x{:04X} type=0x{:04X} size={}".format(
                    group_num, off, group_sig, group_id, type_id, group_size))

                # Show first few bytes of group data
                data_start = off + 16  # after group header
                if data_start < total_size:
                    preview = apcb_data[data_start:data_start+32].hex()
                    print("    Data: {}...".format(preview))

                group_num += 1
                if group_size > 0 and group_size < total_size:
                    off += group_size
                else:
                    off += 16  # skip to next

                if group_num > 50:
                    print("  ... (truncated at 50 groups)")
                    break

            # Scan for slack space (0xFF bytes at end)
            slack_start = total_size
            for i in range(total_size - 1, 0, -1):
                if apcb_data[i] != 0xFF:
                    slack_start = i + 1
                    break
            used_size = slack_start
            slack_size = total_size - slack_start
            print("\n  Used size: {} bytes".format(used_size))
            print("  Slack space: {} bytes (0x{:X})".format(slack_size, slack_size))
            print("  Slack starts at: +0x{:X}".format(slack_start))
        else:
            print("  WARNING: total_size {} > available data {}".format(
                total_size, len(apcb_raw)))

    print()
