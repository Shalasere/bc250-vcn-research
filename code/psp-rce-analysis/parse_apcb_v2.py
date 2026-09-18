#!/usr/bin/env python3
"""APCB parser v2 - based on Ghidra decompilation of FUN_0006804c.

From decompilation:
- APCB header: 32 bytes, starts with "APCB" magic
  +0x00: 4B "APCB"
  +0x04: 2B version
  +0x06: 2B header_size (0x20 = 32)
  +0x08: 4B total_size
  +0x0C: 4B unique_apcb_instance
  +0x10: 1B checksum_byte
  +0x11-0x1F: reserved/padding

- After header: group data blocks
  Each group block has:
  +0x00: 4B group_header (signature/info)
  +0x04: 2B group_id (e.g., 0x1701, 0x1702, ...)
  +0x06: 2B reserved
  +0x08: 4B group_size (total size including header)
  +0x0C: 4B reserved

  Within a group:
  - First 8 bytes after group header = group info (timestamp pointers?)
  - Then token entries, each 6 bytes:
    +0: 1B value_low_or_flags
    +1: 1B value_size_indicator (1=byte, 2=word, 4=dword, 8=qword)
    +2: 4B value (or 2B value + 2B reserved for smaller types)

From FUN_0006804c token lookup:
  token_entry_addr = group_data_base + 8 + (token_id - range_start) * 6
  value_size = *(byte*)(token_entry_addr + 1)

From the APCB type table parsing:
  - Type table entries are 4-byte packed:
    bits[20:8] = type_id (13 bits, 0x1FFF = end marker)
    bits[7:0] = flags/count
    bits[23:21] = additional field
"""
import struct
import os

ABL4_PATH = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_abl4_decompressed.bin"
LIVE_APCB = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\live_apcb.bin"
INT_APCB = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_apcb.bin"

# Known APCB group IDs from decompilation
GROUP_IDS = {
    0x1701: "CBS_CMN (Common CBS tokens, 1-0xFF)",
    0x1702: "CBS_DBG (Debug CBS tokens, 0x101-0x2FF)",
    0x1703: "CBS_DF (Data Fabric tokens, 0x301-0x6FF)",
    0x1704: "CBS_MEM (Memory tokens, 0x701-0x17FF)",
    0x1705: "CBS_GNB (GNB tokens, 0x1801-0x1BFF)",
    0x1706: "CBS_NBIO (NBIO tokens, 0x1C01-0x1FFE)",
    0x1707: "TOKEN_BOOL (Boolean token table)",
}

# Known APCB type IDs used in FUN_0006804c switch
APCB_TYPES = {
    0xA03C: "CBS_CMN_DATA",
    0xA03D: "CBS_DBG_DATA",
    0xA03E: "CBS_DF_DATA",
    0xA03F: "CBS_MEM_DATA",
    0xA040: "CBS_GNB_DATA",
    0xA041: "CBS_NBIO_DATA",
    0xA04D: "CBS_BOOL_DATA",
    0xA04E: "TOKEN_ALL_DATA",
}

def parse_apcb(data, label):
    """Parse an APCB binary blob."""
    print("=" * 60)
    print("=== {} APCB ({} bytes) ===".format(label, len(data)))

    if len(data) < 32:
        print("ERROR: Too small for APCB header")
        return

    # Header
    magic = data[:4]
    if magic != b"APCB":
        print("ERROR: Bad magic: {}".format(magic.hex()))
        return

    version = struct.unpack_from("<H", data, 4)[0]
    hdr_size = struct.unpack_from("<H", data, 6)[0]
    total_size = struct.unpack_from("<I", data, 8)[0]
    unique_id = struct.unpack_from("<I", data, 12)[0]
    checksum = data[16]

    print("Header:")
    print("  Magic: APCB")
    print("  Version: 0x{:04X}".format(version))
    print("  Header size: {} (0x{:X})".format(hdr_size, hdr_size))
    print("  Total size: {} (0x{:X})".format(total_size, total_size))
    print("  Unique ID: 0x{:08X}".format(unique_id))
    print("  Checksum byte: 0x{:02X}".format(checksum))

    # Verify checksum
    if total_size <= len(data):
        cksum = sum(data[:total_size]) & 0xFF
        print("  Checksum valid: {} (sum=0x{:02X})".format(
            "YES" if cksum == 0 else "NO", cksum))

    # Full header hex dump
    print("\n  Full header ({} bytes):".format(min(hdr_size, len(data))))
    for i in range(0, min(hdr_size, len(data)), 16):
        hexb = ' '.join("{:02X}".format(data[i+j]) for j in range(min(16, hdr_size-i)))
        print("    +{:04X}: {}".format(i, hexb))

    # After header: try AGESA APCB V2 group format
    # AGESA APCB V2 has a group header after the APCB header
    # The group header format is more complex than what we initially assumed

    # Let's try different interpretation: the data after header might start with
    # a group directory or directly with group data

    off = hdr_size
    print("\n  Data after header (first 128 bytes):")
    for i in range(0, min(128, total_size - hdr_size), 16):
        if off + i + 16 <= len(data):
            hexb = ' '.join("{:02X}".format(data[off+i+j]) for j in range(min(16, total_size - hdr_size - i)))
            ascii_str = ''.join(chr(data[off+i+j]) if 0x20 <= data[off+i+j] < 0x7F else '.'
                               for j in range(min(16, total_size - hdr_size - i)))
            print("    +{:04X}: {:48s} {}".format(off+i, hexb, ascii_str))

    # Try APCB V2 group header format
    # From AMD AGESA source (openSIL/AGESA):
    # APCB_GROUP_HEADER:
    #   UINT32 Signature;     // "APCB" for groups, or group-specific sig
    #   UINT16 GroupId;
    #   UINT16 Reserved;
    #   UINT32 SizeOfGroup;   // Including this header
    #   UINT32 Reserved2;
    # Total: 16 bytes

    # But also there might be a APCB_V3_HEADER format:
    # After APCB header, there's a priority/board mask word, then groups

    print("\n  === Trying APCB group parsing ===")

    # Method 1: Look for known GroupId values
    print("\n  Scanning for GroupId signatures:")
    for scan_off in range(hdr_size, min(total_size, len(data)) - 16, 4):
        # Check if bytes at scan_off+4..+5 contain a known GroupId
        if scan_off + 6 <= len(data):
            potential_gid = struct.unpack_from("<H", data, scan_off + 4)[0]
            if potential_gid in GROUP_IDS:
                sig = struct.unpack_from("<I", data, scan_off)[0]
                size = struct.unpack_from("<I", data, scan_off + 8)[0]
                rsv = struct.unpack_from("<I", data, scan_off + 12)[0]
                print("    +0x{:04X}: sig=0x{:08X} gid=0x{:04X}={} size={} rsv=0x{:08X}".format(
                    scan_off, sig, potential_gid, GROUP_IDS[potential_gid], size, rsv))

    # Method 2: Look for APCB type IDs (0xA03C-0xA04E)
    print("\n  Scanning for APCB Type IDs:")
    for scan_off in range(hdr_size, min(total_size, len(data)) - 4, 2):
        val = struct.unpack_from("<H", data, scan_off)[0]
        if val in APCB_TYPES:
            context = data[max(0,scan_off-4):scan_off+8].hex()
            print("    +0x{:04X}: TypeId 0x{:04X} = {} (context: {})".format(
                scan_off, val, APCB_TYPES[val], context))

    # Method 3: Try AGESA APCB V3 format — header has extra fields
    # V3 header is typically 0x20 bytes, followed by priority mask + board mask,
    # then group headers.
    # Let's check if the first group header starts at offset 0x28 or 0x30
    print("\n  Trying alternate group header offsets:")
    for try_off in [0x20, 0x24, 0x28, 0x2C, 0x30, 0x34, 0x38, 0x40]:
        if try_off + 16 <= len(data):
            # Check for known group signatures:
            # Group sig could be "APCG" or the groupId packed differently
            val16 = struct.unpack_from("<H", data, try_off + 4)[0]
            val32_0 = struct.unpack_from("<I", data, try_off)[0]
            val32_8 = struct.unpack_from("<I", data, try_off + 8)[0]
            # Check if this looks like a group header
            if val16 in GROUP_IDS or val32_0 in [0x50434247]:  # "GCBP" etc.
                print("    +0x{:02X}: MATCH sig=0x{:08X} gid=0x{:04X} size={}".format(
                    try_off, val32_0, val16, val32_8))
            # Also check if it looks reasonable (size < total_size, etc.)
            if 16 < val32_8 < total_size and val16 != 0:
                print("    +0x{:02X}: CANDIDATE sig=0x{:08X} fld4=0x{:04X} fld8={} fldC=0x{:X}".format(
                    try_off, val32_0, val16, val32_8,
                    struct.unpack_from("<I", data, try_off + 12)[0]))

    # Method 4: Walk based on the ACTUAL AGESA V2 format
    # Based on https://github.com/openSIL/AGESA source analysis:
    # After the 32-byte APCB header, the data is organized as:
    #   APCB_TYPE_HEADER (12 bytes):
    #     +0: UINT16 GroupId
    #     +2: UINT16 TypeId
    #     +4: UINT16 SizeOfType (including this header)
    #     +6: UINT16 InstanceId
    #     +8: UINT16 ContextType
    #     +A: UINT16 ContextFormat
    #   Then TypeSize - 12 bytes of data

    print("\n  === Trying APCB V2 Type Header format (12-byte headers) ===")
    off = hdr_size
    type_num = 0
    while off + 12 <= min(total_size, len(data)):
        gid = struct.unpack_from("<H", data, off)[0]
        tid = struct.unpack_from("<H", data, off + 2)[0]
        tsize = struct.unpack_from("<H", data, off + 4)[0]
        inst = struct.unpack_from("<H", data, off + 6)[0]
        ctx_type = struct.unpack_from("<H", data, off + 8)[0]
        ctx_fmt = struct.unpack_from("<H", data, off + 10)[0]

        # Validate: size should be reasonable and GroupId should be in expected range
        if tsize >= 12 and tsize <= total_size - off:
            gid_name = GROUP_IDS.get(gid, "?")
            tid_name = APCB_TYPES.get(tid, "?")
            print("  Type {:2d} @ +0x{:04X}: GroupId=0x{:04X}({}) TypeId=0x{:04X}({}) Size={} Instance={} CtxType={} CtxFmt={}".format(
                type_num, off, gid, gid_name[:15], tid, tid_name[:15], tsize, inst, ctx_type, ctx_fmt))

            # Dump first 48 bytes of type data
            data_off = off + 12
            if data_off < len(data):
                preview_len = min(48, tsize - 12, len(data) - data_off)
                hexb = data[data_off:data_off + preview_len].hex()
                print("    Data: {}{}".format(hexb[:96], "..." if len(hexb) > 96 else ""))

                # Check if this contains token data (6-byte entries)
                if gid in GROUP_IDS and tsize > 20:
                    data_body = data[data_off:data_off + tsize - 12]
                    # Try to interpret as token entries
                    num_tokens = (tsize - 12 - 8) // 6  # subtract 8-byte header
                    if num_tokens > 0 and num_tokens < 10000:
                        print("    Possible {} token entries (6 bytes each):".format(num_tokens))
                        for ti in range(min(5, num_tokens)):
                            te_off = 8 + ti * 6
                            if te_off + 6 <= len(data_body):
                                te = data_body[te_off:te_off+6]
                                print("      Token[{}]: {}".format(ti, te.hex()))

            off += tsize
            type_num += 1

            # Safety
            if type_num > 100:
                print("  ... (stopped at 100 types)")
                break
        else:
            # Not a valid header — check if we're in padding
            if data[off:off+4] == b'\xFF\xFF\xFF\xFF' or data[off:off+4] == b'\x00\x00\x00\x00':
                remaining = data[off:min(off+64, total_size)]
                if all(b == 0xFF for b in remaining) or all(b == 0 for b in remaining):
                    print("  Padding at +0x{:04X} to end".format(off))
                    break
            print("  Invalid header at +0x{:04X}: gid=0x{:04X} tid=0x{:04X} size={} (breaking)".format(
                off, gid, tid, tsize))
            # Try advancing by 4 to find next valid header
            found_next = False
            for scan in range(off + 2, min(off + 64, total_size), 2):
                sgid = struct.unpack_from("<H", data, scan)[0]
                stsize = struct.unpack_from("<H", data, scan + 4)[0] if scan + 6 <= len(data) else 0
                if sgid in GROUP_IDS and 12 < stsize < total_size:
                    print("  Recovered at +0x{:04X}".format(scan))
                    off = scan
                    found_next = True
                    break
            if not found_next:
                print("  Cannot recover, stopping.")
                break

    print("\n  Total types found: {}".format(type_num))

    # Final: show all non-FF, non-00 data regions
    print("\n  Data occupancy:")
    used_bytes = 0
    for i in range(total_size):
        if data[i] != 0xFF and data[i] != 0x00:
            used_bytes += 1
    print("  Used (non-0x00/0xFF): {} / {} bytes ({:.1f}%)".format(
        used_bytes, total_size, used_bytes / total_size * 100))

# Parse both APCBs
for label, path in [("LIVE", LIVE_APCB), ("INTERNAL", INT_APCB)]:
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
        parse_apcb(data, label)
    else:
        print("File not found: {}".format(path))
    print()
