#!/usr/bin/env python3
"""APCB parser v3 - correct format based on verified group chain.

APCB Header (32 bytes):
  +0x00: 4B "APCB" magic
  +0x04: 2B version (0x0020)
  +0x06: 2B header_size (32)
  +0x08: 4B total_size
  +0x0C: 4B unique_apcb_instance
  +0x10: 1B checksum_byte (sum of all bytes = 0 when valid)
  +0x11-0x1F: reserved (zeros)

Group Header (16 bytes):
  +0x00: 4B ASCII signature ("UNKN", "PSPG", "DFG ", "MEMG", "FCHG", "CBSG")
  +0x04: 2B GroupId (0x0B07 for UNKN, 0x1701-0x1707 for others)
  +0x06: 2B header_size (always 16)
  +0x08: 4B instance_count
  +0x0C: 4B total_group_size (including this header)

Groups chain: next group at current_offset + total_group_size.
"""
import struct
import os

LIVE_APCB = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\live_apcb.bin"
INT_APCB = r"C:\Users\work.DESKTOP-SAM98TB\bc250-research\firmware\internal_apcb.bin"

GROUP_SIGS = {
    b"UNKN": "Unknown/Priority",
    b"PSPG": "PSP Group",
    b"DFG ": "Data Fabric Group",
    b"MEMG": "Memory Group",
    b"FCHG": "FCH Group",
    b"CBSG": "CBS Group (Boolean Tokens)",
}

GROUP_IDS = {
    0x0B07: "UNKN (priority/board mask)",
    0x1701: "CBS_CMN",
    0x1703: "CBS_DF",
    0x1704: "CBS_MEM",
    0x1706: "CBS_NBIO/FCH",
    0x1707: "CBS_BOOL",
}

def parse_apcb(data, label):
    print("=" * 70)
    print("=== {} APCB ({} bytes) ===".format(label, len(data)))

    # Header
    magic = data[:4]
    if magic != b"APCB":
        print("ERROR: Bad magic")
        return

    version = struct.unpack_from("<H", data, 4)[0]
    hdr_size = struct.unpack_from("<H", data, 6)[0]
    total_size = struct.unpack_from("<I", data, 8)[0]
    unique_id = struct.unpack_from("<I", data, 12)[0]
    checksum = data[16]
    cksum = sum(data[:total_size]) & 0xFF

    print("Header: version=0x{:04X} hdr_size={} total={} uid=0x{:08X} cksum=0x{:02X} ({})".format(
        version, hdr_size, total_size, unique_id, checksum,
        "VALID" if cksum == 0 else "INVALID sum=0x{:02X}".format(cksum)))

    # Parse groups
    off = hdr_size
    group_num = 0
    groups = []

    while off + 16 <= min(total_size, len(data)):
        sig = data[off:off+4]
        gid = struct.unpack_from("<H", data, off + 4)[0]
        ghdr_size = struct.unpack_from("<H", data, off + 6)[0]
        inst_count = struct.unpack_from("<I", data, off + 8)[0]
        group_total = struct.unpack_from("<I", data, off + 12)[0]

        sig_name = GROUP_SIGS.get(sig, sig.decode("ascii", errors="replace"))
        gid_name = GROUP_IDS.get(gid, "0x{:04X}".format(gid))

        data_size = group_total - 16 if group_total >= 16 else 0
        print("\nGroup {} @ +0x{:04X}: sig=\"{}\" gid={}  inst={} total={} data={}".format(
            group_num, off, sig.decode("ascii", errors="replace"), gid_name,
            inst_count, group_total, data_size))

        # Dump group data
        data_off = off + 16
        group_data = data[data_off:data_off + data_size] if data_size > 0 else b""

        if group_data:
            # First 64 bytes hex dump
            for i in range(0, min(64, len(group_data)), 16):
                hexb = ' '.join("{:02X}".format(group_data[i+j]) for j in range(min(16, len(group_data)-i)))
                ascii_str = ''.join(chr(group_data[i+j]) if 0x20 <= group_data[i+j] < 0x7F else '.'
                                   for j in range(min(16, len(group_data)-i)))
                print("  +{:04X}: {:48s} {}".format(data_off + i, hexb, ascii_str))
            if len(group_data) > 64:
                print("  ... ({} more bytes)".format(len(group_data) - 64))

        # Parse group-specific content
        if sig == b"UNKN":
            # UNKN group contains priority/board mask info
            if len(group_data) >= 4:
                print("  UNKN data interpretation:")
                # The first bytes seem to be: version(2B), pad(2B), then...
                # +0: 07 0B FF FF — version? flags?
                # +4: 6C 00 — data length 108?
                # +6: 01 02 03 00 00 00 00 — entries...
                pass

        elif sig in (b"PSPG", b"DFG ", b"MEMG", b"FCHG", b"CBSG"):
            # These contain type entries followed by token data
            # Within the group data, there may be sub-structures:
            # A type header or directly token entries

            # From the decompilation: FUN_0006804c loads the group data and then
            # accesses token entries at: base + 8 + (token_id - range_start) * 6
            # So the first 8 bytes are a sub-header, then 6-byte token entries follow

            if len(group_data) >= 8:
                sub_hdr = group_data[:8]
                print("  Sub-header: {}".format(sub_hdr.hex()))

                # Try to interpret as token entries (6 bytes each) after 8-byte sub-header
                token_data = group_data[8:]
                num_tokens = len(token_data) // 6
                remainder = len(token_data) % 6

                if num_tokens > 0:
                    print("  Token entries: {} (6 bytes each), {} remainder bytes".format(
                        num_tokens, remainder))

                    # Count non-default (non-FF) tokens
                    non_default = 0
                    for ti in range(num_tokens):
                        te = token_data[ti*6:ti*6+6]
                        if te != b'\xFF\xFF\xFF\xFF\xFF\xFF' and te != b'\x00\x00\x00\x00\x00\x00':
                            non_default += 1

                    print("  Non-default tokens: {} / {}".format(non_default, num_tokens))

                    # Show first 10 tokens and all non-default ones
                    shown = 0
                    for ti in range(num_tokens):
                        te = token_data[ti*6:ti*6+6]
                        is_default = (te == b'\xFF\xFF\xFF\xFF\xFF\xFF' or te == b'\x00\x00\x00\x00\x00\x00')

                        if ti < 5 or not is_default:
                            # Interpret token entry:
                            # From decompilation: byte[1] = value_size (1,2,4,8)
                            # byte[0] might be flags, remaining bytes = value
                            flags = te[0]
                            vsize = te[1]
                            if vsize in (1, 2, 4):
                                val = struct.unpack_from("<I", te, 2)[0] if vsize == 4 else \
                                      struct.unpack_from("<H", te, 2)[0] if vsize == 2 else te[2]
                                print("    Token[{:4d}]: flags=0x{:02X} size={} val=0x{:X} ({}) raw={}".format(
                                    ti, flags, vsize, val, val, te.hex()))
                            else:
                                print("    Token[{:4d}]: raw={} (size byte=0x{:02X})".format(
                                    ti, te.hex(), vsize))
                            shown += 1

                    if shown > 30:
                        print("    ... (showing {} of {})".format(shown, num_tokens))

        groups.append({
            'offset': off,
            'sig': sig,
            'gid': gid,
            'total': group_total,
            'data_size': data_size,
        })

        if group_total < 16:
            print("  WARNING: group_total ({}) < 16, stopping".format(group_total))
            break

        off += group_total
        group_num += 1

        if group_num > 20:
            print("... (stopped at 20 groups)")
            break

    # Summary
    print("\n--- Summary ---")
    print("Groups: {}".format(len(groups)))
    total_used = sum(g['total'] for g in groups) + hdr_size
    print("Total used: {} / {} bytes".format(total_used, total_size))
    print("Slack space: {} bytes ({:.1f}% free)".format(
        total_size - total_used, (total_size - total_used) / total_size * 100))

    # Verify chain
    expected_end = hdr_size + sum(g['total'] for g in groups)
    print("Chain integrity: {} (expected end +0x{:X}, actual total 0x{:X})".format(
        "OK" if expected_end <= total_size else "OVERFLOW!",
        expected_end, total_size))

# Parse both
for label, path in [("LIVE", LIVE_APCB), ("INTERNAL", INT_APCB)]:
    if os.path.exists(path):
        with open(path, "rb") as f:
            data = f.read()
        parse_apcb(data, label)
        print()
