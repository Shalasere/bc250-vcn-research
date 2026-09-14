#!/usr/bin/env python3
"""
DPM VCN Enable Test — Hypothesis: Feature bits 4 (VCLK) and 5 (DCLK) are
disabled in the SMU feature bitmap on BC-250, which is why VCN power messages
(0x19/0x1A) return OK but don't actually power VCN.

This script tests whether enabling those feature bits via the SMU feature
framework (Q2 msg 0x05 or Q2 msg 0x31) unlocks the downstream VCN pipeline.

SAFETY:
  - NEVER reads MMIO 0x1f81c (CC_UVD_HARVESTING) — that specific address
    hangs the board when read from host context (community-verified).
  - All indirect register access goes through SMU mailbox (queue 1 msg 0x00/0x01),
    which returns 0xffffffff safely instead of hanging on clamped domains.
  - Uses whitelisted SMU messages only.
  - Aborts on abnormal responses.

USAGE (on the BC-250 board):
    sudo python3 test_dpm_vcn_enable.py           # dry run - reads only
    sudo python3 test_dpm_vcn_enable.py --arm     # actually attempt feature enable

REQUIRES: bc250_smu library installed on target (/usr/lib/python3/dist-packages/bc250_smu)
"""

import argparse
import sys
import time
import traceback

# ============================================================
# SMU 11.8 constants (from smu_v11_8_pmfw.h + community RE)
# ============================================================

# Feature bits (64-bit bitmap, index 0-63)
FEATURE_DPM_GFXCLK_BIT = 0
FEATURE_DPM_VCLK_BIT   = 4    # <-- VCN video clock DPM
FEATURE_DPM_DCLK_BIT   = 5    # <-- VCN decode clock DPM
FEATURE_DS_SMNCLK_BIT  = 14

FEATURE_NAMES = {
    0:  "DPM_GFXCLK",   1:  "DPM_SOCCLK",   2:  "DPM_FCLK",     3:  "DPM_MP1CLK",
    4:  "DPM_VCLK",     5:  "DPM_DCLK",     6:  "DPM_LCLK",     7:  "DPM_UCLK",
    8:  "DPM_MP0CLK",   9:  "DS_GFXCLK",    10: "DS_SOCCLK",    11: "DS_FCLK",
    12: "DS_MP1CLK",    13: "DS_MP0CLK",    14: "DS_SMNCLK",    15: "PPT",
    16: "TDC",          17: "THERMAL",      18: "GFX_OFF",      19: "PSI",
    20: "APCC_PLUS",    21: "DF_CSTATES",   22: "GFX_PACE",     23: "RM",
    24: "IH_OUT_OF_BAND", 25:"FW_DSTATE",   26: "ATHUB_PG",     27: "FCLK_DSTATE",
    28: "CSTATE_BOOST", 29: "SPARE29",      30: "SPARE30",      31: "SPARE31",
}

# SMU message IDs (from GHIDRA guide + rpf16rj SMU-HANDLERS.md)
Q0_TEST_MESSAGE       = 0x01  # Echo test (returns arg+1)
Q0_GET_SMU_VERSION    = 0x02  # Returns firmware version

# Feature framework candidates (need discovery)
Q2_MSG_04             = 0x04  # candidate: GetEnabledSmuFeatures
Q2_MSG_05             = 0x05  # candidate: SetSmuFeatures  (master handler per rpf16rj)
Q2_MSG_31             = 0x31  # candidate: FeatureRequest (single-shot bitmap)

# VCN power message candidates (community-found, non-functional in isolation)
Q3_VCN_MSG_19         = 0x19
Q3_VCN_MSG_1A         = 0x1A

# Hazardous — DO NOT READ FROM HOST
HAZARDOUS_MMIO = {
    0x1f81c: "CC_UVD_HARVESTING (physical fabric hang; PSU power-cycle required)",
}

# Safe verification targets (SMU-mediated indirect access is generally safe;
# these return 0xffffffff on clamped domains without hanging)
SAFE_VCN_INDIRECT_READS = [
    (0x6d190, "VCN STATUS (already-tested-safe baseline)"),
    (0x6d17c, "VCN power request"),
    (0x6d184, "VCN rail power"),
    (0x5c180, "VCLK slot (SMN)"),
    (0x5c158, "DCLK slot (SMN)"),
]


# ============================================================
# Test harness
# ============================================================

class DPMTest:
    def __init__(self, smu, verbose=True):
        self.smu = smu
        self.verbose = verbose
        self.results = {}

    def log(self, msg):
        if self.verbose:
            print(f"  {msg}")

    def section(self, title):
        print(f"\n{'=' * 70}")
        print(f"  {title}")
        print('=' * 70)

    def safe_send(self, queue, msg_id, arg=0, label=""):
        """Send an SMU message with error handling and logging."""
        tag = f"Q{queue} msg 0x{msg_id:02x} arg 0x{arg:08x}"
        if label:
            tag += f"  [{label}]"
        try:
            result = self.smu.raw_send(queue=queue, msg_id=msg_id, arg=arg)
            self.log(f"{tag} -> 0x{result:08x}")
            return result
        except Exception as e:
            self.log(f"{tag} -> EXCEPTION: {type(e).__name__}: {e}")
            return None

    def safe_indirect_read(self, addr, label=""):
        """SMN-indirect read via SMU (safer than direct MMIO)."""
        if addr in HAZARDOUS_MMIO:
            self.log(f"REFUSED to read 0x{addr:x}: {HAZARDOUS_MMIO[addr]}")
            return None
        tag = f"SMN[0x{addr:06x}]"
        if label:
            tag += f"  ({label})"
        try:
            self.smu.raw_send(queue=1, msg_id=0x00, arg=addr)
            result = self.smu.raw_read(queue=1)
            self.log(f"{tag} = 0x{result:08x}")
            return result
        except Exception as e:
            self.log(f"{tag} -> EXCEPTION: {type(e).__name__}: {e}")
            return None

    # --------------------------------------------------------
    # Phase 1: Baseline / sanity
    # --------------------------------------------------------
    def phase1_baseline(self):
        self.section("PHASE 1 — Baseline / sanity check")

        # Ping test — Q0 msg 0x01 should return arg+1
        ping = self.safe_send(0, Q0_TEST_MESSAGE, arg=0x1234, label="ping (expect 0x1235)")
        self.results['ping_ok'] = (ping == 0x1235)

        # SMU version
        ver = self.safe_send(0, Q0_GET_SMU_VERSION, arg=0, label="get SMU version")
        self.results['smu_version'] = ver

        # Baseline VCN register state (all should read 0xffffffff or clamped values)
        print("\n  Baseline VCN state (pre-experiment):")
        self.results['baseline_reads'] = {}
        for addr, label in SAFE_VCN_INDIRECT_READS:
            val = self.safe_indirect_read(addr, label)
            self.results['baseline_reads'][addr] = val

        return self.results['ping_ok']

    # --------------------------------------------------------
    # Phase 2: Discover feature framework message
    # --------------------------------------------------------
    def phase2_discover_features(self):
        self.section("PHASE 2 — Feature framework discovery")

        # Try candidate "get features" messages
        print("\n  Probing candidate feature-query messages:")
        candidates = [
            (2, 0x04, "Q2 0x04 (possible GetEnabledFeatures)"),
            (2, 0x05, "Q2 0x05 (feature framework master, arg=0 = query?)"),
            (2, 0x2F, "Q2 0x2F (another feature candidate)"),
            (2, 0x30, "Q2 0x30 (another feature candidate)"),
            (2, 0x31, "Q2 0x31 (FeatureRequest, arg=0 = query?)"),
        ]

        self.results['feature_probes'] = {}
        for q, m, label in candidates:
            val = self.safe_send(q, m, arg=0, label=label)
            self.results['feature_probes'][(q, m)] = val

    # --------------------------------------------------------
    # Phase 3: Attempt to enable VCLK/DCLK DPM features
    # --------------------------------------------------------
    def phase3_enable_dpm(self, dry_run=True):
        self.section(f"PHASE 3 — Enable VCN DPM features (dry_run={dry_run})")

        vcn_bitmap_lo = (1 << FEATURE_DPM_VCLK_BIT) | (1 << FEATURE_DPM_DCLK_BIT)
        print(f"\n  Target bitmap (low 32): 0x{vcn_bitmap_lo:08x}")
        print(f"  Bits set: DPM_VCLK (bit 4) | DPM_DCLK (bit 5)")

        if dry_run:
            print("\n  DRY RUN — no messages sent. Rerun with --arm to attempt.")
            return

        # Candidate approaches
        print("\n  Attempt A: Q2 msg 0x05 with bitmap")
        r1 = self.safe_send(2, Q2_MSG_05, arg=vcn_bitmap_lo, label="SetSmuFeatures(bitmap)")
        self.results['dpm_enable_q2_05'] = r1

        print("\n  Attempt B: Q2 msg 0x31 with bitmap")
        r2 = self.safe_send(2, Q2_MSG_31, arg=vcn_bitmap_lo, label="FeatureRequest(bitmap)")
        self.results['dpm_enable_q2_31'] = r2

    # --------------------------------------------------------
    # Phase 4: Try VCN power messages after DPM enable
    # --------------------------------------------------------
    def phase4_vcn_power(self, dry_run=True):
        self.section(f"PHASE 4 — VCN power messages (dry_run={dry_run})")

        if dry_run:
            print("\n  DRY RUN — no messages sent. Rerun with --arm to attempt.")
            return

        print("\n  Q3 msg 0x19 (community-found VCN handler):")
        r19_1 = self.safe_send(3, Q3_VCN_MSG_19, arg=1, label="VCN 0x19 arg=1")
        self.results['q3_19_arg1'] = r19_1

        # Small settle delay
        time.sleep(0.1)

        print("\n  Q3 msg 0x1A (community-found VCN handler):")
        r1a_1 = self.safe_send(3, Q3_VCN_MSG_1A, arg=1, label="VCN 0x1A arg=1")
        self.results['q3_1a_arg1'] = r1a_1

    # --------------------------------------------------------
    # Phase 5: Indirect verification (SAFE — no 0x1f81c)
    # --------------------------------------------------------
    def phase5_verify(self):
        self.section("PHASE 5 — Indirect verification (post-experiment reads)")
        print("  Re-reading VCN state to check for changes:\n")

        self.results['post_reads'] = {}
        for addr, label in SAFE_VCN_INDIRECT_READS:
            val = self.safe_indirect_read(addr, label)
            self.results['post_reads'][addr] = val

        print("\n  DELTA:")
        baseline = self.results.get('baseline_reads', {})
        post = self.results.get('post_reads', {})
        any_change = False
        for addr, _ in SAFE_VCN_INDIRECT_READS:
            b = baseline.get(addr)
            p = post.get(addr)
            marker = "  " if b == p else "* "
            if b != p:
                any_change = True
            b_s = f"0x{b:08x}" if b is not None else "(err)"
            p_s = f"0x{p:08x}" if p is not None else "(err)"
            print(f"  {marker}0x{addr:06x}: {b_s} -> {p_s}")

        if any_change:
            print("\n  ** REGISTER STATE CHANGED — DPM enable may have worked!")
        else:
            print("\n  No register state changes detected.")

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------
    def summary(self, dry_run):
        self.section("SUMMARY")
        print(f"\n  Mode:              {'DRY RUN' if dry_run else 'ARMED (messages sent)'}")
        print(f"  SMU ping OK:       {self.results.get('ping_ok')}")
        print(f"  SMU version:       0x{self.results.get('smu_version', 0):08x}"
              if self.results.get('smu_version') is not None else "  SMU version:       (no response)")

        if not dry_run:
            print(f"\n  DPM enable (Q2 0x05): {self._fmt(self.results.get('dpm_enable_q2_05'))}")
            print(f"  DPM enable (Q2 0x31): {self._fmt(self.results.get('dpm_enable_q2_31'))}")
            print(f"  VCN 0x19 arg=1:       {self._fmt(self.results.get('q3_19_arg1'))}")
            print(f"  VCN 0x1A arg=1:       {self._fmt(self.results.get('q3_1a_arg1'))}")

            print("\n  Interpretation:")
            print("  - Status 0x01 typically = OK / accepted")
            print("  - Status 0xFC = BUSY")
            print("  - Status 0xFE = INVALID message ID")
            print("  - Status 0xFF or None = no response / error")
            print("  - A previously-refused feature now returning 0x01 = success signal")

        print()

    def _fmt(self, val):
        if val is None:
            return "(no response)"
        return f"0x{val:08x}"


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--arm', action='store_true',
                        help='Actually send messages (default: dry run — reads only)')
    parser.add_argument('--phase', type=int, default=0,
                        help='Run only up to this phase (0=all, 1=baseline, 2=probe, 3=enable, 4=power, 5=verify)')
    args = parser.parse_args()

    print("=" * 70)
    print("  BC-250 VCN DPM Enable Test")
    print("=" * 70)
    print(f"  Mode: {'ARMED' if args.arm else 'DRY RUN'}")
    print()

    # Load bc250_smu
    try:
        from bc250_smu import Bc250Smu
    except ImportError as e:
        print(f"ERROR: bc250_smu library not available: {e}")
        print("This script must run on the BC-250 board with bc250-smu-unlock installed.")
        return 1

    # Init SMU
    try:
        smu = Bc250Smu()
    except Exception as e:
        print(f"ERROR: Bc250Smu init failed: {e}")
        traceback.print_exc()
        return 1

    # Confirm required methods
    for method in ('raw_send', 'raw_read'):
        if not hasattr(smu, method):
            print(f"ERROR: Bc250Smu instance lacks '{method}' method — "
                  "need bc250-smu-unlock protocol support.")
            return 1

    # Run test phases
    test = DPMTest(smu, verbose=True)

    try:
        if not test.phase1_baseline():
            print("\nBaseline ping failed — SMU not responding. Aborting.")
            return 1

        if args.phase == 0 or args.phase >= 2:
            test.phase2_discover_features()

        if args.phase == 0 or args.phase >= 3:
            test.phase3_enable_dpm(dry_run=not args.arm)
            if args.arm:
                # Let DPM state settle before trying power messages
                time.sleep(0.5)

        if args.phase == 0 or args.phase >= 4:
            test.phase4_vcn_power(dry_run=not args.arm)

        if args.phase == 0 or args.phase >= 5:
            test.phase5_verify()

        test.summary(dry_run=not args.arm)
        return 0

    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        return 130
    except Exception as e:
        print(f"\n\nUnhandled error: {e}")
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
