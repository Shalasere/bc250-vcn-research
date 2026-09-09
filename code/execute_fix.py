#!/usr/bin/env python3
"""
Execute VCN Power-Up Fix on BC-250 Hardware

This script:
1. Connects to BC-250 board
2. Runs the corrected power-up sequence
3. Tests MMIO access
4. Reports results
"""

import sys
import time
import socket
from pathlib import Path


class SMUInterface:
    """
    Minimal SMU interface for host-side VCN power sequencing.

    Provides read32/write32/wait_ms for VCNPowerupFixed.
    Actual communication via SMU adapter or direct MMIO.
    """

    def __init__(self, host: str = "localhost", port: int = 22):
        """Initialize SMU interface.

        Args:
            host: Board hostname or IP address
            port: SSH port for board connection
        """
        self.host = host
        self.port = port
        self.registers = {}
        self.connected = False

    def connect(self) -> bool:
        """Attempt to connect to board."""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=5)
            sock.close()
            self.connected = True
            print(f"[OK] Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[FAIL] Connection failed: {e}")
            return False

    def read32(self, addr: int) -> int:
        """Read 32-bit register value.

        Raises:
            RuntimeError: if read fails (via SMUAdapter pattern)
        """
        if not self.connected:
            if addr == 0x6d190:
                return 0xffffffff  # Clamped state: VCN isolation gate active
            return 0x00000000
        raise NotImplementedError("Real SMU interface required")

    def write32(self, addr: int, value: int) -> bool:
        """Write 32-bit register value.

        Raises:
            RuntimeError: if write fails (via SMUAdapter pattern)
        """
        if not self.connected:
            return True
        raise NotImplementedError("Real SMU interface required")

    def read_mmio(self, addr: int) -> int:
        """Read VCN MMIO address.

        Raises:
            RuntimeError: if read fails
        """
        if not self.connected:
            return 0xffffffff
        raise NotImplementedError("Real MMIO interface required")

    def wait_ms(self, ms: int) -> None:
        """Sleep for specified milliseconds."""
        time.sleep(ms / 1000.0)


def main() -> bool:
    """Execute VCN power-up fix and verify results.

    Returns:
        True if fix succeeded, False otherwise
    """
    print("\n" + "="*70)
    print("VCN POWER-UP FIX - HARDWARE EXECUTION")
    print("="*70 + "\n")

    # Step 1: Connect to board
    print("[1] Connecting to BC-250...")
    smu = SMUInterface()

    if not smu.connect():
        print("\n[FAIL] Could not connect to board")
        print("    Board may be unreachable or offline")
        print("    Try:")
        print("    - Check board is powered on")
        print("    - Verify network connectivity")
        print("    - Check IP address (may have DHCP shifted)")
        print("    - Use jumphost if needed\n")
        return False

    # Step 2: Confirm blocker
    print("\n[2] Confirming blocker (VCN MMIO currently clamped)...")
    try:
        val = smu.read_mmio(0x1000)
        print(f"    UVD_VERSION: 0x{val:08x}")

        if val == 0xffffffff:
            print("    [OK] Blocker confirmed")
        else:
            print("    [WARN] Unexpected value - blocker may be partial")
    except Exception as e:
        print(f"    [ERROR] MMIO read failed: {e}")
        print("    This is expected if board access is not fully set up")

    # Step 3: Run fixed sequence
    print("\n[3] Running fixed VCN power-up sequence with polling...")
    print("    (This adds multi-cycle state machine with acknowledgment polling)")

    try:
        from vcn_powerup_fixed import VCNPowerupFixed
        fixer = VCNPowerupFixed(smu, verbose=True)
        print("\n    Sequence execution:")
        print("    " + "-"*66)
        success = fixer.power_up_vcn()
        print("    " + "-"*66)
        print(f"\n    Result: {'SUCCESS' if success else 'FAILED'}")
    except ImportError:
        print("    [FAIL] vcn_powerup_fixed.py not found in path")
        print("    Make sure to run from bc250-research directory")
        return False
    except Exception as e:
        print(f"    [FAIL] Sequence failed with error: {e}")
        return False

    # Step 4: Test MMIO
    print("\n[4] Testing MMIO access...")
    print("    Reading VCN registers (should NOT be 0xffffffff)...")

    try:
        addresses = {
            0x1000: "UVD_VERSION",
            0x1008: "UVD_PGFSM_STATUS",
            0x100c: "UVD_GPCOM_VCPU_CMD",
        }

        all_clamped = True
        for addr, name in addresses.items():
            try:
                val = smu.read_mmio(addr)
                status = "OK" if val != 0xffffffff else "CLAMP"
                print(f"    [{status}] {name:20s} (0x{addr:04x}): 0x{val:08x}")
                if val != 0xffffffff:
                    all_clamped = False
            except Exception as e:
                print(f"    [ERR] {name:20s}: {e}")

        # Report results
        print("\n" + "="*70)
        if all_clamped:
            print("RESULT: FAILED - MMIO still clamped")
            print("="*70)
            print("\nDiagnostics:")
            print("  Hypothesis A (multi-cycle polling) was incorrect")
            print("  Next: Try Hypothesis B (cold-reset register 0x0900c004)")
            print("\n  Test command:")
            print("    smu.write32(0x0900c004, 0x00)")
            print("    val = smu.read_mmio(0x1000)")
            print("    if val != 0xffffffff: print('SUCCESS')")
            return False
        else:
            print("RESULT: SUCCESS - MMIO accessible!")
            print("="*70)
            print("\nVCN register file is now accessible.")
            print("Next steps:")
            print("  1. Load VCN firmware via PSP")
            print("  2. Enable VCN in kernel driver")
            print("  3. Test video decode")
            return True

    except Exception as e:
        print(f"\n[ERR] MMIO test failed: {e}")
        return False


if __name__ == "__main__":
    print("""
VCN POWER-UP FIX EXECUTION
Multi-Cycle PGFSM State Machine with Polling Loops

Expected: MMIO transitions from 0xffffffff to accessible values
    """)

    success = main()

    print("\n" + "="*70)
    if success:
        print("SUCCESS - VCN ISOLATION GATE SOLVED")
    else:
        print("INCOMPLETE - ADDITIONAL STEPS NEEDED")
    print("="*70 + "\n")

    sys.exit(0 if success else 1)
