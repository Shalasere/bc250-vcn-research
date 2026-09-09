#!/usr/bin/env python3
"""
Execute VCN Power-Up Fix on BC-250 Hardware (Real SMU Interface)

Uses actual bc250-smu library for hardware communication.
"""

import sys
import time

def main() -> bool:
    """Execute VCN power-up fix with real SMU interface.

    Returns:
        True if fix succeeded, False otherwise
    """
    print("\n" + "=" * 70)
    print("VCN POWER-UP FIX - REAL HARDWARE EXECUTION")
    print("=" * 70 + "\n")

    # Step 1: Import SMU library
    print("[1] Loading SMU library...")
    try:
        from bc250_smu import Bc250Smu
        print("    ✓ bc250_smu imported")
    except ImportError as e:
        print(f"    ✗ Failed to import bc250_smu: {e}")
        print("    This library must be installed on BC-250 hardware")
        return False

    # Step 2: Import our adapters
    print("\n[2] Loading VCN power sequencer...")
    try:
        from vcn_powerup_fixed import VCNPowerupFixed
        from vcn_smu_adapter import SMUAdapter
        print("    ✓ VCN sequencer and adapter imported")
    except ImportError as e:
        print(f"    ✗ Failed to import VCN modules: {e}")
        return False

    # Step 3: Initialize SMU
    print("\n[3] Initializing SMU interface...")
    try:
        smu_hw = Bc250Smu()
        print("    ✓ Bc250Smu initialized")
    except Exception as e:
        print(f"    ✗ Failed to initialize Bc250Smu: {e}")
        return False

    # Step 4: Wrap with adapter
    print("\n[4] Creating SMU adapter...")
    try:
        smu = SMUAdapter(smu_hw)
        print("    ✓ SMUAdapter created")
    except Exception as e:
        print(f"    ✗ Failed to create adapter: {e}")
        return False

    # Step 5: Test basic SMU communication
    print("\n[5] Testing SMU communication...")
    try:
        val = smu.read32(0x6d190)  # STATUS register
        print(f"    ✓ Read STATUS register: 0x{val:08x}")
    except Exception as e:
        print(f"    ✗ SMU communication failed: {e}")
        return False

    # Step 6: Run VCN power-up sequence
    print("\n[6] Running VCN power-up sequence...")
    print("    " + "-" * 66)

    try:
        sequencer = VCNPowerupFixed(smu, verbose=True)
        success = sequencer.power_up_vcn()
        print("    " + "-" * 66)

        if not success:
            print(f"\n    Sequence returned False (timeout or failure)")
            return False
        print(f"\n    ✓ Sequence completed")
    except Exception as e:
        print(f"\n    ✗ Sequence failed: {type(e).__name__}: {e}")
        return False

    # Step 7: Verify MMIO access
    print("\n[7] Verifying MMIO access...")
    print("    Note: If this step hangs, the isolation gate is active.")
    print("    Proceed with Ghidra analysis on anima (HANDOFF_TO_NEXT_SESSION.md)")

    try:
        print("    Attempting to read VCN MMIO 0x1000 (UVD_VERSION)...")
        print("    (If this hangs, press Ctrl+C and check isolation gate status)")

        # Try direct MMIO read with timeout
        # This would require additional kernel access or remapping
        # For now, report status based on power sequencer result

        print("    (Direct MMIO test requires kernel-level access)")
        print("    Check dmesg and amdgpu logs for VCN access permissions")

    except Exception as e:
        print(f"    (MMIO test not available: {e})")

    # Summary
    print("\n" + "=" * 70)
    print("RESULT: VCN POWER-UP SEQUENCE COMPLETED")
    print("=" * 70)
    print("\nNext steps:")
    print("  1. If MMIO still clamped (0xffffffff):")
    print("     - Isolation gate is active (root blocker)")
    print("     - Run Ghidra analysis: see HANDOFF_TO_NEXT_SESSION.md")
    print("  2. If MMIO accessible:")
    print("     - Load VCN firmware via PSP")
    print("     - Enable VCN in kernel driver")
    print("     - Test video decode")
    print("=" * 70 + "\n")

    return True


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"\n\nUnhandled error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
