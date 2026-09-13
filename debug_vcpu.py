#!/usr/bin/env python3
"""Debug VCPU boot hang - check clock, reset, and firmware state."""

import sys

try:
    from bc250_smu import Bc250Smu
    from vcn_smu_adapter import SMUAdapter
except ImportError as e:
    print(f"ERROR: Missing bc250_smu library: {e}")
    sys.exit(1)

print("=" * 70)
print("VCPU BOOT DEBUG")
print("=" * 70)

smu_hw = Bc250Smu()
smu = SMUAdapter(smu_hw)

# Key registers for VCPU debugging
regs = {
    # PGFSM status/control
    0x6d190: "PGFSM_STATUS",
    0x6d0f8: "PGFSM_CTRL (clock gates)",
    0x6d17c: "PGFSM_CMD (power)",

    # VCPU clock control (Van Gogh)
    0x5c158: "DCLK (decode clock) - check if enabled",
    0x5c180: "VCLK (video clock) - check if enabled",

    # VCPU control registers
    0x20160: "VCPU_CNTL (from TYPE13 readback - had 0x400 bit issue)",
    0x1f804: "STATUS readback register",

    # LMI/memory interface
    0x20148: "LMI_CTRL",
    0x2014c: "LMI_CTRL2",
}

print("\nLive register reads:")
print("-" * 70)

for addr, name in regs.items():
    try:
        val = smu.read32(addr)
        print(f"0x{addr:06x} {name:40s} = 0x{val:08x}")
    except Exception as e:
        print(f"0x{addr:06x} {name:40s} = ERROR: {e}")

print("\n" + "-" * 70)
print("\nKey observations to check:")
print("  1. PGFSM_STATUS: should show power state transitions")
print("  2. DCLK/VCLK: should be non-zero if clocks enabled")
print("  3. VCPU_CNTL bit 10 (0x400): is it stuck at 0?")
print("  4. LMI_CTRL: memory interface state")

print("\nDiagnosis:")

try:
    status = smu.read32(0x6d190)
    print(f"  PGFSM_STATUS = 0x{status:08x}")
    if status == 0xffffffff:
        print("    -> CLAMPED - isolation gate still active!")
    else:
        print("    -> ACCESSIBLE")
except:
    pass

try:
    vcpu_cntl = smu.read32(0x20160)
    print(f"  VCPU_CNTL = 0x{vcpu_cntl:08x}")
    bit_10 = (vcpu_cntl >> 10) & 1
    if bit_10:
        print("    -> Bit 10 SET (good)")
    else:
        print("    -> Bit 10 CLEAR (problem!)")
        print("       Firmware write didn't stick - clock gating issue?")
except:
    pass

print("\n" + "=" * 70 + "\n")
