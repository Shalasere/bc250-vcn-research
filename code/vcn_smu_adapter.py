#!/usr/bin/env python3
"""
Adapter to make Bc250Smu work with VCNPowerupFixed interface.

VCNPowerupFixed expects:
  - smu.write32(addr, value)
  - smu.read32(addr)
  - smu.wait_ms(ms)

This adapter wraps Bc250Smu to provide these methods using SMU mailbox commands.
"""

import time
from typing import Optional


class SMUAdapter:
    """Adapter that provides VCNPowerupFixed interface on top of Bc250Smu"""

    def __init__(self, bc250_smu_instance):
        """Initialize with a Bc250Smu instance"""
        self._smu = bc250_smu_instance
        self._verbose = True

    def log(self, msg):
        if self._verbose:
            print(f"[SMU-ADAPTER] {msg}")

    def write32(self, addr: int, value: int) -> bool:
        """
        Write 32-bit value to SMN address via SMU.

        Uses SMU mailbox protocol via raw_send. Requires bc250-smu-unlock
        library supporting message-based indirect register access.

        Note: Message IDs 0x00/0x01 are from bc250-smu-unlock protocol.
        If bc250_smu doesn't support these, raises AttributeError.

        Args:
            addr: SMN address to write
            value: 32-bit value to write

        Returns:
            True if write sent successfully

        Raises:
            AttributeError: if raw_send method not available
            RuntimeError: if write fails
        """
        if not hasattr(self._smu, 'raw_send'):
            raise AttributeError("bc250_smu instance does not have raw_send method")

        try:
            # SMU indirect register write protocol (bc250-smu-unlock):
            # Queue 1, msg 0x00: write address index
            # Queue 1, msg 0x01: write data value
            self._smu.raw_send(queue=1, msg_id=0x00, arg=addr)
            result = self._smu.raw_send(queue=1, msg_id=0x01, arg=value)

            self.log(f"write32(0x{addr:06x}, 0x{value:08x}) = 0x{result:08x}")
            return True
        except (AttributeError, ValueError, RuntimeError) as e:
            self.log(f"write32 failed: {type(e).__name__}: {e}")
            raise RuntimeError(f"Failed to write 0x{addr:06x} = 0x{value:08x}: {e}") from e

    def read32(self, addr: int) -> int:
        """
        Read 32-bit value from SMN address via SMU.

        Args:
            addr: SMN address to read

        Returns:
            32-bit register value

        Raises:
            RuntimeError: if read fails (cannot distinguish from clamped state)
        """
        if not hasattr(self._smu, 'raw_send') or not hasattr(self._smu, 'raw_read'):
            raise AttributeError("bc250_smu instance missing raw_send or raw_read method")

        try:
            # SMU indirect register read protocol (bc250-smu-unlock)
            self._smu.raw_send(queue=1, msg_id=0x00, arg=addr)
            result = self._smu.raw_read(queue=1)

            self.log(f"read32(0x{addr:06x}) = 0x{result:08x}")
            return result
        except (AttributeError, ValueError, RuntimeError) as e:
            self.log(f"read32 failed: {type(e).__name__}: {e}")
            raise RuntimeError(f"Failed to read 0x{addr:06x}: {e}") from e

    def wait_ms(self, ms: int):
        """Sleep for milliseconds"""
        time.sleep(ms / 1000.0)


class SMUDirectAdapter:
    """
    Direct SMU adapter using memory-mapped I/O if available.

    Falls back to SMUAdapter if direct access not available.
    Validates debugfs format before use.
    """

    def __init__(self, bc250_smu_instance):
        """Initialize with a Bc250Smu instance"""
        self._smu = bc250_smu_instance
        self._fallback = SMUAdapter(bc250_smu_instance)
        self._has_direct = False
        self._verbose = True
        self._debugfs_format_verified = False

        # Check for direct access and verify format
        if self._check_direct_access():
            if self._verify_debugfs_format():
                self._has_direct = True
                self.log("Using direct memory-mapped I/O (format verified)")
            else:
                self.log("Debugfs format unrecognized; falling back to SMU mailbox")
        else:
            self.log("Using SMU mailbox fallback (no direct access)")

    def log(self, msg):
        if self._verbose:
            print(f"[SMU-ADAPTER] {msg}")

    def _check_direct_access(self) -> bool:
        """Check if we have direct register access via /sys/kernel/debug"""
        import os
        try:
            # Try to open amdgpu_regs debug file
            with open('/sys/kernel/debug/dri/0/amdgpu_regs', 'r') as f:
                return True
        except:
            return False

    def _verify_debugfs_format(self) -> bool:
        """
        Verify debugfs format before use.

        Expected format: "0xADDR VALUE" (hex address, hex value, space-separated)
        Reads first line and validates structure.

        Returns:
            True if format is recognized, False otherwise
        """
        try:
            with open('/sys/kernel/debug/dri/0/amdgpu_regs', 'r') as f:
                first_line = f.readline().strip()

                # Skip empty file or comments
                if not first_line or first_line.startswith('#'):
                    # Cannot verify on empty/comment-only file; assume format OK
                    self._debugfs_format_verified = True
                    return True

                # Validate format: "0xHEX VALUE" or similar
                parts = first_line.split()
                if len(parts) < 2:
                    self.log(f"Unexpected debugfs format: {first_line[:40]}")
                    return False

                # Verify first part looks like hex address
                try:
                    addr = int(parts[0], 16)
                    # If we got here, format looks valid
                    self._debugfs_format_verified = True
                    return True
                except ValueError:
                    self.log(f"First field not hex: {parts[0]}")
                    return False

        except Exception as e:
            self.log(f"Format verification failed: {e}")
            return False

    def write32(self, addr: int, value: int) -> bool:
        """Write 32-bit value"""
        if self._has_direct and self._debugfs_format_verified:
            try:
                # Use direct write via debug interface
                with open('/sys/kernel/debug/dri/0/amdgpu_regs', 'w') as f:
                    f.write(f"0x{addr:x} 0x{value:x}\n")
                self.log(f"write32_direct(0x{addr:06x}, 0x{value:08x})")
                return True
            except Exception as e:
                self.log(f"Direct write failed: {e}")
                self._has_direct = False

        return self._fallback.write32(addr, value)

    def read32(self, addr: int) -> int:
        """Read 32-bit value"""
        if self._has_direct and self._debugfs_format_verified:
            try:
                # Use direct read via debug interface
                with open('/sys/kernel/debug/dri/0/amdgpu_regs', 'r') as f:
                    for line in f:
                        if line.startswith(f"0x{addr:x}"):
                            parts = line.split()
                            if len(parts) >= 2:
                                result = int(parts[1], 16)
                                self.log(f"read32_direct(0x{addr:06x}) = 0x{result:08x}")
                                return result
                self._has_direct = False
            except Exception as e:
                self.log(f"Direct read failed: {e}")
                self._has_direct = False

        return self._fallback.read32(addr)

    def wait_ms(self, ms: int):
        """Sleep for milliseconds"""
        time.sleep(ms / 1000.0)
