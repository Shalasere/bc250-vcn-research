# Van Gogh SMU Firmware Decompilation Guide

## Goal
Decompile `FUN_00023b14` (dom6 power sequencer FSM) to identify the missing steps blocking VCN MMIO access.

## Files
- **Firmware:** `vcn-enablement/vangogh_smu_full.bin` (512 KB)
- **Function offset:** 0x00023b14
- **Architecture:** Xtensa (Tensilica RISC, 24-bit instruction words)

## Steps

### 1. Open Ghidra (Interactive Session)

```bash
# On Windows (if Ghidra installed):
# C:\Program Files\ghidra_11.x\ghidraRun.bat

# Or download from: https://ghidra-sre.org/
```

### 2. Create New Project
- File → New Project → Select directory
- Project Name: `BC250-VCN-Research`

### 3. Import Firmware Binary
- File → Import File
- Select: `bc250-research/vcn-enablement/vangogh_smu_full.bin`
- **Language:** Xtensa (if not auto-detected, search "xtensa" in language dropdown)
- **Format:** Raw Binary
- **Base Address:** 0x00000000 (SMU SRAM base)
- Click OK

### 4. Analyze the Binary
- Ghidra will auto-analyze. Wait for it to complete (may take 30-60s)
- Window → Defined Memory Blocks: verify 0x00000000-0x0007FFFF is loaded

### 5. Navigate to FUN_00023b14
- **Go → Go to Address** → type `00023b14`
- This is the dom6 power sequencer control function
- Right-click → Rename to "dom6_power_fsm" for clarity

### 6. Read the Decompilation
- **Window → Decompiler** (if not visible)
- Select the function
- The decompiler pane shows the C-like pseudocode
- Cross-reference with the disassembly pane for exact instruction sequence

### 7. Key Things to Look For

#### a. Register Writes to dom6 Sequencer
Search for writes to these SMN addresses (or their SMU-local equivalents):
```
0x06d17c - cmd (up/down request)
0x06d184 - rail (power rail)
0x06d190 - status (read-only)
0x06d0f8 - ctrl (clock gates)
0x06d100-0x06d150 - slot registers
```

**How to find:** Use **Search → Memory → Find References** for hex value `0x6d17c` (little-endian: `7c d1 06 00`)

#### b. Control Flow
The function likely contains:
1. **Precondition checks** — validate `0x50d6c` (L0 fabric gate)
2. **Clock setup** — program DFS slots (0x16/0x17/0x18)
3. **Gate release** — clear `ctrl` bits
4. **Power sequence** — write `cmd` up-request, wait for status ack
5. **Island enable** — THIS IS LIKELY THE MISSING STEP
   - Could be: ISO bit clear, PGFSM state set, PSP doorbell, etc.

#### c. Unknown Sequences
Look for:
- References to registers outside 0x06d0xx-0x06d1xx (new gate candidate)
- Calls to other functions (might delegate ISO gate clear)
- Poll loops (waiting for status bits)
- Conditional branches (checking power-ready states)

### 8. Compare Against Host Replica

The host sequence (from `--direct-load`) does:
```python
[0] ctrl  0x6d0f8: 0x02 -> 0x00  (release gate)
[1] cmd   0x6d17c: 0x00 -> 0x01  (up request)
[2] rail  0x6d184: 0x00 -> 0x10000  (rail up)
[3] status reads unchanged (0x01010101)
```

**What's missing?** The firmware likely does ADDITIONAL steps in this sequence:
- PGFSM state machine steps (multiple cycles, not just one write)
- Isolation gate clear (separate register/bit)
- Handshake/acknowledgment polling
- PSP coordination (if required)

### 9. Document Findings

Create a file: `vcn-enablement/FUN_00023b14_DISASM.md` with:
- Full function signature
- Pseudocode from decompiler
- Annotated instruction sequence
- Identified missing steps vs. host replica

### 10. Report Back

Share:
- The complete decompilation (copy-paste from decompiler)
- Key observations about the differences
- Any new register/gate candidates discovered

## Expected Outcome

This decompilation should reveal:
- **Why the island remains isolated** — whether it's a missing PGFSM step, an ISO bit, or a separate gate
- **What the PSP does** — if FUN_00023b14 does all the work, then PSP gating is less likely
- **The next actionable lever** — if a firmware step can be mirrored in the host, or if PSP involvement is required

## Troubleshooting

- **Language not auto-selected:** Manually choose Xtensa from dropdown
- **No decompiler output:** Function might be too complex; check disassembly tab
- **Address wrong:** Verify function starts at 0x23b14 (look for entry prologue: `entry a1, 0x20` or `entry a1, 0x30`)
- **Memory layout off:** Re-check base address is 0x00000000

## Community Impact

Once this decompilation is complete, the missing steps become testable on the hardware:
- If it's a firmware step → can be replicated via SMU code execution (already works)
- If it's an ISO bit → can be found + cleared via SMU writes
- If it's PSP gating → documents a hard out-of-scope boundary

Either way, the root cause is **identified and measurable** rather than "impossible."

---

**Timeline:** This analysis is the key blocker. Once complete, we'll know exactly what needs to happen next (firmware step, SMU register write, or PSP intervention).
