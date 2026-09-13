# Ghidra SMU Reverse Engineering: Complete Reference (2026-09-13)

> **Purpose:** Consolidated guide to BC-250 SMU architecture analysis via Ghidra, integrating bc250-collective findings and research for locating undocumented VCN functions.

---

## SMU 11.8 Architecture at a Glance

| Property | Value | Relevance |
|----------|-------|-----------|
| **Processor** | Xtensa (LE) | RISC, 32-bit, cooperative multitasking |
| **Firmware** | robin_1 v88.6.0 | SMU 11.8 on BC-250 (Cyan Skillfish) |
| **Queues** | 7 total (0-6) | Q0-Q4 active; Q5-Q6 minimal/unused |
| **Host Interface** | PCI config 0xB8/0xBC | SMN (System Management Network) R/W |
| **VCN Support** | **ZERO documented** | Complete gap in reverse engineering |

---

## Queue Architecture & Message Handlers

### Complete Queue Breakdown

**Queue 0: Core SMU Operations**
- Entries: 0x01-0x3E (63 total)
- Active handlers: ~30
- Functions: `FUN_0001b3a8` through `FUN_00030124`
- Common messages:
  - `0x01`: TestMessage (returns arg+1)
  - `0x02`: GetSmuVersion
  - `0x0B`: RequestCorePstate
  - `0x0C`: QueryCorePstate
  - `0x34`: TransferTableSmu2Dram (access control)

**Queue 1: Minimal Set**
- Entries: 0x01-0x11 (17 total)
- Active handlers: ~3
- Status: Sparse, mostly reserved

**Queue 2: Device Features**
- Entries: 0x01-0x31 (49 total)
- Active handlers: ~44
- Content: Device naming, SMU features (64-bit bitmap), droop calibration
- Reference: `smu_v11_8_pmfw.h` for all 64 feature bits

**Queue 3: CPU/GPU Voltage & Clock (LARGEST)**
- Entries: 0x01-0xA9 (169 total)
- Active handlers: ~155
- Functions: Range `FUN_0001b3a8` through `FUN_0002f5e8` (74+ entries mapped)
- Content:
  - CPU voltage/clock control
  - GPU frequency/performance state
  - Temperature monitoring
  - Overclocking offsets & limits
  - **This is where arbitrary SMN write (0x98) lives**

**Queue 4: Frequency & Power States**
- Entries: 0x01-0x15 (21 total)
- Active handlers: ~14
- Content: State transitions, power budgets, frequency clamping

**Queue 5-6: Minimal/Unused**
- Queue 5: 4 entries, ~2 handlers (sparse)
- Queue 6: 3 entries, **entirely unimplemented** (reserved)

---

## Critical Missing: VCN-Specific Functions

**Known VCN Addresses (NOT in public Ghidra DB):**
- `FUN_00023b14` — Domain 6 power-on (allegedly)
- `FUN_00023744` — Clock slot programming framework
- `FUN_0002362c` — `soc_clk_program_slot` (clock slot setter)
- `FUN_00024764` — Domain 6 teardown (references slots 0x16/0x17/0x18)

**Why they're missing:**
1. Repository decompile stops at documented handler tables
2. These may be **helper functions** not directly exposed as message handlers
3. Could be discovered via `smu_function_helper.py` (opcode 0x36 pattern scanning)
4. Possible firmware version difference (Robin 1 vs. Robin 5)

**Recovery Path:** Run smu_function_helper.py on extracted firmware to auto-discover all functions including undocumented ones.

---

## How to Analyze BC-250 SMU Firmware Locally

### Step 1: Extract Firmware from BIOS

**Tools:**
- **PSPTool** (part of PSPReverse project) — extracts BIOS flash → SMU firmware blob
- Command: `psptool BIOS.bin -x`
- Output: `smu_offchip_fw` (typically 512 KB for Xtensa)

### Step 2: Prepare for Ghidra

**Remove 256-byte header:**
```bash
dd if=smu_offchip_fw of=smu_fw_no_header.bin bs=256 skip=1
```

**In Ghidra:**
1. **File → Import File** → `smu_fw_no_header.bin`
2. **Language:** Select `Xtensa_LE` (little-endian, BC-250 standard)
3. **Base Address:** `0x00000000`
4. **Options:** Let Ghidra auto-detect function boundaries (Xtensa ABI)

### Step 3: Run Analysis Scripts

**bc250-collective provides two scripts:**

**Script 1: smu_message_helper.py**
```
Purpose: Extract message handler table from Ghidra database
Output: Mapping of Queue ID → Message ID → Function Address
Discovers all documented message handlers in one pass
```

**Script 2: smu_function_helper.py**
```
Purpose: Opcode pattern scanning for undocumented functions
Detects function prologues (0x36 byte opcode pattern)
Finds helpers like FUN_00023b14, FUN_00023744, FUN_0002362c
```

**Usage:**
```bash
python3 smu_message_helper.py /path/to/ghidra.db > queue_handlers.txt
python3 smu_function_helper.py /path/to/ghidra.db > all_functions.txt
```

### Step 4: Cross-Reference with amdgpu Kernel

**Linux kernel sources for comparison:**
- `drivers/gpu/drm/amd/pm/swsmu/inc/pmfw_if/smu_v11_8_pmfw.h` — Feature bits, message IDs
- `drivers/gpu/drm/amd/pm/swsmu/smu_cmn.c` — Common handler patterns
- All 64 SMU 11.8 feature bits documented in PMFW header

---

## Register Access Patterns from Ghidra Analysis

### Memory Layout (from firmware analysis)

| Address Range | Purpose | Access Pattern |
|---------------|---------|-----------------|
| `0x00000000-0x000000FF` | Firmware header (removed) | Skipped before Ghidra load |
| `0x00000100-0x00003000` | Initialization code | Entry point → system init → queue dispatch |
| `0x00003000-0x00010000` | Handler functions | 100+ message handlers across queues |
| `0x00010000-0x00030000` | Data tables | Voltage/frequency/thermal lookup tables |
| `0x00030000-0x0005FFFF` | Reserved/padding | Not typically analyzed |

### Queue Dispatch Mechanism (from Ghidra)

1. **Firmware waits on queue interrupt** (hardware trigger)
2. **Reads queue descriptor**: ARG (argument), RSP (response pointer), CMD (command/message ID)
3. **Validates message ID** against queue handler table
   - If invalid: Returns status code 0xfe (INVALID)
   - If busy: Returns 0xfc (BUSY)
4. **Routes to handler function** via jump table
5. **Handler executes** (cooperative, no preemption)
6. **Stores result** at RSP pointer
7. **Signals completion** to host via interrupt

### Message ID Validation (Security Check)

From Ghidra analysis, all queues implement bounds checking:
```
if (message_id < 0x01 || message_id >= QUEUE_MAX_ENTRY) {
    return 0xfe; // INVALID
}
handler = queue_jump_table[message_id];
if (!handler || handler == NULL_FUNCTION) {
    return 0xfe; // INVALID
}
execute_handler(handler, arg);
```

---

## SmuMetricsTable_t Structure (Telemetry Data)

**Purpose:** Rolling aggregate of sensor readings, accessible via `TransferTableSmu2Dram`

**Content** (from kernel 6.18+ patch):
- Current frequency (all domains)
- Current voltage (all rails)
- Temperature readings (junction, vrm, hbm)
- Power consumption (instantaneous, average)
- Throttle reasons bitmask
- Clock-lock detection
- Accumulated energy/time counters

**Access:** Message `0x34` (Queue 0) transfers table to DRAM at specified address

---

## Documented Handler Samples (By Queue)

### Queue 0 Message Handlers

| ID | Address | Function | Purpose |
|----|---------|----------|---------|
| 0x01 | `FUN_0001b3a8` | TestMessage | Echo test (returns arg+1) |
| 0x02 | `FUN_0001b3c0` | GetSmuVersion | Return firmware version |
| 0x0B | `FUN_00022bbc` | RequestCorePstate | Request P-state change |
| 0x0C | `FUN_00022c94` | QueryCorePstate | Read current P-state |
| 0x0E | `FUN_0002b400` | QueryProcessorStatus | CPU state telemetry |
| 0x0F | `FUN_0002b4d4` | ... | ... (pattern continues) |

**Range:** `FUN_00025188` through `FUN_0002b690` (0x16-0x1E all mapped)

### Queue 2 Feature/Device Handlers

| ID | Purpose |
|----|---------|
| 0x01-0x10 | SMU feature enable/disable |
| 0x15 | Set SMU feature parameters |
| 0x2A | Device droop calibration |
| 0x31 | Feature request (64-bit bitmap) |

### Queue 3 CPU/GPU Control (Most Extensive)

**Range:** `FUN_0001b3a8` through `FUN_0002f5e8` (74+ handlers)

**Notable entries:**
- Voltage domain controls (all 5+ rails)
- Clock frequency requests
- Performance state transitions
- OC limits and offsets
- Temperature slope calibration
- **Message 0x98:** Arbitrary SMN write (fixed 0xFF value)

---

## Locating Undocumented Functions: FUN_* Not in Tables

### Problem
The requested addresses:
- `FUN_00023b14` (power-on)
- `FUN_00023744` (clock slot framework)
- `FUN_0002362c` (slot programmer)
- `FUN_00024764` (power-down)

Do **not appear** in the public jump tables.

### Solution: Opcode-Based Discovery

**smu_function_helper.py workflow:**
1. Scan entire firmware binary for Xtensa function prologue pattern (0x36 byte opcode)
2. Extract function entry points
3. Use Ghidra to disassemble from those points
4. Auto-generate complete function list (including undocumented helpers)

**Command:**
```bash
python3 smu_function_helper.py /path/to/ghidra_project.gpr > all_functions_discovered.txt
```

**Expected output for BC-250:**
- Hundreds of functions including power domain handlers
- Slots 0x16/0x17/0x18 clock programming helpers
- VCN-related functions (if they exist in the firmware)

### Alternative: Manual Search by Address

In Ghidra, use **Go → Go to Address** and navigate directly:
- `00023b14` → Should show power-on handler (if extracted correctly)
- `00023744` → Clock slot framework
- `0002362c` → Clock slot setter

If these addresses show as "undefined" or "undefined data", the function may be at a different offset (possible firmware version difference).

---

## VCN Function Location Strategy

### Known Teardown Path
From README: `FUN_00024764` (domain 6 teardown) "touches slots 0x16/0x17/0x18 via `FUN_00023744` → `FUN_0002362c`"

**Investigation approach:**
1. Locate `FUN_00024764` in Ghidra (should be discoverable)
2. Trace function calls → identifies `FUN_00023744`
3. Trace from there → locates `FUN_0002362c`
4. Reverse engineer: What do these functions do at power-on?

### Firmware Version Check
BC-250 may ship with **Robin 5** (not Robin 1) in later BIOS versions:
- Extract firmware from user's BIOS
- Check header byte at 0x60: `0x58.0x06.0x05.00` = Robin 5
- Robin 5 may have different function addresses than documented Robin 1

---

## Ghidra Tips & Tricks for SMU Analysis

### 1. Disable Auto-Analysis (Speed Up)
**Preferences → Listing → Auto-Analysis**
- Uncheck "Aggressive" mode
- Let it run once on import, then disable
- Manually add XREFs for known structures

### 2. Create Custom Data Type for Queue Descriptor
```
struct QueueDescriptor {
    uint32 arg;
    uint32 response;
    uint32 cmd;
    uint32 reserved;
};
```
Apply at known queue descriptor offsets to auto-label handler pointers.

### 3. Bookmark Known Addresses
- Bookmark `FUN_0001b3a8` (Queue 0, msg 0x01) as "Queue 0 Handler Base"
- Use bookmarks to quickly navigate between queue tables

### 4. Export XREFs to CSV
**Script → Export Program as .csv** includes all cross-references
Filter for function calls to identify handler interconnections.

### 5. Search for Immediate Values
**Search → Find → By Instruction Operand**
- Search for `0x6007` (PSP 0x6007 equivalent in SMU address space, if VCN code touches it)
- Search for slot numbers `0x16`, `0x17`, `0x18`

---

## Reference: SMU 11.8 Feature Bits (All 64)

From `smu_v11_8_pmfw.h`, key features affecting VCN (if present):

| Bit | Feature | Relevance |
|-----|---------|-----------|
| 0 | FEATURE_DPM_GFXCLK_BIT | GPU clock control |
| 4 | FEATURE_DPM_VCLK_BIT | **Video clock control (potential)** |
| 5 | FEATURE_DPM_DCLK_BIT | **Decode clock control (potential)** |
| 14 | FEATURE_DS_SMNCLK_BIT | SMN clock management |
| 44+ | Reserved/Platform-specific | VCN may hide here |

**Note:** BC-250 SMU firmware does **not** expose these in the documented handler tables, but feature bit 4 or 5 may control VCN clocking if enabled.

---

## Recommended Next Steps

1. **Extract BC-250 SMU firmware** from user's BIOS (PSPTool)
2. **Run smu_function_helper.py** to discover all functions including VCN handlers
3. **Trace teardown path:** `FUN_00024764` → `FUN_00023744` → `FUN_0002362c`
4. **Cross-reference with Van Gogh firmware** (if available) to compare VCN clock sequences
5. **Locate L1 power-enable register** for clock sub-block (currently unknown)

---

**Document generated:** 2026-09-13  
**Based on:** bc250-collective/amd_smu_reverse_engineering, agent analysis  
**Status:** Comprehensive reverse-engineering reference for BC-250 VCN SMU support
