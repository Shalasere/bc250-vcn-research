# BC-250 VCN Enablement — Handoff Document (Session 2026-09-06 → Next)

## 🎯 Where We Are

**MAJOR BREAKTHROUGH ACHIEVED:**
- SMU arbitrary code execution ✅ **WORKING**
- Clock/gate sequencing ✅ **FULLY CONTROLLABLE**
- SMU power oracle ✅ **SETTLED (all green)**
- Root blocker ✅ **ISOLATED & MEASURABLE** (not mysterious)
- Community reports ✅ **READY FOR PUBLICATION**

**This session is COMPLETE.** The next session's single objective: Ghidra decompilation of firmware function FUN_00023b14 to identify the missing root isolation gate control.

---

## What You Need to Know

### Current Status
```
SMU-SIDE: ✅ FULLY SOLVED
├─ Exploit: Q2 msg-0x23 queue-overflow works
├─ Clocks: Programmed (0x00 → 0x20), persistent
├─ Enables: ON (0x00000001), persistent  
├─ Gates: Released (0x02 → 0x00), persistent
└─ Oracle: Settled (cmd=0, rail=0, status=up-ack)

BLOCKER: Root isolation gate (between sequencer + register file)
├─ VCN MMIO: Returns 0xffffffff uniformly
├─ Island: Closed at root level (specific, measurable)
└─ Next: Decompile FUN_00023b14 to find missing step
```

### Files Ready on anima (10.0.0.111)

**You have SSH access:**
```bash
ssh apple@10.0.0.111
cd ~/bc250-research
```

**Community-ready reports:**
- `COMMUNITY_REPORT_2026_09_06.md` ⭐ **Main finding**
- `SESSION_SUMMARY_2026_09_06.md` — Technical details
- `GHIDRA_ANALYSIS_GUIDE.md` — Step-by-step guide
- `EXHAUSTION_LOG.md` — Full 25-iteration history
- `vcn_exploit_execution_2026_09_06.txt` — Execution logs

**Firmware for analysis:**
- `vangogh_smu_full.bin` (512 KB) — Van Gogh SMU image

---

## Your Next Task (Single Focus)

### Objective
Decompile `FUN_00023b14` in Van Gogh SMU firmware and identify the missing root isolation gate control.

### Steps

1. **SSH to anima & verify Ghidra**
   ```bash
   ssh apple@10.0.0.111
   cd ~/bc250-research
   which ghidra  # or launch GUI
   ls -la vangogh_smu_full.bin
   ```

2. **Open Ghidra GUI** (or use headless)
   - Import: `vangogh_smu_full.bin`
   - Base address: 0x00000000
   - Language: Xtensa
   - Auto-analyze: Let it complete

3. **Navigate to FUN_00023b14**
   - Go → Address → `00023b14`
   - Open Decompiler window (Window → Decompiler)
   - Open Listing window (Window → Listing)

4. **Analyze the function**
   Reference: `GHIDRA_ANALYSIS_GUIDE.md` for what to look for

   **Key questions:**
   - What does firmware write to dom6 sequencer (0x6d17c, 0x6d184, 0x6d0f8)?
   - Does it write to any OTHER registers (unknown ISO gate)?
   - Are there poll loops (waiting for status bits)?
   - Does it call other functions (might delegate ISO gate)?
   - Does it interact with PSP (separate concern)?

5. **Compare against host sequence**
   From `--direct-load` output:
   ```
   [0] ctrl  0x6d0f8: 0x02 → 0x00
   [1] cmd   0x6d17c: 0x00 → 0x01
   [2] rail  0x6d184: 0x00 → 0x10000
   [3] status: no change observed
   ```
   
   **What does firmware do BEYOND this?**

6. **Document findings**
   Create: `FUN_00023b14_ANALYSIS.md` with:
   - Function disassembly (copy from Listing)
   - Pseudocode (copy from Decompiler)
   - Annotated sequence vs host
   - Identified missing step(s)

7. **Update community report**
   Add to `COMMUNITY_REPORT_2026_09_06.md`:
   ```markdown
   ### Firmware Deep-Dive (Iter #26)
   
   Function FUN_00023b14 analysis revealed:
   - [What firmware does]
   - [Comparison vs host sequence]
   - [Missing step identified]
   - [Root gate control location/mechanism]
   ```

---

## Expected Outcome

You'll find ONE of these:

### Option A: Missing Firmware Sequencing ✅
**Firmware does multi-step state machine:**
- Firmware: write cmd→rail→cmd again (cycling)
- Host: single write sequence (incomplete)
- Solution: Mirror firmware's full cycling in SMU code

### Option B: Unknown ISO Register ✅
**Firmware writes to register outside dom6:**
- Firmware: writes to 0xXXXXXX bit N (ISO gate)
- Host: doesn't know about 0xXXXXXX
- Solution: Discover address, add to SMU sequence

### Option C: PSP-Side Gating ✅
**Firmware coordinates with PSP:**
- Firmware: calls PSP message (separate concern)
- Host: can't access PSP without firmware
- Solution: Documents out-of-scope boundary

**Any of these is a community-worthy finding.**

---

## Files You'll Produce

```
~/bc250-research/
├── FUN_00023b14_ANALYSIS.md          ← Your decompilation output
├── FUN_00023b14_DISASM.md            ← Full assembly (if needed)
└── COMMUNITY_REPORT_2026_09_06.md    ← Updated with findings
```

---

## Deployment Status

All files already on anima. You have:
- ✅ Firmware image
- ✅ Analysis guide
- ✅ Ghidra available
- ✅ WSL available
- ✅ SSH access
- ✅ Community report template

**Nothing else needed. Just analyze and document.**

---

## Token Budget

You have a **fresh 15M token budget** for this task. This is plenty for:
- Ghidra interactive analysis (5-10M)
- Decompilation review + annotation (2-3M)
- Updated community report (1-2M)
- Buffer for verification (2-3M)

---

## Success Criteria

Session is complete when:
1. ✅ FUN_00023b14 decompiled and documented
2. ✅ Comparison vs host sequence completed
3. ✅ Missing step(s) identified
4. ✅ Community report updated with findings
5. ✅ Report ready for Discord/community publication

---

## If You Get Stuck

**Problem:** Can't find Ghidra on anima
→ Check if it's in PATH or installed. Alternative: Use IDA Free on your local machine.

**Problem:** Function not at 0x23b14
→ Search for entry prologue (Xtensa "entry a1, 0x20" or "entry a1, 0x30")

**Problem:** Decompiler output is messy
→ Normal for complex firmware. Fall back to Listing (assembly) view and annotate.

**Problem:** Can't find register writes
→ Search for specific SMN addresses (0x6d17c, etc.) using Search → Memory

---

## Quick Reference

```bash
# SSH to anima
ssh apple@10.0.0.111

# Navigate to research
cd ~/bc250-research
ls -la

# View the main report
cat COMMUNITY_REPORT_2026_09_06.md

# View the guide
cat GHIDRA_ANALYSIS_GUIDE.md

# List what we have
find . -type f -name "*.md" -o -name "*.bin" -o -name "*.txt"
```

---

## Previous Session Summary

**Iteration #1-25:**
- Proved VCN not fuse-harvested (hardware present)
- Mapped layered disable architecture (L0 fabric gate + L1 clock page + SMU code absence)
- Verified no in-scope legitimate path (all external-master writes drop)
- Identified SMU queue-overflow exploit as path forward
- **Iter #23:** Executed exploit successfully (clocks, enables, gates all respond)
- **Iter #24:** Released gates manually, discovered root isolation gate
- **Iter #25:** Planned firmware decompilation (this session's task)

**Key documents:**
- `EXHAUSTION_LOG.md` — Read this for full context
- `vcn_exploit_execution_2026_09_06.txt` — Live execution proof

---

## What's NOT Your Job

❌ Run exploit again (already done, persistent)
❌ Modify board state (already settled)
❌ Write new SMU code (depends on your findings)
❌ Test on BC-250 (decompilation first)
❌ Publish to community yet (that's after analysis)

**Just: Decompile FUN_00023b14 and document what's missing.**

---

## When Done

1. Update `COMMUNITY_REPORT_2026_09_06.md` with firmware findings
2. Create `FUN_00023b14_ANALYSIS.md` with full decompilation
3. Both files ready for community publication
4. Clear statement: "Here's what firmware does. Here's what we're missing. This is the next test to run."

**That's your deliverable.**

---

## You're All Set

Everything is on anima. Ghidra is available. The guide is clear. The question is specific: "What does FUN_00023b14 do that --direct-load doesn't?"

**Answer that and we have the next major milestone.**

---

**Session End:** 2026-09-06 Session 1 (Breakthrough)  
**Next Session:** 2026-09-?? Session 2 (Firmware Deep-Dive)  
**Status:** Ready for Ghidra analysis
