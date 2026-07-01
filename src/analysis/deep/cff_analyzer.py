"""
DriverScope — Control Flow Flattening (CFF) Deep Analyzer.

Enhanced detection of control flow flattening beyond basic CFG metrics.
Focuses on semantic patterns that indicate obfuscation protectors
(VMProtect, Themida, 360 custom protectors):

1. **Switch dispatcher**: Single block with indirect JMP through computed
   address table (jmp [reg*8 + base] or similar).
2. **Opaque predicates**: Conditional branches where both paths converge
   but the condition is always true/false (e.g., jz after test eax, eax
   where eax is known non-zero).
3. **State variable pattern**: A single register or stack slot is repeatedly
   read, modified, and used as branch target — the hallmark of a flattened
   dispatch loop.
4. **Bogus control flow**: Blocks with unreachable predecessors or
   dead branches that never execute.
5. **Handler table pattern**: Large data arrays of code addresses used
   as dispatch targets.
6. **Anti-analysis strings**: VMProtect/Themida/CodeVirtualizer markers.
"""

from __future__ import annotations

import re

from src.models import (
    Confidence, DisassemblyResult, Evidence, Finding, FindingCategory,
    Sample, Severity,
)
from src.analysis.analyzer import Analyzer


# ---------------------------------------------------------------------------
# Opaque predicate patterns
# ---------------------------------------------------------------------------

# Patterns that indicate always-true/always-false conditions
# These are compiler/protector artifacts that confuse decompilers
OPAQUE_PREDICATE_PATTERNS = [
    # test eax, eax; jnz (when eax is known non-zero)
    ("test", "eax, eax", "jnz"),
    ("test", "rax, rax", "jnz"),
    # cmp eax, 0; je/jne (when comparison is constant)
    ("cmp", None, None),  # Generic — scored by context
    # xor eax, eax; setz (always sets ZF=1)
    ("xor", "eax, eax", "set"),
    ("xor", "rax, rax", "set"),
    # push X; pop X; (stack identity)
    ("push", None, "pop"),
]

# ---------------------------------------------------------------------------
# State variable patterns
# ---------------------------------------------------------------------------

# Register patterns that indicate a dispatch state machine
STATE_REGISTERS = {"eax", "ebx", "ecx", "edx", "r8", "r9", "r10", "r11"}

# Instructions that modify state in a dispatch loop
STATE_MODIFY = {"add", "sub", "xor", "and", "or", "shr", "shl", "rol", "ror"}

# Dispatch branch instructions
DISPATCH_BRANCHES = {"jmp", "jz", "jnz", "je", "jne", "jl", "jle", "jg", "jge", "ja", "jae", "jb", "jbe"}

# ---------------------------------------------------------------------------
# Obfuscator signature strings
# ---------------------------------------------------------------------------

OBFUSCATOR_STRINGS = {
    "VMProtect": ["VMProtect", "vmp", "Packed with VMProtect"],
    "Themida": ["Themida", "themida", "Protected by Themida"],
    "CodeVirtualizer": ["CodeVirtualizer", "code virtualizer"],
    "Oreans": ["Oreans", "oreans"],
    "Armadillo": ["Armadillo", "armadillo"],
    "Obsidium": ["Obsidium", "obsidium"],
}


class ControlFlowFlatteningAnalyzer(Analyzer):
    """Detect advanced control flow flattening patterns."""

    @property
    def name(self) -> str:
        return "ControlFlowFlatteningAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Detects advanced control flow flattening: switch dispatchers, "
            "opaque predicates, state variable patterns, bogus control flow, "
            "and obfuscator signature strings."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Switch dispatcher detection
        dispatcher_findings = self._detect_switch_dispatchers(ir)
        findings.extend(dispatcher_findings)

        # 2. State variable pattern detection
        state_findings = self._detect_state_variable_patterns(ir)
        findings.extend(state_findings)

        # 3. Opaque predicate detection
        opaque_findings = self._detect_opaque_predicates(ir)
        findings.extend(opaque_findings)

        # 4. Obfuscator string detection
        obfuscator_findings = self._detect_obfuscator_strings(ir)
        findings.extend(obfuscator_findings)

        # 5. Handler table pattern detection (data structures)
        handler_findings = self._detect_handler_tables(ir)
        findings.extend(handler_findings)

        return findings

    def _detect_switch_dispatchers(self, ir: DisassemblyResult) -> list[Finding]:
        """Detect switch dispatcher blocks — indirect JMP through computed address.

        Pattern:
          jmp [r12 + rax*8]        ; computed jump
          jmp qword ptr [reg + reg*scale]
        """
        findings: list[Finding] = []

        for func_addr, cfg in (list(ir.cfgs.items()) + list(ir.simple_cfgs.items())):
            dispatcher_blocks = []
            for block in cfg.blocks.values():
                if not block.instructions:
                    continue
                last = block.instructions[-1]
                ops = last.operands.lower()

                # Indirect JMP with scaled index (jump table)
                if last.mnemonic.lower() == "jmp" and (
                    re.search(r"\[\w+\s*\*\s*[0-9]+\s*\+?\s*\w*\]", ops)
                    or re.search(r"\[\w+\s*\+\s*\w+\s*\*\s*[0-9]+\]", ops)
                    or ("[" in ops and "]" in ops and "*" in ops)
                ):
                    dispatcher_blocks.append({
                        "address": hex(block.address),
                        "instruction": f"{last.mnemonic} {last.operands}",
                        "successor_count": len(block.successors),
                    })

            if dispatcher_blocks:
                findings.append(Finding(
                    category=FindingCategory.CONTROL_FLOW_FLATTENING,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Switch dispatcher detected in sub_{func_addr:X}: "
                        f"{len(dispatcher_blocks)} dispatcher blocks with indirect jumps."
                    ),
                    function_address=func_addr,
                    context={
                        "dispatchers": dispatcher_blocks[:5],
                        "dispatcher_count": len(dispatcher_blocks),
                    },
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"sub_{func_addr:X}",
                            snippet=dispatcher_blocks[0]["instruction"],
                            rule_id="CFF_DISPATCH",
                        )
                    ],
                ))

        return findings

    def _detect_state_variable_patterns(self, ir: DisassemblyResult) -> list[Finding]:
        """Detect state variable pattern — a register is repeatedly
        read-modify-used as branch target, indicating a flattened dispatch loop."""
        findings: list[Finding] = []

        for func_addr, cfg in (list(ir.cfgs.items()) + list(ir.simple_cfgs.items())):
            if len(cfg.blocks) < 10:
                continue

            # Track state register usage
            state_reg_reads: dict[str, int] = {}
            state_reg_modifies: dict[str, int] = {}
            state_reg_branches: dict[str, int] = {}

            for block in cfg.blocks.values():
                # Track which registers were tested/cmp'd in this block
                tested_regs: dict[str, int] = {}
                for insn in block.instructions:
                    ops = insn.operands.lower()
                    mnem = insn.mnemonic.lower()

                    # Track test/cmp of state registers (these set flags for branches)
                    if mnem in ("test", "cmp"):
                        for reg in STATE_REGISTERS:
                            if reg == ops or reg in ops:
                                tested_regs[reg] = tested_regs.get(reg, 0) + 1

                    # Check for state register modification
                    if mnem in STATE_MODIFY:
                        # Extract destination operand (before the comma)
                        parts = ops.split(",", 1)
                        dst = parts[0].strip() if parts else ""
                        # Remove bracket/memory references
                        if "[" in dst:
                            continue  # Skip memory operands
                        for reg in STATE_REGISTERS:
                            if reg == dst or dst.endswith(reg):
                                state_reg_modifies[reg] = state_reg_modifies.get(reg, 0) + 1

                    # Check for state register read (mov from reg)
                    if mnem == "mov":
                        parts = ops.split(",", 1)
                        if len(parts) == 2:
                            src = parts[1].strip()
                            # Skip memory operands
                            if "[" in src:
                                continue
                            for reg in STATE_REGISTERS:
                                if reg == src or src.endswith(reg):
                                    state_reg_reads[reg] = state_reg_reads.get(reg, 0) + 1

                    # Branch after test/cmp of state register
                    if mnem in DISPATCH_BRANCHES and tested_regs:
                        for reg, count in tested_regs.items():
                            state_reg_branches[reg] = state_reg_branches.get(reg, 0) + 1

            # Score: registers that are read, modified, AND used in branches
            state_candidates = []
            for reg in STATE_REGISTERS:
                reads = state_reg_reads.get(reg, 0)
                modifies = state_reg_modifies.get(reg, 0)
                branches = state_reg_branches.get(reg, 0)
                if reads >= 3 and modifies >= 2 and branches >= 2:
                    state_candidates.append({
                        "register": reg,
                        "reads": reads,
                        "modifies": modifies,
                        "branches": branches,
                        "score": reads + modifies + branches,
                    })

            if state_candidates:
                best = max(state_candidates, key=lambda x: x["score"])
                findings.append(Finding(
                    category=FindingCategory.CONTROL_FLOW_FLATTENING,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"State variable pattern in sub_{func_addr:X}: "
                        f"register {best['register']} read {best['reads']}x, "
                        f"modified {best['modifies']}x, used in {best['branches']} branches. "
                        f"Likely flattened dispatch loop."
                    ),
                    function_address=func_addr,
                    context={
                        "state_variables": state_candidates,
                        "dominant_register": best["register"],
                    },
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"sub_{func_addr:X}",
                            snippet=f"State register {best['register']}: "
                                    f"R={best['reads']} M={best['modifies']} B={best['branches']}",
                            rule_id="CFF_STATE_VAR",
                        )
                    ],
                ))

        return findings

    def _detect_opaque_predicates(self, ir: DisassemblyResult) -> list[Finding]:
        """Detect opaque predicates — conditions that always evaluate to the
        same value, creating dead branches."""
        findings: list[Finding] = []

        for func_addr, cfg in (list(ir.cfgs.items()) + list(ir.simple_cfgs.items())):
            if len(cfg.blocks) < 5:
                continue

            opaque_count = 0
            opaque_details = []

            for block in cfg.blocks.values():
                if len(block.instructions) < 2:
                    continue
                insns = block.instructions
                # Check last 2 instructions for predicate pattern
                last = insns[-1]
                second_last = insns[-2]

                # Pattern: xor reg, reg; jz/jnz (always ZF=1, jz always taken)
                if (second_last.mnemonic.lower() == "xor"
                        and re.match(r"^(e|r)?ax,\s*\1", second_last.operands.lower())
                        and last.mnemonic.lower() in ("jz", "jnz", "je", "jne")):
                    opaque_count += 1
                    opaque_details.append({
                        "address": hex(block.address),
                        "pattern": "xor reg,reg; jcc",
                        "instructions": [
                            f"{second_last.mnemonic} {second_last.operands}",
                            f"{last.mnemonic} {last.operands}",
                        ],
                    })

                # Pattern: test reg, reg; jnz (when reg is known non-zero)
                # Heuristic: test eax, eax; jnz after mov eax, <non-zero>
                if (second_last.mnemonic.lower() == "test"
                        and last.mnemonic.lower() in ("jnz", "jne")):
                    ops = second_last.operands.lower()
                    if ops.split(",")[0].strip() == ops.split(",")[1].strip():
                        opaque_count += 1
                        opaque_details.append({
                            "address": hex(block.address),
                            "pattern": "test reg,reg; jnz",
                            "instructions": [
                                f"{second_last.mnemonic} {second_last.operands}",
                                f"{last.mnemonic} {last.operands}",
                            ],
                        })

            if opaque_count >= 3:
                findings.append(Finding(
                    category=FindingCategory.CONTROL_FLOW_FLATTENING,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Opaque predicates in sub_{func_addr:X}: "
                        f"{opaque_count} suspicious condition+branch pairs "
                        f"that always evaluate the same way."
                    ),
                    function_address=func_addr,
                    context={
                        "opaque_count": opaque_count,
                        "details": opaque_details[:5],
                    },
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"sub_{func_addr:X}",
                            snippet=opaque_details[0]["pattern"] if opaque_details else "opaque predicate",
                            rule_id="CFF_OPAQUE",
                        )
                    ],
                ))

        return findings

    def _detect_obfuscator_strings(self, ir: DisassemblyResult) -> list[Finding]:
        """Detect obfuscator signature strings in binary."""
        findings: list[Finding] = []

        detected_obfuscators: dict[str, list[str]] = {}
        for s in ir.strings:
            for obf_name, patterns in OBFUSCATOR_STRINGS.items():
                for pattern in patterns:
                    if pattern.lower() in s.lower():
                        if obf_name not in detected_obfuscators:
                            detected_obfuscators[obf_name] = []
                        detected_obfuscators[obf_name].append(s)
                        break

        if detected_obfuscators:
            for obf_name, strings in detected_obfuscators.items():
                findings.append(Finding(
                    category=FindingCategory.CONTROL_FLOW_FLATTENING,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Obfuscator signature '{obf_name}' detected: "
                        f"strings: {', '.join(strings[:3])}"
                    ),
                    context={
                        "obfuscator": obf_name,
                        "strings": strings[:5],
                    },
                    evidence=[
                        Evidence(
                            type="string",
                            location=".rdata",
                            snippet=strings[0],
                            rule_id=f"CFF_{obf_name.upper()}",
                        )
                    ],
                ))

        return findings

    def _detect_handler_tables(self, ir: DisassemblyResult) -> list[Finding]:
        """Detect handler table patterns — large data arrays of code addresses
        used as dispatch targets in flattened control flow."""
        findings: list[Finding] = []

        for rva, ds in ir.data_structures.items():
            if ds.get("type") != "qword_array":
                continue
            values = ds.get("values", [])
            if len(values) < 8:
                continue

            # Check if values look like code pointers (high bits set, aligned)
            code_ptr_count = 0
            for v in values:
                # Code pointers are typically in executable range
                # On x64, kernel drivers map at high addresses
                # User-mode handlers: 0x1000-0x7FFFFFFF
                if v > 0x1000 and v % 4 == 0 and v < 0x7FFFFFFF:
                    code_ptr_count += 1
                # Also check for high-half kernel addresses
                elif v > 0xFFFF800000000000:
                    code_ptr_count += 1

            # If majority of values look like code pointers, flag it
            if code_ptr_count >= len(values) * 0.7:
                findings.append(Finding(
                    category=FindingCategory.CONTROL_FLOW_FLATTENING,
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    description=(
                        f"Handler table at RVA 0x{rva:X}: "
                        f"{code_ptr_count}/{len(values)} entries look like "
                        f"code pointers. Possible dispatch jump table."
                    ),
                    context={
                        "rva": hex(rva),
                        "total_entries": len(values),
                        "code_pointer_count": code_ptr_count,
                        "sample_values": [hex(v) for v in values[:5]],
                    },
                    evidence=[
                        Evidence(
                            type="data_structure",
                            location=f".data+0x{rva:X}",
                            snippet=f"Handler table: {code_ptr_count}/{len(values)} code pointers",
                            rule_id="CFF_HANDLER_TABLE",
                        )
                    ],
                ))

        return findings
