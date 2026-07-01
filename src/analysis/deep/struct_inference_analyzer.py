"""
DriverScope — Structure Inference Analyzer.

Infers driver-defined structure layouts from register+offset access patterns:
- x64: `[rcx+0x10]`, `[rdx+8]`, `[rax+0x20]`
- x86: `[eax+0x10]`, `[ecx+8]`, `[esi+0x20]`
- C++ vtable detection: `call qword ptr [rax]` (x64) / `call dword ptr [eax]` (x86)

Detects custom kernel structures used by the driver for:
- Device extension structs
- Request context objects
- Whitelist/blacklist entry structures
- C++ objects with virtual method tables
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from src.analysis.analyzer import Analyzer
from src.models import Confidence, DisassemblyResult, Finding, FindingCategory, Sample, Severity


class StructInferenceAnalyzer(Analyzer):
    """Infer structure layouts from [reg+offset] access patterns (x64 + x86)."""

    name = "StructInferenceAnalyzer"
    description = "Structure layout inference from register+offset memory accesses (x64 + x86)"

    # x64: rcx, rdx, r8-r15 are common struct base registers
    # x86: eax, ecx, edx, ebx, esi, edi are common struct base registers

    # Capstone / AT&T format: [reg+offset]
    MEM_ACCESS_RE_BRACKET = re.compile(
        r"\[(rcx|rdx|r8|r9|r10|r11|rax|rbx|rsi|rdi|r12|r13|r14|r15"
        r"|eax|ecx|edx|ebx|esi|edi)\+([0-9a-fx]+)\]",
        re.IGNORECASE,
    )

    # Ghidra format: `RDX 0x38, RBX` means `[rdx+0x38], rbx`
    # Pattern: REG HEX/DEC followed by a comma (memory write) or as second operand
    # Include RBP for stack-based struct access (common in prologue/epilogue)
    MEM_ACCESS_RE_GHIDRA = re.compile(
        r"(rcx|rdx|r8|r9|r10|r11|rax|rbx|rsi|rdi|r12|r13|r14|r15|rbp"
        r"|eax|ecx|edx|ebx|esi|edi|ebp)\s+"
        r"(0x[0-9a-fA-F]+|[0-9]+)"
        r"(?:\s*,|\s*$)",
        re.IGNORECASE,
    )

    # Vtable call patterns (x64 and x86)
    VTABLE_CALL_RE = re.compile(
        r"call\s+(?:q|d)word\s+ptr\s+\[(rax|rcx|rdx|rbx|rsi|rdi|r[8-9]|r1[0-5]|eax|ecx|edx|ebx|esi|edi)(?:\+([0-9a-fx]+))?\]",
        re.IGNORECASE,
    )

    # Minimum distinct offsets to consider a struct
    MIN_FIELD_COUNT = 3

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        all_cfgs = ir.cfgs or ir.simple_cfgs
        for func_addr, cfg in all_cfgs.items():
            # Collect struct access patterns
            struct_accesses = self._collect_struct_accesses(cfg)

            # Infer struct layouts
            for reg, offsets in struct_accesses.items():
                if len(offsets) < self.MIN_FIELD_COUNT:
                    continue

                inferred = self._infer_struct(reg, sorted(offsets), func_addr)
                if inferred:
                    findings.append(Finding(
                        category=FindingCategory.STRUCT_INFERRED,
                        severity=Severity.INFO,
                        confidence=Confidence.MEDIUM,
                        description=inferred["description"],
                        function_address=func_addr,
                        context={
                            "register": reg,
                            "field_offsets": inferred["field_offsets"],
                            "field_sizes": inferred["field_sizes"],
                            "estimated_size": inferred["estimated_size"],
                            "access_count": inferred["access_count"],
                        },
                        evidence=[{
                            "type": "instruction_pattern",
                            "location": f"func 0x{func_addr:X}",
                            "snippet": inferred["snippet"],
                            "rule_id": "SI001",
                        }],
                    ))

            # Detect C++ vtable usage
            vtable_patterns = self._detect_vtable_calls(cfg, func_addr)
            for vp in vtable_patterns:
                findings.append(Finding(
                    category=FindingCategory.CPP_OBJECT_DETECTED,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description=vp["description"],
                    function_address=func_addr,
                    context={
                        "object_register": vp["object_reg"],
                        "vtable_offset": vp["vtable_offset"],
                        "method_count": vp["method_count"],
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"func 0x{func_addr:X}",
                        "snippet": vp["snippet"],
                        "rule_id": "SI002",
                    }],
                ))

        return findings

    def _collect_struct_accesses(self, cfg) -> dict[str, set[int]]:
        """Collect all [reg+offset] accesses per register.

        Handles both Capstone format (`[rcx+0x10]`) and Ghidra format
        (`RCX 0x10, RAX`).
        """
        reg_offsets: dict[str, set[int]] = defaultdict(set)

        for block_addr, block in cfg.blocks.items():
            for insn in block.instructions:
                full_text = f"{insn.mnemonic} {insn.operands}"

                # Capstone / bracket format
                m = self.MEM_ACCESS_RE_BRACKET.search(full_text)
                if m:
                    reg = m.group(1).lower()
                    offset = int(m.group(2), 0)
                    reg_offsets[reg].add(offset)
                    continue

                # Ghidra format: REG OFFSET, ...
                m = self.MEM_ACCESS_RE_GHIDRA.search(full_text)
                if m:
                    reg = m.group(1).lower()
                    offset = int(m.group(2), 0)
                    reg_offsets[reg].add(offset)
                    continue

        return reg_offsets

    def _infer_struct(
        self, reg: str, offsets: list[int], func_addr: int
    ) -> dict[str, Any] | None:
        """Infer a struct layout from a set of offsets."""
        if not offsets:
            return None

        field_sizes = []
        for i in range(len(offsets) - 1):
            gap = offsets[i + 1] - offsets[i]
            if gap <= 1:
                field_sizes.append(1)
            elif gap <= 2:
                field_sizes.append(2)
            elif gap <= 4:
                field_sizes.append(4)
            elif gap <= 8:
                field_sizes.append(8)
            else:
                field_sizes.append(gap)

        if field_sizes:
            last_gap = offsets[-1] - offsets[-2] if len(offsets) > 1 else 8
            field_sizes[-1] = min(last_gap, 8)

        estimated_size = offsets[-1] + (field_sizes[-1] if field_sizes else 8)

        field_strs = []
        for off, sz in zip(offsets, field_sizes):
            field_strs.append(f"+0x{off:02X}({sz})")

        return {
            "field_offsets": offsets,
            "field_sizes": field_sizes,
            "estimated_size": estimated_size,
            "access_count": len(offsets),
            "description": (
                f"Inferred struct via {reg} in func 0x{func_addr:X}: "
                f"{len(offsets)} fields, size ~{estimated_size} bytes "
                f"[{', '.join(field_strs)}]"
            ),
            "snippet": f"[{reg}+0x{offsets[0]:X}], [{reg}+0x{offsets[-1]:X}]",
        }

    def _detect_vtable_calls(self, cfg, func_addr: int) -> list[dict[str, Any]]:
        """Detect C++ vtable call patterns."""
        results = []
        vtable_calls: dict[str, list[int]] = defaultdict(list)

        for block_addr, block in cfg.blocks.items():
            for insn in block.instructions:
                full_text = f"{insn.mnemonic} {insn.operands}"
                m = self.VTABLE_CALL_RE.search(full_text)
                if m:
                    reg = m.group(1).lower()
                    vtable_offset = int(m.group(2), 0) if m.group(2) else 0
                    vtable_calls[reg].append(vtable_offset)

        for reg, offsets in vtable_calls.items():
            if len(offsets) >= 2:
                results.append({
                    "object_reg": reg,
                    "vtable_offset": offsets[0],
                    "method_count": len(offsets),
                    "description": (
                        f"C++ vtable usage via {reg} in func 0x{func_addr:X}: "
                        f"{len(offsets)} virtual method calls"
                    ),
                    "snippet": f"call dword ptr [{reg}+0x{offsets[0]:X}]",
                })

        return results
