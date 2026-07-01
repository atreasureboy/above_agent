"""
DriverScope — Comparison Tracer.

Traces `cmp` and `test` instructions to their data sources,
detecting whitelist/blacklist check patterns.

Supports:
- x64: `cmp reg, [rip+offset]`
- x86: `cmp reg, [0xXXXXXXXX]` (direct address) or `cmp reg, [ebp+offset]`

Core logic for finding hidden whitelist/blacklist tables:
1. Find cmp against memory (RIP-relative or direct address)
2. Resolve the target address
3. Cross-reference against known data structures from DataStructureAnalyzer
4. If the compared-against data is in a DWORD/QWORD array, flag as
   whitelist/blacklist check
5. Track array iteration patterns: cmp in a loop = array iteration check
"""

from __future__ import annotations

import re
from typing import Any

from src.analysis.analyzer import Analyzer
from src.models import Confidence, DisassemblyResult, Finding, FindingCategory, Sample, Severity


class ComparisonTracer(Analyzer):
    """Trace cmp/test instructions to data sources, detect whitelist/blacklist checks."""

    name = "ComparisonTracer"
    description = "Comparison instruction tracing for whitelist/blacklist detection (x64 + x86)"

    # cmp patterns
    CMP_IMM_RE = re.compile(
        r"cmp\s+\w+,\s*(?:0x)?([0-9a-f]+)",
        re.IGNORECASE,
    )
    # x64: cmp reg, [rip+offset]
    CMP_RIP_MEM_RE = re.compile(
        r"cmp\s+\w+,\s*\[rip\+([^\]]+)\]",
        re.IGNORECASE,
    )
    # x86: cmp reg, [0xXXXXXXXX]
    CMP_X86_ADDR_RE = re.compile(
        r"cmp\s+\w+,\s*\[(?:dword\s+|byte\s+|word\s+)?(0x[0-9a-f]+)\]",
        re.IGNORECASE,
    )
    TEST_RE = re.compile(
        r"test\s+\w+,\s*\[rip\+([^\]]+)\]",
        re.IGNORECASE,
    )
    TEST_X86_ADDR_RE = re.compile(
        r"test\s+\w+,\s*\[(?:dword\s+|byte\s+|word\s+)?(0x[0-9a-f]+)\]",
        re.IGNORECASE,
    )

    # Patterns suggesting whitelist/blacklist logic
    WHITELIST_KEYWORDS = {
        "allow", "whitelist", "trusted", "safe", "good", "pass",
        "skip", "continue", "ok", "valid", "known",
    }
    BLACKLIST_KEYWORDS = {
        "block", "blacklist", "deny", "untrusted", "bad", "fail",
        "reject", "error", "invalid", "unknown", "malicious",
    }

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []
        cmp_traces: list[dict[str, Any]] = []

        known_data_rvas = set(ir.data_structures.keys())

        all_cfgs = ir.cfgs or ir.simple_cfgs
        for func_addr, cfg in all_cfgs.items():
            func_traces = self._analyze_function(cfg, func_addr, known_data_rvas, ir)
            cmp_traces.extend(func_traces)

            for trace in func_traces:
                severity = Severity.INFO
                category = FindingCategory.ARRAY_ITERATION_CMP

                if trace["is_whitelist_check"]:
                    category = FindingCategory.WHITELIST_CHECK_DETECTED
                    severity = Severity.MEDIUM
                elif trace["is_blacklist_check"]:
                    category = FindingCategory.BLACKLIST_CHECK_DETECTED
                    severity = Severity.MEDIUM

                findings.append(Finding(
                    category=category,
                    severity=severity,
                    confidence=Confidence.HIGH if trace["data_rva"] else Confidence.MEDIUM,
                    description=trace["description"],
                    function_address=func_addr,
                    instruction_address=trace["insn_addr"],
                    context={
                        "insn_text": trace["insn_text"],
                        "data_rva": trace["data_rva"],
                        "is_whitelist": trace["is_whitelist_check"],
                        "is_blacklist": trace["is_blacklist_check"],
                        "is_array_iteration": trace["is_array_iteration"],
                        "compared_value": trace["compared_value"],
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"func 0x{func_addr:X}",
                        "snippet": trace["insn_text"],
                        "rule_id": "CT001" if trace["data_rva"] else "CT002",
                    }],
                ))

        ir.comparison_traces = cmp_traces
        return findings

    def _analyze_function(
        self, cfg, func_addr: int, known_data_rvas: set, ir: DisassemblyResult
    ) -> list[dict[str, Any]]:
        """Scan a function for cmp/test patterns."""
        traces = []

        for block_addr, block in cfg.blocks.items():
            for insn in block.instructions:
                full_text = f"{insn.mnemonic} {insn.operands}"

                # x64: cmp against RIP-relative memory
                rva = self._resolve_cmp_rva(insn, block_addr)
                is_x86 = False

                # x86: cmp against direct address
                if rva is None:
                    rva = self._resolve_x86_cmp_addr(insn)
                    is_x86 = rva is not None

                if rva is not None:
                    is_whitelist, is_blacklist = self._classify_check(
                        full_text, rva, ir
                    )
                    is_array_iter = self._is_array_iteration(block, insn.address)

                    compared_val = "memory"
                    if rva in known_data_rvas:
                        ds = ir.data_structures[rva]
                        compared_val = ds.get("semantic_hint", "known_data")

                    traces.append({
                        "insn_addr": insn.address,
                        "insn_text": full_text,
                        "data_rva": rva,
                        "compared_value": compared_val,
                        "is_whitelist_check": is_whitelist,
                        "is_blacklist_check": is_blacklist,
                        "is_array_iteration": is_array_iter,
                        "description": self._build_description(
                            insn, rva, full_text, is_whitelist, is_blacklist, ir
                        ),
                    })
                else:
                    # cmp against immediate
                    m = self.CMP_IMM_RE.search(full_text)
                    if m:
                        imm_val = int(m.group(1), 16)
                        is_whitelist, is_blacklist = self._check_imm_hint(imm_val)
                        traces.append({
                            "insn_addr": insn.address,
                            "insn_text": full_text,
                            "data_rva": None,
                            "compared_value": hex(imm_val),
                            "is_whitelist_check": is_whitelist,
                            "is_blacklist_check": is_blacklist,
                            "is_array_iteration": False,
                            "description": f"cmp immediate 0x{imm_val:X} in func 0x{func_addr:X}",
                        })

        return traces

    def _resolve_cmp_rva(self, insn, block_addr: int) -> int | None:
        """Resolve RIP-relative offset from a cmp instruction (x64)."""
        operands = insn.operands
        match = re.search(r"\[rip\+([^\]]+)\]", operands)
        if not match:
            return None
        offset_str = match.group(1).strip()
        try:
            offset = int(offset_str, 16)
        except ValueError:
            return None
        rip = insn.address + insn.size
        return rip + offset

    def _resolve_x86_cmp_addr(self, insn) -> int | None:
        """Resolve direct address from cmp instruction (x86)."""
        operands = insn.operands
        match = self.CMP_X86_ADDR_RE.search(f"{insn.mnemonic} {operands}")
        if not match:
            return None
        addr_str = match.group(1).strip()
        try:
            return int(addr_str, 16)
        except ValueError:
            return None

    def _classify_check(
        self, insn_text: str, data_rva: int, ir: DisassemblyResult
    ) -> tuple[bool, bool]:
        """Classify if a cmp is a whitelist or blacklist check."""
        lower = insn_text.lower()

        if data_rva in ir.data_structures:
            ds = ir.data_structures[data_rva]
            hint = ds.get("semantic_hint", "").lower()
            if any(kw in hint for kw in ("whitelist", "allow", "trusted", "safe")):
                return True, False
            if any(kw in hint for kw in ("blacklist", "deny", "block", "malicious")):
                return False, True

        for kw in self.WHITELIST_KEYWORDS:
            if kw in lower:
                return True, False
        for kw in self.BLACKLIST_KEYWORDS:
            if kw in lower:
                return False, True

        return False, False

    def _check_imm_hint(self, imm: int) -> tuple[bool, bool]:
        """Check if an immediate value hints at whitelist/blacklist."""
        if imm == 0x00000000:  # STATUS_SUCCESS
            return True, False
        if imm == 0xC0000022:  # STATUS_ACCESS_DENIED
            return False, True
        if imm == 0xC0000001:  # STATUS_UNSUCCESSFUL
            return False, True
        if imm == 0xC000000D:  # STATUS_INVALID_PARAMETER
            return False, True
        if imm == 0xC0000005:  # STATUS_ACCESS_VIOLATION
            return False, True
        if imm == 0xC00000BB:  # STATUS_NOT_SUPPORTED
            return False, True
        return False, False

    def _is_array_iteration(self, block, insn_addr: int) -> bool:
        """Detect if cmp is inside a loop (array iteration pattern)."""
        for succ in getattr(block, "successors", []):
            succ_addr = succ.address if hasattr(succ, "address") else succ
            if succ_addr <= block.address:
                return True
        return False

    def _build_description(
        self, insn, data_rva: int, insn_text: str,
        is_whitelist: bool, is_blacklist: bool, ir: DisassemblyResult
    ) -> str:
        """Build a human-readable description."""
        parts = []
        if data_rva:
            parts.append(f"cmp against data at 0x{data_rva:X}")
            if data_rva in ir.data_structures:
                ds = ir.data_structures[data_rva]
                hint = ds.get("semantic_hint", "")
                if hint:
                    parts.append(f"({hint})")
        else:
            parts.append("cmp immediate")

        if is_whitelist:
            parts.append("— whitelist check")
        elif is_blacklist:
            parts.append("— blacklist check")

        return " ".join(parts)
