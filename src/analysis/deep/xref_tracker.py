"""
DriverScope — Cross-Reference Tracker.

Scans all function CFGs for data-relative memory accesses and builds
a mapping: target_addr -> [(func_addr, insn_addr, access_type, insn_text)].

Supports:
- x64: RIP-relative addressing `[rip+offset]`
- x86: Direct absolute addresses `[0xXXXXXXXX]`

Identifies "hot" data structures (referenced by >= 5 functions)
as likely config tables, whitelists, or global state.
"""

from __future__ import annotations

import re
from typing import Any

from src.analysis.analyzer import Analyzer
from src.models import Confidence, DisassemblyResult, Finding, FindingCategory, Sample, Severity


class XrefTracker(Analyzer):
    """Track data cross-references across all functions (x64 RIP + x86 direct)."""

    name = "XrefTracker"
    description = "Cross-reference tracking for data accesses (x64 RIP + x86 direct)"

    # x64 RIP-relative addressing patterns (Capstone format)
    RIP_READ_PATTERNS = re.compile(
        r"mov\s+\w+,\s*\[rip\+"
        r"|lea\s+\w+,\s*\[rip\+"
        r"|cmp\s+\w+,\s*\[rip\+"
        r"|add\s+\w+,\s*\[rip\+"
        r"|and\s+\w+,\s*\[rip\+"
        r"|or\s+\w+,\s*\[rip\+"
        r"|xor\s+\w+,\s*\[rip\+"
        r"|test\s+\w+,\s*\[rip\+"
    )
    RIP_WRITE_PATTERN = re.compile(r"mov\s+\[rip\+")
    RIP_CALL_PATTERN = re.compile(r"call\s+\[rip\+")

    # Ghidra RIP-relative format: `qword ptr [RIP + 0x1234]` or flat `RIP 0x1234`
    GHIDRA_RIP_PATTERN = re.compile(
        r"\[rip\s*\+\s*(0x[0-9a-fA-F]+|[0-9]+)\]",
        re.IGNORECASE,
    )
    GHIDRA_RIP_FLAT = re.compile(
        r"(?:mov|lea|cmp|add|and|or|xor|test)\s+(\w+)\s*,?\s*rip\s+(0x[0-9a-fA-F]+|[0-9]+)",
        re.IGNORECASE,
    )
    # Ghidra resolved absolute: operand is just a hex address (no register)
    # e.g., `mov RAX, fffff800`12345678` or `mov RAX, 0xfffff80012345678`
    GHIDRA_ABSOLUTE = re.compile(
        r"(?:mov|lea|cmp)\s+(\w+)\s*,?\s*(?:qword\s+ptr\s+)?(0x(?:[0-9a-fA-F]{8,16}))",
        re.IGNORECASE,
    )

    # x86 direct address patterns: [0xXXXXXXXX] or [dword 0xXXXXXXXX]
    X86_ADDR_PATTERN = re.compile(
        r"\[(?:dword\s+|byte\s+|word\s+|qword\s+)?(0x[0-9a-f]+)\]",
        re.IGNORECASE,
    )
    X86_ADDR_READ_PATTERN = re.compile(
        r"mov\s+\w+,\s*\[(?:dword\s+|byte\s+|word\s+|qword\s+)?0x[0-9a-f]+\]"
        r"|cmp\s+\w+,\s*\[(?:dword\s+|byte\s+|word\s+|qword\s+)?0x[0-9a-f]+\]"
        r"|test\s+\w+,\s*\[(?:dword\s+|byte\s+|word\s+|qword\s+)?0x[0-9a-f]+\]",
        re.IGNORECASE,
    )
    X86_ADDR_WRITE_PATTERN = re.compile(
        r"mov\s+\[(?:dword\s+|byte\s+|word\s+|qword\s+)?0x[0-9a-f]+\]",
        re.IGNORECASE,
    )
    X86_ADDR_CALL_PATTERN = re.compile(
        r"call\s+\[(?:dword\s+|byte\s+|word\s+|qword\s+)?0x[0-9a-f]+\]",
        re.IGNORECASE,
    )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []
        addr_refs: dict[int, list[dict[str, Any]]] = {}

        # Build set of valid RVA ranges from PE sections
        valid_ranges, image_base = self._get_section_ranges(sample.path)

        all_cfgs = ir.cfgs or ir.simple_cfgs
        for func_addr, cfg in all_cfgs.items():
            for block_addr, block in cfg.blocks.items():
                for insn in block.instructions:
                    full_text = f"{insn.mnemonic} {insn.operands}"

                    # Try x64 RIP-relative (Capstone bracket format)
                    target = self._resolve_rip_relative(insn, block_addr)

                    # Try Ghidra RIP-relative format
                    if target is None:
                        target = self._resolve_ghidra_rip(insn, block_addr, image_base)

                    # Fall back to x86 direct address
                    if target is None:
                        target = self._resolve_x86_addr(insn)
                        is_x86 = target is not None
                    else:
                        is_x86 = False

                    if target is None:
                        continue

                    # For x86, the address in the instruction is a VA (ImageBase + RVA).
                    # Convert to RVA by subtracting ImageBase, then check against section ranges.
                    if is_x86 and image_base and target >= image_base:
                        rva = target - image_base
                        if not self._is_in_valid_range(rva, valid_ranges):
                            continue
                        target = rva  # Store as RVA for consistency
                    elif is_x86 and valid_ranges:
                        # Already an RVA or no ImageBase — check directly
                        if not self._is_in_valid_range(target, valid_ranges):
                            continue

                    access_type = self._classify_access(full_text, is_x86)
                    ref = {
                        "func_addr": func_addr,
                        "insn_addr": insn.address,
                        "access_type": access_type,
                        "insn_text": full_text,
                    }

                    addr_refs.setdefault(target, []).append(ref)

        # Store in IR
        ir.data_references = [
            {**ref, "rva": addr}
            for addr, refs in addr_refs.items()
            for ref in refs
        ]

        # Build data_xrefs for backward compatibility
        for addr, refs in addr_refs.items():
            for ref in refs:
                func_refs = ir.data_xrefs.setdefault(ref["func_addr"], [])
                func_refs.append({
                    "type": ref["access_type"],
                    "target_addr": addr,
                    "source_insn": ref["insn_addr"],
                })

        # Identify hot data structures
        for addr, refs in addr_refs.items():
            unique_funcs = set(r["func_addr"] for r in refs)
            if len(unique_funcs) >= 5:
                read_count = sum(1 for r in refs if r["access_type"] == "read")
                write_count = sum(1 for r in refs if r["access_type"] == "write")
                findings.append(Finding(
                    category=FindingCategory.XREF_HOT_DATA,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Hot data structure at 0x{addr:X}: "
                        f"referenced by {len(unique_funcs)} functions "
                        f"({read_count} reads, {write_count} writes)"
                    ),
                    instruction_address=addr,
                    context={
                        "rva": addr,
                        "referencing_functions": list(unique_funcs),
                        "read_count": read_count,
                        "write_count": write_count,
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"0x{addr:X}",
                        "snippet": refs[0]["insn_text"],
                        "rule_id": "XREF001",
                    }],
                ))

        return findings

    def _resolve_rip_relative(self, insn, block_addr: int) -> int | None:
        """Resolve RIP-relative offset to an address (x64 Capstone format)."""
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

    def _resolve_ghidra_rip(self, insn, block_addr: int, image_base: int | None) -> int | None:
        """Resolve RIP-relative from Ghidra operand format.

        Handles two formats:
        1. Bracket: `qword ptr [RIP + 0x1234]` → resolves to absolute VA
        2. Flat: `mov RAX, RIP 0x1234` → resolves to absolute VA
        """
        operands = insn.operands
        full_text = f"{insn.mnemonic} {operands}"

        # Bracket format: `[RIP + 0x1234]`
        m = self.GHIDRA_RIP_PATTERN.search(operands)
        if m:
            offset = int(m.group(1), 0)
            rip = insn.address + insn.size
            return rip + offset

        # Flat format: `mov RAX, RIP 0x1234`
        m = self.GHIDRA_RIP_FLAT.search(full_text)
        if m:
            offset = int(m.group(2), 0)
            rip = insn.address + insn.size
            return rip + offset

        # Ghidra may have resolved the RIP-relative to an absolute address.
        # Check if the operand is a large absolute address (VA).
        m = self.GHIDRA_ABSOLUTE.search(full_text)
        if m:
            addr = int(m.group(2), 0)
            # Only accept if it looks like a kernel VA (high address)
            if addr > 0xFFFF000000000000:
                return addr

        return None

    def _resolve_x86_addr(self, insn) -> int | None:
        """Resolve direct address in x86 instruction [0xXXXXXXXX]."""
        operands = insn.operands
        match = self.X86_ADDR_PATTERN.search(operands)
        if not match:
            return None
        addr_str = match.group(1).strip()
        try:
            return int(addr_str, 16)
        except ValueError:
            return None

    def _get_section_ranges(self, pe_path: str) -> tuple[list[tuple[int, int]], int | None]:
        """Get (list of (start_rva, end_rva) tuples, image_base) from PE sections."""
        ranges = []
        image_base = None
        try:
            import pefile
            pe = pefile.PE(str(pe_path), fast_load=True)
            image_base = pe.OPTIONAL_HEADER.ImageBase
            for sec in pe.sections:
                start = sec.VirtualAddress
                end = start + sec.Misc_VirtualSize
                ranges.append((start, end))
            pe.close()
        except Exception:
            pass
        return ranges, image_base

    def _is_in_valid_range(self, addr: int, valid_ranges: list[tuple[int, int]]) -> bool:
        """Check if an RVA falls within any PE section range."""
        for start, end in valid_ranges:
            if start <= addr < end:
                return True
        return False

    def _classify_access(self, insn_text: str, is_x86: bool = False) -> str:
        """Classify access type from instruction text."""
        lower = insn_text.lower()
        if is_x86:
            if self.X86_ADDR_WRITE_PATTERN.search(lower):
                return "write"
            if self.X86_ADDR_CALL_PATTERN.search(lower):
                return "call"
            if lower.startswith("lea "):
                return "address_of"
            return "read"
        else:
            if self.RIP_WRITE_PATTERN.search(lower):
                return "write"
            if self.RIP_CALL_PATTERN.search(lower):
                return "call"
            if lower.startswith("lea "):
                return "address_of"
            return "read"
