"""
DriverScope — Stack String Analyzer.

Reconstructs strings built byte-by-byte on the stack via
`mov byte/word ptr [stack_reg+offset], imm8` sequences.

Supports:
- x64: `mov byte ptr [rsp+offset], imm8`
- x86: `mov byte ptr [esp+offset], imm8` or `mov byte ptr [ebp-offset], imm8`

Detects both ASCII (byte writes) and UTF-16 (word writes) stack strings.
Windows kernel drivers frequently use this to hide device names,
registry paths, and API names from static string extraction.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from src.analysis.analyzer import Analyzer
from src.models import Confidence, DisassemblyResult, Finding, FindingCategory, Sample, Severity


class StackStringAnalyzer(Analyzer):
    """Reconstruct stack-built strings from mov byte/word ptr [stack_reg+offset/N], imm."""

    name = "StackStringAnalyzer"
    description = "Reconstruct stack-built strings (mov byte/word ptr [stack+N], imm)"

    # x64 Capstone patterns
    BYTE_WRITE_RE = re.compile(
        r"mov\s+byte\s+ptr\s+\[rsp\+([0-9a-fx]+)\],\s*(?:0x)?([0-9a-f]+)",
        re.IGNORECASE,
    )
    WORD_WRITE_RE = re.compile(
        r"mov\s+word\s+ptr\s+\[rsp\+([0-9a-fx]+)\],\s*(?:0x)?([0-9a-f]+)",
        re.IGNORECASE,
    )

    # x86 Capstone patterns
    BYTE_WRITE_X86_RE = re.compile(
        r"mov\s+byte\s+ptr\s+\[(?:esp\+([0-9a-fx]+)|ebp-([0-9a-fx]+))\],\s*(?:0x)?([0-9a-f]+)",
        re.IGNORECASE,
    )
    WORD_WRITE_X86_RE = re.compile(
        r"mov\s+word\s+ptr\s+\[(?:esp\+([0-9a-fx]+)|ebp-([0-9a-fx]+))\],\s*(?:0x)?([0-9a-f]+)",
        re.IGNORECASE,
    )

    # Ghidra operand format: `mov RSP 0x10, 0x41` or `BYTE PTR [RSP + 0x10], 0x41`
    # Also handles `stack` address space: `BYTE PTR [stack - 0x20]`
    # Ghidra uses uppercase register names and may include size prefix in operands
    BYTE_WRITE_GHIDRA_RE = re.compile(
        r"(?:mov\s+)?(?:byte\s+ptr\s+)?\[(?:(rsp|esp|stack)\s*[\+\-]\s*([0-9a-fx]+))\],?\s*(?:0x)?([0-9a-f]+)"
        r"|(?:mov\s+)?(?:byte\s+ptr\s+)?\[(?:(rbp|ebp)\s*[\-]\s*([0-9a-fx]+))\],?\s*(?:0x)?([0-9a-f]+)"
        r"|(?:mov\s+)(?:(rsp|esp|stack))\s+([0-9a-fx]+),\s*(?:0x)?([0-9a-f]+)",
        re.IGNORECASE,
    )
    WORD_WRITE_GHIDRA_RE = re.compile(
        r"(?:mov\s+)?(?:word\s+ptr\s+)?\[(?:(rsp|esp|stack)\s*[\+\-]\s*([0-9a-fx]+))\],?\s*(?:0x)?([0-9a-f]+)"
        r"|(?:mov\s+)?(?:word\s+ptr\s+)?\[(?:(rbp|ebp)\s*[\-]\s*([0-9a-fx]+))\],?\s*(0x[0-9a-f]+)"
        r"|(?:mov\s+)(?:(rsp|esp|stack))\s+([0-9a-fx]+),\s*(?:0x)?([0-9a-f]+)",
        re.IGNORECASE,
    )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []
        all_stack_strings: list[dict[str, Any]] = []

        all_cfgs = ir.cfgs or ir.simple_cfgs
        for func_addr, cfg in all_cfgs.items():
            func_strings = self._analyze_function(cfg, func_addr)
            all_stack_strings.extend(func_strings)

            for ss in func_strings:
                findings.append(Finding(
                    category=FindingCategory.STACK_STRING_RECONSTRUCTED,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=f"Stack string reconstructed in func 0x{func_addr:X}: \"{ss['string']}\" ({ss['encoding']})",
                    function_address=func_addr,
                    instruction_address=ss["address"],
                    context={
                        "string": ss["string"],
                        "encoding": ss["encoding"],
                        "insn_count": len(ss["insn_addresses"]),
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"func 0x{func_addr:X}",
                        "snippet": ss["string"],
                        "rule_id": "SS001",
                    }],
                ))

        ir.stack_strings = all_stack_strings
        return findings

    def _analyze_function(self, cfg, func_addr: int) -> list[dict[str, Any]]:
        """Scan all basic blocks for stack string patterns."""
        byte_writes: dict[int, tuple[int, int]] = {}
        word_writes: dict[int, tuple[int, int]] = {}

        for block_addr, block in cfg.blocks.items():
            for insn in block.instructions:
                text = f"{insn.mnemonic} {insn.operands}"

                # Try x64 Capstone patterns first
                m = self.BYTE_WRITE_RE.search(text)
                if m:
                    offset = int(m.group(1), 16)
                    value = int(m.group(2), 16)
                    byte_writes[offset] = (value, insn.address)
                    continue

                m = self.WORD_WRITE_RE.search(text)
                if m:
                    offset = int(m.group(1), 16)
                    value = int(m.group(2), 16)
                    word_writes[offset] = (value, insn.address)
                    continue

                # Try x86 Capstone patterns
                m = self.BYTE_WRITE_X86_RE.search(text)
                if m:
                    esp_off = m.group(1)
                    ebp_off = m.group(2)
                    value = int(m.group(3), 16)
                    offset = int(esp_off, 16) if esp_off else -int(ebp_off, 16)
                    byte_writes[offset] = (value, insn.address)
                    continue

                m = self.WORD_WRITE_X86_RE.search(text)
                if m:
                    esp_off = m.group(1)
                    ebp_off = m.group(2)
                    value = int(m.group(3), 16)
                    offset = int(esp_off, 16) if esp_off else -int(ebp_off, 16)
                    word_writes[offset] = (value, insn.address)
                    continue

                # Try Ghidra format patterns
                ghidra_result = self._try_parse_ghidra_byte_write(text)
                if ghidra_result is not None:
                    offset, value = ghidra_result
                    byte_writes[offset] = (value, insn.address)
                    continue

                ghidra_result = self._try_parse_ghidra_word_write(text)
                if ghidra_result is not None:
                    offset, value = ghidra_result
                    word_writes[offset] = (value, insn.address)

        results = []

        # Reconstruct ASCII stack strings from consecutive byte writes
        results.extend(self._reconstruct_ascii(byte_writes, func_addr))

        # Reconstruct UTF-16 stack strings from consecutive word writes
        results.extend(self._reconstruct_utf16(word_writes, func_addr))

        return results

    # ------------------------------------------------------------------
    # Ghidra operand format parsing
    # ------------------------------------------------------------------

    _GHIDRA_BRACKET_BYTE = re.compile(
        r"byte\s+ptr\s+\[([A-Za-z]+)\s*([\+\-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]",
        re.IGNORECASE,
    )
    _GHIDRA_BRACKET_WORD = re.compile(
        r"word\s+ptr\s+\[([A-Za-z]+)\s*([\+\-])\s*(0x[0-9a-fA-F]+|[0-9]+)\]",
        re.IGNORECASE,
    )
    # Immediate after the bracket: `..., 0x41` or `, 0x41`
    _GHIDRA_IMMEDIATE = re.compile(r"(?:\]\s*,?|mov\s+[A-Za-z]+\s+[A-Za-z0-9]+\s*,)\s*(0x[0-9a-fA-F]+|[0-9]+)", re.IGNORECASE)
    # Flat format: `mov RSP 0x20, 0x41`
    _GHIDRA_FLAT_BYTE = re.compile(
        r"mov\s+(RSP|ESP)\s+([0-9a-fx]+),\s*(0x[0-9a-fA-F]+|[0-9]+)",
        re.IGNORECASE,
    )
    _GHIDRA_FLAT_WORD = re.compile(
        r"mov\s+(RSP|ESP)\s+([0-9a-fx]+),\s*(0x[0-9a-fA-F]+|[0-9]+)",
        re.IGNORECASE,
    )

    def _try_parse_ghidra_byte_write(self, text: str) -> tuple[int, int] | None:
        """Parse Ghidra format byte stack write."""
        # Bracket format: `BYTE PTR [RSP + 0x20], 0x41`
        m = self._GHIDRA_BRACKET_BYTE.search(text)
        if m:
            reg = m.group(1).upper()
            sign = m.group(2)
            offset = int(m.group(3), 0)
            if sign == "-":
                offset = -offset
            imm = self._GHIDRA_IMMEDIATE.search(text)
            if imm:
                value = int(imm.group(1), 0)
                return (offset, value)
        # Flat format: `mov RSP 0x20, 0x41`
        m = self._GHIDRA_FLAT_BYTE.search(text)
        if m:
            offset = int(m.group(2), 0)
            value = int(m.group(3), 0)
            return (offset, value)
        return None

    def _try_parse_ghidra_word_write(self, text: str) -> tuple[int, int] | None:
        """Parse Ghidra format word stack write."""
        # Bracket format: `WORD PTR [RSP + 0x20], 0x0041`
        m = self._GHIDRA_BRACKET_WORD.search(text)
        if m:
            reg = m.group(1).upper()
            sign = m.group(2)
            offset = int(m.group(3), 0)
            if sign == "-":
                offset = -offset
            imm = self._GHIDRA_IMMEDIATE.search(text)
            if imm:
                value = int(imm.group(1), 0)
                return (offset, value)
        # Flat format: same as byte but context tells us it's word
        m = self._GHIDRA_FLAT_WORD.search(text)
        if m and "word" in text.lower():
            offset = int(m.group(2), 0)
            value = int(m.group(3), 0)
            return (offset, value)
        return None

    # ------------------------------------------------------------------
    # String reconstruction
    # ------------------------------------------------------------------

    def _reconstruct_ascii(self, writes: dict[int, tuple[int, int]], func_addr: int) -> list[dict]:
        """Reconstruct ASCII strings from consecutive byte writes."""
        if len(writes) < 3:
            return []

        sorted_offsets = sorted(writes.keys())
        results = []

        current_run: list[tuple[int, int, int]] = []
        for offset in sorted_offsets:
            value, insn_addr = writes[offset]
            if not current_run or offset == current_run[-1][0] + 1:
                current_run.append((offset, value, insn_addr))
            else:
                if len(current_run) >= 3:
                    s = self._try_decode_ascii(current_run)
                    if s:
                        results.append(s)
                current_run = [(offset, value, insn_addr)]

        if len(current_run) >= 3:
            s = self._try_decode_ascii(current_run)
            if s:
                results.append(s)

        return results

    def _try_decode_ascii(self, run: list[tuple[int, int, int]]) -> dict | None:
        """Decode a run of byte writes as an ASCII string."""
        chars = []
        insn_addrs = []
        for offset, value, insn_addr in run:
            if value == 0:
                break
            if 0x20 <= value <= 0x7E:
                chars.append(chr(value))
            elif value in (0x0A, 0x0D, 0x09):
                chars.append(chr(value))
            else:
                return None
            insn_addrs.append(insn_addr)

        s = "".join(chars)
        if len(s) >= 3:
            return {
                "address": run[0][2],
                "func_addr": run[0][2],
                "string": s,
                "encoding": "ascii",
                "insn_addresses": insn_addrs,
                "func_name": "",
            }
        return None

    def _reconstruct_utf16(self, writes: dict[int, tuple[int, int]], func_addr: int) -> list[dict]:
        """Reconstruct UTF-16 strings from consecutive word writes."""
        if len(writes) < 2:
            return []

        sorted_offsets = sorted(writes.keys())
        results = []

        current_run: list[tuple[int, int, int]] = []
        for offset in sorted_offsets:
            value, insn_addr = writes[offset]
            if not current_run or offset == current_run[-1][0] + 2:
                current_run.append((offset, value, insn_addr))
            else:
                if len(current_run) >= 2:
                    s = self._try_decode_utf16(current_run)
                    if s:
                        results.append(s)
                current_run = [(offset, value, insn_addr)]

        if len(current_run) >= 2:
            s = self._try_decode_utf16(current_run)
            if s:
                results.append(s)

        return results

    def _try_decode_utf16(self, run: list[tuple[int, int, int]]) -> dict | None:
        """Decode a run of word writes as a UTF-16 string."""
        chars = []
        insn_addrs = []
        for offset, value, insn_addr in run:
            if value == 0:
                break
            if 0x20 <= value <= 0x7E:
                chars.append(chr(value))
            else:
                return None
            insn_addrs.append(insn_addr)

        s = "".join(chars)
        if len(s) >= 3:
            return {
                "address": run[0][2],
                "func_addr": run[0][2],
                "string": s,
                "encoding": "utf16",
                "insn_addresses": insn_addrs,
                "func_name": "",
            }
        return None
