"""
DriverScope — Wide String Analyzer.

Extracts UTF-16 (wide) strings from PE .rdata/.data sections
and detects UNICODE_STRING struct construction patterns.

Windows kernel uses Unicode extensively: device names
(\\\\Device\\Xxx), registry paths (\\\\Registry\\Machine\\...),
and API names are all UTF-16 encoded.
"""

from __future__ import annotations

import re
from pathlib import Path

from src.analysis.analyzer import Analyzer
from src.models import Confidence, DisassemblyResult, Finding, FindingCategory, Sample, Severity


class WideStringAnalyzer(Analyzer):
    """Extract UTF-16 strings from PE sections and detect UNICODE_STRING construction."""

    name = "WideStringAnalyzer"
    description = "UTF-16 string extraction and UNICODE_STRING construction detection"

    # UNICODE_STRING construction patterns
    UNICODE_STRING_LEN_RE = re.compile(
        r"mov\s+word\s+ptr\s+\[",
        re.IGNORECASE,
    )
    UNICODE_STRING_BUF_RE = re.compile(
        r"lea\s+\w+,\s*\[",
        re.IGNORECASE,
    )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # Extract wide strings from PE sections
        wide_strings = self._extract_wide_strings(sample.path)
        ir.wide_strings = wide_strings

        for ws in wide_strings:
            severity = Severity.INFO
            hint = self._classify_wide_string(ws["string"])
            if hint:
                severity = Severity.LOW
                findings.append(Finding(
                    category=FindingCategory.WIDE_STRING_FOUND,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    description=f"Wide string: \"{ws['string']}\" ({hint})",
                    context={
                        "string": ws["string"],
                        "section": ws.get("section", ""),
                        "rva": ws.get("rva", 0),
                        "category": hint,
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"{ws.get('section', 'unknown')} @ 0x{ws.get('rva', 0):X}",
                        "snippet": ws["string"],
                        "rule_id": "WS001",
                    }],
                ))

        # Detect UNICODE_STRING construction patterns
        unicode_constructs = self._detect_unicode_string_constructs(ir)
        for uc in unicode_constructs:
            findings.append(Finding(
                category=FindingCategory.WIDE_STRING_FOUND,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                description=f"UNICODE_STRING constructed in func 0x{uc['func_addr']:X} (length={uc['length']})",
                function_address=uc["func_addr"],
                context={
                    "length": uc["length"],
                    "max_length": uc["max_length"],
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": f"func 0x{uc['func_addr']:X}",
                    "snippet": uc["pattern"],
                    "rule_id": "WS002",
                }],
            ))

        return findings

    def _extract_wide_strings(self, pe_path: Path) -> list[dict]:
        """Extract UTF-16 strings from PE .rdata/.data sections."""
        try:
            import pefile
            pe = pefile.PE(str(pe_path), fast_load=True)
        except Exception:
            return []

        results = []
        target_sections = {".rdata", ".data", "PAGE", ".rodata"}

        for section in pe.sections:
            name = section.Name.decode("ascii", errors="replace").rstrip("\x00")
            if name not in target_sections:
                continue

            try:
                raw_data = section.get_data()
            except Exception:
                continue

            # Scan for UTF-16 strings: alternating printable ASCII + null byte
            i = 0
            while i < len(raw_data) - 4:
                if raw_data[i + 1] == 0 and 0x20 <= raw_data[i] <= 0x7E:
                    # Start of potential wide string
                    chars = []
                    start = i
                    j = i
                    while j + 1 < len(raw_data) and raw_data[j + 1] == 0 and 0x20 <= raw_data[j] <= 0x7E:
                        chars.append(chr(raw_data[j]))
                        j += 2

                    s = "".join(chars)
                    if len(s) >= 3:
                        rva = section.VirtualAddress + (start - section.PointerToRawData)
                        results.append({
                            "string": s,
                            "section": name,
                            "rva": rva,
                            "length": len(s) * 2,
                        })
                        i = j
                    else:
                        i += 2
                else:
                    i += 1

        pe.close()
        return results

    def _detect_unicode_string_constructs(self, ir: DisassemblyResult) -> list[dict]:
        """Detect UNICODE_STRING construction patterns in CFGs."""
        results = []

        for func_addr, cfg in ir.cfgs.items():
            # Look for pattern: mov word ptr [X], len; mov word ptr [Y], max_len; lea Z, [buf]
            has_len = False
            has_max_len = False
            has_buf = False
            pattern_parts = []

            for block_addr, block in cfg.blocks.items():
                for insn in block.instructions:
                    text = f"{insn.mnemonic} {insn.operands}"
                    if self.UNICODE_STRING_LEN_RE.search(text):
                        has_len = True
                        pattern_parts.append(text.strip())
                    if has_len and self.UNICODE_STRING_BUF_RE.search(text):
                        has_buf = True
                        pattern_parts.append(text.strip())
                        break

            if has_len and has_buf:
                results.append({
                    "func_addr": func_addr,
                    "pattern": "; ".join(pattern_parts[:3]),
                    "length": 0,
                    "max_length": 0,
                })

        return results

    def _classify_wide_string(self, s: str) -> str | None:
        """Classify a wide string by its content pattern."""
        if s.startswith("\\Device\\"):
            return "device_path"
        if s.startswith("\\DosDevices\\") or s.startswith("\\??\\"):
            return "dos_device_path"
        if s.startswith("\\Registry\\") or s.startswith("HKLM\\") or s.startswith("HKCU\\"):
            return "registry_path"
        if s.startswith("C:\\") or s.startswith("\\SystemRoot\\"):
            return "file_path"
        if s.startswith("http://") or s.startswith("https://"):
            return "url"
        if "\\" in s and s.endswith(".sys"):
            return "driver_path"
        if "\\system32\\" in s.lower() or "\\windows\\" in s.lower():
            return "system_path"
        return None
