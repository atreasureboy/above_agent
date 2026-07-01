"""
DriverScope — Data Structure Analyzer.

Scans PE .rdata/.data sections for structured data:
- DWORD arrays (IOCTL codes, constants)
- QWORD arrays (function pointer tables, vtables)
- Hash tables
- String RVA arrays (whitelist/blacklist string tables)
- Encrypted blobs (high-entropy regions)

Identifies data structures used by the driver for dispatch tables,
whitelist/blacklist lookups, and configuration.
"""

from __future__ import annotations

import math
import struct
from pathlib import Path
from typing import Any

from src.analysis.analyzer import Analyzer
from src.models import Confidence, DisassemblyResult, Finding, FindingCategory, Sample, Severity


class DataStructureAnalyzer(Analyzer):
    """Identify structured data in PE .rdata/.data sections."""

    name = "DataStructureAnalyzer"
    description = "PE section data structure identification (arrays, tables, hash tables, encrypted blobs)"

    # CTL_CODE device type ranges
    KNOWN_DEVICE_TYPES = {
        0x00000001: "FILE_DEVICE_BEEP",
        0x00000002: "FILE_DEVICE_CD_ROM",
        0x00000003: "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
        0x00000004: "FILE_DEVICE_CONTROLLER",
        0x00000005: "FILE_DEVICE_DATALINK",
        0x00000006: "FILE_DEVICE_DFS",
        0x00000007: "FILE_DEVICE_DISK",
        0x00000008: "FILE_DEVICE_DISK_FILE_SYSTEM",
        0x00000009: "FILE_DEVICE_FILE_SYSTEM",
        0x0000000A: "FILE_DEVICE_INPORT_PORT",
        0x0000000B: "FILE_DEVICE_KEYBOARD",
        0x0000000E: "FILE_DEVICE_MAILSLOT",
        0x0000000F: "FILE_DEVICE_MIDI_IN",
        0x00000010: "FILE_DEVICE_MIDI_OUT",
        0x00000011: "FILE_DEVICE_MOUSE",
        0x00000012: "FILE_DEVICE_MULTI_UNC_PROVIDER",
        0x00000013: "FILE_DEVICE_NAMED_PIPE",
        0x00000014: "FILE_DEVICE_NETWORK",
        0x00000015: "FILE_DEVICE_NETWORK_BROWSER",
        0x00000016: "FILE_DEVICE_NETWORK_FILE_SYSTEM",
        0x00000017: "FILE_DEVICE_NULL",
        0x00000018: "FILE_DEVICE_PARALLEL_PORT",
        0x00000019: "FILE_DEVICE_PHYSICAL_NETCARD",
        0x0000001A: "FILE_DEVICE_PRINTER",
        0x0000001B: "FILE_DEVICE_SCANNER",
        0x0000001C: "FILE_DEVICE_SERIAL_MOUSE_PORT",
        0x0000001D: "FILE_DEVICE_SERIAL_PORT",
        0x0000001E: "FILE_DEVICE_SCREEN",
        0x0000001F: "FILE_DEVICE_SOUND",
        0x00000020: "FILE_DEVICE_STREAMS",
        0x00000021: "FILE_DEVICE_TAPE",
        0x00000022: "FILE_DEVICE_TAPE_FILE_SYSTEM",
        0x00000023: "FILE_DEVICE_TRANSPORT",
        0x00000024: "FILE_DEVICE_UNKNOWN",
        0x00000025: "FILE_DEVICE_VIDEO",
        0x00000026: "FILE_DEVICE_VIRTUAL_DISK",
        0x00000027: "FILE_DEVICE_WAVE_IN",
        0x00000028: "FILE_DEVICE_WAVE_OUT",
        0x00000029: "FILE_DEVICE_8042_PORT",
        0x0000002A: "FILE_DEVICE_NETWORK_REDIRECTOR",
        0x0000002B: "FILE_DEVICE_BATTERY",
        0x0000002C: "FILE_DEVICE_BUS_EXTENDER",
        0x0000002D: "FILE_DEVICE_MODEM",
        0x0000002E: "FILE_DEVICE_VDM",
        0x00000035: "FILE_DEVICE_RDR",
        0x00000039: "FILE_DEVICE_IEEE1284_4",
        0x00000050: "FILE_DEVICE_KS",
        0x00000061: "FILE_DEVICE_KSEC",
        0x00000080: "FILE_DEVICE_FIPS",
        0x00008000: "FILE_DEVICE_360_CUSTOM",  # 360 uses 0x8000
    }

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []
        data_structures: dict[int, dict[str, Any]] = {}

        try:
            import pefile
            pe = pefile.PE(str(sample.path), fast_load=True)
        except Exception:
            return findings

        target_sections = {".rdata", ".data", "PAGE", ".rodata"}

        for section in pe.sections:
            name = section.Name.decode("ascii", errors="replace").rstrip("\x00")
            if name not in target_sections:
                continue

            try:
                raw_data = section.get_data()
            except Exception:
                continue

            base_rva = section.VirtualAddress

            # DWORD array analysis
            findings.extend(self._analyze_dword_arrays(
                raw_data, base_rva, name, ir, data_structures
            ))

            # QWORD array analysis (function pointers, vtables)
            findings.extend(self._analyze_qword_arrays(
                raw_data, base_rva, name, ir, data_structures
            ))

            # Entropy analysis for encrypted blobs
            findings.extend(self._analyze_entropy_regions(
                raw_data, base_rva, name, data_structures
            ))

        ir.data_structures = data_structures
        pe.close()
        return findings

    def _analyze_dword_arrays(
        self, data: bytes, base_rva: int, section_name: str,
        ir: DisassemblyResult, data_structures: dict
    ) -> list[Finding]:
        """Find contiguous DWORD arrays with semantic meaning."""
        findings = []
        if len(data) < 16:
            return findings

        # Scan for runs of >= 4 consecutive DWORDs
        i = 0
        while i < len(data) - 16:
            # Check if next 4+ dwords look like a coherent array
            if i + 16 > len(data):
                break

            dword_count = 0
            j = i
            values = []
            while j + 4 <= len(data):
                val = struct.unpack_from("<I", data, j)[0]
                if val == 0:
                    break
                values.append(val)
                dword_count += 1
                j += 4
                if dword_count >= 64:  # max run
                    break

            if dword_count >= 4:
                rva = base_rva + i
                ioctl_match = self._check_ioctl_codes(values)
                func_ptr_match = self._check_function_pointers(values)

                if ioctl_match:
                    semantic = f"IOCTL codes ({len(ioctl_match)} matched)"
                    data_structures[rva] = {
                        "type": "dword_array",
                        "section": section_name,
                        "element_count": dword_count,
                        "element_size": 4,
                        "semantic_hint": semantic,
                        "sample_values": values[:10],
                        "ioctl_codes": ioctl_match,
                    }
                    findings.append(Finding(
                        category=FindingCategory.DATA_STRUCTURE_IDENTIFIED,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"IOCTL code table at {section_name}:0x{rva:X} ({dword_count} entries, {len(ioctl_match)} matched)",
                        instruction_address=rva,
                        context={
                            "rva": rva,
                            "section": section_name,
                            "type": "ioctl_table",
                            "element_count": dword_count,
                            "matched_codes": [hex(c) for c in ioctl_match[:20]],
                        },
                        evidence=[{
                            "type": "instruction_pattern",
                            "location": f"{section_name}:0x{rva:X}",
                            "snippet": f"[{', '.join(hex(c) for c in ioctl_match[:5])}]",
                            "rule_id": "DS001",
                        }],
                    ))
                elif func_ptr_match:
                    data_structures[rva] = {
                        "type": "qword_array",
                        "section": section_name,
                        "element_count": dword_count,
                        "element_size": 4,
                        "semantic_hint": "Possible address table",
                        "sample_values": values[:10],
                    }
                else:
                    # Generic dword array — could be hashes, constants, etc.
                    entropy = self._shannon_entropy(b"".join(v.to_bytes(4, "little") for v in values[:50]))
                    if entropy > 5.5:
                        semantic = "High-entropy (possible hash table or encrypted)"
                    elif entropy < 2.0:
                        semantic = "Low-entropy (possible constants or padding)"
                    else:
                        semantic = "Mixed entropy (possible data table)"

                    data_structures[rva] = {
                        "type": "dword_array",
                        "section": section_name,
                        "element_count": dword_count,
                        "element_size": 4,
                        "entropy": round(entropy, 2),
                        "semantic_hint": semantic,
                        "sample_values": values[:10],
                    }

                i = j
            else:
                i += 4

        return findings

    def _analyze_qword_arrays(
        self, data: bytes, base_rva: int, section_name: str,
        ir: DisassemblyResult, data_structures: dict
    ) -> list[Finding]:
        """Find contiguous QWORD arrays (function pointer tables, vtables)."""
        findings = []
        if len(data) < 32:
            return findings

        i = 0
        while i < len(data) - 32:
            if i + 32 > len(data):
                break

            qword_count = 0
            j = i
            values = []
            while j + 8 <= len(data):
                val = struct.unpack_from("<Q", data, j)[0]
                if val == 0:
                    break
                values.append(val)
                qword_count += 1
                j += 8
                if qword_count >= 64:
                    break

            if qword_count >= 4:
                rva = base_rva + i
                # Check if values look like function pointers (within code section range)
                code_section = None
                try:
                    import pefile
                    pe = pefile.PE(str(ir.sample_path), fast_load=True)
                    for sec in pe.sections:
                        if b"text" in sec.Name or b"PAGE" in sec.Name:
                            code_section = sec
                            break
                    pe.close()
                except Exception:
                    pass

                in_code_count = 0
                if code_section:
                    code_start = code_section.VirtualAddress
                    code_end = code_start + code_section.Misc_VirtualSize
                    for v in values:
                        if code_start <= v < code_end:
                            in_code_count += 1

                if in_code_count >= len(values) * 0.6:
                    data_structures[rva] = {
                        "type": "qword_array",
                        "section": section_name,
                        "element_count": qword_count,
                        "element_size": 8,
                        "semantic_hint": f"Function pointer table ({in_code_count}/{qword_count} in code section)",
                        "sample_values": [hex(v) for v in values[:10]],
                    }
                    findings.append(Finding(
                        category=FindingCategory.DATA_STRUCTURE_IDENTIFIED,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"Function pointer table at {section_name}:0x{rva:X} ({qword_count} entries)",
                        instruction_address=rva,
                        context={
                            "rva": rva,
                            "section": section_name,
                            "type": "function_pointer_table",
                            "element_count": qword_count,
                            "in_code_section": in_code_count,
                        },
                        evidence=[{
                            "type": "instruction_pattern",
                            "location": f"{section_name}:0x{rva:X}",
                            "snippet": f"[{', '.join(str(v) for v in values[:3])}]",
                            "rule_id": "DS002",
                        }],
                    ))

                i = j
            else:
                i += 8

        return findings

    def _analyze_entropy_regions(
        self, data: bytes, base_rva: int, section_name: str,
        data_structures: dict
    ) -> list[Finding]:
        """Find high-entropy regions that may be encrypted data."""
        findings = []
        window_size = 64

        for i in range(0, len(data) - window_size, window_size // 2):
            chunk = data[i:i + window_size]
            entropy = self._shannon_entropy(chunk)
            if entropy > 6.5:
                rva = base_rva + i
                data_structures[rva] = {
                    "type": "encrypted_blob",
                    "section": section_name,
                    "element_count": window_size,
                    "element_size": 1,
                    "entropy": round(entropy, 2),
                    "semantic_hint": "High entropy — possible encrypted data",
                }
                findings.append(Finding(
                    category=FindingCategory.DATA_STRUCTURE_IDENTIFIED,
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description=f"High-entropy region at {section_name}:0x{rva:X} (entropy={entropy:.2f}, possible encrypted data)",
                    instruction_address=rva,
                    context={
                        "rva": rva,
                        "section": section_name,
                        "type": "encrypted_blob",
                        "entropy": round(entropy, 2),
                        "size": window_size,
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"{section_name}:0x{rva:X}",
                        "snippet": f"entropy={entropy:.2f}",
                        "rule_id": "DS003",
                    }],
                ))

        return findings

    def _check_ioctl_codes(self, values: list[int]) -> list[int]:
        """Check if DWORD values look like CTL_CODE IOCTL codes."""
        matched = []
        for v in values:
            device_type = (v >> 16) & 0xFFFF
            if device_type in self.KNOWN_DEVICE_TYPES:
                matched.append(v)
        return matched

    def _check_function_pointers(self, values: list[int]) -> bool:
        """Check if DWORD values could be function pointer offsets."""
        # If all values are similar magnitude and non-zero, might be pointers
        if not values:
            return False
        min_v = min(values)
        max_v = max(values)
        return min_v > 0x1000 and max_v < 0xFFFF0000 and (max_v - min_v) < 0x100000

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Compute Shannon entropy of a byte sequence."""
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        length = len(data)
        entropy = 0.0
        for f in freq:
            if f > 0:
                p = f / length
                entropy -= p * math.log2(p)
        return entropy
