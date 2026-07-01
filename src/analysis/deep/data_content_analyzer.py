"""
DriverScope — Data Content Analyzer.

Interprets the actual content of data structures identified by DataStructureAnalyzer:
- String RVA arrays: DWORD values that point to strings (whitelist/blacklist process names,
  device paths, registry keys)
- Function pointer tables: DWORD/QWORD values pointing to code, resolved to function names
- Known constant tables: NTSTATUS codes, Windows object type flags, IOCTL function codes
- Purpose inference: classifies data tables by their content patterns

Generic framework — applies to any Windows driver, not just 360.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path
from typing import Any

from src.analysis.analyzer import Analyzer
from src.models import (
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)

# ---------------------------------------------------------------------------
# Known constant databases
# ---------------------------------------------------------------------------

NTSTATUS_CODES: dict[int, str] = {
    0x00000000: "STATUS_SUCCESS",
    0x00000001: "STATUS_WAIT_1",
    0xC0000001: "STATUS_UNSUCCESSFUL",
    0xC0000002: "STATUS_NOT_IMPLEMENTED",
    0xC0000003: "STATUS_INVALID_INFO_CLASS",
    0xC0000004: "STATUS_INFO_LENGTH_MISMATCH",
    0xC0000005: "STATUS_ACCESS_VIOLATION",
    0xC0000006: "STATUS_IN_PAGE_ERROR",
    0xC0000008: "STATUS_INVALID_HANDLE",
    0xC000000D: "STATUS_INVALID_PARAMETER",
    0xC000000E: "STATUS_NO_SUCH_DEVICE",
    0xC000000F: "STATUS_NO_SUCH_FILE",
    0xC0000010: "STATUS_INVALID_DEVICE_REQUEST",
    0xC0000011: "STATUS_END_OF_FILE",
    0xC0000013: "STATUS_NO_MEDIA_IN_DEVICE",
    0xC0000017: "STATUS_NO_MEMORY",
    0xC0000018: "STATUS_CONFLICTING_ADDRESSES",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC0000024: "STATUS_OBJECT_TYPE_MISMATCH",
    0xC0000033: "STATUS_OBJECT_NAME_INVALID",
    0xC0000034: "STATUS_OBJECT_NAME_NOT_FOUND",
    0xC0000035: "STATUS_OBJECT_NAME_COLLISION",
    0xC00000BB: "STATUS_NOT_SUPPORTED",
    0xC00000FD: "STATUS_STACK_OVERFLOW",
    0xC000010A: "STATUS_PROCESS_IS_TERMINATING",
    0xC0000225: "STATUS_NOT_FOUND",
    0xC0000368: "STATUS_INVALID_IMAGE_HASH",
}

# Patterns for string-based classification
PROCESS_NAME_RE = re.compile(r"^[\w\-]+\.exe$", re.IGNORECASE)
DRIVER_NAME_RE = re.compile(r"^[\w\-]+\.sys$", re.IGNORECASE)
DEVICE_PATH_RE = re.compile(r"^\\\\(Device|DosDevices)\\", re.IGNORECASE)
REGISTRY_PATH_RE = re.compile(r"^\\\\(Registry|HKLM|HKCU)\\\\", re.IGNORECASE)
DLL_NAME_RE = re.compile(r"^[\w\-]+\.dll$", re.IGNORECASE)
IP_ADDRESS_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
GUID_RE = re.compile(
    r"^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$"
)

# API name pattern: Windows API names (Nt*, Zw*, Rtl*, etc.) or common Win32 API names
API_NAME_RE = re.compile(
    r"^(Nt|Zw|Rtl|Ex|Ke|Io|Mm|Ps|Se|Ob|Cm|Lpc|Alpc|Ldr)"
    r"[A-Z][a-zA-Z0-9]+$"
)
WIN32_API_RE = re.compile(
    r"^(Create|Open|Close|Read|Write|Delete|Set|Get|Find|Send|Recv)"
    r"[A-Z][a-zA-Z0-9]+$"
)

# Minimum distinct NTSTATUS codes to qualify as a status table
MIN_NTSTATUS_DISTINCT = 2


class DataContentAnalyzer(Analyzer):
    """Interpret data structure content: string tables, function pointers, constants."""

    name = "DataContentAnalyzer"
    description = "Data content semantic analysis (string RVA arrays, function pointer tables, constant tables)"

    @property
    def is_correlator(self) -> bool:
        """Must run after DataStructureAnalyzer has populated ir.data_structures."""
        return True

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        if not ir.data_structures:
            return findings

        # Build string RVA lookup for fast matching
        string_rvas: dict[int, str] = {}
        if ir.string_rvas:
            if isinstance(ir.string_rvas, dict):
                string_rvas = dict(ir.string_rvas)
            elif isinstance(ir.string_rvas, list):
                # MemoryMapAnalyzer stores list[dict] — extract individual strings
                for entry in ir.string_rvas:
                    if isinstance(entry, dict):
                        for s in entry.get("strings", []):
                            table_rva = entry.get("table_rva", 0)
                            if s:
                                string_rvas[table_rva] = s
        for entry in getattr(ir, "string_locations", []):
            if "rva" in entry and "value" in entry:
                string_rvas[entry["rva"]] = entry["value"]

        # Determine image base for VA→RVA conversion
        image_base = self._get_image_base(sample.path)

        # Determine code section range for function pointer detection
        code_start, code_end = self._get_code_range(sample.path)

        # Load PE for raw byte reading
        try:
            import pefile
            pe = pefile.PE(str(sample.path), fast_load=True)
        except Exception:
            pe = None

        for rva, ds in ir.data_structures.items():
            element_count = ds.get("element_count", 0)
            element_size = ds.get("element_size", 0)
            ds_type = ds.get("type", "")
            section = ds.get("section", "")
            section_rva = self._section_rva_for_ds(rva, ds)

            # Read full array values from PE if available (DataStructureAnalyzer only stores first 10)
            all_values = self._read_array_values(pe, section_rva, element_count, element_size) if pe else ds.get("sample_values", [])

            # --- String RVA array detection ---
            if ds_type == "dword_array" and element_size == 4 and element_count >= 4:
                str_findings = self._check_string_rva_array(
                    rva, ds, string_rvas, all_values, image_base, pe
                )
                findings.extend(str_findings)

            # --- Function pointer table resolution ---
            if ds_type in ("dword_array", "qword_array") and element_count >= 4:
                fp_findings = self._check_function_pointer_table(
                    rva, ds, all_values, code_start, code_end, ir, element_size
                )
                findings.extend(fp_findings)

            # --- NTSTATUS constant table detection ---
            if ds_type == "dword_array" and element_size == 4 and element_count >= 4:
                nt_findings = self._check_ntstatus_table(rva, ds, all_values)
                findings.extend(nt_findings)

        # --- Comprehensive purpose inference (combines all signals) ---
        if ir.data_references or ir.data_xrefs:
            inference_findings = self._infer_table_purpose(
                ir.data_structures, ir.data_references, ir.string_rvas, ir.comparison_traces
            )
            findings.extend(inference_findings)

        if pe:
            pe.close()

        return findings

    # ------------------------------------------------------------------
    # PE section helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _read_array_values(pe, array_rva: int | None, count: int, element_size: int) -> list[int]:
        """Read array elements from PE at the given RVA."""
        if pe is None or array_rva is None or count == 0 or element_size == 0:
            return []

        total_size = count * element_size
        if total_size > 1024 * 1024:  # cap at 1MB
            return []

        raw = None
        for section in pe.sections:
            sec_start = section.VirtualAddress
            sec_end = sec_start + section.Misc_VirtualSize
            if sec_start <= array_rva < sec_end:
                offset = array_rva - sec_start
                raw = section.get_data()
                if offset + total_size <= len(raw):
                    data = raw[offset:offset + total_size]
                else:
                    data = raw[offset:]
                    count = len(data) // element_size
                break

        if not data:
            return []

        values = []
        fmt = {1: "B", 2: "<H", 4: "<I", 8: "<Q"}.get(element_size)
        if fmt is None:
            return []

        for i in range(count):
            try:
                values.append(struct.unpack_from(fmt, data, i * element_size)[0])
            except Exception:
                break
        return values

    @staticmethod
    def _section_rva_for_ds(rva: int, ds: dict) -> int | None:
        """Get the base RVA of a data structure from its stored info."""
        return rva

    @staticmethod
    def _get_image_base(pe_path: str) -> int | None:
        """Get PE image base address."""
        try:
            import pefile
            pe = pefile.PE(str(pe_path), fast_load=True)
            base = pe.OPTIONAL_HEADER.ImageBase
            pe.close()
            return base
        except Exception:
            return None

    @staticmethod
    def _get_code_range(pe_path: str) -> tuple[int | None, int | None]:
        """Get (start_rva, end_rva) of the code section."""
        try:
            import pefile
            pe = pefile.PE(str(pe_path), fast_load=True)
            for sec in pe.sections:
                name = sec.Name.decode("ascii", errors="replace").rstrip("\x00")
                chars = sec.Characteristics
                if (chars & 0x20000000) or (chars & 0x00000020) or b"text" in sec.Name or b"PAGE" in sec.Name:
                    start = sec.VirtualAddress
                    end = start + sec.Misc_VirtualSize
                    pe.close()
                    return start, end
            pe.close()
        except Exception:
            pass
        return None, None

    @staticmethod
    def _read_string_at_rva(pe, rva: int, max_len: int = 128) -> str | None:
        """Try to read an ASCII string at a given RVA.

        If the RVA points to the middle of a string (e.g. ``"iceToDosName"``
        instead of ``"DeviceToDosName"``), scans backwards to find the
        string start (first non-printable byte + 1).
        """
        if pe is None:
            return None

        for section in pe.sections:
            sec_start = section.VirtualAddress
            sec_end = sec_start + section.Misc_VirtualSize
            if sec_start <= rva < sec_end:
                offset = rva - sec_start
                raw = section.get_data()
                if offset >= len(raw):
                    return None

                # Scan backwards to find the string start (first non-printable byte)
                start = offset
                search_back = min(offset, 32)  # look back at most 32 bytes
                for i in range(offset - 1, offset - search_back - 1, -1):
                    if i < 0:
                        break
                    b = raw[i]
                    if 0x20 <= b <= 0x7E:
                        start = i
                    else:
                        break

                # Read until null byte or max_len
                end = raw.find(b"\x00", start)
                if end == -1:
                    end = min(start + max_len, len(raw))
                else:
                    end = min(end, start + max_len)
                try:
                    s = raw[start:end].decode("ascii")
                    if len(s) >= 3 and all(0x20 <= ord(c) <= 0x7E for c in s):
                        return s
                except (UnicodeDecodeError, ValueError):
                    pass
                return None
        return None

    # ------------------------------------------------------------------
    # String RVA array detection
    # ------------------------------------------------------------------

    def _check_string_rva_array(
        self,
        rva: int,
        ds: dict,
        string_rvas: dict[int, str],
        values: list[int],
        image_base: int | None,
        pe,
    ) -> list[Finding]:
        """Check if DWORD values are RVAs pointing to strings."""
        findings = []
        if not values:
            return findings

        matched_strings = []

        for val in values:
            # Try direct RVA match
            if val in string_rvas:
                matched_strings.append(string_rvas[val])
                continue
            # Try as VA (subtract image base)
            if image_base and val > image_base:
                candidate_rva = val - image_base
                if candidate_rva in string_rvas:
                    matched_strings.append(string_rvas[candidate_rva])
                    continue
            # Try to read string directly at this RVA from PE
            s = self._read_string_at_rva(pe, val)
            if s and len(s) >= 3:
                matched_strings.append(s)

        if len(matched_strings) >= 3:
            total_checked = len(values)
            match_ratio = len(matched_strings) / max(total_checked, 1)
            confidence = Confidence.HIGH if match_ratio > 0.7 else Confidence.MEDIUM

            purpose = self._classify_string_purpose(matched_strings)

            snippet = ", ".join(matched_strings[:5])
            if len(matched_strings) > 5:
                snippet += f" ... (+{len(matched_strings) - 5} more)"

            findings.append(Finding(
                category=FindingCategory.STRING_TABLE_IDENTIFIED,
                severity=Severity.MEDIUM if purpose != "unknown" else Severity.LOW,
                confidence=confidence,
                description=(
                    f"String table at 0x{rva:X} ({ds['section']}): "
                    f"{len(matched_strings)}/{total_checked} entries match strings — "
                    f"purpose: {purpose}"
                ),
                instruction_address=rva,
                context={
                    "rva": rva,
                    "section": ds.get("section", ""),
                    "type": "string_table",
                    "matched_count": len(matched_strings),
                    "total_count": total_checked,
                    "match_ratio": round(match_ratio, 2),
                    "purpose": purpose,
                    "sample_strings": matched_strings[:10],
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": f"{ds.get('section', '')}:0x{rva:X}",
                    "snippet": snippet,
                    "rule_id": "DC001",
                }],
            ))

        return findings

    # ------------------------------------------------------------------
    # Function pointer table resolution
    # ------------------------------------------------------------------

    def _check_function_pointer_table(
        self,
        rva: int,
        ds: dict,
        values: list[int],
        code_start: int | None,
        code_end: int | None,
        ir: DisassemblyResult,
        element_size: int,
    ) -> list[Finding]:
        """Check if array values are function pointers and resolve names."""
        findings = []
        if code_start is None or code_end is None or not values:
            return findings

        resolved_funcs = []

        for val in values[:30]:  # Check first 30 entries
            if code_start <= val < code_end:
                func_name = None
                if val in ir.functions:
                    func_name = ir.functions[val].name
                elif val in ir.simple_cfgs:
                    func_name = f"sub_{val:X}"

                if func_name:
                    resolved_funcs.append(func_name)
                else:
                    resolved_funcs.append(f"sub_{val:X}")

        if len(resolved_funcs) >= 4:
            total_checked = len(values)
            findings.append(Finding(
                category=FindingCategory.DATA_CONTENT_ANALYZED,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                description=(
                    f"Function pointer table at 0x{rva:X} ({ds['section']}): "
                    f"{len(resolved_funcs)}/{total_checked} resolved — "
                    f"[{', '.join(resolved_funcs[:5])}{'...' if len(resolved_funcs) > 5 else ''}]"
                ),
                instruction_address=rva,
                context={
                    "rva": rva,
                    "section": ds.get("section", ""),
                    "type": "function_pointer_table",
                    "resolved_count": len(resolved_funcs),
                    "total_count": total_checked,
                    "function_names": resolved_funcs[:10],
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": f"{ds.get('section', '')}:0x{rva:X}",
                    "snippet": ", ".join(resolved_funcs[:5]),
                    "rule_id": "DC002",
                }],
            ))

        return findings

    # ------------------------------------------------------------------
    # NTSTATUS constant table detection
    # ------------------------------------------------------------------

    def _check_ntstatus_table(
        self, rva: int, ds: dict, values: list[int]
    ) -> list[Finding]:
        """Check if DWORD values are NTSTATUS codes."""
        findings = []
        if not values:
            return findings

        matched_codes: list[str] = []
        distinct_codes: set[str] = set()

        for val in values[:50]:
            if val in NTSTATUS_CODES:
                code_name = NTSTATUS_CODES[val]
                matched_codes.append(code_name)
                distinct_codes.add(code_name)

        # Require at least MIN_NTSTATUS_DISTINCT distinct codes to avoid
        # false positives from repeated 0x00000001 or 0x00000000
        if len(distinct_codes) >= MIN_NTSTATUS_DISTINCT and len(matched_codes) >= 3:
            findings.append(Finding(
                category=FindingCategory.DATA_CONTENT_ANALYZED,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                description=(
                    f"NTSTATUS code table at 0x{rva:X} ({ds['section']}): "
                    f"{len(matched_codes)} matches, {len(distinct_codes)} distinct — "
                    f"[{', '.join(sorted(distinct_codes)[:8])}]"
                ),
                instruction_address=rva,
                context={
                    "rva": rva,
                    "section": ds.get("section", ""),
                    "type": "ntstatus_table",
                    "matched_count": len(matched_codes),
                    "distinct_count": len(distinct_codes),
                    "matched_codes": sorted(distinct_codes)[:10],
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": f"{ds.get('section', '')}:0x{rva:X}",
                    "snippet": ", ".join(sorted(distinct_codes)[:5]),
                    "rule_id": "DC003",
                }],
            ))

        return findings

    # ------------------------------------------------------------------
    # Purpose inference (combines all signals)
    # ------------------------------------------------------------------

    def _infer_table_purpose(
        self,
        data_structures: dict,
        data_references: list,
        string_rvas: dict[int, str],
        comparison_traces: list,
    ) -> list[Finding]:
        """Infer the purpose of data tables based on content and usage patterns."""
        findings = []

        # Build a map of RVA -> reference count
        rva_ref_count: dict[int, int] = {}
        for ref in data_references:
            target = ref.get("rva", 0)
            rva_ref_count[target] = rva_ref_count.get(target, 0) + 1

        # Build a map of RVA -> comparison traces
        rva_cmp_count: dict[int, int] = {}
        for trace in comparison_traces:
            target = trace.get("data_rva")
            if target and target in data_structures:
                rva_cmp_count[target] = rva_cmp_count.get(target, 0) + 1

        # Find hot tables with many references and comparisons
        for rva, ds in data_structures.items():
            ref_count = rva_ref_count.get(rva, 0)
            cmp_count = rva_cmp_count.get(rva, 0)

            # A table that is both heavily referenced AND compared against
            # is likely a whitelist/blacklist or lookup table
            if ref_count >= 10 and cmp_count >= 3:
                hint = ds.get("semantic_hint", "")
                element_count = ds.get("element_count", 0)

                findings.append(Finding(
                    category=FindingCategory.DATA_CONTENT_ANALYZED,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Hot lookup table at 0x{rva:X}: "
                        f"referenced {ref_count} times, "
                        f"compared {cmp_count} times, "
                        f"{element_count} entries — "
                        f"likely whitelist/blacklist/config table"
                    ),
                    instruction_address=rva,
                    context={
                        "rva": rva,
                        "reference_count": ref_count,
                        "comparison_count": cmp_count,
                        "element_count": element_count,
                        "semantic_hint": hint,
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"0x{rva:X}",
                        "snippet": f"refs={ref_count}, cmps={cmp_count}",
                        "rule_id": "DC004",
                    }],
                ))

        return findings

    # ------------------------------------------------------------------
    # String purpose classification
    # ------------------------------------------------------------------

    @staticmethod
    def _classify_string_purpose(strings: list[str]) -> str:
        """Classify the purpose of a string table based on its content."""
        if not strings:
            return "unknown"

        categories = {
            "process_names": 0,
            "driver_names": 0,
            "device_paths": 0,
            "registry_paths": 0,
            "dll_names": 0,
            "ip_addresses": 0,
            "guids": 0,
            "api_names": 0,
        }

        for s in strings:
            if PROCESS_NAME_RE.match(s):
                categories["process_names"] += 1
            elif DRIVER_NAME_RE.match(s):
                categories["driver_names"] += 1
            elif DEVICE_PATH_RE.match(s):
                categories["device_paths"] += 1
            elif REGISTRY_PATH_RE.match(s):
                categories["registry_paths"] += 1
            elif DLL_NAME_RE.match(s):
                categories["dll_names"] += 1
            elif IP_ADDRESS_RE.match(s):
                categories["ip_addresses"] += 1
            elif GUID_RE.match(s):
                categories["guids"] += 1
            elif API_NAME_RE.match(s) or WIN32_API_RE.match(s):
                categories["api_names"] += 1

        dominant = max(categories, key=categories.get)
        count = categories[dominant]

        if count >= 2:  # At least 2 matches of a category to classify
            return {
                "process_names": "process whitelist/blacklist",
                "driver_names": "driver whitelist/blacklist",
                "device_paths": "device path table",
                "registry_paths": "registry path table",
                "dll_names": "DLL whitelist/blacklist",
                "ip_addresses": "IP address table",
                "guids": "GUID/CLSID table",
                "api_names": "API name lookup table",
            }[dominant]

        # Mixed categories — still try to give useful label
        active = {k: v for k, v in categories.items() if v > 0}
        if len(active) >= 2:
            parts = []
            if active.get("process_names"):
                parts.append("process list")
            if active.get("api_names"):
                parts.append("API names")
            if active.get("driver_names"):
                parts.append("driver list")
            if active.get("device_paths"):
                parts.append("device paths")
            if active.get("registry_paths"):
                parts.append("registry paths")
            if parts:
                return f"mixed {' + '.join(parts[:3])}"
            return "mixed identifier table"

        return "unknown"
