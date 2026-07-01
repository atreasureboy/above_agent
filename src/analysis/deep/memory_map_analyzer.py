"""
DriverScope — Memory Map Analyzer.

Locates and interprets runtime-allocated data tables in PE files:
1. **String RVA resolution** — DWORD arrays pointing to string data in PE sections,
   resolved to actual string content and classified as whitelist/blacklist.
2. **Function pointer table resolution** — QWORD arrays pointing into code sections,
   classified as dispatch tables, hook tables, or callback registries.
3. **Known structure inference** — detection of OB_CALLBACK_REGISTRATION,
   FLT_OPERATION_REGISTRATION, and other kernel structure layouts.
4. **Xref tracing** — cross-references from data tables to functions using them,
   detecting cmp-against-table (whitelist/blacklist check) and indirect-call-into-table
   (dispatch) patterns.
5. **Runtime allocation speculation** — identification of ExAllocatePoolWithTag +
   memset/memcpy initialization patterns that suggest runtime-allocated tables.
6. **360-specific whitelist detection** — process name whitelists (.exe suffix),
   path whitelists (\\Device\\, C:\\Program Files\\360\\), and registry path
   whitelists (\\Registry\\Machine\\...).
"""

from __future__ import annotations

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


class MemoryMapAnalyzer(Analyzer):
    """Locate and interpret runtime-allocated data tables in PE files."""

    name = "MemoryMapAnalyzer"
    description = (
        "Dynamic memory table positioning: string RVA resolution, "
        "function pointer table detection, xref tracing, runtime table "
        "speculation, and 360-specific whitelist detection"
    )

    # Process name whitelist patterns
    _EXE_SUFFIX = ".exe"

    # 360 path prefixes
    _360_PATH_PREFIXES = (
        "c:\\program files\\360",
        "c:\\program files (x86)\\360",
        "c:\\windows\\system32\\360",
    )

    # Device path prefixes
    _DEVICE_PREFIXES = (
        "\\device\\",
        "\\dosdevices\\",
        "\\??\\",
    )

    # Registry path prefixes
    _REGISTRY_PREFIXES = (
        "\\registry\\machine\\",
        "\\registry\\user\\",
        "\\registry\\a\\",
        "hklm\\",
        "hkcu\\",
    )

    # Known structure sizes (for structure inference)
    KNOWN_STRUCT_SIZES = {
        0x30: "OB_CALLBACK_REGISTRATION_v1",
        0x38: "OB_CALLBACK_REGISTRATION_v2",
        0x48: "OB_CALLBACK_REGISTRATION_v3",
        0x18: "FLT_OPERATION_REGISTRATION",
        0x30: "FLT_REGISTRATION_v1",
        0x38: "FLT_REGISTRATION_v2",
        0x48: "FLT_REGISTRATION_v3",
    }

    # Pool allocation APIs
    ALLOC_APIS = {
        "ExAllocatePoolWithTag",
        "ExAllocatePool",
        "ExAllocatePool2",
        "ExAllocatePool3",
        "ExAllocatePoolWithTagPriority",
    }

    # Memory initialization APIs
    INIT_APIS = {
        "memset",
        "memcpy",
        "RtlFillMemory",
        "RtlCopyMemory",
        "RtlMoveMemory",
        "RtlZeroMemory",
    }

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # Resolve string RVAs from existing wide strings
        findings.extend(self._resolve_string_rvas(sample, ir))

        # Resolve function pointer tables from existing data structures
        findings.extend(self._resolve_func_ptr_tables(sample, ir))

        # Trace xrefs from data tables to code
        findings.extend(self._trace_xrefs(sample, ir))

        # Speculate runtime-allocated tables
        findings.extend(self._speculate_runtime_tables(sample, ir))

        # 360-specific whitelist detection
        findings.extend(self._detect_360_whitelist(sample, ir))

        return findings

    # ------------------------------------------------------------------
    # String RVA Resolution
    # ------------------------------------------------------------------

    def _resolve_string_rvas(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        """Scan PE .rdata/.data for DWORD arrays that point to string data."""
        findings = []
        string_rvas: list[dict[str, Any]] = []

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

            # Scan for runs of 4+ consecutive DWORDs
            i = 0
            while i < len(raw_data) - 16:
                values = []
                j = i
                while j + 4 <= len(raw_data):
                    val = struct.unpack_from("<I", raw_data, j)[0]
                    if val == 0:
                        break
                    values.append(val)
                    j += 4
                    if len(values) >= 64:
                        break

                if len(values) >= 4:
                    rva = base_rva + i
                    # Check how many values point to valid string RVAs
                    string_refs = self._resolve_string_pointers(values, pe)
                    if string_refs:
                        string_rvas.append({
                            "table_rva": rva,
                            "section": name,
                            "count": len(values),
                            "resolved": len(string_refs),
                            "strings": string_refs,
                        })
                        findings.append(Finding(
                            category=FindingCategory.STRING_RVA_RESOLVED,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            description=(
                                f"String RVA table at {name}:0x{rva:X} "
                                f"({len(string_refs)}/{len(values)} resolved)"
                            ),
                            instruction_address=rva,
                            context={
                                "table_rva": rva,
                                "section": name,
                                "total_entries": len(values),
                                "resolved_count": len(string_refs),
                                "strings": string_refs[:20],
                            },
                            evidence=[{
                                "type": "instruction_pattern",
                                "location": f"{name}:0x{rva:X}",
                                "snippet": f"[{', '.join(s for s in string_refs[:5])}]",
                                "rule_id": "MM001",
                            }],
                        ))
                    i = j
                else:
                    i += 4

        ir.string_rvas = string_rvas
        pe.close()
        return findings

    def _resolve_string_pointers(self, values: list[int], pe) -> list[str]:
        """Resolve DWORD values that point to string data in PE sections."""
        resolved = []
        for val in values:
            s = self._read_string_at_rva(pe, val)
            if s and len(s) >= 3:
                resolved.append(s)
        return resolved

    def _read_string_at_rva(self, pe, rva: int) -> str | None:
        """Read a null-terminated string from a PE RVA."""
        try:
            data = pe.get_data(rva, 256)
        except Exception:
            return None

        # Try ASCII first
        result = []
        for b in data:
            if b == 0:
                break
            if 0x20 <= b <= 0x7E:
                result.append(chr(b))
            else:
                return None  # Not a clean ASCII string
        if len(result) >= 3:
            return "".join(result)

        # Try UTF-16 (wide string)
        result = []
        i = 0
        while i + 1 < len(data):
            if data[i + 1] != 0:
                break  # Not wide string format
            ch = data[i]
            if ch == 0:
                break
            if 0x20 <= ch <= 0x7E:
                result.append(chr(ch))
            else:
                return None
            i += 2
        if len(result) >= 3:
            return "".join(result)

        return None

    # ------------------------------------------------------------------
    # Function Pointer Table Resolution
    # ------------------------------------------------------------------

    def _resolve_func_ptr_tables(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        """Enhance existing data structure findings with function pointer classification."""
        findings = []
        dispatch_tables: list[dict[str, Any]] = []

        for rva, ds in (ir.data_structures or {}).items():
            if ds.get("type") != "qword_array":
                continue
            hint = ds.get("semantic_hint", "")
            if "function pointer" in hint.lower() or "address table" in hint.lower():
                sample_values = ds.get("sample_values", [])
                # Convert hex strings back to ints if needed
                ptrs = []
                for v in sample_values:
                    if isinstance(v, str):
                        try:
                            ptrs.append(int(v, 16))
                        except ValueError:
                            continue
                    elif isinstance(v, int):
                        ptrs.append(v)

                known_apis = self._match_function_pointers(ptrs, ir)
                if known_apis:
                    table_type = self._classify_table_type(known_apis)
                    dispatch_tables.append({
                        "table_rva": rva,
                        "section": ds.get("section", ""),
                        "element_count": ds.get("element_count", 0),
                        "known_apis": known_apis,
                        "table_type": table_type,
                    })
                    findings.append(Finding(
                        category=FindingCategory.DISPATCH_TABLE_RESOLVED,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=(
                            f"{table_type} at 0x{rva:X} "
                            f"({len(known_apis)} known APIs)"
                        ),
                        instruction_address=rva,
                        context={
                            "table_rva": rva,
                            "table_type": table_type,
                            "known_apis": known_apis[:10],
                        },
                        evidence=[{
                            "type": "instruction_pattern",
                            "location": f"{ds.get('section', '')}:0x{rva:X}",
                            "snippet": f"[{', '.join(a for a in known_apis[:5])}]",
                            "rule_id": "MM002",
                        }],
                    ))

        ir.dispatch_tables = dispatch_tables
        return findings

    def _match_function_pointers(self, ptrs: list[int], ir: DisassemblyResult) -> list[str]:
        """Match function pointer values against known API names in IR."""
        matched = []
        func_api_details = ir.function_api_details or {}
        for ptr in ptrs:
            if ptr in func_api_details:
                api_info = func_api_details[ptr]
                api_name = api_info.name if hasattr(api_info, 'name') else str(api_info)
                matched.append(api_name)
        return matched

    def _classify_table_type(self, known_apis: list[str]) -> str:
        """Classify a function pointer table by its API content."""
        api_lower = [a.lower() for a in known_apis]

        # Check for hook-related APIs
        hook_indicators = {"hook", "intercept", "replace", "swap"}
        if any(any(ind in api for ind in hook_indicators) for api in api_lower):
            return "hook_table"

        # Check for callback-related APIs
        callback_indicators = {"callback", "register", "notify"}
        if any(any(ind in api for ind in callback_indicators) for api in api_lower):
            return "callback_table"

        # Check for dispatch-related APIs
        dispatch_indicators = {"dispatch", "handler", "ioctl", "irp"}
        if any(any(ind in api for ind in dispatch_indicators) for api in api_lower):
            return "dispatch_table"

        return "function_pointer_table"

    # ------------------------------------------------------------------
    # Xref Tracing
    # ------------------------------------------------------------------

    def _trace_xrefs(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        """Cross-reference data tables with code that uses them."""
        findings = []
        xref_usages: list[dict[str, Any]] = []

        known_data_rvas = set((ir.data_structures or {}).keys())
        if not known_data_rvas:
            return findings

        all_cfgs = ir.cfgs or ir.simple_cfgs or {}
        for func_addr, cfg in all_cfgs.items():
            func_xrefs = []
            for block_addr, block in cfg.blocks.items():
                for insn in block.instructions:
                    full_text = f"{insn.mnemonic} {insn.operands}"
                    target_rva = self._extract_memory_target(insn, block_addr)
                    if target_rva and target_rva in known_data_rvas:
                        usage_type = self._classify_xref_usage(insn.mnemonic)
                        func_xrefs.append({
                            "insn_addr": insn.address,
                            "insn_text": full_text,
                            "data_rva": target_rva,
                            "usage_type": usage_type,
                        })

            if func_xrefs:
                xref_usages.append({
                    "func_addr": func_addr,
                    "xrefs": func_xrefs,
                })
                # Report if table is used as whitelist/blacklist check or dispatch
                has_check = any(x["usage_type"] == "check" for x in func_xrefs)
                has_dispatch = any(x["usage_type"] == "dispatch" for x in func_xrefs)
                has_iterate = any(x["usage_type"] == "iterate" for x in func_xrefs)

                if has_check or has_dispatch:
                    findings.append(Finding(
                        category=FindingCategory.XREF_TABLE_USAGE,
                        severity=Severity.MEDIUM if has_check else Severity.LOW,
                        confidence=Confidence.HIGH,
                        description=(
                            f"Func 0x{func_addr:X} references "
                            f"{len(func_xrefs)} data table entries"
                            f"{' (whitelist/blacklist check)' if has_check else ''}"
                            f"{' (dispatch)' if has_dispatch else ''}"
                            f"{' (array iteration)' if has_iterate else ''}"
                        ),
                        function_address=func_addr,
                        context={
                            "xref_count": len(func_xrefs),
                            "has_check": has_check,
                            "has_dispatch": has_dispatch,
                            "has_iterate": has_iterate,
                        },
                        evidence=[{
                            "type": "instruction_pattern",
                            "location": f"func 0x{func_addr:X}",
                            "snippet": func_xrefs[0]["insn_text"],
                            "rule_id": "MM003",
                        }],
                    ))

        ir.xref_usages = xref_usages
        return findings

    def _extract_memory_target(self, insn, block_addr: int) -> int | None:
        """Extract the target RVA from a memory reference instruction."""
        import re

        # x64: [rip+offset]
        m = re.search(r"\[rip\+([^\]]+)\]", insn.operands)
        if m:
            try:
                offset = int(m.group(1).strip(), 16)
                rip = insn.address + insn.size
                return rip + offset
            except ValueError:
                return None

        # x86: [0xXXXXXXXX]
        m = re.search(r"\[(?:dword\s+|byte\s+|word\s+)?(0x[0-9a-f]+)\]", insn.operands)
        if m:
            try:
                return int(m.group(1).strip(), 16)
            except ValueError:
                return None

        return None

    def _classify_xref_usage(self, mnemonic: str) -> str:
        """Classify how an instruction uses a data table entry."""
        if mnemonic == "cmp":
            return "check"
        if mnemonic == "test":
            return "check"
        if mnemonic in ("call", "jmp"):
            return "dispatch"
        if mnemonic in ("mov", "lea", "add", "sub"):
            return "iterate"
        return "reference"

    # ------------------------------------------------------------------
    # Runtime Allocation Speculation
    # ------------------------------------------------------------------

    def _speculate_runtime_tables(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        """Detect ExAllocatePoolWithTag + memset/memcpy patterns."""
        findings = []
        runtime_tables: list[dict[str, Any]] = []

        func_api_details = ir.function_api_details or {}

        for func_addr, api_list in func_api_details.items():
            # Check if function calls an allocation API
            has_alloc = False
            has_init = False
            alloc_api = ""

            for api_info in api_list:
                api_name = api_info.name if hasattr(api_info, 'name') else str(api_info)
                if api_name in self.ALLOC_APIS:
                    has_alloc = True
                    alloc_api = api_name
                if api_name in self.INIT_APIS:
                    has_init = True

            if has_alloc and has_init:
                runtime_tables.append({
                    "func_addr": func_addr,
                    "alloc_api": alloc_api,
                    "pattern": "alloc+init",
                })
                findings.append(Finding(
                    category=FindingCategory.RUNTIME_ALLOC_TABLE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Runtime-allocated table in func 0x{func_addr:X} "
                        f"({alloc_api} + initialization)"
                    ),
                    function_address=func_addr,
                    context={
                        "alloc_api": alloc_api,
                        "pattern": "alloc+init",
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"func 0x{func_addr:X}",
                        "snippet": f"{alloc_api} + init",
                        "rule_id": "MM004",
                    }],
                ))

        ir.runtime_tables = runtime_tables
        return findings

    # ------------------------------------------------------------------
    # 360-specific Whitelist Detection
    # ------------------------------------------------------------------

    def _detect_360_whitelist(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        """Detect 360-specific whitelist patterns in string data."""
        findings = []
        whitelist_entries: list[dict[str, Any]] = []

        # Aggregate strings from wide strings, string RVAs, and comparison traces
        all_strings: set[str] = set()

        # From wide strings
        for ws in (ir.wide_strings or []):
            s = ws.get("string", "")
            if s:
                all_strings.add(s.lower())

        # From string RVA tables
        for entry in (getattr(ir, 'string_rvas', []) or []):
            for s in entry.get("strings", []):
                if s:
                    all_strings.add(s.lower())

        # Classify whitelist entries
        process_whitelist = []
        path_whitelist = []
        registry_whitelist = []
        _360_specific = []

        for s in sorted(all_strings):
            if s.endswith(self._EXE_SUFFIX):
                process_whitelist.append(s)
            if any(s.startswith(p) for p in self._DEVICE_PREFIXES):
                path_whitelist.append(s)
            if any(s.startswith(p) for p in self._REGISTRY_PREFIXES):
                registry_whitelist.append(s)
            if any(s.startswith(p) for p in self._360_PATH_PREFIXES):
                _360_specific.append(s)

        # Report findings
        if process_whitelist:
            whitelist_entries.append({
                "type": "process_whitelist",
                "count": len(process_whitelist),
                "entries": process_whitelist[:20],
            })
            findings.append(Finding(
                category=FindingCategory.WHITELIST_TABLE_DETECTED,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=f"Process whitelist detected ({len(process_whitelist)} entries)",
                context={
                    "type": "process_whitelist",
                    "count": len(process_whitelist),
                    "entries": process_whitelist[:20],
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": "data section",
                    "snippet": f"[{', '.join(process_whitelist[:3])}]",
                    "rule_id": "MM005",
                }],
            ))

        if path_whitelist:
            whitelist_entries.append({
                "type": "path_whitelist",
                "count": len(path_whitelist),
                "entries": path_whitelist[:20],
            })
            findings.append(Finding(
                category=FindingCategory.WHITELIST_TABLE_DETECTED,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=f"Path whitelist detected ({len(path_whitelist)} entries)",
                context={
                    "type": "path_whitelist",
                    "count": len(path_whitelist),
                    "entries": path_whitelist[:20],
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": "data section",
                    "snippet": f"[{', '.join(path_whitelist[:3])}]",
                    "rule_id": "MM006",
                }],
            ))

        if registry_whitelist:
            whitelist_entries.append({
                "type": "registry_whitelist",
                "count": len(registry_whitelist),
                "entries": registry_whitelist[:20],
            })
            findings.append(Finding(
                category=FindingCategory.WHITELIST_TABLE_DETECTED,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=f"Registry whitelist detected ({len(registry_whitelist)} entries)",
                context={
                    "type": "registry_whitelist",
                    "count": len(registry_whitelist),
                    "entries": registry_whitelist[:20],
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": "data section",
                    "snippet": f"[{', '.join(registry_whitelist[:3])}]",
                    "rule_id": "MM007",
                }],
            ))

        if _360_specific:
            whitelist_entries.append({
                "type": "_360_specific",
                "count": len(_360_specific),
                "entries": _360_specific[:20],
            })
            findings.append(Finding(
                category=FindingCategory.WHITELIST_TABLE_DETECTED,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description=f"360-specific whitelist detected ({len(_360_specific)} entries)",
                context={
                    "type": "_360_specific",
                    "count": len(_360_specific),
                    "entries": _360_specific[:20],
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": "data section",
                    "snippet": f"[{', '.join(_360_specific[:3])}]",
                    "rule_id": "MM008",
                }],
            ))

        ir.whitelist_entries = whitelist_entries
        return findings
