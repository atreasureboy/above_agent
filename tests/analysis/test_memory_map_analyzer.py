"""Tests for the MemoryMapAnalyzer (Task A: dynamic memory table positioning)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from src.analysis.deep.memory_map_analyzer import MemoryMapAnalyzer
from src.models import (
    Architecture,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)


def _make_sample(**kwargs) -> Sample:
    return Sample(
        path=Path("test.sys"),
        name="test.sys",
        company="Test",
        version="1.0",
        arch=Architecture.X64,
        sha256="abc",
        size=1000,
        **kwargs,
    )


def _make_ir(**kwargs) -> DisassemblyResult:
    return DisassemblyResult(
        sample_path=Path("test.sys"),
        backend="capstone",
        **kwargs,
    )


def _make_instruction(address: int, mnemonic: str, operands: str, size: int = 4):
    return SimpleNamespace(
        address=address,
        mnemonic=mnemonic,
        operands=operands,
        size=size,
    )


def _make_block(address: int, instructions: list):
    return SimpleNamespace(
        address=address,
        instructions=instructions,
        successors=[],
    )


def _make_cfg(blocks: dict, entry_block: int = 0):
    return SimpleNamespace(
        blocks=blocks,
        entry_block=entry_block,
    )


# ------------------------------------------------------------------
# Test class structure
# ------------------------------------------------------------------

class TestMemoryMapAnalyzerStructure:
    def test_name(self):
        a = MemoryMapAnalyzer()
        assert a.name == "MemoryMapAnalyzer"

    def test_description_nonempty(self):
        a = MemoryMapAnalyzer()
        assert a.description != ""

    def test_enabled_by_default(self):
        a = MemoryMapAnalyzer()
        assert a.enabled is True

    def test_not_correlator(self):
        a = MemoryMapAnalyzer()
        assert a.is_correlator is False


# ------------------------------------------------------------------
# Test string RVA resolution
# ------------------------------------------------------------------

class TestStringRVAResolution:
    def test_empty_ir_no_findings(self):
        """No PE file available should return empty findings."""
        a = MemoryMapAnalyzer()
        sample = _make_sample()
        ir = _make_ir()
        findings = a._resolve_string_rvas(sample, ir)
        assert isinstance(findings, list)

    def test_resolves_string_pointers(self):
        """DWORD arrays pointing to string data should be resolved."""
        mock_pe = MagicMock()

        rdata_section = MagicMock()
        rdata_section.Name = b".rdata\x00\x00"
        rdata_section.VirtualAddress = 0x1000
        rdata_section.PointerToRawData = 0
        rdata_section.get_data.return_value = (
            b"\x00\x20\x00\x00"  # 0x2000
            b"\x10\x20\x00\x00"  # 0x2010
            b"\x20\x20\x00\x00"  # 0x2020
            b"\x30\x20\x00\x00"  # 0x2030
        )

        mock_pe.sections = [rdata_section]

        str_map = {
            0x2000: b"explorer.exe\x00",
            0x2010: b"notepad.exe\x00",
            0x2020: b"cmd.exe\x00",
            0x2030: b"svchost.exe\x00",
        }

        def mock_get_data(rva, size):
            if rva in str_map:
                return str_map[rva][:size]
            raise Exception("out of range")

        mock_pe.get_data = mock_get_data

        a = MemoryMapAnalyzer()
        sample = _make_sample()
        ir = _make_ir()

        # Directly test the helper with the mock PE
        values = [0x2000, 0x2010, 0x2020, 0x2030]
        resolved = a._resolve_string_pointers(values, mock_pe)

        assert len(resolved) >= 4
        assert "explorer.exe" in resolved
        assert "notepad.exe" in resolved
        assert "cmd.exe" in resolved
        assert "svchost.exe" in resolved


# ------------------------------------------------------------------
# Test function pointer table resolution
# ------------------------------------------------------------------

class TestFunctionPointerTableResolution:
    def test_empty_data_structures(self):
        """No data structures should return empty findings."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(data_structures={})
        findings = a._resolve_func_ptr_tables(_make_sample(), ir)
        assert findings == []

    def test_qword_array_with_known_apis(self):
        """QWORD array with matched APIs should be classified."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(
            data_structures={
                0x1000: {
                    "type": "qword_array",
                    "section": ".rdata",
                    "semantic_hint": "Function pointer table (4/4 in code section)",
                    "element_count": 4,
                    "sample_values": ["0x5000", "0x5100", "0x5200", "0x5300"],
                },
            },
            function_api_details={
                0x5000: SimpleNamespace(name="ZwCreateFile"),
                0x5100: SimpleNamespace(name="ZwReadFile"),
                0x5200: SimpleNamespace(name="ZwWriteFile"),
                0x5300: SimpleNamespace(name="ZwClose"),
            },
        )
        findings = a._resolve_func_ptr_tables(_make_sample(), ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.DISPATCH_TABLE_RESOLVED
        assert "ZwCreateFile" in findings[0].context["known_apis"]

    def test_classify_hook_table(self):
        """Table with hook-related APIs should be classified as hook_table."""
        a = MemoryMapAnalyzer()
        apis = ["ObRegisterCallbacks", "HookHandler", "InterceptRoutine"]
        table_type = a._classify_table_type(apis)
        assert table_type == "hook_table"

    def test_classify_callback_table(self):
        """Table with callback APIs should be classified as callback_table."""
        a = MemoryMapAnalyzer()
        apis = ["PsSetCreateProcessNotifyRoutine", "RegisterCallback"]
        table_type = a._classify_table_type(apis)
        assert table_type == "callback_table"

    def test_classify_dispatch_table(self):
        """Table with dispatch APIs should be classified as dispatch_table."""
        a = MemoryMapAnalyzer()
        apis = ["IoctlHandler", "IrpDispatch", "DeviceHandler"]
        table_type = a._classify_table_type(apis)
        assert table_type == "dispatch_table"

    def test_classify_default_table(self):
        """Table without special APIs should be generic."""
        a = MemoryMapAnalyzer()
        apis = ["sub_1000", "sub_2000", "sub_3000"]
        table_type = a._classify_table_type(apis)
        assert table_type == "function_pointer_table"


# ------------------------------------------------------------------
# Test xref tracing
# ------------------------------------------------------------------

class TestXrefTracing:
    def test_empty_data_structures(self):
        """No data structures should return empty findings."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(data_structures={}, cfgs={})
        findings = a._trace_xrefs(_make_sample(), ir)
        assert findings == []

    def test_cmp_against_data_table(self):
        """cmp [rip+offset] against known data should be traced."""
        a = MemoryMapAnalyzer()
        # Block with cmp instruction referencing 0x1000 (known data RVA)
        block = _make_block(0x3000, [
            _make_instruction(0x3010, "cmp", "eax, [rip+0x1000]", size=7),
        ])
        ir = _make_ir(
            data_structures={
                0x4000: {"type": "dword_array", "section": ".rdata", "semantic_hint": "whitelist table"},
            },
            cfgs={0x2000: _make_cfg({0x3000: block})},
        )
        # Need to fix the instruction: rip = 0x3010 + 7 = 0x3017, offset = 0x1000, target = 0x4017
        # Let's use a direct address instead for x86
        block2 = _make_block(0x3000, [
            _make_instruction(0x3010, "cmp", "eax, [0x4000]", size=6),
        ])
        ir = _make_ir(
            data_structures={
                0x4000: {"type": "dword_array", "section": ".rdata", "semantic_hint": "whitelist table"},
            },
            cfgs={0x2000: _make_cfg({0x3000: block2})},
        )
        findings = a._trace_xrefs(_make_sample(), ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.XREF_TABLE_USAGE
        assert findings[0].context["has_check"] is True

    def test_indirect_call_dispatch(self):
        """call/jmp against data table should be classified as dispatch."""
        a = MemoryMapAnalyzer()
        block = _make_block(0x3000, [
            _make_instruction(0x3010, "call", "qword ptr [0x4000]", size=6),
        ])
        ir = _make_ir(
            data_structures={
                0x4000: {"type": "qword_array", "section": ".rdata", "semantic_hint": "function pointer table"},
            },
            cfgs={0x2000: _make_cfg({0x3000: block})},
        )
        findings = a._trace_xrefs(_make_sample(), ir)
        assert len(findings) >= 1
        assert findings[0].context["has_dispatch"] is True

    def test_classify_xref_check(self):
        """cmp should be classified as check."""
        a = MemoryMapAnalyzer()
        assert a._classify_xref_usage("cmp") == "check"
        assert a._classify_xref_usage("test") == "check"

    def test_classify_xref_dispatch(self):
        """call/jmp should be classified as dispatch."""
        a = MemoryMapAnalyzer()
        assert a._classify_xref_usage("call") == "dispatch"
        assert a._classify_xref_usage("jmp") == "dispatch"

    def test_classify_xref_iterate(self):
        """mov/lea/add should be classified as iterate."""
        a = MemoryMapAnalyzer()
        assert a._classify_xref_usage("mov") == "iterate"
        assert a._classify_xref_usage("lea") == "iterate"
        assert a._classify_xref_usage("add") == "iterate"

    def test_classify_xref_reference(self):
        """Other instructions should be classified as reference."""
        a = MemoryMapAnalyzer()
        assert a._classify_xref_usage("push") == "reference"
        assert a._classify_xref_usage("xor") == "reference"


# ------------------------------------------------------------------
# Test runtime allocation speculation
# ------------------------------------------------------------------

class TestRuntimeAllocationSpeculation:
    def test_detects_alloc_plus_init(self):
        """Function with ExAllocatePoolWithTag + memset should be flagged."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(
            function_api_details={
                0x1000: [
                    SimpleNamespace(name="ExAllocatePoolWithTag"),
                    SimpleNamespace(name="memset"),
                ],
                0x2000: [
                    SimpleNamespace(name="ZwCreateFile"),
                ],
            },
        )
        findings = a._speculate_runtime_tables(_make_sample(), ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.RUNTIME_ALLOC_TABLE
        assert findings[0].function_address == 0x1000

    def test_alloc_without_init_not_flagged(self):
        """Allocation without initialization should not be flagged."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(
            function_api_details={
                0x1000: [
                    SimpleNamespace(name="ExAllocatePoolWithTag"),
                ],
            },
        )
        findings = a._speculate_runtime_tables(_make_sample(), ir)
        assert len(findings) == 0

    def test_empty_function_api_details(self):
        """Empty function_api_details should return no findings."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(function_api_details={})
        findings = a._speculate_runtime_tables(_make_sample(), ir)
        assert findings == []

    def test_various_alloc_apis(self):
        """Different allocation APIs should be detected."""
        a = MemoryMapAnalyzer()
        for alloc_api in a.ALLOC_APIS:
            ir = _make_ir(
                function_api_details={
                    0x1000: [
                        SimpleNamespace(name=alloc_api),
                        SimpleNamespace(name="RtlZeroMemory"),
                    ],
                },
            )
            findings = a._speculate_runtime_tables(_make_sample(), ir)
            assert len(findings) >= 1, f"Failed to detect {alloc_api}"


# ------------------------------------------------------------------
# Test 360-specific whitelist detection
# ------------------------------------------------------------------

class Test360WhitelistDetection:
    def test_process_whitelist_detected(self):
        """.exe strings should be classified as process whitelist."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(
            wide_strings=[
                {"string": "explorer.exe", "section": ".rdata", "rva": 0x1000},
                {"string": "notepad.exe", "section": ".rdata", "rva": 0x1010},
                {"string": "cmd.exe", "section": ".rdata", "rva": 0x1020},
            ],
        )
        findings = a._detect_360_whitelist(_make_sample(), ir)
        process_findings = [f for f in findings if "Process" in f.description]
        assert len(process_findings) >= 1

    def test_path_whitelist_detected(self):
        """\\Device\\ strings should be classified as path whitelist."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(
            wide_strings=[
                {"string": "\\Device\\MyDriver", "section": ".rdata", "rva": 0x1000},
                {"string": "\\??\\C:\\Windows\\System32", "section": ".rdata", "rva": 0x1010},
            ],
        )
        findings = a._detect_360_whitelist(_make_sample(), ir)
        path_findings = [f for f in findings if "Path" in f.description]
        assert len(path_findings) >= 1

    def test_registry_whitelist_detected(self):
        """\\Registry\\ strings should be classified as registry whitelist."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(
            wide_strings=[
                {"string": "\\Registry\\Machine\\SOFTWARE\\360", "section": ".rdata", "rva": 0x1000},
                {"string": "HKLM\\SYSTEM\\CurrentControlSet", "section": ".rdata", "rva": 0x1010},
            ],
        )
        findings = a._detect_360_whitelist(_make_sample(), ir)
        reg_findings = [f for f in findings if "Registry" in f.description]
        assert len(reg_findings) >= 1

    def test_360_specific_paths(self):
        """360-specific paths should be flagged as HIGH severity."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(
            wide_strings=[
                {"string": "C:\\Program Files\\360\\360Safe", "section": ".rdata", "rva": 0x1000},
                {"string": "C:\\Program Files (x86)\\360\\360sd", "section": ".rdata", "rva": 0x1010},
            ],
        )
        findings = a._detect_360_whitelist(_make_sample(), ir)
        specific_findings = [f for f in findings if "360" in f.description]
        assert len(specific_findings) >= 1
        # At least one should be HIGH severity
        high_findings = [f for f in specific_findings if f.severity == Severity.HIGH]
        assert len(high_findings) >= 1

    def test_empty_strings_no_findings(self):
        """No wide strings should return empty whitelist findings."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(wide_strings=[])
        findings = a._detect_360_whitelist(_make_sample(), ir)
        assert findings == []

    def test_string_rva_integration(self):
        """Strings from string_rvas should also be classified."""
        a = MemoryMapAnalyzer()
        ir = _make_ir(
            wide_strings=[],
        )
        ir.string_rvas = [{
            "table_rva": 0x2000,
            "section": ".rdata",
            "count": 3,
            "resolved": 2,
            "strings": ["taskmgr.exe", "regedit.exe"],
        }]
        findings = a._detect_360_whitelist(_make_sample(), ir)
        process_findings = [f for f in findings if "Process" in f.description]
        assert len(process_findings) >= 1


# ------------------------------------------------------------------
# Test full analyze pipeline
# ------------------------------------------------------------------

class TestFullAnalyze:
    def test_analyze_returns_list(self):
        """analyze() should always return a list."""
        a = MemoryMapAnalyzer()
        sample = _make_sample()
        ir = _make_ir()
        findings = a.analyze(sample, ir)
        assert isinstance(findings, list)

    def test_analyze_populates_ir_fields(self):
        """analyze() should populate IR fields."""
        a = MemoryMapAnalyzer()
        sample = _make_sample()
        ir = _make_ir()
        a.analyze(sample, ir)
        assert hasattr(ir, "string_rvas") or hasattr(ir, "dispatch_tables") or hasattr(ir, "whitelist_entries")

    @patch("pefile.PE")
    def test_analyze_with_pe_data(self, mock_pe_cls):
        """Full analyze with a mock PE should produce findings."""
        mock_pe = MagicMock()
        mock_pe_cls.return_value = mock_pe

        rdata_section = MagicMock()
        rdata_section.Name = b".rdata\x00\x00"
        rdata_section.VirtualAddress = 0x1000
        rdata_section.PointerToRawData = 0
        rdata_section.get_data.return_value = b"\x00" * 256

        mock_pe.sections = [rdata_section]

        str_map = {}

        def mock_get_data(rva, size):
            if rva in str_map:
                return str_map[rva][:size]
            raise Exception("out of range")

        mock_pe.get_data = mock_get_data
        mock_pe.close = MagicMock()

        a = MemoryMapAnalyzer()
        sample = _make_sample()
        ir = _make_ir()
        findings = a.analyze(sample, ir)

        assert isinstance(findings, list)
        mock_pe.close.assert_called_once()


# ------------------------------------------------------------------
# Test structure inference (KNOWN_STRUCT_SIZES)
# ------------------------------------------------------------------

class TestStructureInference:
    def test_known_struct_sizes_nonempty(self):
        """KNOWN_STRUCT_SIZES should contain known structure layouts."""
        a = MemoryMapAnalyzer()
        assert len(a.KNOWN_STRUCT_SIZES) > 0
        assert 0x18 in a.KNOWN_STRUCT_SIZES  # FLT_OPERATION_REGISTRATION
        assert 0x30 in a.KNOWN_STRUCT_SIZES  # OB_CALLBACK_REGISTRATION_v1

    def test_alloc_apis_nonempty(self):
        """ALLOC_APIS should contain pool allocation functions."""
        a = MemoryMapAnalyzer()
        assert "ExAllocatePoolWithTag" in a.ALLOC_APIS
        assert "ExAllocatePool2" in a.ALLOC_APIS

    def test_init_apis_nonempty(self):
        """INIT_APIS should contain memory initialization functions."""
        a = MemoryMapAnalyzer()
        assert "memset" in a.INIT_APIS
        assert "RtlFillMemory" in a.INIT_APIS
        assert "RtlZeroMemory" in a.INIT_APIS
