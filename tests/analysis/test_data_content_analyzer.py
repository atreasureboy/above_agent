"""Tests for data_content_analyzer.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.analysis.deep.data_content_analyzer import (
    DataContentAnalyzer,
    NTSTATUS_CODES,
    MIN_NTSTATUS_DISTINCT,
    PROCESS_NAME_RE,
    DRIVER_NAME_RE,
    DEVICE_PATH_RE,
    REGISTRY_PATH_RE,
    DLL_NAME_RE,
    IP_ADDRESS_RE,
    GUID_RE,
    API_NAME_RE,
)
from src.models import (
    Confidence,
    DisassemblyResult,
    FindingCategory,
    Function,
    Sample,
    Architecture,
    Severity,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _sample() -> Sample:
    return Sample(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
        is_driver=True,
    )


def _add_function(ir: DisassemblyResult, addr: int, name: str = None) -> Function:
    func = Function(name=name or f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func
    return func


class TestDataContentConstants:
    """Test constant definitions."""

    def test_ntstatus_codes_populated(self):
        assert len(NTSTATUS_CODES) > 15
        assert NTSTATUS_CODES[0x00000000] == "STATUS_SUCCESS"
        assert NTSTATUS_CODES[0xC0000005] == "STATUS_ACCESS_VIOLATION"

    def test_min_ntstatus_distinct(self):
        assert MIN_NTSTATUS_DISTINCT == 2

    def test_process_name_regex(self):
        assert PROCESS_NAME_RE.match("svchost.exe")
        assert PROCESS_NAME_RE.match("notepad.exe")
        assert not PROCESS_NAME_RE.match("\\Device\\MyDriver")

    def test_driver_name_regex(self):
        assert DRIVER_NAME_RE.match("360sys.sys")
        assert DRIVER_NAME_RE.match("my-driver.sys")
        assert not DRIVER_NAME_RE.match("hello.txt")

    def test_device_path_regex(self):
        assert DEVICE_PATH_RE.match("\\\\Device\\MyDriver")
        assert DEVICE_PATH_RE.match("\\\\DosDevices\\MyLink")
        assert not DEVICE_PATH_RE.match("C:\\Windows")

    def test_registry_path_regex(self):
        assert REGISTRY_PATH_RE.match("\\\\Registry\\\\Machine\\\\SYSTEM")
        assert REGISTRY_PATH_RE.match("\\\\HKLM\\\\SOFTWARE\\\\Test")
        assert not REGISTRY_PATH_RE.match("C:\\\\Windows")

    def test_dll_name_regex(self):
        assert DLL_NAME_RE.match("ntdll.dll")
        assert DLL_NAME_RE.match("kernel32.dll")

    def test_ip_address_regex(self):
        assert IP_ADDRESS_RE.match("192.168.1.1")
        assert IP_ADDRESS_RE.match("10.0.0.255")

    def test_guid_regex(self):
        assert GUID_RE.match("{12345678-1234-1234-1234-123456789ABC}")
        assert not GUID_RE.match("12345678-1234-1234-1234-123456789ABC")  # no braces

    def test_api_name_regex(self):
        assert API_NAME_RE.match("NtCreateFile")
        assert API_NAME_RE.match("ZwOpenProcess")
        assert API_NAME_RE.match("RtlCopyMemory")
        assert not API_NAME_RE.match("random_text")


class TestDataContentAnalyzerBasics:
    """Test basic analyzer functionality."""

    def test_analyzer_name(self):
        analyzer = DataContentAnalyzer()
        assert analyzer.name == "DataContentAnalyzer"

    def test_analyzer_description(self):
        analyzer = DataContentAnalyzer()
        assert "content" in analyzer.description.lower()

    def test_is_correlator(self):
        analyzer = DataContentAnalyzer()
        assert analyzer.is_correlator is True

    def test_empty_ir_no_findings(self):
        ir = _make_ir()
        sample = _sample()
        analyzer = DataContentAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert findings == []

    def test_no_data_structures_no_findings(self):
        ir = _make_ir()
        ir.strings.append("Hello")
        sample = _sample()
        analyzer = DataContentAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert findings == []


class TestStringPurposeClassification:
    """Test _classify_string_purpose static method."""

    def test_process_whitelist(self):
        strings = ["svchost.exe", "explorer.exe", "csrss.exe"]
        purpose = DataContentAnalyzer._classify_string_purpose(strings)
        assert "process" in purpose.lower()

    def test_driver_whitelist(self):
        strings = ["ntfs.sys", "tcpip.sys", "360sys.sys"]
        purpose = DataContentAnalyzer._classify_string_purpose(strings)
        assert "driver" in purpose.lower()

    def test_device_paths(self):
        strings = ["\\\\Device\\MyDriver", "\\\\Device\\Other", "\\\\DosDevices\\Link"]
        purpose = DataContentAnalyzer._classify_string_purpose(strings)
        assert "device" in purpose.lower()

    def test_registry_paths(self):
        strings = ["\\\\Registry\\\\Machine\\\\SYSTEM", "\\\\HKLM\\\\SOFTWARE\\\\Test"]
        purpose = DataContentAnalyzer._classify_string_purpose(strings)
        assert "registry" in purpose.lower()

    def test_dll_names(self):
        strings = ["ntdll.dll", "kernel32.dll", "user32.dll"]
        purpose = DataContentAnalyzer._classify_string_purpose(strings)
        assert "dll" in purpose.lower()

    def test_ip_addresses(self):
        strings = ["192.168.1.1", "10.0.0.1", "172.16.0.1"]
        purpose = DataContentAnalyzer._classify_string_purpose(strings)
        assert "ip" in purpose.lower()

    def test_guids(self):
        strings = [
            "{12345678-1234-1234-1234-123456789ABC}",
            "{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}",
        ]
        purpose = DataContentAnalyzer._classify_string_purpose(strings)
        assert "guid" in purpose.lower()

    def test_api_names(self):
        strings = ["NtCreateFile", "ZwOpenProcess", "RtlCopyMemory"]
        purpose = DataContentAnalyzer._classify_string_purpose(strings)
        assert "api" in purpose.lower()

    def test_unknown_purpose(self):
        strings = ["hello", "world", "foo"]
        purpose = DataContentAnalyzer._classify_string_purpose(strings)
        assert purpose == "unknown"

    def test_empty_strings_unknown(self):
        purpose = DataContentAnalyzer._classify_string_purpose([])
        assert purpose == "unknown"

    def test_mixed_categories(self):
        strings = ["svchost.exe", "NtCreateFile", "\\Device\\Test"]
        purpose = DataContentAnalyzer._classify_string_purpose(strings)
        assert "mixed" in purpose.lower()


class TestNTSTATUSDetection:
    """Test NTSTATUS constant table detection."""

    def test_ntstatus_table_detected(self):
        ir = _make_ir()
        ir.data_structures[0x1000] = {
            "type": "dword_array",
            "section": ".rdata",
            "element_count": 10,
            "element_size": 4,
            "sample_values": [
                0x00000000,  # STATUS_SUCCESS
                0xC0000005,  # STATUS_ACCESS_VIOLATION
                0xC000000D,  # STATUS_INVALID_PARAMETER
                0xC0000022,  # STATUS_ACCESS_DENIED
                0x12345678,  # non-NTSTATUS
            ],
        }
        sample = _sample()
        analyzer = DataContentAnalyzer()
        findings = analyzer.analyze(sample, ir)
        nt_findings = [f for f in findings
                      if f.category == FindingCategory.DATA_CONTENT_ANALYZED
                      and "NTSTATUS" in f.description]
        assert len(nt_findings) >= 1
        assert nt_findings[0].context["distinct_count"] >= 2

    def test_insufficient_ntstatus_no_finding(self):
        """Only 1 distinct NTSTATUS code should not trigger detection."""
        ir = _make_ir()
        ir.data_structures[0x1000] = {
            "type": "dword_array",
            "section": ".rdata",
            "element_count": 10,
            "element_size": 4,
            "sample_values": [
                0x00000000,  # STATUS_SUCCESS
                0x00000000,
                0x00000000,
                0x12345678,
            ],
        }
        sample = _sample()
        analyzer = DataContentAnalyzer()
        findings = analyzer.analyze(sample, ir)
        nt_findings = [f for f in findings
                      if f.context.get("type") == "ntstatus_table"]
        assert len(nt_findings) == 0


class TestFunctionPointerTableDetection:
    """Test function pointer table detection."""

    def test_function_pointer_table_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x10000, "Handler1")
        _add_function(ir, 0x11000, "Handler2")
        _add_function(ir, 0x12000, "Handler3")
        _add_function(ir, 0x13000, "Handler4")
        ir.data_structures[0x2000] = {
            "type": "dword_array",
            "section": ".data",
            "element_count": 8,
            "element_size": 4,
            "sample_values": [0x10000, 0x11000, 0x12000, 0x13000, 0x10000, 0x11000],
        }
        sample = _sample()
        analyzer = DataContentAnalyzer()
        # Mock code range so function pointer detection works
        with patch.object(analyzer, "_get_code_range", return_value=(0x1000, 0x20000)):
            findings = analyzer.analyze(sample, ir)
        fp_findings = [f for f in findings
                      if f.context.get("type") == "function_pointer_table"]
        assert len(fp_findings) >= 1
        assert fp_findings[0].context["resolved_count"] >= 4

    def test_non_code_pointers_no_finding(self):
        """Values not in code range should not produce function pointer findings."""
        ir = _make_ir()
        ir.data_structures[0x2000] = {
            "type": "qword_array",
            "section": ".data",
            "element_count": 8,
            "element_size": 8,
            "sample_values": [0xABCDEF, 0x123456, 0x789ABC, 0xDEF012],
        }
        sample = _sample()
        analyzer = DataContentAnalyzer()
        findings = analyzer.analyze(sample, ir)
        # Without code range info, function pointer detection won't fire


class TestStringRVADetection:
    """Test string RVA array detection."""

    def test_string_rva_table_detected(self):
        ir = _make_ir()
        ir.string_rvas = {
            0x5000: "svchost.exe",
            0x5010: "explorer.exe",
            0x5020: "notepad.exe",
            0x5030: "calc.exe",
        }
        ir.data_structures[0x3000] = {
            "type": "dword_array",
            "section": ".rdata",
            "element_count": 4,
            "element_size": 4,
            "sample_values": [0x5000, 0x5010, 0x5020, 0x5030],
        }
        sample = _sample()
        analyzer = DataContentAnalyzer()
        findings = analyzer.analyze(sample, ir)
        str_findings = [f for f in findings
                       if f.category == FindingCategory.STRING_TABLE_IDENTIFIED]
        assert len(str_findings) >= 1
        assert str_findings[0].context["matched_count"] >= 3


class TestPurposeInference:
    """Test table purpose inference from references and comparisons."""

    def test_hot_table_detected(self):
        ir = _make_ir()
        ir.data_structures[0x1000] = {
            "type": "dword_array",
            "section": ".rdata",
            "element_count": 20,
            "element_size": 4,
            "semantic_hint": "whitelist",
        }
        ir.data_references = [
            {"rva": 0x1000} for _ in range(15)
        ]
        ir.comparison_traces = [
            {"data_rva": 0x1000, "insn_addr": 0x100},
            {"data_rva": 0x1000, "insn_addr": 0x200},
            {"data_rva": 0x1000, "insn_addr": 0x300},
            {"data_rva": 0x1000, "insn_addr": 0x400},
        ]
        sample = _sample()
        analyzer = DataContentAnalyzer()
        findings = analyzer.analyze(sample, ir)
        hot_findings = [f for f in findings
                       if "Hot lookup table" in f.description]
        assert len(hot_findings) >= 1
        assert hot_findings[0].context["reference_count"] >= 10
        assert hot_findings[0].context["comparison_count"] >= 3

    def test_low_reference_count_no_hot_table(self):
        ir = _make_ir()
        ir.data_structures[0x1000] = {
            "type": "dword_array",
            "section": ".rdata",
            "element_count": 10,
            "element_size": 4,
        }
        ir.data_references = [{"rva": 0x1000}]  # only 1 ref
        ir.comparison_traces = [
            {"data_rva": 0x1000, "insn_addr": 0x100},
            {"data_rva": 0x1000, "insn_addr": 0x200},
        ]
        sample = _sample()
        analyzer = DataContentAnalyzer()
        findings = analyzer.analyze(sample, ir)
        hot_findings = [f for f in findings if "Hot lookup table" in f.description]
        assert len(hot_findings) == 0


class TestPEHelpers:
    """Test PE-related helper methods."""

    def test_read_array_values_no_pe(self):
        result = DataContentAnalyzer._read_array_values(None, 0x1000, 10, 4)
        assert result == []

    def test_read_array_values_invalid_size(self):
        result = DataContentAnalyzer._read_array_values(None, 0x1000, 10, 3)
        assert result == []

    def test_get_image_base_invalid(self):
        result = DataContentAnalyzer._get_image_base("/nonexistent/test.sys")
        assert result is None

    def test_get_code_range_invalid(self):
        start, end = DataContentAnalyzer._get_code_range("/nonexistent/test.sys")
        assert start is None
        assert end is None

    def test_read_string_at_rva_no_pe(self):
        result = DataContentAnalyzer._read_string_at_rva(None, 0x1000)
        assert result is None


class TestFindingsHaveEvidence:
    """Test that all findings have proper evidence."""

    def test_ntstatus_finding_evidence(self):
        ir = _make_ir()
        ir.data_structures[0x1000] = {
            "type": "dword_array",
            "section": ".rdata",
            "element_count": 5,
            "element_size": 4,
            "sample_values": [0x0, 0xC0000005, 0xC0000022],
        }
        sample = _sample()
        analyzer = DataContentAnalyzer()
        findings = analyzer.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0
