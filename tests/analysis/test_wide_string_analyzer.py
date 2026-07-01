"""Tests for wide_string_analyzer.py."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

from src.analysis.deep.wide_string_analyzer import WideStringAnalyzer
from src.models import (
    BasicBlock, CFG, Confidence, DisassemblyResult, FindingCategory,
    Function, Instruction, Sample, Architecture, Severity,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _add_function(ir: DisassemblyResult, addr: int, name: str = None) -> Function:
    func = Function(name=name or f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func
    return func


def _add_cfg_with_insns(ir: DisassemblyResult, func_addr: int, instructions: list[tuple[str, str]]) -> None:
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    insns = [
        Instruction(address=func_addr + 0x10 + i * 4, mnemonic=mnem, operands=ops, size=4)
        for i, (mnem, ops) in enumerate(instructions)
    ]
    block = BasicBlock(address=func_addr, end_address=func_addr + 0x100, instructions=insns, successors=[])
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg


def _sample() -> Sample:
    return Sample(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
        is_driver=True,
    )


class TestWideStringAnalyzerBasics:
    """Test basic analyzer functionality."""

    def test_analyzer_name(self):
        analyzer = WideStringAnalyzer()
        assert analyzer.name == "WideStringAnalyzer"

    def test_analyzer_description(self):
        analyzer = WideStringAnalyzer()
        assert "UTF-16" in analyzer.description or "UNICODE" in analyzer.description

    def test_empty_ir_no_findings(self):
        ir = _make_ir()
        sample = _sample()
        analyzer = WideStringAnalyzer()
        with patch.object(analyzer, "_extract_wide_strings", return_value=[]):
            findings = analyzer.analyze(sample, ir)
        assert findings == []


class TestClassifyWideString:
    """Test _classify_wide_string static method."""

    def test_device_path(self):
        analyzer = WideStringAnalyzer()
        assert analyzer._classify_wide_string("\\Device\\MyDriver") == "device_path"

    def test_dos_device_path(self):
        analyzer = WideStringAnalyzer()
        assert analyzer._classify_wide_string("\\DosDevices\\MyLink") == "dos_device_path"
        assert analyzer._classify_wide_string("\\??\\C:\\Windows") == "dos_device_path"

    def test_registry_path(self):
        analyzer = WideStringAnalyzer()
        assert analyzer._classify_wide_string("\\Registry\\Machine\\SYSTEM") == "registry_path"
        assert analyzer._classify_wide_string("HKLM\\SOFTWARE\\Test") == "registry_path"
        assert analyzer._classify_wide_string("HKCU\\Software\\Test") == "registry_path"

    def test_file_path(self):
        analyzer = WideStringAnalyzer()
        assert analyzer._classify_wide_string("C:\\Windows\\test.sys") == "file_path"
        assert analyzer._classify_wide_string("\\SystemRoot\\System32\\drivers\\test.sys") == "file_path"

    def test_url(self):
        analyzer = WideStringAnalyzer()
        assert analyzer._classify_wide_string("http://example.com") == "url"
        assert analyzer._classify_wide_string("https://example.com/api") == "url"

    def test_driver_path(self):
        analyzer = WideStringAnalyzer()
        assert analyzer._classify_wide_string("\\Windows\\System32\\drivers\\test.sys") == "driver_path"

    def test_system_path(self):
        analyzer = WideStringAnalyzer()
        # C:\ paths match "file_path" first, so system_path is for other drive paths with system32
        assert analyzer._classify_wide_string("\\SystemRoot\\System32\\config") == "file_path"
        # Paths containing \system32\ or \windows\ that don't match earlier patterns
        assert analyzer._classify_wide_string("D:\\something\\System32\\drivers") == "system_path"

    def test_unknown_returns_none(self):
        analyzer = WideStringAnalyzer()
        assert analyzer._classify_wide_string("hello world") is None
        assert analyzer._classify_wide_string("") is None


class TestExtractWideStrings:
    """Test _extract_wide_strings PE parsing."""

    def test_no_pe_returns_empty(self):
        analyzer = WideStringAnalyzer()
        result = analyzer._extract_wide_strings(Path("/nonexistent/test.sys"))
        assert result == []

    def test_mock_pe_returns_results(self):
        """With a mocked PE object, wide strings should be extracted."""
        analyzer = WideStringAnalyzer()

        # Build mock PE with UTF-16 encoded wide string in .rdata
        wide_str = b"D\x00e\x00v\x00i\x00c\x00e\x00\x00\x00"  # "Device" + null terminator
        section_data = b"\x00" * 16 + wide_str + b"\x00" * 16

        mock_section = MagicMock()
        mock_section.Name = b".rdata\x00\x00"
        mock_section.VirtualAddress = 0x1000
        mock_section.PointerToRawData = 0
        mock_section.get_data.return_value = section_data

        mock_pe = MagicMock()
        mock_pe.sections = [mock_section]

        with patch("pefile.PE", return_value=mock_pe):
            result = analyzer._extract_wide_strings(Path("test.sys"))

        assert len(result) >= 1
        assert any("Device" in r["string"] for r in result)

    def test_short_string_not_extracted(self):
        """UTF-16 strings shorter than 3 chars should not be extracted."""
        analyzer = WideStringAnalyzer()

        # "AB" in UTF-16 (only 2 chars)
        wide_str = b"A\x00B\x00\x00\x00"
        section_data = b"\x00" * 8 + wide_str + b"\x00" * 8

        mock_section = MagicMock()
        mock_section.Name = b".rdata\x00\x00"
        mock_section.VirtualAddress = 0x1000
        mock_section.PointerToRawData = 0
        mock_section.get_data.return_value = section_data

        mock_pe = MagicMock()
        mock_pe.sections = [mock_section]

        with patch("pefile.PE", return_value=mock_pe):
            result = analyzer._extract_wide_strings(Path("test.sys"))

        assert len(result) == 0

    def test_non_target_section_ignored(self):
        """Strings in .text or .code sections should not be extracted."""
        analyzer = WideStringAnalyzer()

        wide_str = b"T\x00e\x00s\x00t\x00\x00\x00"
        section_data = b"\x00" * 8 + wide_str + b"\x00" * 8

        mock_section = MagicMock()
        mock_section.Name = b".text\x00\x00\x00"
        mock_section.VirtualAddress = 0x1000
        mock_section.PointerToRawData = 0
        mock_section.get_data.return_value = section_data

        mock_pe = MagicMock()
        mock_pe.sections = [mock_section]

        with patch("pefile.PE", return_value=mock_pe):
            result = analyzer._extract_wide_strings(Path("test.sys"))

        assert result == []


class TestUnicodeStringConstructs:
    """Test UNICODE_STRING construction pattern detection."""

    def test_detect_unicode_string_construct(self):
        """mov word ptr + lea pattern should be detected."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "word ptr [rax], 0x10"),
            ("mov", "word ptr [rax+2], 0x20"),
            ("lea", "rbx, [rcx+0x10]"),
        ])
        analyzer = WideStringAnalyzer()
        constructs = analyzer._detect_unicode_string_constructs(ir)
        assert len(constructs) >= 1
        assert constructs[0]["func_addr"] == 0x1000

    def test_no_construct_without_buf(self):
        """mov word ptr without lea should not be detected."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "word ptr [rax], 0x10"),
            ("mov", "word ptr [rax+2], 0x20"),
        ])
        analyzer = WideStringAnalyzer()
        constructs = analyzer._detect_unicode_string_constructs(ir)
        assert len(constructs) == 0

    def test_empty_cfg(self):
        """Empty CFG should not crash."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        analyzer = WideStringAnalyzer()
        constructs = analyzer._detect_unicode_string_constructs(ir)
        assert constructs == []


class TestIntegration:
    """Test full analyze() integration."""

    def test_wide_string_finding_has_evidence(self):
        """Wide string findings should have evidence."""
        ir = _make_ir()
        sample = _sample()
        analyzer = WideStringAnalyzer()

        with patch.object(analyzer, "_extract_wide_strings", return_value=[{
            "string": "\\Device\\MyDriver",
            "section": ".rdata",
            "rva": 0x1000,
            "length": 28,
        }]):
            with patch.object(analyzer, "_detect_unicode_string_constructs", return_value=[]):
                findings = analyzer.analyze(sample, ir)

        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.WIDE_STRING_FOUND
        assert findings[0].severity == Severity.LOW
        assert findings[0].context["category"] == "device_path"

    def test_unicode_construct_finding(self):
        """UNICODE_STRING construct findings should have correct category."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "word ptr [rax], 0x10"),
            ("lea", "rbx, [rcx+0x10]"),
        ])
        sample = _sample()
        analyzer = WideStringAnalyzer()

        with patch.object(analyzer, "_extract_wide_strings", return_value=[]):
            findings = analyzer.analyze(sample, ir)

        construct_findings = [f for f in findings if "UNICODE_STRING" in f.description]
        assert len(construct_findings) >= 1
        assert construct_findings[0].severity == Severity.INFO

    def test_populates_ir_wide_strings(self):
        """Analysis should populate ir.wide_strings."""
        ir = _make_ir()
        sample = _sample()
        analyzer = WideStringAnalyzer()

        test_strings = [{"string": "TestWide", "section": ".rdata", "rva": 0x1000, "length": 16}]
        with patch.object(analyzer, "_extract_wide_strings", return_value=test_strings):
            with patch.object(analyzer, "_detect_unicode_string_constructs", return_value=[]):
                analyzer.analyze(sample, ir)

        assert ir.wide_strings == test_strings
