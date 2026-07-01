"""Tests for Named Pipe communication detection (Phase 5b)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.core.namedpipe_detector import (
    NamedPipeDetector,
    NAMED_PIPE_APIS,
    PIPE_STRING_PATTERNS,
    PIPE_FSCTL_CODES,
    detect_named_pipe_apis,
    detect_named_pipe_strings,
    detect_pipe_fsctl_codes,
)
from src.models import (
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Severity,
    Sample,
    Architecture,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _add_function(ir: DisassemblyResult, addr: int, api_names: list[str] | None = None) -> None:
    func = Function(name=f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func
    if api_names:
        ir.function_apis[addr] = api_names


def _add_cfg_with_insns(ir: DisassemblyResult, func_addr: int, instructions: list[tuple[str, str]]) -> None:
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    insns = [
        Instruction(address=func_addr + 0x10 + i * 4, mnemonic=mnem, operands=ops, size=4)
        for i, (mnem, ops) in enumerate(instructions)
    ]
    block = BasicBlock(address=func_addr, end_address=func_addr + 0x100, instructions=insns, successors=[])
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg


class TestNamedPipeConstants:
    """Test named pipe detection constant definitions."""

    def test_named_pipe_apis_defined(self):
        assert "NtCreateNamedPipeFile" in NAMED_PIPE_APIS
        assert "ZwCreateNamedPipeFile" in NAMED_PIPE_APIS
        assert "NtFsControlFile" in NAMED_PIPE_APIS
        assert "ZwFsControlFile" in NAMED_PIPE_APIS
        assert "NtReadFile" in NAMED_PIPE_APIS
        assert "NtWriteFile" in NAMED_PIPE_APIS

    def test_pipe_string_patterns_defined(self):
        assert "\\Device\\NamedPipe" in PIPE_STRING_PATTERNS
        assert "\\??\\pipe" in PIPE_STRING_PATTERNS
        assert "360Pipe" in PIPE_STRING_PATTERNS
        assert "360Tray" in PIPE_STRING_PATTERNS

    def test_fsctl_codes_defined(self):
        assert 0x110044 in PIPE_FSCTL_CODES  # FSCTL_PIPE_TRANSCEIVE
        assert 0x110050 in PIPE_FSCTL_CODES  # FSCTL_PIPE_WAIT
        assert 0x11001C in PIPE_FSCTL_CODES  # FSCTL_PIPE_LISTEN


class TestNamedPipeApiDetection:
    """Test named pipe API detection."""

    def test_create_named_pipe_critical(self):
        """NtCreateNamedPipeFile + read/write should be CRITICAL."""
        ir = _make_ir()
        _add_function(ir, 0x1000, [
            "NtCreateNamedPipeFile",
            "NtReadFile",
            "NtWriteFile",
        ])
        findings = detect_named_pipe_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].category == FindingCategory.NAMED_PIPE

    def test_create_and_read_write_high(self):
        """ZwCreateFile + ZwReadFile should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, [
            "ZwCreateFile",
            "ZwReadFile",
            "ZwWriteFile",
        ])
        findings = detect_named_pipe_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_fsctl_only_high(self):
        """FsControlFile alone should be HIGH."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["NtFsControlFile"])
        findings = detect_named_pipe_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_create_only_medium(self):
        """Create without RW should be MEDIUM."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ZwCreateFile"])
        findings = detect_named_pipe_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_read_only_low(self):
        """ReadFile alone should be LOW."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["NtReadFile"])
        findings = detect_named_pipe_apis(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_multiple_pipe_functions(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["NtCreateNamedPipeFile"])
        _add_function(ir, 0x2000, ["NtReadFile"])
        _add_function(ir, 0x3000, ["NtWriteFile"])
        findings = detect_named_pipe_apis(ir)
        assert len(findings) == 1
        ctx = findings[0].context
        assert len(ctx["pipe_functions"]) == 3

    def test_no_pipe_apis(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["IoCreateDevice"])
        findings = detect_named_pipe_apis(ir)
        assert findings == []


class TestNamedPipeStringDetection:
    """Test named pipe string detection."""

    def test_device_namedpipe_string(self):
        ir = _make_ir()
        ir.strings.append("\\Device\\NamedPipe\\MyPipe")
        findings = detect_named_pipe_strings(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_360_pipe_critical(self):
        """360-specific pipe name should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("\\Device\\NamedPipe\\360AntiHackPipe")
        findings = detect_named_pipe_strings(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_360tray_critical(self):
        ir = _make_ir()
        ir.strings.append("\\??\\pipe\\360TrayComm")
        findings = detect_named_pipe_strings(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_qhpipe_critical(self):
        ir = _make_ir()
        ir.strings.append("\\??\\pipe\\QHP_SafePipe")
        findings = detect_named_pipe_strings(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_generic_pipe_medium(self):
        ir = _make_ir()
        ir.strings.append("\\??\\pipe\\GenericPipe")
        findings = detect_named_pipe_strings(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_no_pipe_strings(self):
        ir = _make_ir()
        findings = detect_named_pipe_strings(ir)
        assert findings == []


class TestPipeFsctlDetection:
    """Test FSCTL pipe operation code detection."""

    def test_pipe_transceive_detected(self):
        """FSCTL_PIPE_TRANSCEIVE should be detected."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "eax, 0x110044"),
        ])
        findings = detect_pipe_fsctl_codes(ir)
        assert len(findings) == 1

    def test_pipe_wait_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "eax, 0x110050"),
        ])
        findings = detect_pipe_fsctl_codes(ir)
        assert len(findings) == 1

    def test_pipe_listen_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rcx, 0x11001c"),
        ])
        findings = detect_pipe_fsctl_codes(ir)
        assert len(findings) == 1

    def test_no_fsctl_codes(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, rbx"),
        ])
        findings = detect_pipe_fsctl_codes(ir)
        assert findings == []

    def test_empty_ir(self):
        ir = _make_ir()
        findings = detect_pipe_fsctl_codes(ir)
        assert findings == []


class TestNamedPipeDetectorIntegration:
    """Test NamedPipeDetector end-to-end."""

    def test_analyzer_name(self):
        detector = NamedPipeDetector()
        assert detector.name == "NamedPipeDetector"

    def test_analyzer_description(self):
        detector = NamedPipeDetector()
        desc = detector.description
        assert "named pipe" in desc.lower() or "pipe" in desc.lower()

    def test_analyze_empty_ir(self):
        ir = _make_ir()
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = NamedPipeDetector()
        findings = detector.analyze(sample, ir)
        assert findings == []

    def test_analyze_detects_pipe_and_string(self):
        """Named pipe APIs + 360 pipe strings should produce findings."""
        ir = _make_ir()
        _add_function(ir, 0x1000, [
            "NtCreateNamedPipeFile",
            "NtReadFile",
        ])
        ir.strings.append("\\Device\\NamedPipe\\360AntiHack")

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = NamedPipeDetector()
        findings = detector.analyze(sample, ir)

        categories = {f.category for f in findings}
        assert FindingCategory.NAMED_PIPE in categories

    def test_analyze_findings_have_evidence(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["NtCreateNamedPipeFile"])
        ir.strings.append("\\??\\pipe\\360Tray")

        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = NamedPipeDetector()
        findings = detector.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0
