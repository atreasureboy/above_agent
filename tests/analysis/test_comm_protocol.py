"""Tests for the CommProtocolAnalyzer (Task D: communication protocol reverse engineering)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.analysis.deep.comm_protocol_analyzer import (
    CommProtocolAnalyzer,
    METHOD_NAMES,
    DEVICE_TYPE_NAMES,
    API_SEMANTICS,
)
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


# ------------------------------------------------------------------
# Test structure
# ------------------------------------------------------------------

class TestCommProtocolAnalyzerStructure:
    def test_name(self):
        a = CommProtocolAnalyzer()
        assert a.name == "CommProtocolAnalyzer"

    def test_description_nonempty(self):
        a = CommProtocolAnalyzer()
        assert a.description != ""

    def test_enabled_by_default(self):
        a = CommProtocolAnalyzer()
        assert a.enabled is True

    def test_not_correlator(self):
        a = CommProtocolAnalyzer()
        assert a.is_correlator is False


# ------------------------------------------------------------------
# Test constants
# ------------------------------------------------------------------

class TestConstants:
    def test_method_names(self):
        assert METHOD_NAMES[0] == "METHOD_BUFFERED"
        assert METHOD_NAMES[3] == "METHOD_NEITHER"

    def test_device_types(self):
        assert 0x22 in DEVICE_TYPE_NAMES
        assert 0x8000 in DEVICE_TYPE_NAMES

    def test_api_semantics(self):
        assert "memory" in API_SEMANTICS["MmMapIoSpaceEx"]
        assert "process termination" in API_SEMANTICS["ZwTerminateProcess"]


# ------------------------------------------------------------------
# Test IOCTL code decoding
# ------------------------------------------------------------------

class TestIOCTLDecoding:
    def test_decode_buffered_ioctl(self):
        """METHOD_BUFFERED IOCTL should be decoded correctly."""
        a = CommProtocolAnalyzer()
        # CTL_CODE(0x22, 0x100, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x220400
        ir = _make_ir(ioctl_codes=[0x220400])
        findings = a._decode_ioctl_codes(ir)
        assert len(findings) >= 1
        assert findings[0].context["device_type"] == 0x22
        assert findings[0].context["method"] == 0
        assert findings[0].context["method_name"] == "METHOD_BUFFERED"

    def test_decode_neither_ioctl(self):
        """METHOD_NEITHER IOCTL should have MEDIUM severity."""
        a = CommProtocolAnalyzer()
        # CTL_CODE(0x22, 0x101, METHOD_NEITHER, FILE_ANY_ACCESS) = 0x220403
        ir = _make_ir(ioctl_codes=[0x220403])
        findings = a._decode_ioctl_codes(ir)
        assert len(findings) >= 1
        assert findings[0].context["method"] == 3
        assert findings[0].context["method_name"] == "METHOD_NEITHER"
        assert findings[0].severity == Severity.MEDIUM

    def test_decode_360_custom(self):
        """360 custom device type should be detected."""
        a = CommProtocolAnalyzer()
        # CTL_CODE(0x8000, 0x0, METHOD_BUFFERED, FILE_ANY_ACCESS) = 0x80000000
        ir = _make_ir(ioctl_codes=[0x80000000])
        findings = a._decode_ioctl_codes(ir)
        assert len(findings) >= 1
        assert findings[0].context["device_type"] == 0x8000
        assert findings[0].context["device_type_name"] == "FILE_DEVICE_360_CUSTOM"

    def test_decode_multiple_ioctls(self):
        """Multiple IOCTLs should all be decoded."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(ioctl_codes=[0x220400, 0x220404, 0x220408])
        findings = a._decode_ioctl_codes(ir)
        assert len(findings) >= 3

    def test_empty_ioctl_codes(self):
        """Empty ioctl_codes should return no findings."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(ioctl_codes=[])
        findings = a._decode_ioctl_codes(ir)
        assert findings == []

    def test_decoded_ioctls_populated(self):
        """IR should have decoded_ioctls populated."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(ioctl_codes=[0x220400])
        a._decode_ioctl_codes(ir)
        assert hasattr(ir, "decoded_ioctls")
        assert len(ir.decoded_ioctls) == 1


# ------------------------------------------------------------------
# Test buffer method analysis
# ------------------------------------------------------------------

class TestBufferMethodAnalysis:
    def test_neither_without_probe(self):
        """METHOD_NEITHER without ProbeForRead should be flagged HIGH."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(
            ioctl_codes=[0x220403],  # METHOD_NEITHER
            ioctl_handlers={0x220403: 0x1000},
            function_apis={0x1000: ["ZwCreateFile"]},
        )
        ir.decoded_ioctls = [{
            "ioctl_code": 0x220403,
            "method": 3,
            "device_type": 0x22,
        }]
        findings = a._analyze_buffer_methods(ir)
        unsafe = [f for f in findings if f.severity == Severity.HIGH]
        assert len(unsafe) >= 1

    def test_neither_with_probe(self):
        """METHOD_NEITHER with ProbeForRead should be validated."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(
            ioctl_codes=[0x220403],
            ioctl_handlers={0x220403: 0x1000},
            function_apis={0x1000: ["ProbeForRead"]},
        )
        ir.decoded_ioctls = [{
            "ioctl_code": 0x220403,
            "method": 3,
            "device_type": 0x22,
        }]
        findings = a._analyze_buffer_methods(ir)
        validated = [f for f in findings if f.category == FindingCategory.VALIDATED_SURFACE]
        assert len(validated) >= 1

    def test_buffered_is_safe(self):
        """METHOD_BUFFERED should be classified as safe."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(ioctl_codes=[0x220400])
        ir.decoded_ioctls = [{
            "ioctl_code": 0x220400,
            "method": 0,
            "device_type": 0x22,
        }]
        findings = a._analyze_buffer_methods(ir)
        safe = [f for f in findings if f.category == FindingCategory.VALIDATED_SURFACE]
        assert len(safe) >= 1


# ------------------------------------------------------------------
# Test ALPC port analysis
# ------------------------------------------------------------------

class TestALPCPortAnalysis:
    def test_alpc_port_detected(self):
        """ALPC port names should be detected from wide strings."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(
            wide_strings=[
                {"string": "\\Alpc\\MyPort", "section": ".rdata", "rva": 0x1000},
                {"string": "\\RPC Control\\MyRpc", "section": ".rdata", "rva": 0x1010},
            ],
        )
        findings = a._analyze_alpc_ports(ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.ALPC_PORT_NAME

    def test_no_alpc_ports(self):
        """No ALPC ports should return no findings."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(wide_strings=[])
        findings = a._analyze_alpc_ports(ir)
        assert findings == []


# ------------------------------------------------------------------
# Test NamedPipe analysis
# ------------------------------------------------------------------

class TestNamedPipeAnalysis:
    def test_pipe_detected(self):
        """Named pipe names should be detected from wide strings."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(
            wide_strings=[
                {"string": "\\\\.\\pipe\\MyPipe", "section": ".rdata", "rva": 0x1000},
            ],
        )
        findings = a._analyze_named_pipes(ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.NAMED_PIPE

    def test_no_pipes(self):
        """No named pipes should return no findings."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(wide_strings=[])
        findings = a._analyze_named_pipes(ir)
        assert findings == []


# ------------------------------------------------------------------
# Test command semantics inference
# ------------------------------------------------------------------

class TestCommandSemanticsInference:
    def test_memory_primitive_detected(self):
        """Handler with MmMapIoSpaceEx should be inferred as memory primitive."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(
            ioctl_handlers={0x220400: 0x1000},
            function_apis={0x1000: ["MmMapIoSpaceEx", "ZwMapViewOfSection"]},
        )
        findings = a._infer_command_semantics(ir)
        assert len(findings) >= 1
        assert "memory" in findings[0].description.lower()

    def test_process_control_detected(self):
        """Handler with ZwTerminateProcess should be inferred as process control."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(
            ioctl_handlers={0x220400: 0x1000},
            function_apis={0x1000: ["ZwTerminateProcess"]},
        )
        findings = a._infer_command_semantics(ir)
        assert len(findings) >= 1
        assert "process termination" in findings[0].description.lower()

    def test_no_semantics_for_unknown_apis(self):
        """Handler with unknown APIs should not produce semantic findings."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(
            ioctl_handlers={0x220400: 0x1000},
            function_apis={0x1000: ["sub_1234", "unknown_func"]},
        )
        findings = a._infer_command_semantics(ir)
        assert findings == []

    def test_empty_handlers(self):
        """Empty ioctl_handlers should return no findings."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(ioctl_handlers={})
        findings = a._infer_command_semantics(ir)
        assert findings == []

    def test_inferred_commands_populated(self):
        """IR should have inferred_commands populated."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(
            ioctl_handlers={0x220400: 0x1000},
            function_apis={0x1000: ["MmMapIoSpaceEx"]},
        )
        a._infer_command_semantics(ir)
        assert hasattr(ir, "inferred_commands")
        assert len(ir.inferred_commands) == 1


# ------------------------------------------------------------------
# Test full analyze pipeline
# ------------------------------------------------------------------

class TestFullAnalyze:
    def test_analyze_returns_list(self):
        """analyze() should always return a list."""
        a = CommProtocolAnalyzer()
        sample = _make_sample()
        ir = _make_ir()
        findings = a.analyze(sample, ir)
        assert isinstance(findings, list)

    def test_analyze_with_ioctls_and_strings(self):
        """Full analyze with IOCTLs and strings should produce findings."""
        a = CommProtocolAnalyzer()
        sample = _make_sample()
        ir = _make_ir(
            ioctl_codes=[0x220400, 0x220403],
            ioctl_handlers={0x220400: 0x1000},
            function_apis={0x1000: ["MmMapIoSpaceEx"]},
            wide_strings=[
                {"string": "\\Alpc\\TestPort", "section": ".rdata", "rva": 0x1000},
                {"string": "\\\\.\\pipe\\TestPipe", "section": ".rdata", "rva": 0x1010},
            ],
        )
        findings = a.analyze(sample, ir)
        assert isinstance(findings, list)
        # Should have at least IOCTL decode findings
        ioctl_findings = [f for f in findings if f.category == FindingCategory.IOCTL_CODE_EXPOSED]
        assert len(ioctl_findings) >= 2

    def test_probe_check_from_dynamic_imports(self):
        """ProbeForRead from dynamic_imports should be detected."""
        a = CommProtocolAnalyzer()
        ir = _make_ir(
            dynamic_imports={
                0x1010: {"api_name": "ProbeForWrite", "func_addr": 0x1000},
            },
        )
        assert a._check_for_probe(0x1000, ir) is True
