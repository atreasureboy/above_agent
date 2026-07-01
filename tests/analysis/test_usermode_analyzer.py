"""Tests for usermode_analyzer.py."""

import pytest
from pathlib import Path

from src.analysis.core.usermode_analyzer import UserModeAnalyzer
from src.models import (
    Architecture, DisassemblyResult, FindingCategory, Sample,
    SignatureStatus, Severity,
)


def _make_sample(**kwargs) -> Sample:
    defaults = dict(
        path=Path("test.exe"),
        name="test.exe",
        company="Test Corp",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="a" * 64,
        size=1024,
        is_usermode=True,
        binary_type="exe",
    )
    defaults.update(kwargs)
    return Sample(**defaults)


def _make_ir(**kwargs) -> DisassemblyResult:
    defaults = dict(
        sample_path=Path("test.exe"),
        backend="capstone",
    )
    defaults.update(kwargs)
    return DisassemblyResult(**defaults)


class TestUserModeAnalyzer:
    def setup_method(self):
        self.analyzer = UserModeAnalyzer()

    def test_name(self):
        assert self.analyzer.name == "UserModeAnalyzer"

    def test_enabled(self):
        assert self.analyzer.enabled is True

    def test_dangerous_imports_detected(self):
        sample = _make_sample(imports=["CreateRemoteThread", "WriteProcessMemory"])
        ir = _make_ir()
        findings = self.analyzer.analyze(sample, ir)

        dangerous = [f for f in findings if f.category == FindingCategory.DANGEROUS_USERMODE_IMPORT]
        assert len(dangerous) > 0

    def test_com_interface_detected(self):
        sample = _make_sample(
            com_interfaces=["DllGetClassObject", "DllCanUnloadNow"],
        )
        ir = _make_ir()
        findings = self.analyzer.analyze(sample, ir)

        com = [f for f in findings if f.category == FindingCategory.COM_INTERFACE_EXPOSED]
        assert len(com) == 1

    def test_service_entrypoint_detected(self):
        sample = _make_sample(
            service_info={"has_service_entry": True, "service_exports": ["ServiceMain"]},
        )
        ir = _make_ir()
        findings = self.analyzer.analyze(sample, ir)

        svc = [f for f in findings if f.category == FindingCategory.SERVICE_REGISTRATION]
        assert len(svc) == 1

    def test_embedded_driver_detected(self):
        sample = _make_sample(embedded_files=[Path("test.exe"), Path("test.exe")])
        ir = _make_ir()
        findings = self.analyzer.analyze(sample, ir)

        emb = [f for f in findings if f.category == FindingCategory.EMBEDDED_DRIVER]
        assert len(emb) == 1

    def test_device_path_string_detected(self):
        ir = _make_ir(strings=[r"\\.\TestDevice", "normal string"])
        sample = _make_sample()
        findings = self.analyzer.analyze(sample, ir)

        bridge = [f for f in findings if f.category == FindingCategory.USERMODE_KERNEL_BRIDGE]
        assert len(bridge) == 1

    def test_no_findings_for_clean_sample(self):
        sample = _make_sample(
            imports=["kernel32.dll"],
            com_interfaces=[],
            service_info={},
            embedded_files=[],
        )
        ir = _make_ir(strings=["normal string", "no paths here"])
        findings = self.analyzer.analyze(sample, ir)

        # Should have no high-severity findings
        high = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
        assert len(high) == 0

    def test_url_strings_found(self):
        ir = _make_ir(strings=["https://example.com/api/v1/telemetry"])
        sample = _make_sample()
        findings = self.analyzer.analyze(sample, ir)

        url = [f for f in findings if f.category == FindingCategory.DANGEROUS_STRING]
        assert len(url) == 1
