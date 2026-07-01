"""Tests for IOCTLAnalyzer."""

import pytest
from pathlib import Path
from src.models import (
    Architecture, DisassemblyResult, Finding, FindingCategory,
    Function, Sample, Severity, Confidence,
)
from src.analysis.core.ioctl_analyzer import IOCTLAnalyzer


def _make_sample() -> Sample:
    return Sample(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1000,
        is_driver=True, driver_type="WDM",
    )


class TestIOCTLAnalyzer:
    def setup_method(self):
        self.analyzer = IOCTLAnalyzer()

    def test_name(self):
        assert self.analyzer.name == "IOCTLAnalyzer"

    def test_description_non_empty(self):
        assert len(self.analyzer.description) > 10

    def test_enabled_by_default(self):
        assert self.analyzer.enabled is True

    def test_no_findings_when_no_ioctl_codes(self):
        sample = _make_sample()
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        findings = self.analyzer.analyze(sample, ir)
        assert findings == []

    def test_finding_for_ioctl_code_without_handler(self):
        """When ioctl_codes exist but ioctl_handlers is empty, report at LOW confidence."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            ioctl_codes=[0x22A004],  # Some IOCTL code
        )
        findings = self.analyzer.analyze(sample, ir)
        assert len(findings) == 1
        f = findings[0]
        assert f.category == FindingCategory.IOCTL_CODE_EXPOSED
        assert f.confidence == Confidence.LOW
        assert f.ioctl_code == 0x22A004

    def test_finding_for_ioctl_code_with_handler(self):
        """When ioctl_handlers has a mapping, report at HIGH confidence."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            ioctl_handlers={0x22A004: 0x1234},
        )
        findings = self.analyzer.analyze(sample, ir)
        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == Confidence.HIGH
        assert f.function_address == 0x1234
        assert "sub_1234" in f.description

    def test_multiple_ioctl_codes(self):
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            ioctl_handlers={
                0x22A004: 0x1000,
                0x22A008: 0x2000,
                0x22A00C: 0x3000,
            },
        )
        findings = self.analyzer.analyze(sample, ir)
        assert len(findings) == 3

    def test_method_neither_has_higher_severity(self):
        """METHOD_NEITHER (3) IOCTLs should be MEDIUM severity."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            ioctl_handlers={0x22A003: 0x1000},  # Method 3 = NEITHER
        )
        findings = self.analyzer.analyze(sample, ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_method_buffered_has_lower_severity(self):
        """METHOD_BUFFERED (0) IOCTLs should be LOW severity."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            ioctl_handlers={0x22A000: 0x1000},  # Method 0 = BUFFERED
        )
        findings = self.analyzer.analyze(sample, ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_evidence_included(self):
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            ioctl_handlers={0x22A004: 0x1234},
        )
        findings = self.analyzer.analyze(sample, ir)
        assert len(findings[0].evidence) > 0
        assert findings[0].evidence[0].rule_id == "IOCTL_HANDLER_MAP"

    def test_method_out_direct_has_medium_severity(self):
        """METHOD_OUT_DIRECT (2) IOCTLs should be MEDIUM severity."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            ioctl_handlers={0x22A002: 0x1000},  # Method 2 = OUT_DIRECT
        )
        findings = self.analyzer.analyze(sample, ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_method_in_direct_has_low_severity(self):
        """METHOD_IN_DIRECT (1) IOCTLs should be LOW severity."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            ioctl_handlers={0x22A001: 0x1000},  # Method 1 = IN_DIRECT
        )
        findings = self.analyzer.analyze(sample, ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_method_in_description(self):
        """Finding description should include the method name."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            ioctl_handlers={0x22A003: 0x1000},  # NEITHER
        )
        findings = self.analyzer.analyze(sample, ir)
        assert "NEITHER" in findings[0].description
