"""Tests for StringAnalyzer."""

import pytest
from pathlib import Path
from src.models import Architecture, DisassemblyResult, Sample
from src.analysis.core.string_analyzer import StringAnalyzer


def _make_sample() -> Sample:
    return Sample(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1000,
        is_driver=True, driver_type="WDM",
    )


class TestStringAnalyzer:
    def setup_method(self):
        self.analyzer = StringAnalyzer()

    def test_name(self):
        assert self.analyzer.name == "StringAnalyzer"

    def test_enabled_by_default(self):
        assert self.analyzer.enabled is True

    def test_no_findings_when_no_strings(self):
        sample = _make_sample()
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        findings = self.analyzer.analyze(sample, ir)
        assert findings == []

    def test_finding_for_physical_memory_string(self):
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            strings=[r"\Device\PhysicalMemory", "hello"],
        )
        findings = self.analyzer.analyze(sample, ir)
        assert len(findings) >= 2  # Pattern match + summary
        assert any("physical" in f.description.lower() for f in findings)

    def test_finding_for_dbgprint_string(self):
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            strings=["DbgPrint called"],
        )
        findings = self.analyzer.analyze(sample, ir)
        assert len(findings) >= 1

    def test_no_false_positive_for_safe_strings(self):
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            strings=["Microsoft", "Windows", "Driver"],
        )
        findings = self.analyzer.analyze(sample, ir)
        assert findings == []

    def test_summary_finding(self):
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            strings=[r"\Device\PhysicalMemory", "DEBUG=1"],
        )
        findings = self.analyzer.analyze(sample, ir)
        # Last finding should be summary
        assert any("indicator" in f.description.lower() for f in findings)
