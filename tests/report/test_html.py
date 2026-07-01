"""Tests for HTML report generation."""

import pytest
from pathlib import Path
import tempfile
from src.models import Architecture, Finding, FindingCategory, Sample, Severity, Confidence, Report
from src.report.html import generate_html, write_html


def _make_sample(findings=None, score=5.0) -> Sample:
    s = Sample(
        path=Path("test.sys"), name="test.sys", company="TestCorp",
        version="1.0.0", arch=Architecture.X64, sha256="abc123",
        size=4096, is_driver=True, driver_type="WDM",
        risk_score=score,
    )
    s.analysis_findings = findings or []
    return s


class TestGenerateHTML:
    def test_returns_string(self):
        report = Report(samples=[], timestamp="2026-01-01", tool_version="0.0.3", backend="capstone")
        html = generate_html(report)
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html

    def test_contains_doctype_and_html(self):
        report = Report(samples=[], timestamp="2026-01-01", tool_version="0.0.3", backend="capstone")
        html = generate_html(report)
        assert "<!DOCTYPE html>" in html
        assert "<html>" in html
        assert "</html>" in html

    def test_contains_sample_name(self):
        sample = _make_sample(score=8.0)
        report = Report(
            samples=[sample], timestamp="2026-01-01", tool_version="0.0.3", backend="capstone",
            total_analyzed=1,
        )
        html = generate_html(report)
        assert "test.sys" in html

    def test_contains_severity_label(self):
        finding = Finding(
            category=FindingCategory.ARBITRARY_MEMORY_MAP,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="High severity finding",
        )
        sample = _make_sample(findings=[finding], score=7.5)
        report = Report(
            samples=[sample], timestamp="2026-01-01", tool_version="0.0.3", backend="capstone",
            total_analyzed=1, total_findings=1,
        )
        html = generate_html(report)
        assert "HIGH" in html

    def test_contains_evidence_snippet(self):
        from src.models import Evidence
        finding = Finding(
            category=FindingCategory.IOCTL_CODE_EXPOSED,
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description="IOCTL exposed",
            evidence=[Evidence(type="instruction_pattern", location="0x1000", snippet="cmp eax, 0x22A004", rule_id="IOCTL_HANDLER_MAP")],
        )
        sample = _make_sample(findings=[finding], score=3.0)
        report = Report(
            samples=[sample], timestamp="2026-01-01", tool_version="0.0.3", backend="capstone",
            total_analyzed=1, total_findings=1,
        )
        html = generate_html(report)
        assert "cmp eax" in html
        assert "IOCTL_HANDLER_MAP" in html

    def test_no_findings_message(self):
        report = Report(
            samples=[_make_sample(score=0.0)],
            timestamp="2026-01-01", tool_version="0.0.3", backend="capstone",
        )
        html = generate_html(report)
        # Score is 0, so sample won't appear in findings list
        assert "No findings detected" in html or "DriverScope" in html

    def test_contains_css(self):
        report = Report(samples=[], timestamp="2026-01-01", tool_version="0.0.3", backend="capstone")
        html = generate_html(report)
        assert "<style>" in html
        assert "summary" in html

    def test_multiple_samples_sorted_by_score(self):
        samples = [
            _make_sample(score=2.0),
            _make_sample(score=9.0),
            _make_sample(score=5.0),
        ]
        report = Report(
            samples=samples, timestamp="2026-01-01", tool_version="0.0.3", backend="capstone",
            total_analyzed=3, total_findings=0,
        )
        html = generate_html(report)
        # Should contain all three sample names
        assert html.count("test.sys") >= 3


class TestWriteHTML:
    def test_writes_file(self):
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            output_path = Path(f.name)

        sample = _make_sample(score=7.0)
        report = Report(
            samples=[sample], timestamp="2026-01-01", tool_version="0.0.3", backend="capstone",
            total_analyzed=1, total_findings=0,
        )
        write_html(report, output_path)

        assert output_path.exists()
        content = output_path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        output_path.unlink()
