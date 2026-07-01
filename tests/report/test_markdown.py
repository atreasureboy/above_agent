"""Tests for Markdown report generator — Phase 4."""

import pytest
from pathlib import Path
import tempfile

from src.models import (
    Architecture, Confidence, Evidence, Finding, FindingCategory,
    Function, Report, Sample, Severity,
)
from src.report.markdown import generate_markdown, write_markdown


def _make_sample_with_findings():
    sample = Sample(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1000,
    )
    sample.risk_score = 7.5
    sample.analysis_findings = [
        Finding(
            category=FindingCategory.ARBITRARY_MEMORY_MAP,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description="Calls MmMapIoSpace without validation",
            function_address=0x1000,
            api_name="MmMapIoSpace",
            evidence=[
                Evidence(
                    type="import",
                    location="IAT@0x5000",
                    snippet="ntoskrnl.MmMapIoSpace",
                    rule_id="PRIM_MM_MAP",
                )
            ],
        ),
    ]
    return sample


class TestMarkdownReport:
    def test_generates_valid_markdown(self):
        sample = _make_sample_with_findings()
        report = Report(
            samples=[sample],
            timestamp="2026-05-19T00:00:00",
            tool_version="0.0.7",
            backend="capstone",
            total_analyzed=1,
            total_findings=1,
            summary={"avg_risk_score": 7.5},
        )
        md = generate_markdown(report)
        assert "test.sys" in md
        assert "MmMapIoSpace" in md
        assert "7.5" in md

    def test_empty_report(self):
        report = Report(
            samples=[],
            timestamp="2026-05-19T00:00:00",
            tool_version="0.0.7",
            backend="capstone",
        )
        md = generate_markdown(report)
        assert isinstance(md, str)
        assert len(md) > 0

    def test_write_markdown_to_file(self):
        sample = _make_sample_with_findings()
        report = Report(
            samples=[sample],
            timestamp="2026-05-19T00:00:00",
            tool_version="0.0.7",
            backend="capstone",
            total_analyzed=1,
            total_findings=1,
        )
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            output_path = Path(f.name)
        try:
            write_markdown(report, output_path)
            content = output_path.read_text(encoding="utf-8")
            assert "test.sys" in content
        finally:
            output_path.unlink(missing_ok=True)

    def test_includes_severity_table(self):
        sample = _make_sample_with_findings()
        report = Report(
            samples=[sample],
            timestamp="2026-05-19T00:00:00",
            tool_version="0.0.7",
            backend="capstone",
            total_analyzed=1,
            total_findings=1,
            summary={"avg_risk_score": 7.5, "critical_count": 0, "high_count": 1},
        )
        md = generate_markdown(report)
        assert "|" in md  # Markdown table

    def test_multiple_samples_sorted_by_score(self):
        samples = []
        for i, score in enumerate([3.0, 8.0, 5.0]):
            s = Sample(
                path=Path(f"drv{i}.sys"), name=f"drv{i}.sys", company="Test",
                version="1.0", arch=Architecture.X64, sha256=f"sha{i}", size=1000,
            )
            s.risk_score = score
            samples.append(s)
        report = Report(
            samples=samples,
            timestamp="2026-05-19T00:00:00",
            tool_version="0.0.7",
            backend="capstone",
            total_analyzed=3,
        )
        md = generate_markdown(report)
        # 8.0 should appear before 5.0 and 3.0
        pos_8 = md.index("8.0")
        pos_5 = md.index("5.0")
        pos_3 = md.index("3.0")
        assert pos_8 < pos_5 < pos_3
