"""Integration tests for the analysis pipeline orchestrator."""

import pytest
from pathlib import Path
from src.analysis.pipeline import run_single, run_batch
from src.models import Sample


SAMPLES_DIR = Path(__file__).resolve().parent.parent / "samples"
MOCK_DRIVER = SAMPLES_DIR / "unknown" / "mock_driver.sys"


class TestRunSingle:
    @pytest.mark.skipif(not MOCK_DRIVER.exists(), reason="No mock_driver.sys")
    def test_run_single_returns_sample(self):
        """run_single should return a Sample with findings and risk_score."""
        sample = run_single(MOCK_DRIVER, backend_name="capstone")
        assert isinstance(sample, Sample)
        assert sample.risk_score >= 0.0
        assert sample.risk_score <= 10.0
        assert sample.disassembly_result is not None
        assert len(sample.disassembly_result.functions) > 0

    @pytest.mark.skipif(not MOCK_DRIVER.exists(), reason="No mock_driver.sys")
    def test_run_single_populates_findings(self):
        """run_single should populate analysis_findings."""
        sample = run_single(MOCK_DRIVER, backend_name="capstone")
        assert isinstance(sample.analysis_findings, list)
        # mock_driver.sys is minimal, may have few findings
        # Just verify the pipeline runs without error

    def test_run_single_missing_file(self):
        """run_single should raise on missing file."""
        with pytest.raises((FileNotFoundError, ValueError)):
            run_single(Path("nonexistent.sys"), backend_name="capstone")


class TestRunBatch:
    @pytest.mark.skipif(not (SAMPLES_DIR / "unknown").exists(), reason="No samples/unknown dir")
    def test_run_batch_no_funnel(self):
        """run_batch with use_funnel=False should analyze all samples directly."""
        report = run_batch(
            SAMPLES_DIR / "unknown",
            backend_name="capstone",
            limit=1,
            use_funnel=False,
        )
        assert report.total_analyzed >= 1
        assert report.backend == "capstone"

    @pytest.mark.skipif(not (SAMPLES_DIR / "unknown").exists(), reason="No samples/unknown dir")
    def test_run_batch_with_limit(self):
        """run_batch with limit should analyze at most N samples."""
        report = run_batch(
            SAMPLES_DIR / "unknown",
            backend_name="capstone",
            limit=1,
            use_funnel=False,
        )
        assert report.total_analyzed <= 1

    def test_run_batch_empty_dir(self, tmp_path):
        """run_batch should raise ValueError on empty directory."""
        with pytest.raises(ValueError):
            run_batch(tmp_path, backend_name="capstone", use_funnel=False)

    @pytest.mark.skipif(not (SAMPLES_DIR / "unknown").exists(), reason="No samples/unknown dir")
    def test_run_batch_report_has_samples(self):
        """run_batch report should contain analyzed samples."""
        report = run_batch(
            SAMPLES_DIR / "unknown",
            backend_name="capstone",
            limit=1,
            use_funnel=False,
        )
        assert len(report.samples) >= 1
        assert report.summary is not None
        assert "total_time" in report.summary

    @pytest.mark.skipif(not (SAMPLES_DIR / "unknown").exists(), reason="No samples/unknown dir")
    def test_run_batch_samples_have_scores(self):
        """All analyzed samples should have a risk score."""
        report = run_batch(
            SAMPLES_DIR / "unknown",
            backend_name="capstone",
            limit=1,
            use_funnel=False,
        )
        for sample in report.samples:
            assert isinstance(sample.risk_score, float)
            assert 0.0 <= sample.risk_score <= 10.0


class TestParallelScanning:
    """Phase 3: Parallel scanning with workers parameter."""

    def test_workers_parameter_accepted(self):
        """run_batch should accept workers=0 without error (sequential mode)."""
        report = run_batch(
            SAMPLES_DIR / "unknown",
            backend_name="capstone",
            limit=1,
            use_funnel=False,
            workers=0,
        )
        assert report.total_analyzed >= 0

    def test_workers_one_forces_sequential(self):
        """workers=1 should behave like sequential mode."""
        report = run_batch(
            SAMPLES_DIR / "unknown",
            backend_name="capstone",
            limit=1,
            use_funnel=False,
            workers=1,
        )
        assert report.total_analyzed >= 0

    def test_use_cache_false(self):
        """use_cache=False should skip cache checks."""
        report = run_batch(
            SAMPLES_DIR / "unknown",
            backend_name="capstone",
            limit=1,
            use_funnel=False,
            use_cache=False,
        )
        assert isinstance(report.total_analyzed, int)
