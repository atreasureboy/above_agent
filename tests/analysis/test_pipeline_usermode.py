"""Tests for user-mode integration in run_batch() pipeline."""

import concurrent.futures
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from src.analysis.pipeline import run_batch
from src.models import Architecture, Confidence, Finding, FindingCategory, Sample, Severity


def _make_driver_sample(name: str = "test.sys", **kwargs) -> Sample:
    defaults = dict(
        path=Path(name),
        name=name,
        company="Test Corp",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="a" * 64,
        size=1024,
        is_driver=True,
        driver_type="WDM",
        subsystem="NATIVE",
        imports=["ntoskrnl.exe"],
    )
    defaults.update(kwargs)
    return Sample(**defaults)


def _make_usermode_sample(name: str = "helper.exe", **kwargs) -> Sample:
    defaults = dict(
        path=Path(name),
        name=name,
        company="Test Corp",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="b" * 64,
        size=2048,
        is_usermode=True,
        binary_type="exe",
        imports=["kernel32.dll", "ntdll.dll"],
    )
    defaults.update(kwargs)
    return Sample(**defaults)


# Module-level mock paths
INGEST_DIR_PATCH = "src.analysis.pipeline.ingest_directory"
INGEST_UM_PATCH = "src.ingestion.usermode_parser.ingest_directory_usermode"
FUNNEL_PATCH = "src.analysis.funnel.run_funnel"
PIPELINE_INTERNAL_PATCH = "src.analysis.pipeline._run_pipeline_internal"


def _enriched(sample):
    """Helper to return an enriched sample (mock result)."""
    sample.risk_score = 3.0
    sample.analysis_findings = []
    return sample


class TestRunBatchUsermode:
    """Test run_batch() with include_usermode=True."""

    @patch(INGEST_DIR_PATCH)
    @patch(INGEST_UM_PATCH)
    def test_usermode_samples_added_when_flag_true(
        self, mock_ingest_usermode, mock_ingest_dir,
    ):
        """When include_usermode=True, user-mode samples are included."""
        driver = _make_driver_sample("driver.sys")
        usermode = _make_usermode_sample("helper.exe")

        mock_ingest_dir.return_value = [driver]
        mock_ingest_usermode.return_value = [usermode]

        with patch(PIPELINE_INTERNAL_PATCH, side_effect=_enriched):
            report = run_batch(
                Path("/fake/dir"),
                include_usermode=True,
                use_funnel=False,
                use_cache=False,
            )

        # Both driver and user-mode sample should be in the report
        assert len(report.samples) == 2
        assert any(s.is_usermode for s in report.samples)
        assert any(not s.is_usermode for s in report.samples)

    @patch(INGEST_DIR_PATCH)
    @patch(INGEST_UM_PATCH)
    def test_usermode_samples_excluded_when_flag_false(
        self, mock_ingest_usermode, mock_ingest_dir,
    ):
        """When include_usermode=False (default), user-mode samples are excluded."""
        driver = _make_driver_sample("driver.sys")
        usermode = _make_usermode_sample("helper.exe")

        mock_ingest_dir.return_value = [driver]
        mock_ingest_usermode.return_value = [usermode]

        with patch(PIPELINE_INTERNAL_PATCH, side_effect=_enriched):
            report = run_batch(
                Path("/fake/dir"),
                include_usermode=False,
                use_funnel=False,
                use_cache=False,
            )

        # Only the driver should be in the report
        assert len(report.samples) == 1
        assert not any(s.is_usermode for s in report.samples)

    @patch(INGEST_DIR_PATCH)
    @patch(INGEST_UM_PATCH)
    def test_usermode_bypasses_funnel(
        self, mock_ingest_usermode, mock_ingest_dir,
    ):
        """User-mode samples bypass the funnel and go directly to L4."""
        # Need >5 samples to trigger funnel
        drivers = [_make_driver_sample(f"driver{i}.sys") for i in range(6)]
        usermode_samples = [_make_usermode_sample(f"helper{i}.exe") for i in range(2)]

        mock_ingest_dir.return_value = drivers
        mock_ingest_usermode.return_value = usermode_samples

        with patch(FUNNEL_PATCH) as mock_funnel:
            mock_funnel.return_value = {
                "survivors": drivers[:2],  # Only 2 survive funnel
                "stats": {"l0_enumerated": 6, "l4_candidates": 2},
            }
            with patch(PIPELINE_INTERNAL_PATCH, side_effect=_enriched):
                report = run_batch(
                    Path("/fake/dir"),
                    include_usermode=True,
                    use_funnel=True,
                    use_cache=False,
                )

        # Funnel was called for kernel drivers
        mock_funnel.assert_called_once()
        # 2 funnel survivors + 2 user-mode samples = 4 total
        assert len(report.samples) == 4
        assert sum(1 for s in report.samples if s.is_usermode) == 2
        assert sum(1 for s in report.samples if not s.is_usermode) == 2

    @patch(INGEST_DIR_PATCH)
    @patch(INGEST_UM_PATCH)
    def test_usermode_in_parallel_mode(
        self, mock_ingest_usermode, mock_ingest_dir,
    ):
        """User-mode samples participate in parallel analysis."""
        driver = _make_driver_sample("driver.sys", risk_score=3.0)
        usermode = _make_usermode_sample("helper.exe", risk_score=2.0)

        mock_ingest_dir.return_value = [driver]
        mock_ingest_usermode.return_value = [usermode]

        # Replace ProcessPoolExecutor with ThreadPoolExecutor to avoid
        # pickling issues, and let _run_pipeline_internal run with mocked deps
        def fake_init(self, max_workers=None):
            # Use ThreadPoolExecutor instead
            object.__setattr__(self, '_max_workers', max_workers)
            object.__setattr__(self, '_executor', concurrent.futures.ThreadPoolExecutor(max_workers=max_workers))

        def fake_submit(self, fn, *args, **kwargs):
            return self._executor.submit(fn, *args, **kwargs)

        def fake_enter(self):
            return self

        def fake_exit(self, *args):
            self._executor.shutdown(wait=True)

        with patch("src.analysis.pipeline._run_pipeline_internal", side_effect=_enriched):
            with patch.object(concurrent.futures.ProcessPoolExecutor, "__init__", fake_init):
                with patch.object(concurrent.futures.ProcessPoolExecutor, "submit", fake_submit):
                    with patch.object(concurrent.futures.ProcessPoolExecutor, "__enter__", fake_enter):
                        with patch.object(concurrent.futures.ProcessPoolExecutor, "__exit__", fake_exit):
                            report = run_batch(
                                Path("/fake/dir"),
                                include_usermode=True,
                                use_funnel=False,
                                use_cache=False,
                                workers=2,
                            )

        # Both samples should be in the report
        assert len(report.samples) == 2


class TestRunPipelineInternalUsermode:
    """Test _run_pipeline_internal() with user-mode samples."""

    def test_usermode_skips_disassembly(self):
        """User-mode samples skip disassembly (ir=None)."""
        from src.analysis.pipeline import _run_pipeline_internal

        usermode = _make_usermode_sample("helper.exe")

        with patch("src.analysis.pipeline.run_all_analyzers") as mock_analyzers:
            mock_analyzers.return_value = []
            with patch("src.analysis.pipeline.DefaultScoringEngine") as mock_scoring:
                mock_engine = MagicMock()
                mock_engine.score.return_value.overall = 3.5
                mock_scoring.return_value = mock_engine

                result = _run_pipeline_internal(usermode, "capstone", print_layer=False)

        # Disassembly should not be called (no capstone/ghidra import)
        assert result.disassembly_result is None
        # Analyzers should still be called with ir=None
        mock_analyzers.assert_called_once()

    def test_usermode_analysis_findings_populated(self):
        """User-mode samples get analysis findings from UserModeAnalyzer."""
        from src.analysis.pipeline import _run_pipeline_internal

        usermode = _make_usermode_sample(
            "helper.exe",
            imports=["CreateRemoteThread", "WriteProcessMemory"],
        )

        test_finding = Finding(
            category=FindingCategory.DANGEROUS_USERMODE_IMPORT,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Dangerous user-mode import detected",
        )

        with patch("src.analysis.pipeline.run_all_analyzers") as mock_analyzers:
            mock_analyzers.return_value = [test_finding]
            with patch("src.analysis.pipeline.DefaultScoringEngine") as mock_scoring:
                mock_engine = MagicMock()
                mock_engine.score.return_value.overall = 6.0
                mock_engine.explain.return_value = ["Test explanation"]
                mock_scoring.return_value = mock_engine

                result = _run_pipeline_internal(usermode, "capstone", print_layer=False)

        assert len(result.analysis_findings) == 1
        assert result.analysis_findings[0].category == FindingCategory.DANGEROUS_USERMODE_IMPORT
        assert result.risk_score == 6.0
