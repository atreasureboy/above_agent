"""Tests for src.analysis.deep module (Ghidra deep analysis).

Since Ghidra may not be installed on the test machine, these tests
mock the GhidraBackend to verify the integration logic.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.models import (
    APICallInfo,
    BasicBlock,
    CFG,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Severity,
    Confidence,
)


def _make_mock_ir() -> DisassemblyResult:
    """Create a minimal DisassemblyResult for testing."""
    ir = DisassemblyResult(
        sample_path=Path("test.sys"),
        backend="ghidra",
    )

    # Create a function with a dangerous API call
    handler = Function(name="sub_140001000", address=0x140001000, size=0x200)
    handler.calls = [0x140002000]
    ir.functions[handler.address] = handler

    helper = Function(name="sub_140002000", address=0x140002000, size=0x100)
    ir.functions[helper.address] = helper

    # Create a simple CFG for the handler
    cfg = CFG(function_address=handler.address, entry_block=0x140001000)
    block = BasicBlock(
        address=0x140001000,
        end_address=0x140001200,
        instructions=[
            Instruction(address=0x140001010, mnemonic="mov", operands="rax, rcx"),
            Instruction(address=0x140001020, mnemonic="call", operands="sub_140002000"),
        ],
        successors=[0x140002000],
    )
    cfg.blocks[0x140001000] = block
    ir.cfgs[handler.address] = ir.simple_cfgs[handler.address] = cfg

    # IOCTL handler mapping
    ir.ioctl_handlers[0x22A004] = handler.address

    # API index
    ir.function_apis[helper.address] = ["MmMapIoSpaceEx"]
    ir.function_api_details[helper.address] = [
        APICallInfo(name="MmMapIoSpaceEx", call_address=0x140002050),
    ]

    return ir


class TestDeepAnalysisModule:
    """Test the deep analysis module integration."""

    def test_run_deep_analysis_ghidra_not_available(self):
        """Should raise RuntimeError when Ghidra is not installed."""
        from src.analysis.deep import run_deep_analysis

        with patch("src.analysis.deep.GhidraBackend") as mock_backend_cls:
            mock_backend = MagicMock()
            mock_backend.is_available.return_value = False
            mock_backend_cls.return_value = mock_backend

            with pytest.raises(RuntimeError, match="Ghidra analyzeHeadless not found"):
                run_deep_analysis(Path("test.sys"))

    def test_run_deep_analysis_success(self):
        """Should return enriched sample when Ghidra analysis succeeds."""
        from src.analysis.deep import run_deep_analysis

        mock_ir = _make_mock_ir()

        with patch("src.analysis.deep.GhidraBackend") as mock_backend_cls:
            mock_backend = MagicMock()
            mock_backend.is_available.return_value = True
            mock_backend.get_version.return_value = "Ghidra 11.0"
            mock_backend.analyze.return_value = mock_ir
            mock_backend_cls.return_value = mock_backend

            with patch("src.analysis.deep.ingest") as mock_ingest:
                mock_sample = MagicMock()
                mock_sample.name = "test"
                mock_sample.arch.value = "x64"
                mock_sample.sha256 = "abc123def456" * 5  # 60+ char hex string
                mock_sample.disassembly_result = None
                mock_sample.analysis_findings = []
                mock_sample.risk_score = 0.0
                mock_ingest.return_value = mock_sample

                with patch("src.analysis.deep.run_all_analyzers") as mock_run:
                    mock_run.return_value = [
                        Finding(
                            category=FindingCategory.ARBITRARY_MEMORY_MAP,
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH,
                            description="MmMapIoSpaceEx without validation",
                            function_address=0x140002000,
                            api_name="MmMapIoSpaceEx",
                            instruction_address=0x140002050,
                        ),
                    ]
                    mock_sample.analysis_findings = mock_run.return_value

                    with patch("src.analysis.deep.DefaultScoringEngine") as mock_engine_cls:
                        mock_engine = MagicMock()
                        mock_engine.score.return_value.overall = 8.5
                        mock_engine.explain.return_value = ["MmMapIoSpaceEx found"]
                        mock_engine_cls.return_value = mock_engine

                        with patch("src.analysis.cache.AnalysisCache") as mock_cache_cls:
                            mock_cache = MagicMock()
                            mock_cache.get_ir.return_value = None
                            mock_cache_cls.return_value = mock_cache

                            result = run_deep_analysis(Path("test.sys"), verbose=False)

                            assert result["risk_score"] == 8.5
                            assert result["ghidra_version"] == "Ghidra 11.0"
                            assert len(result["findings"]) == 1
                            assert result["ir"] is mock_ir
                            mock_backend.analyze.assert_called_once_with(Path("test.sys"))

    def test_deep_module_imports(self):
        """Verify the deep module has all expected exports."""
        from src.analysis.deep import run_deep_analysis
        assert callable(run_deep_analysis)


class TestDeepAnalysisIntegration:
    """Test that deep analysis integrates with the pipeline config."""

    def test_pipeline_config_has_deep_fields(self):
        """PipelineConfig should have ghidra_deep* fields."""
        from src.config import PipelineConfig

        config = PipelineConfig(target=Path("samples"))
        assert hasattr(config, "ghidra_deep")
        assert hasattr(config, "ghidra_deep_threshold")
        assert hasattr(config, "ghidra_deep_max")
        assert hasattr(config, "ghidra_deep_timeout")
        assert config.ghidra_deep is False  # default off
        assert config.ghidra_deep_threshold == 5.0
        assert config.ghidra_deep_max == 5
        assert config.ghidra_deep_timeout == 300

    def test_scan_result_has_deep_fields(self):
        """ScanResult should track deep analysis stats."""
        from src.pipeline import ScanResult

        result = ScanResult()
        assert hasattr(result, "deep_completed")
        assert hasattr(result, "deep_failed")
        assert hasattr(result, "deep_elapsed")
        assert result.deep_completed == 0
        assert result.deep_failed == 0
        assert result.deep_elapsed == 0.0
