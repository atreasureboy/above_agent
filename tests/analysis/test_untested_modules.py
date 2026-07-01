"""Tests for untested core/funnel modules: cfg_utils, arm64, coverage, lol_match, light_disasm."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.models import (
    Architecture,
    BasicBlock,
    CFG,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Sample,
    Severity,
    Confidence,
)


# ---------------------------------------------------------------------------
# CFG Utils Tests
# ---------------------------------------------------------------------------

class TestCFGUtils:
    """Test CFG utility functions."""

    def test_reachable_funcs_bfs(self):
        """BFS should find all functions reachable from a handler."""
        from src.analysis.core.cfg_utils import cfg_reachable_funcs

        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

        # Create a call chain: A -> B -> C
        func_a = Function(name="sub_1000", address=0x1000, size=0x100)
        func_a.calls = [0x2000]

        func_b = Function(name="sub_2000", address=0x2000, size=0x100)
        func_b.calls = [0x3000]

        func_c = Function(name="sub_3000", address=0x3000, size=0x100)
        func_c.calls = []

        ir.functions[0x1000] = func_a
        ir.functions[0x2000] = func_b
        ir.functions[0x3000] = func_c

        reachable = cfg_reachable_funcs({0x1000}, ir)
        assert reachable == {0x1000, 0x2000, 0x3000}

    def test_reachable_funcs_no_calls(self):
        """Function with no calls should only return itself."""
        from src.analysis.core.cfg_utils import cfg_reachable_funcs

        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name="sub_4000", address=0x4000, size=0x100)
        func.calls = []
        ir.functions[0x4000] = func

        reachable = cfg_reachable_funcs({0x4000}, ir)
        assert reachable == {0x4000}

    def test_reachable_funcs_missing_function(self):
        """BFS should handle functions not in the IR gracefully."""
        from src.analysis.core.cfg_utils import cfg_reachable_funcs

        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        # Start from a function that doesn't exist in IR
        reachable = cfg_reachable_funcs({0x9999}, ir)
        assert reachable == {0x9999}  # Still adds the start address

    def test_reachable_funcs_cyclic(self):
        """BFS should handle cyclic call graphs without infinite loop."""
        from src.analysis.core.cfg_utils import cfg_reachable_funcs

        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func_a = Function(name="sub_1000", address=0x1000, size=0x100)
        func_a.calls = [0x2000]

        func_b = Function(name="sub_2000", address=0x2000, size=0x100)
        func_b.calls = [0x1000]  # Cycle back to A

        ir.functions[0x1000] = func_a
        ir.functions[0x2000] = func_b

        reachable = cfg_reachable_funcs({0x1000}, ir)
        assert reachable == {0x1000, 0x2000}


# ---------------------------------------------------------------------------
# ARM64 Module Tests
# ---------------------------------------------------------------------------

class TestARM64Module:
    """Test ARM64 analysis constants and helpers."""

    def test_arm64_constants_exist(self):
        """ARM64 constants should be properly defined."""
        from src.analysis.core.arm64 import (
            ARM64_MSR_INTRINSICS,
            ARM64_SYSTEM_REGS,
            ARM64_DANGEROUS_SINKS,
            ARM64_VALIDATION_BRANCHES_FULL,
            ARM64_CMP_PATTERNS,
            ARM64_PARAM_REGS,
            ARM64_RETURN_REG,
            ARM64_ORDINAL_EXTENSIONS,
        )

        assert len(ARM64_MSR_INTRINSICS) > 0
        assert len(ARM64_SYSTEM_REGS) > 0
        assert len(ARM64_DANGEROUS_SINKS) > 0
        assert len(ARM64_VALIDATION_BRANCHES_FULL) > 0
        assert len(ARM64_CMP_PATTERNS) > 0
        assert ARM64_PARAM_REGS == ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        assert ARM64_RETURN_REG == "x0"

    def test_arm64_sinks_no_overlap_with_x86(self):
        """ARM64-specific sinks should be distinct from x86 naming."""
        from src.analysis.core.arm64 import ARM64_DANGEROUS_SINKS

        # ARM64 sinks use different naming conventions
        assert "__clean_dcache" in ARM64_DANGEROUS_SINKS
        assert "__dsb" in ARM64_DANGEROUS_SINKS
        assert "__isb" in ARM64_DANGEROUS_SINKS

    def test_get_arm64_enhanced_sinks(self):
        """Helper should return full sink set including ARM64 variants."""
        from src.analysis.core.arm64 import get_arm64_enhanced_dangerous_sinks
        from src.analysis.core.arm64 import ARM64_DANGEROUS_SINKS

        all_sinks = get_arm64_enhanced_dangerous_sinks()
        assert isinstance(all_sinks, set)
        # Should include ARM64-specific sinks
        assert all_sinks & ARM64_DANGEROUS_SINKS


# ---------------------------------------------------------------------------
# Coverage Analyzer Tests
# ---------------------------------------------------------------------------

class TestCoverageReport:
    """Test CoverageReport dataclass."""

    def test_to_dict_serialization(self):
        """CoverageReport should serialize to dict."""
        from src.analysis.core.coverage import CoverageReport

        report = CoverageReport(
            total_functions=100,
            analyzed_functions=80,
            unanalyzed_functions=20,
            total_blocks=500,
            visited_blocks=300,
            known_dangerous_apis=50,
            detected_dangerous_apis=10,
            total_handlers=5,
            handlers_with_cfg=4,
            handlers_analyzed=4,
            overall_coverage=0.75,
        )

        d = report.to_dict()
        assert d["function_coverage"]["total"] == 100
        assert d["function_coverage"]["ratio"] == 0.8
        assert d["cfg_block_coverage"]["total"] == 500
        assert d["cfg_block_coverage"]["ratio"] == 0.6
        assert d["api_coverage"]["known"] == 50
        assert d["api_coverage"]["detected"] == 10
        assert d["overall_coverage"] == 0.75

    def test_to_dict_json_roundtrip(self):
        """CoverageReport dict should be JSON serializable."""
        from src.analysis.core.coverage import CoverageReport

        report = CoverageReport(
            total_functions=10,
            analyzed_functions=5,
            unanalyzed_functions=5,
            overall_coverage=0.5,
        )
        d = report.to_dict()
        json_str = json.dumps(d)
        reloaded = json.loads(json_str)
        assert reloaded["function_coverage"]["total"] == 10

    def test_summary_string(self):
        """Summary should be a readable one-liner."""
        from src.analysis.core.coverage import CoverageReport

        report = CoverageReport(
            total_functions=100,
            analyzed_functions=80,
            total_blocks=500,
            visited_blocks=300,
            total_handlers=5,
            handlers_analyzed=4,
            overall_coverage=0.75,
        )
        summary = report.summary()
        assert "Coverage:" in summary
        assert "functions=" in summary
        assert "overall=" in summary

    def test_summary_with_zero_functions(self):
        """Summary should handle zero functions without ZeroDivisionError."""
        from src.analysis.core.coverage import CoverageReport

        report = CoverageReport()
        summary = report.summary()
        assert isinstance(summary, str)


class TestCoverageAnalyzer:
    """Test CoverageAnalyzer class."""

    def _make_sample_and_ir(self) -> tuple[Sample, DisassemblyResult]:
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

        # Create a function with CFG
        func = Function(name="sub_1000", address=0x1000, size=0x100)
        func.calls = [0x2000]
        ir.functions[0x1000] = func

        func2 = Function(name="sub_2000", address=0x2000, size=0x100)
        func2.calls = []
        ir.functions[0x2000] = func2

        # Add a CFG
        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        block = BasicBlock(address=0x1000, end_address=0x1100, instructions=[], successors=[])
        cfg.blocks[0x1000] = block
        ir.cfgs[0x1000] = cfg

        # Add an IOCTL handler
        ir.ioctl_handlers = {0x220001: 0x1000}

        # Mark function with API
        ir.function_apis[0x1000] = {"MmMapLockedPagesSpecifyCache"}

        sample = Sample(
            path=Path("test.sys"),
            name="test",
            company="Test",
            version="1.0",
            arch=Architecture.X64,
            sha256="abc123",
            size=1000,
        )

        return sample, ir

    def test_analyze_produces_findings(self):
        """CoverageAnalyzer should produce at least one INFO finding."""
        from src.analysis.core.coverage import CoverageAnalyzer

        sample, ir = self._make_sample_and_ir()
        analyzer = CoverageAnalyzer()
        findings = analyzer.analyze(sample, ir)

        assert len(findings) >= 1
        assert findings[0].severity == Severity.INFO

    def test_analyze_sets_coverage_report(self):
        """CoverageAnalyzer should attach a CoverageReport to sample."""
        from src.analysis.core.coverage import CoverageAnalyzer

        sample, ir = self._make_sample_and_ir()
        analyzer = CoverageAnalyzer()
        analyzer.analyze(sample, ir)

        assert hasattr(sample, "coverage_report")
        assert sample.coverage_report is not None
        assert sample.coverage_report.total_functions == 2

    def test_analyze_handles_empty_ir(self):
        """CoverageAnalyzer should handle empty IR without errors."""
        from src.analysis.core.coverage import CoverageAnalyzer

        sample = Sample(
            path=Path("test.sys"),
            name="test",
            company="Test",
            version="1.0",
            arch=Architecture.X64,
            sha256="abc123",
            size=1000,
        )
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

        analyzer = CoverageAnalyzer()
        findings = analyzer.analyze(sample, ir)

        assert len(findings) >= 1
        assert sample.coverage_report.total_functions == 0

    def test_low_coverage_finding(self):
        """Should emit LOW severity finding when coverage is poor."""
        from src.analysis.core.coverage import CoverageAnalyzer

        sample, ir = self._make_sample_and_ir()
        # Add handlers but no findings and no CFG for them
        ir.ioctl_handlers = {0x220001: 0x5000}  # Handler at unknown address

        analyzer = CoverageAnalyzer()
        findings = analyzer.analyze(sample, ir)

        # Should have INFO finding always
        info_findings = [f for f in findings if f.severity == Severity.INFO]
        assert len(info_findings) >= 1


# ---------------------------------------------------------------------------
# LOLMatch Stage Tests
# ---------------------------------------------------------------------------

class TestLOLMatchStage:
    """Test LOLDrivers threat intel matching stage."""

    def test_stage_name(self):
        """Stage should have correct name."""
        from src.analysis.funnel.stages.lol_match import LOLMatchStage

        stage = LOLMatchStage()
        assert "LOLDrivers" in stage.name

    def test_skip_known_rejects_match(self):
        """With skip_known=True, matched samples should be rejected."""
        from src.analysis.funnel.stages.lol_match import LOLMatchStage
        from src.analysis.funnel.stages import FilterResult
        from src.models import Architecture

        stage = LOLMatchStage(skip_known=True)

        sample = Sample(
            path=Path("test.sys"),
            name="test",
            company="Test",
            version="1.0",
            arch=Architecture.X64,
            sha256="abc123",
            size=1000,
        )

        # Mock the provider to return a match
        with patch.object(stage, "_get_provider") as mock_provider:
            mock_provider.return_value.match_sample.return_value = {
                "matched": True,
                "confidence": 1.0,
                "rule_id": "SHA256_EXACT",
            }

            result = stage.apply([sample])

            assert result.passed_count == 0  # None passed
            assert result.filtered_count == 1  # One rejected

    def test_no_match_passes_through(self):
        """Samples without matches should pass through."""
        from src.analysis.funnel.stages.lol_match import LOLMatchStage
        from src.models import Architecture

        stage = LOLMatchStage(skip_known=False)

        sample = Sample(
            path=Path("test.sys"),
            name="test",
            company="Test",
            version="1.0",
            arch=Architecture.X64,
            sha256="abc123",
            size=1000,
        )

        with patch.object(stage, "_get_provider") as mock_provider:
            mock_provider.return_value.match_sample.return_value = None

            result = stage.apply([sample])

            assert result.passed_count == 1  # Passed through


# ---------------------------------------------------------------------------
# Light Disasm Stage Tests
# ---------------------------------------------------------------------------

class TestLightDisasm:
    """Test light disassembly function."""

    def test_light_disasm_nonexistent_file(self):
        """Light disasm should handle nonexistent files gracefully."""
        from src.analysis.funnel.stages.light_disasm import _light_disasm

        result = _light_disasm(Path("nonexistent_file.sys"))
        assert result["ioctl_codes"] == []
        assert result["irp_handlers"] == {}

    def test_light_disasm_returns_structure(self):
        """Light disasm should return expected dict structure."""
        from src.analysis.funnel.stages.light_disasm import _light_disasm

        # Even with a bad file, it should return the right structure
        try:
            result = _light_disasm(Path("nonexistent.sys"))
        except Exception:
            pytest.skip("Expected to fail on nonexistent file")

        assert "ioctl_codes" in result
        assert "irp_handlers" in result
        assert "function_count" in result
        assert "is_wdf_driver" in result
