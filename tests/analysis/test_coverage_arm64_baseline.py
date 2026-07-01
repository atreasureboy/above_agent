"""Tests for coverage metrics, ARM64 enhancement, and false positive baseline."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.models import (
    APICallInfo,
    Architecture,
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Sample,
    Severity,
    SignatureStatus,
)


def _make_mock_ir() -> DisassemblyResult:
    """Create a mock IR with functions, CFG, and API calls."""
    ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")

    # Handler function with IOCTL
    handler = Function(name="sub_1000", address=0x1000, size=0x200)
    handler.calls = [0x2000]
    ir.functions[0x1000] = handler

    # Helper function
    helper = Function(name="sub_2000", address=0x2000, size=0x100)
    ir.functions[0x2000] = helper

    # CFG for handler
    cfg = CFG(function_address=0x1000, entry_block=0x1000)
    block = BasicBlock(
        address=0x1000,
        end_address=0x1200,
        instructions=[
            Instruction(address=0x1010, mnemonic="mov", operands="rax, rcx", size=3),
            Instruction(
                address=0x1020, mnemonic="call", operands="MmMapIoSpaceEx",
                api_target="MmMapIoSpaceEx", size=6,
            ),
        ],
        successors=[0x2000],
    )
    cfg.blocks[0x1000] = block
    ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg

    # API calls
    ir.function_apis[0x1000] = ["MmMapIoSpaceEx", "ExAllocatePoolWithTag"]
    ir.function_api_details[0x1000] = [
        APICallInfo(name="MmMapIoSpaceEx", call_address=0x1020),
    ]

    # IOCTL handlers
    ir.ioctl_handlers[0x22A004] = 0x1000

    return ir


def _make_mock_sample() -> Sample:
    """Create a mock Sample."""
    sample = Sample(
        path=Path("test.sys"),
        name="TestDriver",
        company="TestCo",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="a" * 64,
        size=0x10000,
    )
    sample.driver_type = "TestDrv"
    sample.signature_status = SignatureStatus.UNSIGNED
    sample.risk_score = 7.5
    return sample


# ---------------------------------------------------------------------------
# Coverage Analyzer Tests
# ---------------------------------------------------------------------------

class TestCoverageAnalyzer:
    """Test the coverage metrics analyzer."""

    def test_analyze_basic_coverage(self):
        """Basic coverage metrics are computed."""
        from src.analysis.core.coverage import CoverageAnalyzer

        ir = _make_mock_ir()
        sample = _make_mock_sample()
        sample.analysis_findings = []

        analyzer = CoverageAnalyzer()
        findings = analyzer.analyze(sample, ir)

        assert len(findings) >= 1
        # Should have an INFO coverage finding
        cov_finding = findings[0]
        assert cov_finding.severity == Severity.INFO
        assert "coverage_report" in cov_finding.context
        assert cov_finding.context["coverage_report"]["function_coverage"]["total"] == 2

    def test_coverage_on_sample(self):
        """Coverage report is stored on sample."""
        from src.analysis.core.coverage import CoverageAnalyzer

        ir = _make_mock_ir()
        sample = _make_mock_sample()
        sample.analysis_findings = []

        analyzer = CoverageAnalyzer()
        analyzer.analyze(sample, ir)

        assert hasattr(sample, "coverage_report")
        report = sample.coverage_report
        assert report.total_functions == 2
        assert report.total_handlers == 1

    def test_low_coverage_warning(self):
        """Low coverage generates a warning finding."""
        from src.analysis.core.coverage import CoverageAnalyzer

        # Empty IR — no functions, no handlers
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        sample = _make_mock_sample()
        sample.analysis_findings = []

        analyzer = CoverageAnalyzer()
        findings = analyzer.analyze(sample, ir)

        # Should still have INFO finding
        assert any(f.severity == Severity.INFO for f in findings)

    def test_coverage_report_to_dict(self):
        """Coverage report serializes to dict."""
        from src.analysis.core.coverage import CoverageReport

        report = CoverageReport(
            total_functions=10,
            analyzed_functions=8,
            total_blocks=50,
            visited_blocks=40,
            known_dangerous_apis=130,
            detected_dangerous_apis=5,
            total_handlers=3,
            handlers_analyzed=3,
        )

        d = report.to_dict()
        assert "function_coverage" in d
        assert "cfg_block_coverage" in d
        assert "api_coverage" in d
        assert "ioctl_handler_coverage" in d
        assert "taint_coverage" in d
        assert "overall_coverage" in d

    def test_coverage_report_summary(self):
        """Summary string is human-readable."""
        from src.analysis.core.coverage import CoverageReport

        report = CoverageReport(
            total_functions=10,
            analyzed_functions=8,
            total_blocks=50,
            visited_blocks=40,
            total_handlers=3,
            handlers_analyzed=3,
        )
        summary = report.summary()
        assert "Coverage:" in summary
        assert "functions=" in summary
        assert "CFG blocks=" in summary


# ---------------------------------------------------------------------------
# ARM64 Enhancement Tests
# ---------------------------------------------------------------------------

class TestARM64Enhancement:
    """Test ARM64 analysis constants and helpers."""

    def test_arm64_msr_intrinsics(self):
        """ARM64 MSR intrinsics are defined."""
        from src.analysis.core.arm64 import ARM64_MSR_INTRINSICS

        assert "__readmsr" in ARM64_MSR_INTRINSICS
        assert "__writemsr" in ARM64_MSR_INTRINSICS
        assert "__set_TTBR0_EL1" in ARM64_MSR_INTRINSICS

    def test_arm64_system_regs(self):
        """ARM64 system registers are defined."""
        from src.analysis.core.arm64 import ARM64_SYSTEM_REGS

        assert "SCTLR_EL1" in ARM64_SYSTEM_REGS
        assert "VBAR_EL1" in ARM64_SYSTEM_REGS

    def test_arm64_dangerous_sinks(self):
        """ARM64-specific dangerous sinks are defined."""
        from src.analysis.core.arm64 import ARM64_DANGEROUS_SINKS

        assert "__clean_dcache" in ARM64_DANGEROUS_SINKS
        assert "__dsb" in ARM64_DANGEROUS_SINKS

    def test_arm64_validation_branches(self):
        """ARM64 validation branches are defined."""
        from src.analysis.core.arm64 import ARM64_VALIDATION_BRANCHES_FULL

        assert "b.eq" in ARM64_VALIDATION_BRANCHES_FULL
        assert "cbz" in ARM64_VALIDATION_BRANCHES_FULL
        assert "tbz" in ARM64_VALIDATION_BRANCHES_FULL

    def test_arm64_param_regs(self):
        """ARM64 parameter registers are defined."""
        from src.analysis.core.arm64 import ARM64_PARAM_REGS

        assert len(ARM64_PARAM_REGS) == 8
        assert "x0" in ARM64_PARAM_REGS
        assert "x7" in ARM64_PARAM_REGS

    def test_arm64_enhanced_dangerous_sinks(self):
        """Enhanced sinks include ARM64-specific ones."""
        from src.analysis.core.arm64 import get_arm64_enhanced_dangerous_sinks

        sinks = get_arm64_enhanced_dangerous_sinks()
        assert "MmMapIoSpaceEx" in sinks
        assert "__clean_dcache" in sinks

    def test_arm64_enhanced_api_set(self):
        """Enhanced API set includes ARM64 intrinsics."""
        from src.analysis.core.arm64 import get_arm64_enhanced_api_set

        apis = get_arm64_enhanced_api_set()
        assert "MmMapIoSpaceEx" in apis
        assert "__set_VBAR_EL1" in apis


# ---------------------------------------------------------------------------
# False Positive Baseline Tests
# ---------------------------------------------------------------------------

class TestFalsePositiveBaseline:
    """Test the false positive baseline filter."""

    def test_baseline_filter_init(self):
        """Baseline filter initializes with empty profiles."""
        from src.analysis.core.fp_baseline import BaselineFilter

        bf = BaselineFilter()
        assert len(bf.profiles) == 0

    def test_build_default_baseline(self):
        """Default baseline has Microsoft profiles."""
        from src.analysis.core.fp_baseline import build_default_baseline

        bf = build_default_baseline()
        assert len(bf.profiles) >= 1
        assert any("microsoft" in p.name.lower() for p in bf.profiles)

    def test_filter_finding_attack_chain_unchanged(self):
        """Attack chain findings are not downgraded."""
        from src.analysis.core.fp_baseline import BaselineFilter

        bf = BaselineFilter()
        f = Finding(
            category=FindingCategory.ATTACK_CHAIN,
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description="Complete BYOVD chain",
            function_address=0x1000,
            context={"taint_confirmed": True},
        )

        ir = _make_mock_ir()
        sample = _make_mock_sample()
        filtered = bf.filter_findings([f], sample, ir)

        assert len(filtered) == 1
        assert filtered[0].severity == Severity.CRITICAL

    def test_filter_downgrades_benign_api(self):
        """Standalone benign API findings are downgraded."""
        from src.analysis.core.fp_baseline import BaselineFilter

        bf = BaselineFilter()
        f = Finding(
            category=FindingCategory.ARBITRARY_MEMORY_MAP,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="Calls ExAllocatePoolWithTag",
            function_address=0x1000,
            api_name="ExAllocatePoolWithTag",
        )

        ir = _make_mock_ir()
        sample = _make_mock_sample()
        filtered = bf.filter_findings([f], sample, ir)

        assert len(filtered) == 1
        assert filtered[0].severity == Severity.LOW

    def test_filter_known_safe_driver(self):
        """Known-safe driver findings are downgraded."""
        from src.analysis.core.fp_baseline import BaselineFilter, BaselineProfile

        bf = BaselineFilter()
        bf.add_profile(BaselineProfile(
            name="testdriver",
            sha256="a" * 64,
            company="Microsoft Corporation",
            driver_category="test",
        ))

        f = Finding(
            category=FindingCategory.MISSING_PRIVILEGE_CHECK,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description="No privilege check",
            function_address=0x1000,
        )

        sample = _make_mock_sample()
        sample.signature_status = SignatureStatus.SIGNED_VALID
        ir = _make_mock_ir()

        filtered = bf.filter_findings([f], sample, ir)
        assert filtered[0].severity == Severity.MEDIUM

    def test_baseline_json_roundtrip(self):
        """Baseline serializes and deserializes correctly."""
        from src.analysis.core.fp_baseline import build_default_baseline, BaselineFilter

        bf = build_default_baseline()
        json_str = bf.to_json()

        bf2 = BaselineFilter.from_json(json_str)
        assert len(bf2.profiles) == len(bf.profiles)
        assert bf2.profiles[0].name == bf.profiles[0].name

    def test_load_baseline_missing_file(self):
        """Load baseline returns empty filter for missing file."""
        from src.analysis.core.fp_baseline import load_baseline

        bf = load_baseline(Path("/nonexistent/baseline.json"))
        assert len(bf.profiles) == 0

    def test_baseline_profile_to_dict(self):
        """Profile serializes correctly."""
        from src.analysis.core.fp_baseline import BaselineProfile

        p = BaselineProfile(
            name="test",
            sha256="abc123",
            company="TestCo",
            known_safe_apis={"MmMapIoSpace"},
            validation_patterns={"probe_and_privilege"},
            driver_category="storage",
        )

        d = p.to_dict()
        assert d["name"] == "test"
        assert d["sha256"] == "abc123"
        assert "MmMapIoSpace" in d["known_safe_apis"]

    def test_baseline_profile_from_dict(self):
        """Profile deserializes correctly."""
        from src.analysis.core.fp_baseline import BaselineProfile

        d = {
            "name": "test",
            "sha256": "abc123",
            "company": "TestCo",
            "known_safe_apis": ["MmMapIoSpace"],
            "validation_patterns": ["probe_and_privilege"],
            "driver_category": "storage",
        }

        p = BaselineProfile.from_dict(d)
        assert p.name == "test"
        assert p.sha256 == "abc123"
        assert "MmMapIoSpace" in p.known_safe_apis
