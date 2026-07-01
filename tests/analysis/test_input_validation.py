"""Tests for InputValidationAnalyzer."""

import pytest
from pathlib import Path
from unittest.mock import MagicMock
from src.models import (
    Architecture, DisassemblyResult, Finding, Function,
    Sample, Severity, Confidence, BasicBlock, CFG, Instruction,
)
from src.analysis.dataflow.input_tracker import (
    InputValidationAnalyzer, TaintTracker, DANGEROUS_SINKS, run_taint_analysis,
)


def _make_sample(**kwargs) -> Sample:
    defaults = dict(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1000,
        is_driver=True, driver_type="WDM",
    )
    defaults.update(kwargs)
    return Sample(**defaults)


class TestInputValidationAnalyzer:
    def setup_method(self):
        self.analyzer = InputValidationAnalyzer()

    def test_name(self):
        assert self.analyzer.name == "InputValidationAnalyzer"

    def test_enabled_by_default(self):
        assert self.analyzer.enabled is True

    def test_no_findings_when_no_handlers(self):
        sample = _make_sample()
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        findings = self.analyzer.analyze(sample, ir)
        assert findings == []

    def test_no_findings_when_no_dangerous_sinks(self):
        """Handler exists but calls no dangerous APIs."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
        )
        findings = self.analyzer.analyze(sample, ir)
        assert findings == []

    def test_finding_when_dangerous_api_without_validation(self):
        """Handler calls dangerous API with no validation."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100, calls=[])},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        # Should have UNVALIDATED_USER_INPUT and MISSING_SIZE_CHECK
        unvalidated = [f for f in findings if "unvalidated" in f.category.value]
        assert len(unvalidated) >= 1

    def test_partial_validation_finding(self):
        """Handler has some validation APIs and dangerous APIs."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x200, calls=[])},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace", "SeSinglePrivilegeCheck"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        partial = [f for f in findings if "partial" in f.category.value]
        assert len(partial) >= 1

    def test_evidence_included(self):
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["KeWriteMsr"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        assert any(len(f.evidence) > 0 for f in findings)

    def test_wdf_driver_all_functions_reachable(self):
        """WDF drivers: all functions with dangerous sinks are considered reachable."""
        sample = _make_sample(driver_type="WDF/KMDF")
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={
                0x1000: Function(name="sub_1000", address=0x1000, size=0x100),
                0x2000: Function(name="sub_2000", address=0x2000, size=0x100),
            },
            irp_handlers={0xE: 0x1000},  # Has IOCTL capability → WDF means all reachable
            is_wdf_driver=True,
            function_apis={0x2000: ["MmMapIoSpace"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        # sub_2000 should be analyzed even though it's not an explicit handler
        unvalidated = [f for f in findings if "unvalidated" in f.category.value]
        assert any("2000" in f.description for f in unvalidated)

    def test_sync_not_counted_as_validation(self):
        """Synchronization APIs should not be counted as real input validation."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace", "ExAcquireFastMutex"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        # Should still have unvalidated finding (sync is not validation)
        unvalidated = [f for f in findings if "unvalidated" in f.category.value]
        assert len(unvalidated) >= 1
        # Should have a PARTIAL_VALIDATION or note about sync-only
        sync_findings = [f for f in findings if "sync" in f.description.lower() or "synchronization" in f.description.lower()]
        assert len(sync_findings) >= 1

    def test_missing_privilege_check_severity(self):
        """Missing privilege check for KeWriteMsr should be HIGH severity."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["KeWriteMsr"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        priv_findings = [f for f in findings if f.category.value == "missing_privilege_check"]
        assert len(priv_findings) >= 1
        assert priv_findings[0].severity == Severity.HIGH

    def test_multiple_handlers(self):
        """Multiple IOCTL handlers should each be analyzed independently."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={
                0x1000: Function(name="sub_1000", address=0x1000, size=0x100),
                0x2000: Function(name="sub_2000", address=0x2000, size=0x100),
            },
            irp_handlers={0xE: 0x1000, 0xF: 0x2000},  # 0xF = IRP_MJ_INTERNAL_DEVICE_CONTROL
            ioctl_handlers={0x222000: 0x2000},  # Additional handler via ioctl_handlers
            function_apis={0x1000: ["MmMapIoSpace"], 0x2000: ["KeWriteMsr"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        # Both handlers should produce findings (0xE handler + ioctl_handlers)
        handler_addrs = {f.function_address for f in findings if f.function_address}
        assert 0x1000 in handler_addrs  # From 0xE irp_handler
        assert 0x2000 in handler_addrs  # From ioctl_handlers


# ---------------------------------------------------------------------------
# P2: Deobfuscated sink detection tests
# ---------------------------------------------------------------------------

class TestDeobfuscatedSinkDetection:
    """Test that Phase 0 resolved API hashes are recognized as taint sinks."""

    def test_is_deobfuscated_sink_known_api(self):
        """A resolved dangerous API in function_apis should be recognized as sink."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        ir.function_apis[0x1000] = ["MmMapIoSpaceEx"]

        tracker = TaintTracker(ir)
        assert tracker._is_deobfuscated_sink(ir, "MmMapIoSpaceEx")

    def test_is_deobfuscated_sink_not_dangerous(self):
        """A non-dangerous resolved API should NOT be recognized as sink."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        ir.function_apis[0x1000] = ["IoCreateDevice"]

        tracker = TaintTracker(ir)
        assert not tracker._is_deobfuscated_sink(ir, "IoCreateDevice")

    def test_is_deobfuscated_sink_empty_target(self):
        """Empty api_target should return False."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)
        assert not tracker._is_deobfuscated_sink(ir, "")
        assert not tracker._is_deobfuscated_sink(ir, None)

    def test_is_deobfuscated_sink_dynamic_imports(self):
        """Dangerous APIs in dynamic_imports should be recognized as sinks."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        ir.dynamic_imports[0x2000] = ["MmCopyVirtualMemory"]

        tracker = TaintTracker(ir)
        assert tracker._is_deobfuscated_sink(ir, "MmCopyVirtualMemory")

    def test_callback_functions_analyzed(self):
        """Functions registered via ObRegisterCallbacks should be analyzed for validation."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={
                0x1000: Function(name="sub_1000", address=0x1000, size=0x200, calls=[0x2000]),
                0x2000: Function(name="sub_2000", address=0x2000, size=0x200),
            },
            irp_handlers={0xE: 0x1000},
            function_apis={
                0x1000: ["ObRegisterCallbacks"],
                0x2000: ["MmMapIoSpaceEx"],
            },
        )
        analyzer = InputValidationAnalyzer()
        findings = analyzer.analyze(sample, ir)
        # The callback function (0x2000) should be analyzed
        assert any("2000" in f.description for f in findings)
