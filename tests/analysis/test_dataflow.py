"""Tests for dataflow input tracking enhancements — Phase 1."""

import pytest
from pathlib import Path
from src.models import (
    Architecture, DisassemblyResult, Function, Sample, FindingCategory,
)
from src.analysis.dataflow.input_tracker import InputValidationAnalyzer


def _make_sample(**kwargs) -> Sample:
    defaults = dict(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1000,
        is_driver=True, driver_type="WDM",
    )
    defaults.update(kwargs)
    return Sample(**defaults)


class TestInputTrackerDataflow:
    """Phase 1: IRP field access detection and real validation."""

    def setup_method(self):
        self.analyzer = InputValidationAnalyzer()

    def test_irp_access_detected_via_function_apis(self):
        """Handler with dangerous API should be flagged as having IRP access."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        unvalidated = [f for f in findings if f.category == FindingCategory.UNVALIDATED_USER_INPUT]
        assert len(unvalidated) >= 1
        # With IRP access confirmed, confidence should be HIGH
        assert unvalidated[0].confidence.value >= 0.9

    def test_real_validation_lowens_confidence(self):
        """Handler with ProbeForRead should not have HIGH confidence unvalidated finding."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace", "ProbeForRead"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        unvalidated = [f for f in findings if f.category == FindingCategory.UNVALIDATED_USER_INPUT]
        # Since probe is present, there should be NO unvalidated_user_input finding
        assert len(unvalidated) == 0

    def test_partial_validation_lists_missing_checks(self):
        """Partial validation finding should list what's missing."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x200)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace", "ProbeForRead"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        partial = [f for f in findings if f.category == FindingCategory.PARTIAL_VALIDATION]
        assert len(partial) >= 1
        assert "privilege" in partial[0].description.lower()

    def test_sync_only_finding(self):
        """Sync-only handler should get PARTIAL_VALIDATION with VAL_SYNC_ONLY."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace", "KeAcquireSpinLock"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        sync = [f for f in findings if f.context.get("sync_apis")]
        assert len(sync) >= 1
        assert "KeAcquireSpinLock" in sync[0].context["sync_apis"]

    def test_full_validation_no_partial(self):
        """Handler with probe + privilege + size should not get partial finding."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x300)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: [
                "MmMapIoSpace", "ProbeForRead",
                "SeSinglePrivilegeCheck", "RtlCompareMemory",
            ]},
        )
        findings = self.analyzer.analyze(sample, ir)
        partial = [f for f in findings if f.category == FindingCategory.PARTIAL_VALIDATION]
        # No partial when all checks are present
        assert len(partial) == 0

    def test_find_input_source_returns_true_for_dangerous_api(self):
        """_find_input_source should return True when dangerous API is present."""
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            function_apis={0x1000: ["MmMapIoSpace"]},
        )
        func = ir.functions[0x1000]
        assert self.analyzer._find_input_source(0x1000, func, ir) is True

    def test_find_input_source_returns_false_without_api(self):
        """_find_input_source should return False when no dangerous API."""
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100, calls=[])},
        )
        func = ir.functions[0x1000]
        assert self.analyzer._find_input_source(0x1000, func, ir) is False

    def test_has_real_validation_with_compare_api(self):
        """_has_real_validation should return True for APIs with 'compare' in name."""
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            function_apis={0x1000: ["RtlCompareMemory"]},
        )
        func = Function(name="sub_1000", address=0x1000, size=0x100)
        assert self.analyzer._has_real_validation(0x1000, func, ir) is True

    def test_has_real_validation_false_without_api(self):
        """_has_real_validation should return False for unrelated APIs."""
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            function_apis={0x1000: ["ExAllocatePoolWithTag"]},
        )
        func = Function(name="sub_1000", address=0x1000, size=0x100)
        assert self.analyzer._has_real_validation(0x1000, func, ir) is False

    def test_probe_api_not_counted_as_unvalidated(self):
        """Handler with ProbeForWrite should not get UNVALIDATED_USER_INPUT."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace", "ProbeForWrite"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        unvalidated = [f for f in findings if f.category == FindingCategory.UNVALIDATED_USER_INPUT]
        assert len(unvalidated) == 0

    def test_privilege_only_still_missing_probe(self):
        """Handler with only SeSinglePrivilegeCheck should still flag missing probe."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace", "SeSinglePrivilegeCheck"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        unvalidated = [f for f in findings if f.category == FindingCategory.UNVALIDATED_USER_INPUT]
        assert len(unvalidated) >= 1

    def test_evidence_rule_ids(self):
        """Evidence should include correct rule IDs."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        rule_ids = {e.rule_id for f in findings for e in f.evidence}
        assert "VAL_NO_PROBE" in rule_ids
        assert "VAL_NO_SIZE" in rule_ids
        assert "VAL_NO_PRIV" in rule_ids

    def test_iotl_dispatcher_address_added_to_handlers(self):
        """ioctl_dispatcher address should be included in handler analysis."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x3000: Function(name="dispatcher", address=0x3000, size=0x100)},
            ioctl_dispatcher=0x3000,
            function_apis={0x3000: ["MmMapIoSpace"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        handler_addrs = {f.function_address for f in findings if f.function_address}
        assert 0x3000 in handler_addrs

    def test_zero_handler_discarded(self):
        """Zero address handler should be discarded."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0: Function(name="sub_0", address=0, size=0x100)},
            irp_handlers={0xE: 0},
        )
        findings = self.analyzer.analyze(sample, ir)
        assert findings == []

    def test_exgetpreviousmode_as_privilege(self):
        """ExGetPreviousMode should count as privilege check."""
        sample = _make_sample()
        ir = DisassemblyResult(
            sample_path=Path("test.sys"), backend="capstone",
            functions={0x1000: Function(name="sub_1000", address=0x1000, size=0x100)},
            irp_handlers={0xE: 0x1000},
            function_apis={0x1000: ["MmMapIoSpace", "ExGetPreviousMode"]},
        )
        findings = self.analyzer.analyze(sample, ir)
        priv = [f for f in findings if f.category == FindingCategory.MISSING_PRIVILEGE_CHECK]
        assert len(priv) == 0
