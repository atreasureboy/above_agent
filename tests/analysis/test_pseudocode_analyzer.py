"""Tests for Phase 5: Pseudocode analyzer and Ghidra decompiler extension."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.models import (
    Architecture,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Sample,
    Severity,
)
from src.analysis.core.pseudocode_analyzer import (
    PseudocodeAnalyzer,
    IOCTL_VALIDATION_PATTERNS,
    STRUCT_FIELD_PATTERNS,
    VTABLE_PATTERNS,
)


def _make_sample() -> Sample:
    return Sample(
        path=Path("test.sys"),
        name="TestDriver",
        company="TestCo",
        version="1.0.0.0",
        arch=Architecture.X64,
        sha256="a" * 64,
        size=0x10000,
    )


def _make_ir_with_pseudocode(pseudo: str, apis: list[str] | None = None) -> DisassemblyResult:
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="ghidra")
    func = Function(
        name="sub_1000", address=0x1000, size=0x200,
        pseudo_code=pseudo,
        signature="NTSTATUS sub_1000(PDEVICE_OBJECT DeviceObject, PIRP Irp)",
        local_vars=[
            {"name": "status", "type": "NTSTATUS", "stack_offset": -0x10},
            {"name": "buffer", "type": "PVOID", "stack_offset": -0x20},
        ],
    )
    ir.functions[0x1000] = func
    if apis:
        ir.function_apis[0x1000] = apis
    return ir


# ---------------------------------------------------------------------------
# Pattern Unit Tests
# ---------------------------------------------------------------------------

class TestPseudocodePatterns:
    """Test individual pseudocode pattern matching."""

    def test_ioctl_validation_patterns_exist(self):
        """IOCTL validation patterns should be defined."""
        assert len(IOCTL_VALIDATION_PATTERNS) >= 3

    def test_struct_field_patterns_exist(self):
        """Struct field patterns should be defined."""
        assert len(STRUCT_FIELD_PATTERNS) >= 3

    def test_vtable_patterns_exist(self):
        """Vtable patterns should be defined."""
        assert len(VTABLE_PATTERNS) >= 3

    def test_ctl_code_pattern_matches(self):
        pattern = IOCTL_VALIDATION_PATTERNS[0][0]
        assert pattern.search("switch(IrpStack->Parameters.DeviceIoControl.IoControlCode)")
        assert pattern.search("CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED)")

    def test_struct_field_matches_irp(self):
        pattern = STRUCT_FIELD_PATTERNS[0][0]
        assert pattern.search("Irp->Tail.Overlay.CurrentStackLocation")

    def test_vtable_pattern_matches(self):
        pattern = VTABLE_PATTERNS[0]
        assert pattern.search("this->vtable[3]()")


# ---------------------------------------------------------------------------
# PseudocodeAnalyzer Integration Tests
# ---------------------------------------------------------------------------

class TestPseudocodeAnalyzer:
    """Test PseudocodeAnalyzer end-to-end."""

    def test_no_pseudocode_returns_empty(self):
        """Driver without pseudocode should produce no findings from this analyzer."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        ir.functions[0x1000] = Function(name="sub_1000", address=0x1000, size=0x100)
        sample = _make_sample()
        analyzer = PseudocodeAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert len(findings) == 0

    def test_ioctl_control_code_detected(self):
        """Pseudocode with IoControlCode should produce IOCTL_CODE_EXPOSED finding."""
        pseudo = """
        NTSTATUS sub_1000(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
            PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
            ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
            if (ioControlCode == 0x22A004) {
                MmMapIoSpaceEx(physicalAddress, numberOfBytes, cacheType);
            }
            return STATUS_SUCCESS;
        }
        """
        ir = _make_ir_with_pseudocode(pseudo, ["MmMapIoSpaceEx"])
        sample = _make_sample()
        analyzer = PseudocodeAnalyzer()
        findings = analyzer.analyze(sample, ir)

        ioctl_findings = [
            f for f in findings
            if f.category == FindingCategory.IOCTL_CODE_EXPOSED
        ]
        assert len(ioctl_findings) >= 1

    def test_struct_field_access_detected(self):
        """Pseudocode with IRP->Tail field access should produce finding."""
        pseudo = """
        NTSTATUS sub_1000(PIRP Irp) {
            PIO_STACK_LOCATION stack = Irp->Tail.Overlay.CurrentStackLocation;
            stack->MajorFunction = 0xE;
            return STATUS_SUCCESS;
        }
        """
        ir = _make_ir_with_pseudocode(pseudo)
        sample = _make_sample()
        analyzer = PseudocodeAnalyzer()
        findings = analyzer.analyze(sample, ir)

        struct_findings = [
            f for f in findings
            if f.category == FindingCategory.UNVALIDATED_DATA_FLOW
        ]
        assert len(struct_findings) >= 1

    def test_vtable_call_detected(self):
        """Pseudocode with vtable access should produce CUSTOM_CODE_EXECUTION finding."""
        pseudo = """
        void process_device(DeviceExt *ext) {
            ext->ops->vtable[3](ext->device);
        }
        """
        ir = _make_ir_with_pseudocode(pseudo)
        sample = _make_sample()
        analyzer = PseudocodeAnalyzer()
        findings = analyzer.analyze(sample, ir)

        vtable_findings = [
            f for f in findings
            if f.category == FindingCategory.CUSTOM_CODE_EXECUTION
        ]
        assert len(vtable_findings) >= 1

    def test_no_validation_with_dangerous_api(self):
        """Function with dangerous API but no validation in pseudocode → HIGH finding."""
        pseudo = """
        NTSTATUS sub_1000(PIRP Irp) {
            PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
            MmMapIoSpaceEx(physicalAddress, numberOfBytes, cacheType);
            return STATUS_SUCCESS;
        }
        """
        ir = _make_ir_with_pseudocode(pseudo, ["MmMapIoSpaceEx"])
        sample = _make_sample()
        analyzer = PseudocodeAnalyzer()
        findings = analyzer.analyze(sample, ir)

        no_val_findings = [
            f for f in findings
            if f.category == FindingCategory.UNVALIDATED_USER_INPUT
            and f.severity == Severity.HIGH
        ]
        assert len(no_val_findings) >= 1

    def test_function_signature_populated(self):
        """Function should have signature and local_vars from Ghidra decompiler."""
        ir = _make_ir_with_pseudocode("dummy", ["MmMapIoSpaceEx"])
        func = ir.functions[0x1000]
        assert func.signature != ""
        assert len(func.local_vars) == 2
        assert func.local_vars[0]["name"] == "status"
        assert func.local_vars[0]["type"] == "NTSTATUS"

    def test_analyzer_properties(self):
        """PseudocodeAnalyzer should have correct properties."""
        analyzer = PseudocodeAnalyzer()
        assert analyzer.name == "PseudocodeAnalyzer"
        assert analyzer.enabled is True
        assert analyzer.is_correlator is False
