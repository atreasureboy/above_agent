"""Tests for enhanced and new analyzers.

Tests for:
- StackStringAnalyzer (Ghidra format support)
- XrefTracker (Ghidra format support)
- PseudocodeAnalyzer (new)
- BYOVDChainCorrelator (new)
- FilterDriverAnalyzer enhancements
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.models import (
    Architecture,
    BasicBlock,
    CFG,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Severity,
    Confidence,
    Sample,
)


def _make_basic_ir() -> tuple[Sample, DisassemblyResult]:
    """Create a minimal sample + IR for testing."""
    sample = Sample(
        name="test_driver",
        path=Path("test.sys"),
        sha256="a" * 64,
        arch=Architecture.X64,
        company="",
        version="",
        size=0,
    )
    ir = DisassemblyResult(
        sample_path=Path("test.sys"),
        backend="ghidra",
    )
    ir.image_base = 0xFFFFF80012340000
    return sample, ir


def _add_function(ir: DisassemblyResult, addr: int, name: str, size: int,
                  calls: list[int] | None = None,
                  apis: list[str] | None = None,
                  pseudo_code: str = "",
                  instructions: list[Instruction] | None = None):
    """Add a function to the IR."""
    func = Function(name=name, address=addr, size=size)
    if calls:
        func.calls = list(calls)
    ir.functions[addr] = func
    if apis:
        ir.function_apis[addr] = list(apis)
    if pseudo_code:
        func.pseudo_code = pseudo_code

    # Always create a CFG so analyzers iterating cfgs can find the function
    if instructions:
        cfg = CFG(function_address=addr, entry_block=addr)
        block = BasicBlock(
            address=addr,
            end_address=addr + size,
            instructions=instructions,
        )
        cfg.blocks[addr] = block
        ir.cfgs[addr] = ir.simple_cfgs[addr] = cfg
    elif addr not in ir.cfgs:
        cfg = CFG(function_address=addr, entry_block=addr)
        block = BasicBlock(
            address=addr,
            end_address=addr + size,
            instructions=[],
        )
        cfg.blocks[addr] = block
        ir.cfgs[addr] = ir.simple_cfgs[addr] = cfg


# ===================================================================
# StackStringAnalyzer — Ghidra format
# ===================================================================

class TestStackStringGhidraFormat:
    """Test StackStringAnalyzer with Ghidra operand formats."""

    def test_ghidra_byte_ptr_bracket_format(self):
        """Match Ghidra format: BYTE PTR [RSP + 0x20], 0x41."""
        from src.analysis.deep.stack_string_analyzer import StackStringAnalyzer

        analyzer = StackStringAnalyzer()
        # Test the regex directly
        text = "mov BYTE PTR [RSP + 0x20], 0x41"
        result = analyzer._try_parse_ghidra_byte_write(text)
        assert result is not None
        offset, value = result
        assert offset == 0x20
        assert value == 0x41

    def test_ghidra_byte_ptr_lowercase(self):
        """Match lowercase Ghidra format."""
        from src.analysis.deep.stack_string_analyzer import StackStringAnalyzer

        analyzer = StackStringAnalyzer()
        text = "mov byte ptr [rsp + 0x10], 0x55"
        result = analyzer._try_parse_ghidra_byte_write(text)
        assert result is not None
        assert result == (0x10, 0x55)

    def test_ghidra_word_ptr_bracket_format(self):
        """Match Ghidra WORD PTR format."""
        from src.analysis.deep.stack_string_analyzer import StackStringAnalyzer

        analyzer = StackStringAnalyzer()
        text = "mov WORD PTR [RSP + 0x30], 0x0041"
        result = analyzer._try_parse_ghidra_word_write(text)
        assert result is not None
        assert result[0] == 0x30

    def test_ghidra_flat_format(self):
        """Match Ghidra flat format: mov RSP 0x20, 0x41."""
        from src.analysis.deep.stack_string_analyzer import StackStringAnalyzer

        analyzer = StackStringAnalyzer()
        text = "mov RSP 0x20, 0x41"
        result = analyzer._try_parse_ghidra_byte_write(text)
        assert result is not None
        assert result == (0x20, 0x41)

    def test_capstone_format_still_works(self):
        """Capstone format should still match."""
        from src.analysis.deep.stack_string_analyzer import StackStringAnalyzer

        analyzer = StackStringAnalyzer()
        sample, ir = _make_basic_ir()

        # Create function with Capstone-format stack string instructions
        instructions = [
            Instruction(address=0x1000, mnemonic="mov", operands="byte ptr [rsp+0x20], 0x48"),
            Instruction(address=0x1001, mnemonic="mov", operands="byte ptr [rsp+0x21], 0x65"),
            Instruction(address=0x1002, mnemonic="mov", operands="byte ptr [rsp+0x22], 0x6c"),
            Instruction(address=0x1003, mnemonic="mov", operands="byte ptr [rsp+0x23], 0x6c"),
            Instruction(address=0x1004, mnemonic="mov", operands="byte ptr [rsp+0x24], 0x6f"),
        ]
        _add_function(ir, 0x1000, "test_func", 0x100, instructions=instructions)

        findings = analyzer.analyze(sample, ir)
        assert any("Hello" in f.description for f in findings), f"Expected 'Hello' in findings: {[f.description for f in findings]}"

    def test_ghidra_utf16_stack_string(self):
        """UTF-16 stack string via Ghidra WORD PTR format."""
        from src.analysis.deep.stack_string_analyzer import StackStringAnalyzer

        analyzer = StackStringAnalyzer()
        sample, ir = _make_basic_ir()

        instructions = [
            Instruction(address=0x2000, mnemonic="mov", operands="WORD PTR [RSP + 0x10], 0x0041"),
            Instruction(address=0x2001, mnemonic="mov", operands="WORD PTR [RSP + 0x12], 0x0042"),
            Instruction(address=0x2002, mnemonic="mov", operands="WORD PTR [RSP + 0x14], 0x0043"),
        ]
        _add_function(ir, 0x2000, "utf16_func", 0x100, instructions=instructions)

        findings = analyzer.analyze(sample, ir)
        assert any("ABC" in f.description for f in findings)


# ===================================================================
# XrefTracker — Ghidra format
# ===================================================================

class TestXrefTrackerGhidraFormat:
    """Test XrefTracker with Ghidra operand formats."""

    def test_ghidra_rip_bracket_format(self):
        """Match Ghidra format: qword ptr [RIP + 0x1234]."""
        from src.analysis.deep.xref_tracker import XrefTracker

        tracker = XrefTracker()
        insn = MagicMock()
        insn.operands = "RAX, qword ptr [RIP + 0x1234]"
        insn.address = 0xFFFFF80012345000
        insn.size = 7
        insn.mnemonic = "mov"

        target = tracker._resolve_ghidra_rip(insn, 0xFFFFF80012345000, 0xFFFFF80012340000)
        assert target is not None
        assert target == 0xFFFFF80012345000 + 7 + 0x1234

    def test_ghidra_absolute_address(self):
        """Match Ghidra resolved absolute address."""
        from src.analysis.deep.xref_tracker import XrefTracker

        tracker = XrefTracker()
        insn = MagicMock()
        insn.operands = "RAX, 0xFFFFF80012345678"
        insn.address = 0xFFFFF80012345000
        insn.size = 7
        insn.mnemonic = "mov"

        target = tracker._resolve_ghidra_rip(insn, 0xFFFFF80012345000, 0xFFFFF80012340000)
        assert target is not None
        assert target == 0xFFFFF80012345678

    def test_capstone_rip_still_works(self):
        """Capstone [rip+offset] format should still work."""
        from src.analysis.deep.xref_tracker import XrefTracker

        tracker = XrefTracker()
        insn = MagicMock()
        # Capstone format: no spaces inside brackets
        insn.operands = "rax, qword ptr [rip+0x1234]"
        insn.address = 0xFFFFF80012345000
        insn.size = 7
        insn.mnemonic = "mov"

        target = tracker._resolve_rip_relative(insn, 0xFFFFF80012345000)
        assert target is not None
        expected = 0xFFFFF80012345000 + 7 + 0x1234
        assert target == expected


# ===================================================================
# PseudocodeAnalyzer
# ===================================================================

class TestPseudocodeAnalyzer:
    """Test the new PseudocodeAnalyzer."""

    def _make_analyzer_and_ir(self):
        from src.analysis.core.pseudocode_analyzer import PseudocodeAnalyzer
        sample, ir = _make_basic_ir()
        analyzer = PseudocodeAnalyzer()
        return analyzer, sample, ir

    def test_detect_unvalidated_ioctl_handler(self):
        """IOCTL handler with dangerous API but no validation should be flagged."""
        analyzer, sample, ir = self._make_analyzer_and_ir()

        _add_function(
            ir, 0x1000, "IoctlHandler", 0x200,
            apis=["MmMapIoSpaceEx"],
            pseudo_code="""
void IoctlHandler(IRP *Irp) {
    PVOID buf = Irp->UserBuffer;
    ULONG len = Irp->Parameters.DeviceIoControl.InputLength;
    RtlCopyMemory(LocalBuffer, buf, len);
    Irp->IoStatus.Status = STATUS_SUCCESS;
}
""",
        )
        ir.ioctl_handlers[0x22A004] = 0x1000

        findings = analyzer.analyze(sample, ir)
        assert any(f.category == FindingCategory.UNVALIDATED_USER_INPUT for f in findings)

    def test_detect_validated_handler(self):
        """Handler with validation keywords should not be flagged as unvalidated."""
        analyzer, sample, ir = self._make_analyzer_and_ir()

        _add_function(
            ir, 0x2000, "SafeHandler", 0x300,
            apis=["MmMapIoSpaceEx"],
            pseudo_code="""
void SafeHandler(IRP *Irp) {
    if (ExGetPreviousMode() != KernelMode) {
        ProbeForRead(Irp->UserBuffer, InputLength, 1);
    }
    if (InputBufferLength < sizeof(INPUT_STRUCT)) {
        return STATUS_INVALID_PARAMETER;
    }
}
""",
        )
        ir.ioctl_handlers[0x22B004] = 0x2000

        findings = analyzer.analyze(sample, ir)
        assert not any(f.category == FindingCategory.UNVALIDATED_USER_INPUT for f in findings)

    def test_detect_struct_field_access(self):
        """Pseudocode with IRP struct field access should produce UNVALIDATED_DATA_FLOW."""
        analyzer, sample, ir = self._make_analyzer_and_ir()

        _add_function(
            ir, 0x3000, "ProcessIrp", 0x100,
            pseudo_code="""
void ProcessIrp(IRP *Irp) {
    auto stack = Irp->Tail.Overlay.CurrentStackLocation;
    auto params = stack->Parameters.DeviceIoControl;
    // direct use without validation
}
""",
        )

        findings = analyzer.analyze(sample, ir)
        assert any(f.category == FindingCategory.UNVALIDATED_DATA_FLOW for f in findings)

    def test_empty_pseudocode_skipped(self):
        """Functions without pseudocode should be skipped."""
        analyzer, sample, ir = self._make_analyzer_and_ir()
        _add_function(ir, 0x6000, "NoPseudo", 0x100)

        findings = analyzer.analyze(sample, ir)
        assert len(findings) == 0


# ===================================================================
# BYOVDChainCorrelator
# ===================================================================

class TestBYOVDChainCorrelator:
    """Test the BYOVDChainCorrelator (core version)."""

    def _make_correlator_and_ir(self):
        from src.analysis.core.correlator import BYOVDChainCorrelator
        sample, ir = _make_basic_ir()
        sample.analysis_findings = []
        correlator = BYOVDChainCorrelator()
        return correlator, sample, ir

    def test_is_correlator_flag(self):
        """BYOVDChainCorrelator should be marked as correlator."""
        from src.analysis.core.correlator import BYOVDChainCorrelator
        assert BYOVDChainCorrelator().is_correlator is True


# ===================================================================
# FilterDriverAnalyzer enhancements
# ===================================================================

class TestFilterDriverAnalyzerEnhanced:
    """Test FilterDriverAnalyzer with operation_rules support."""

    def _make_analyzer_and_ir(self):
        from src.analysis.deep.filter_driver_analyzer import FilterDriverAnalyzer
        sample, ir = _make_basic_ir()
        analyzer = FilterDriverAnalyzer()
        return analyzer, sample, ir

    def test_analyze_operation_rules(self):
        """Should produce findings from operation_rules."""
        analyzer, sample, ir = self._make_analyzer_and_ir()
        ir.is_minifilter = True

        # Simulate operation rules populated by MiniFilterRuleExtractor
        ir.operation_rules = [
            {
                "rva": 0x5000,
                "major_function": 0x00,  # IRP_MJ_CREATE
                "flags": 0,
                "pre_operation": 0x1000,
                "post_operation": 0x2000,
            },
            {
                "rva": 0x5018,
                "major_function": 0x0E,  # IRP_MJ_DEVICE_CONTROL
                "flags": 0,
                "pre_operation": 0x3000,
                "post_operation": None,
            },
        ]

        # Add the callback functions
        _add_function(ir, 0x1000, "PreCreate", 0x100)
        _add_function(ir, 0x2000, "PostCreate", 0x100)
        _add_function(ir, 0x3000, "PreDeviceControl", 0x100)

        findings = analyzer.analyze(sample, ir)
        filter_findings = [f for f in findings if f.category == FindingCategory.FILTER_CALLBACK_ANALYZED]
        assert len(filter_findings) >= 2

    def test_minifilter_handlers_populated(self):
        """When MiniFilterRuleExtractor populates minifilter_handlers, FilterDriverAnalyzer should find them."""
        analyzer, sample, ir = self._make_analyzer_and_ir()
        ir.is_minifilter = True

        # Populate minifilter_handlers as MiniFilterRuleExtractor would
        ir.minifilter_handlers[0x00] = 0x1000  # IRP_MJ_CREATE → PreCreate
        ir.minifilter_handlers[0x03] = 0x2000  # IRP_MJ_READ → PreRead

        _add_function(ir, 0x1000, "PreCreate", 0x100,
                      apis=["PsGetCurrentProcessId", "FltGetFileNameInformation"])
        _add_function(ir, 0x2000, "PreRead", 0x100,
                      apis=["FltReadFile"])

        findings = analyzer.analyze(sample, ir)
        assert len(findings) > 0

    def test_is_correlator_flag(self):
        """FilterDriverAnalyzer should be marked as correlator."""
        from src.analysis.deep.filter_driver_analyzer import FilterDriverAnalyzer
        assert FilterDriverAnalyzer().is_correlator is True
