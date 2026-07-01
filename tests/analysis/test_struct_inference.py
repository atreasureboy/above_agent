"""Tests for struct_inference_analyzer.py."""

from __future__ import annotations

from pathlib import Path

from src.analysis.deep.struct_inference_analyzer import StructInferenceAnalyzer
from src.models import (
    BasicBlock, CFG, Confidence, DisassemblyResult, FindingCategory,
    Function, Instruction, Sample, Architecture, Severity,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _add_function(ir: DisassemblyResult, addr: int, name: str = None) -> Function:
    func = Function(name=name or f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func
    return func


def _add_cfg_with_insns(ir: DisassemblyResult, func_addr: int, instructions: list[tuple[str, str]]) -> None:
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    insns = [
        Instruction(address=func_addr + 0x10 + i * 4, mnemonic=mnem, operands=ops, size=4)
        for i, (mnem, ops) in enumerate(instructions)
    ]
    block = BasicBlock(address=func_addr, end_address=func_addr + 0x100, instructions=insns, successors=[])
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg


def _sample() -> Sample:
    return Sample(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
        is_driver=True,
    )


class TestStructInferenceBasics:
    """Test basic analyzer functionality."""

    def test_analyzer_name(self):
        analyzer = StructInferenceAnalyzer()
        assert analyzer.name == "StructInferenceAnalyzer"

    def test_analyzer_description(self):
        analyzer = StructInferenceAnalyzer()
        assert "structure" in analyzer.description.lower()

    def test_empty_ir_no_findings(self):
        ir = _make_ir()
        sample = _sample()
        analyzer = StructInferenceAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert findings == []

    def test_min_field_count(self):
        analyzer = StructInferenceAnalyzer()
        assert analyzer.MIN_FIELD_COUNT == 3


class TestStructAccessDetection:
    """Test struct access pattern detection."""

    def test_x64_struct_access_detected(self):
        """Multiple [rcx+offset] accesses should trigger struct inference."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, [rcx+0x10]"),
            ("mov", "rbx, [rcx+0x20]"),
            ("mov", "rdx, [rcx+0x30]"),
            ("mov", "r8, [rcx+0x40]"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        struct_findings = [f for f in findings if f.category == FindingCategory.STRUCT_INFERRED]
        assert len(struct_findings) >= 1
        assert struct_findings[0].context.get("access_count", 0) >= 3

    def test_x64_rdx_struct_access(self):
        ir = _make_ir()
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("mov", "rax, [rdx+0x0]"),
            ("mov", "rbx, [rdx+0x8]"),
            ("mov", "rcx, [rdx+0x10]"),
            ("mov", "r9, [rdx+0x18]"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        struct_findings = [f for f in findings if f.category == FindingCategory.STRUCT_INFERRED]
        assert len(struct_findings) >= 1

    def test_x64_rax_struct_access(self):
        """RAX-based struct access should be detected."""
        ir = _make_ir()
        _add_function(ir, 0x3000)
        _add_cfg_with_insns(ir, 0x3000, [
            ("mov", "[rax+0x0], rbx"),
            ("mov", "[rax+0x8], rcx"),
            ("mov", "[rax+0x10], rdx"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        struct_findings = [f for f in findings if f.category == FindingCategory.STRUCT_INFERRED]
        assert len(struct_findings) >= 1

    def test_too_few_fields_no_finding(self):
        """Less than 3 distinct offsets should not trigger struct inference."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, [rcx+0x10]"),
            ("mov", "rbx, [rcx+0x10]"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        struct_findings = [f for f in findings if f.category == FindingCategory.STRUCT_INFERRED]
        assert len(struct_findings) == 0

    def test_different_registers_separate_structs(self):
        """RCX and RDX accesses should be treated as separate structs."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, [rcx+0x10]"),
            ("mov", "rbx, [rcx+0x20]"),
            ("mov", "rcx, [rcx+0x30]"),
            ("mov", "rdx, [rdx+0x10]"),
            ("mov", "r8, [rdx+0x20]"),
            ("mov", "r9, [rdx+0x30]"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        struct_findings = [f for f in findings if f.category == FindingCategory.STRUCT_INFERRED]
        # Should find at least 1 struct (could be 2 if separated by register)
        assert len(struct_findings) >= 1


class TestGhidraFormatStructAccess:
    """Test Ghidra-format struct access detection."""

    def test_ghidra_flat_struct_access(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "RDX 0x10, RBX"),
            ("mov", "RDX 0x20, RCX"),
            ("mov", "RDX 0x30, R8"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        struct_findings = [f for f in findings if f.category == FindingCategory.STRUCT_INFERRED]
        # Ghidra flat format should match


class TestVtableDetection:
    """Test C++ vtable call detection."""

    def test_x64_vtable_call_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, [rcx+0x10]"),
            ("mov", "rbx, [rcx+0x20]"),
            ("mov", "rcx, [rcx+0x30]"),
            ("mov", "rax, [rax]"),
            ("call", "qword ptr [rax]"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        vtbl_findings = [f for f in findings if f.category == FindingCategory.CPP_OBJECT_DETECTED]
        struct_findings = [f for f in findings if f.category == FindingCategory.STRUCT_INFERRED]
        assert len(vtbl_findings) > 0 or len(struct_findings) > 0

    def test_x86_vtable_call_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("mov", "eax, [ecx+0x10]"),
            ("mov", "ebx, [ecx+0x20]"),
            ("mov", "ecx, [ecx+0x30]"),
            ("mov", "eax, [eax]"),
            ("call", "dword ptr [eax]"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        vtbl_findings = [f for f in findings if f.category == FindingCategory.CPP_OBJECT_DETECTED]
        struct_findings = [f for f in findings if f.category == FindingCategory.STRUCT_INFERRED]
        assert len(vtbl_findings) > 0 or len(struct_findings) > 0


class TestFindingsStructure:
    """Test finding structure and content."""

    def test_findings_have_evidence(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, [rcx+0x0]"),
            ("mov", "rbx, [rcx+0x8]"),
            ("mov", "rcx, [rcx+0x10]"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0

    def test_struct_info_severity(self):
        """Struct findings should be INFO severity."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, [rcx+0x0]"),
            ("mov", "rbx, [rcx+0x8]"),
            ("mov", "rcx, [rcx+0x10]"),
            ("mov", "rdx, [rcx+0x18]"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        for f in findings:
            if f.category == FindingCategory.STRUCT_INFERRED:
                assert f.severity == Severity.INFO

    def test_struct_context_has_fields(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, [rcx+0x0]"),
            ("mov", "rbx, [rcx+0x8]"),
            ("mov", "rcx, [rcx+0x10]"),
        ])
        analyzer = StructInferenceAnalyzer()
        sample = _sample()
        findings = analyzer.analyze(sample, ir)
        for f in findings:
            if f.category == FindingCategory.STRUCT_INFERRED:
                assert "access_count" in f.context
                assert "field_offsets" in f.context
                assert "register" in f.context
