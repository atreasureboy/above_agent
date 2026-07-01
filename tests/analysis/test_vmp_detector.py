"""Tests for VMProtect / Themida deep analysis (Phase 3)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.core.vmp_detector import (
    VmProtectDetector,
    VM_STRINGS,
    VM_ENTRY_SIGNATURES,
    detect_vm_entries,
    detect_vm_handlers,
    detect_vm_protect_overall,
)
from src.models import (
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Severity,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _add_function(ir: DisassemblyResult, addr: int) -> None:
    func = Function(name=f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func


def _add_cfg_with_insns(ir: DisassemblyResult, func_addr: int, instructions: list[tuple[str, str]]) -> None:
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    insns = [
        Instruction(address=func_addr + 0x10 + i * 4, mnemonic=mnem, operands=ops, size=4)
        for i, (mnem, ops) in enumerate(instructions)
    ]
    block = BasicBlock(address=func_addr, end_address=func_addr + 0x100, instructions=insns, successors=[])
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg


class TestVMProtectConstants:
    """Test VMProtect detection constant definitions."""

    def test_vm_protect_strings_defined(self):
        assert "VMProtect" in VM_STRINGS
        assert ".vmp0" in VM_STRINGS
        assert ".vmp1" in VM_STRINGS
        assert ".vmp2" in VM_STRINGS
        assert "Themida" in VM_STRINGS
        assert "WinLicense" in VM_STRINGS

    def test_vm_entry_signatures_defined(self):
        patterns = [p for p, _, _ in VM_ENTRY_SIGNATURES]
        types = [t for _, t, _ in VM_ENTRY_SIGNATURES]
        assert any("pushf" in p for p in patterns)
        assert any("pushad" in p for p in patterns)
        assert "push_flags" in types
        assert "pushad" in types
        assert "push_reg" in types


class TestVMEntryDetection:
    """Test VM entry point detection."""

    def test_x86_vm_prologue_detected(self):
        """pushfd + pushad + register pushes should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("pushfd", ""),
            ("pushad", ""),
            ("push", "rax"),
            ("push", "rbx"),
            ("push", "rcx"),
            ("push", "rdx"),
            ("push", "rsi"),
            ("push", "rdi"),
        ])
        findings = detect_vm_entries(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.VM_ENTRY
        assert findings[0].context["vm_entry_count"] == 1

    def test_x64_register_pushes_detected(self):
        """6+ individual register pushes should suggest VM entry."""
        ir = _make_ir()
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("push", "rax"),
            ("push", "rbx"),
            ("push", "rcx"),
            ("push", "rdx"),
            ("push", "rsi"),
            ("push", "rdi"),
            ("push", "r8"),
            ("push", "r9"),
        ])
        findings = detect_vm_entries(ir)
        assert len(findings) == 1

    def test_vmprotect_string_detected(self):
        """VMProtect string should trigger detection."""
        ir = _make_ir()
        ir.strings.append("VMProtect begin")
        findings = detect_vm_entries(ir)
        assert len(findings) == 1

    def test_themida_string_detected(self):
        """Themida string should trigger detection."""
        ir = _make_ir()
        ir.strings.append("Themida protected section")
        findings = detect_vm_entries(ir)
        assert len(findings) == 1

    def test_vmp_section_detected(self):
        """.vmp0 section string should trigger detection."""
        ir = _make_ir()
        ir.strings.append(".vmp0")
        findings = detect_vm_entries(ir)
        assert len(findings) == 1

    def test_multiple_vm_entries(self):
        """Multiple VM entry functions should all be counted."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("pushfd", ""), ("pushad", ""),
            ("push", "rax"), ("push", "rbx"),
            ("push", "rcx"), ("push", "rdx"),
        ])
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("pushfd", ""),
            ("push", "rax"), ("push", "rbx"),
            ("push", "rcx"), ("push", "rdx"),
            ("push", "rsi"),
        ])
        findings = detect_vm_entries(ir)
        assert len(findings) == 1
        assert findings[0].context["vm_entry_count"] == 2

    def test_critical_with_many_entries_and_strings(self):
        """3+ VM entries + strings should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("VMProtect begin")
        for addr in [0x1000, 0x2000, 0x3000]:
            _add_function(ir, addr)
            _add_cfg_with_insns(ir, addr, [
                ("pushfd", ""), ("pushad", ""),
                ("push", "rax"), ("push", "rbx"),
                ("push", "rcx"), ("push", "rdx"),
            ])
        findings = detect_vm_entries(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_few_pushes_not_flagged(self):
        """Fewer than 5 pushes should not trigger VM entry."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("push", "rbp"),
            ("push", "rbx"),
            ("push", "rsi"),
        ])
        findings = detect_vm_entries(ir)
        assert findings == []

    def test_empty_ir_no_crash(self):
        ir = _make_ir()
        findings = detect_vm_entries(ir)
        assert findings == []


class TestVMHandlerDetection:
    """Test VM handler dispatch loop detection."""

    def test_vm_handler_with_many_indirect_branches(self):
        """Function with many blocks and indirect branches should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        # Create many blocks - each with an indirect branch at the end
        cfg = CFG(function_address=0x1000, entry_block=0x1000)
        for i in range(25):
            block_addr = 0x1000 + i * 0x10
            insns = [
                Instruction(address=block_addr + 0x10, mnemonic="mov", operands=f"r{i % 15 + 1}, {i * 3}", size=4),
                Instruction(address=block_addr + 0x20, mnemonic="mov", operands=f"r{(i+1) % 15 + 1}, {i * 7}", size=4),
                Instruction(address=block_addr + 0x30, mnemonic="mov", operands="rax, qword ptr [rsi+r12]", size=4),
                Instruction(address=block_addr + 0x40, mnemonic="jmp", operands="qword ptr [rsi+r12]", size=4),
            ]
            successors = [0x1000 + ((i + 1) % 25) * 0x10]
            block = BasicBlock(address=block_addr, end_address=block_addr + 0x50, instructions=insns, successors=successors)
            cfg.blocks[block_addr] = block
        ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg
        findings = detect_vm_handlers(ir)
        assert len(findings) == 1

    def test_small_function_not_flagged(self):
        """Small function should not be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, rbx"),
            ("jmp", "qword ptr [rax]"),
        ])
        findings = detect_vm_handlers(ir)
        assert findings == []

    def test_empty_ir_no_crash(self):
        ir = _make_ir()
        findings = detect_vm_handlers(ir)
        assert findings == []


class TestVMProtectOverall:
    """Test overall VMProtect correlation."""

    def test_correlated_vm_signals(self):
        """VM entries + VM handlers should produce correlated finding."""
        ir = _make_ir()
        ir.strings.append("VMProtect begin")
        # VM entry
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("pushfd", ""), ("pushad", ""),
            ("push", "rax"), ("push", "rbx"),
            ("push", "rcx"), ("push", "rdx"),
        ])
        # VM handler (25+ blocks with indirect branches)
        _add_function(ir, 0x2000)
        cfg = CFG(function_address=0x2000, entry_block=0x2000)
        for i in range(25):
            block_addr = 0x2000 + i * 0x10
            insns = [
                Instruction(address=block_addr + 0x10, mnemonic="mov", operands=f"r{i % 15 + 1}, {i * 3}", size=4),
                Instruction(address=block_addr + 0x20, mnemonic="mov", operands="rax, qword ptr [rsi+r12]", size=4),
                Instruction(address=block_addr + 0x30, mnemonic="jmp", operands="qword ptr [rsi+r12]", size=4),
            ]
            block = BasicBlock(address=block_addr, end_address=block_addr + 0x40, instructions=insns, successors=[])
            cfg.blocks[block_addr] = block
        ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = cfg

        findings = detect_vm_protect_overall(ir)
        assert len(findings) >= 1

    def test_no_vm_no_findings(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, rbx"),
        ])
        findings = detect_vm_protect_overall(ir)
        assert findings == []

    def test_empty_ir_no_crash(self):
        ir = _make_ir()
        findings = detect_vm_protect_overall(ir)
        assert findings == []


class TestVmProtectDetectorIntegration:
    """Test VmProtectDetector end-to-end."""

    def test_analyzer_name(self):
        detector = VmProtectDetector()
        assert detector.name == "VmProtectDetector"

    def test_analyzer_description(self):
        detector = VmProtectDetector()
        assert "VMProtect" in detector.description
        assert "Themida" in detector.description

    def test_analyze_empty_ir(self):
        from src.models import Sample, Architecture
        ir = _make_ir()
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = VmProtectDetector()
        findings = detector.analyze(sample, ir)
        assert findings == []

    def test_analyze_detects_vm_entry(self):
        from src.models import Sample, Architecture
        ir = _make_ir()
        ir.strings.append("VMProtect begin")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("pushfd", ""), ("pushad", ""),
            ("push", "rax"), ("push", "rbx"),
            ("push", "rcx"), ("push", "rdx"),
        ])
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = VmProtectDetector()
        findings = detector.analyze(sample, ir)
        categories = {f.category for f in findings}
        assert FindingCategory.VM_ENTRY in categories

    def test_analyze_findings_have_evidence(self):
        from src.models import Sample, Architecture
        ir = _make_ir()
        ir.strings.append("VMProtect begin")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("pushfd", ""), ("pushad", ""),
            ("push", "rax"), ("push", "rbx"),
            ("push", "rcx"), ("push", "rdx"),
        ])
        sample = Sample(
            path=Path("test.sys"), name="test.sys", company="Test",
            version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
            is_driver=True,
        )
        detector = VmProtectDetector()
        findings = detector.analyze(sample, ir)
        for f in findings:
            assert len(f.evidence) > 0
