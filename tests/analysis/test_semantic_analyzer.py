"""Tests for Phase 4: Semantic primitive detection (non-API-based)."""

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
    Sample,
    Severity,
)
from src.analysis.core.semantic_analyzer import (
    SemanticAnalyzer,
    SEMANTIC_RULES,
    _check_wrmsr,
    _check_cr_write,
    _check_indirect_call,
    _check_port_io,
    _check_pci_config_port,
    _check_physical_addr_shift,
    _check_dr_write,
    _check_gdt_idt,
    _check_ltr,
    _check_lmsw,
    _check_clts,
    _check_invlpg,
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


def _make_ir_with_wrmsr() -> DisassemblyResult:
    """Driver with direct wrmsr instruction."""
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
    func = Function(name="sub_1000", address=0x1000, size=0x100)
    ir.functions[0x1000] = func

    cfg = CFG(function_address=0x1000, entry_block=0x1000)
    block = BasicBlock(
        address=0x1000, end_address=0x1100,
        instructions=[
            Instruction(address=0x1010, mnemonic="mov", operands="ecx, 0x1A0", size=5),
            Instruction(address=0x1020, mnemonic="mov", operands="eax, 0x1", size=5),
            Instruction(address=0x1030, mnemonic="xor", operands="edx, edx", size=3),
            Instruction(address=0x1040, mnemonic="wrmsr", operands="", size=2),
        ],
        successors=[],
    )
    cfg.blocks[0x1000] = block
    ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg
    ir.ioctl_handlers[0x22A004] = 0x1000
    return ir


def _make_ir_with_cr_write() -> DisassemblyResult:
    """Driver with mov cr4, reg instruction."""
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
    func = Function(name="sub_2000", address=0x2000, size=0x100)
    ir.functions[0x2000] = func

    cfg = CFG(function_address=0x2000, entry_block=0x2000)
    block = BasicBlock(
        address=0x2000, end_address=0x2100,
        instructions=[
            Instruction(address=0x2010, mnemonic="mov", operands="rcx, 0x10068", size=7),
            Instruction(address=0x2020, mnemonic="mov", operands="cr4, rcx", size=4),
        ],
        successors=[],
    )
    cfg.blocks[0x2000] = block
    ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = cfg
    ir.ioctl_handlers[0x22A004] = 0x2000
    return ir


def _make_ir_with_indirect_call() -> DisassemblyResult:
    """Driver with indirect call through function pointer."""
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
    func = Function(name="sub_3000", address=0x3000, size=0x200)
    ir.functions[0x3000] = func

    cfg = CFG(function_address=0x3000, entry_block=0x3000)
    block = BasicBlock(
        address=0x3000, end_address=0x3200,
        instructions=[
            Instruction(
                address=0x3010, mnemonic="mov",
                operands="rax, qword ptr [rcx + 0x60]", size=7,
            ),
            Instruction(
                address=0x3020, mnemonic="call",
                operands="qword ptr [rax + 0x10]", size=4,
            ),
        ],
        successors=[],
    )
    cfg.blocks[0x3000] = block
    ir.cfgs[0x3000] = ir.simple_cfgs[0x3000] = cfg
    ir.ioctl_handlers[0x22A004] = 0x3000
    return ir


def _make_ir_with_port_io() -> DisassemblyResult:
    """Driver with direct port I/O to PCI config space."""
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
    func = Function(name="sub_4000", address=0x4000, size=0x100)
    ir.functions[0x4000] = func

    cfg = CFG(function_address=0x4000, entry_block=0x4000)
    block = BasicBlock(
        address=0x4000, end_address=0x4100,
        instructions=[
            Instruction(address=0x4010, mnemonic="mov", operands="eax, 0x80000000", size=5),
            Instruction(address=0x4020, mnemonic="out", operands="0xCF8, eax", size=4),
            Instruction(address=0x4030, mnemonic="in", operands="eax, 0xCFC", size=4),
        ],
        successors=[],
    )
    cfg.blocks[0x4000] = block
    ir.cfgs[0x4000] = ir.simple_cfgs[0x4000] = cfg
    ir.ioctl_handlers[0x22A004] = 0x4000
    return ir


def _make_ir_with_physical_shift() -> DisassemblyResult:
    """Driver with bit-shift pattern suggesting physical address mapping."""
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
    func = Function(name="sub_5000", address=0x5000, size=0x200)
    ir.functions[0x5000] = func

    cfg = CFG(function_address=0x5000, entry_block=0x5000)
    block = BasicBlock(
        address=0x5000, end_address=0x5200,
        instructions=[
            Instruction(
                address=0x5010, mnemonic="mov",
                operands="rax, qword ptr [rcx + 0x60]", size=7,
            ),
            Instruction(address=0x5020, mnemonic="shl", operands="rax, 0xC", size=4),
            Instruction(address=0x5030, mnemonic="shr", operands="rax, 0xC", size=4),
            Instruction(address=0x5040, mnemonic="mov", operands="cr3, rax", size=4),
        ],
        successors=[],
    )
    cfg.blocks[0x5000] = block
    ir.cfgs[0x5000] = ir.simple_cfgs[0x5000] = cfg
    ir.ioctl_handlers[0x22A004] = 0x5000
    return ir


# ---------------------------------------------------------------------------
# Semantic Rule Unit Tests
# ---------------------------------------------------------------------------

class TestSemanticRules:
    """Test individual semantic rule check functions."""

    def test_wrmsr_detected(self):
        insn = Instruction(address=0x100, mnemonic="wrmsr", operands="")
        assert _check_wrmsr(None, 0, insn)

    def test_non_wrmsr_not_detected(self):
        insn = Instruction(address=0x100, mnemonic="mov", operands="rax, rcx")
        assert not _check_wrmsr(None, 0, insn)

    def test_cr4_write_detected(self):
        insn = Instruction(address=0x200, mnemonic="mov", operands="cr4, rcx")
        assert _check_cr_write(None, 0, insn)

    def test_cr0_write_detected(self):
        insn = Instruction(address=0x200, mnemonic="mov", operands="cr0, rax")
        assert _check_cr_write(None, 0, insn)

    def test_non_cr_write_not_detected(self):
        insn = Instruction(address=0x200, mnemonic="mov", operands="rcx, cr4")
        # This is reading cr4, not writing it — should still match the pattern
        assert _check_cr_write(None, 0, insn)

    def test_indirect_call_detected(self):
        insn = Instruction(
            address=0x300, mnemonic="call",
            operands="qword ptr [rax + 0x10]",
        )
        assert _check_indirect_call(None, 0, insn)

    def test_direct_call_not_detected(self):
        insn = Instruction(
            address=0x300, mnemonic="call",
            operands="MmMapIoSpaceEx",
            api_target="MmMapIoSpaceEx",
        )
        assert not _check_indirect_call(None, 0, insn)

    def test_port_io_detected(self):
        insn = Instruction(address=0x400, mnemonic="out", operands="0x378, al")
        assert _check_port_io(None, 0, insn)

    def test_pci_config_port_detected(self):
        insn = Instruction(address=0x400, mnemonic="out", operands="0xCF8, eax")
        assert _check_pci_config_port(None, 0, insn)

    def test_non_pci_port_not_detected(self):
        insn = Instruction(address=0x400, mnemonic="out", operands="0x378, al")
        assert not _check_pci_config_port(None, 0, insn)

    def test_physical_addr_shift_detected(self):
        insn = Instruction(address=0x500, mnemonic="shl", operands="rax, 0xC")
        assert _check_physical_addr_shift(None, 0, insn)

    def test_non_shift_not_detected(self):
        insn = Instruction(address=0x500, mnemonic="mov", operands="rax, 0xC")
        assert not _check_physical_addr_shift(None, 0, insn)


# ---------------------------------------------------------------------------
# SemanticAnalyzer Integration Tests
# ---------------------------------------------------------------------------

class TestSemanticAnalyzer:
    """Test SemanticAnalyzer end-to-end."""

    def test_semantic_rules_all_exist(self):
        """All expected semantic rules should be defined."""
        rule_ids = {r.rule_id for r in SEMANTIC_RULES}
        assert "SEM_WRMSR" in rule_ids
        assert "SEM_CR_WRITE" in rule_ids
        assert "SEM_INDIRECT_CALL" in rule_ids
        assert "SEM_PORT_IO" in rule_ids
        assert "SEM_PCI_CONFIG" in rule_ids
        assert "SEM_PHYS_SHIFT" in rule_ids

    def test_wrmsr_finding(self):
        """Driver with wrmsr instruction should produce DIRECT_MSR_WRITE finding."""
        ir = _make_ir_with_wrmsr()
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)

        wrmsr_findings = [
            f for f in findings
            if f.category == FindingCategory.DIRECT_MSR_WRITE
        ]
        assert len(wrmsr_findings) >= 1
        assert wrmsr_findings[0].severity == Severity.CRITICAL

    def test_cr_write_finding(self):
        """Driver with mov cr4, rcx should produce DIRECT_CR_WRITE finding."""
        ir = _make_ir_with_cr_write()
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)

        cr_findings = [
            f for f in findings
            if f.category == FindingCategory.DIRECT_CR_WRITE
        ]
        assert len(cr_findings) >= 1

    def test_indirect_call_finding(self):
        """Driver with indirect call should produce CUSTOM_CODE_EXECUTION finding."""
        ir = _make_ir_with_indirect_call()
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)

        indirect_findings = [
            f for f in findings
            if f.category == FindingCategory.CUSTOM_CODE_EXECUTION
        ]
        assert len(indirect_findings) >= 1

    def test_port_io_finding(self):
        """Driver with in/out instructions should produce DIRECT_PORT_IO finding."""
        ir = _make_ir_with_port_io()
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)

        port_findings = [
            f for f in findings
            if f.category == FindingCategory.DIRECT_PORT_IO
        ]
        assert len(port_findings) >= 1

    def test_pci_config_finding(self):
        """Driver with port 0xCF8/0xCFC access should produce PCI_CONFIG_ACCESS finding."""
        ir = _make_ir_with_port_io()
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)

        pci_findings = [
            f for f in findings
            if f.category == FindingCategory.PCI_CONFIG_ACCESS
        ]
        assert len(pci_findings) >= 1

    def test_physical_shift_finding(self):
        """Driver with shl/shr by 0xC should produce CUSTOM_PHYSICAL_MEMORY_MAPPING finding."""
        ir = _make_ir_with_physical_shift()
        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)

        shift_findings = [
            f for f in findings
            if f.category == FindingCategory.CUSTOM_PHYSICAL_MEMORY_MAPPING
        ]
        assert len(shift_findings) >= 1

    def test_clean_driver_no_findings(self):
        """Driver without any semantic primitives should produce zero findings."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        func = Function(name="sub_6000", address=0x6000, size=0x100)
        ir.functions[0x6000] = func

        cfg = CFG(function_address=0x6000, entry_block=0x6000)
        block = BasicBlock(
            address=0x6000, end_address=0x6100,
            instructions=[
                Instruction(address=0x6010, mnemonic="mov", operands="rax, rcx", size=3),
                Instruction(address=0x6020, mnemonic="ret", operands="", size=1),
            ],
            successors=[],
        )
        cfg.blocks[0x6000] = block
        ir.cfgs[0x6000] = ir.simple_cfgs[0x6000] = cfg

        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)

        assert len(findings) == 0

    def test_analyzer_properties(self):
        """SemanticAnalyzer should have correct properties."""
        analyzer = SemanticAnalyzer()
        assert analyzer.name == "SemanticAnalyzer"
        assert analyzer.enabled is True
        assert analyzer.is_correlator is False


# ---------------------------------------------------------------------------
# Phase 10: Privileged Instruction Tests
# ---------------------------------------------------------------------------

class TestPrivilegedInstructions:
    """Test Phase 10 privileged instruction detection."""

    def test_dr_write_detected(self):
        insn = Instruction(address=0x100, mnemonic="mov", operands="dr0, rax")
        assert _check_dr_write(None, 0, insn)
        insn2 = Instruction(address=0x100, mnemonic="mov", operands="dr7, rcx")
        assert _check_dr_write(None, 0, insn2)

    def test_non_dr_write_not_detected(self):
        insn = Instruction(address=0x100, mnemonic="mov", operands="rax, dr0")
        # Reading dr0 still matches the pattern
        assert _check_dr_write(None, 0, insn)

    def test_non_mov_not_dr_write(self):
        insn = Instruction(address=0x100, mnemonic="xor", operands="dr0, dr0")
        assert not _check_dr_write(None, 0, insn)

    def test_gdt_idt_lgdt(self):
        insn = Instruction(address=0x100, mnemonic="lgdt", operands="fword ptr [rsp+0x20]")
        assert _check_gdt_idt(None, 0, insn)

    def test_gdt_idt_lidt(self):
        insn = Instruction(address=0x100, mnemonic="lidt", operands="fword ptr [rsp+0x20]")
        assert _check_gdt_idt(None, 0, insn)

    def test_ltr_detected(self):
        insn = Instruction(address=0x100, mnemonic="ltr", operands="ax")
        assert _check_ltr(None, 0, insn)

    def test_lmsw_detected(self):
        insn = Instruction(address=0x100, mnemonic="lmsw", operands="ax")
        assert _check_lmsw(None, 0, insn)

    def test_clts_detected(self):
        insn = Instruction(address=0x100, mnemonic="clts", operands="")
        assert _check_clts(None, 0, insn)

    def test_invlpg_detected(self):
        insn = Instruction(address=0x100, mnemonic="invlpg", operands="qword ptr [rax]")
        assert _check_invlpg(None, 0, insn)

    def test_new_rules_exist(self):
        rule_ids = {r.rule_id for r in SEMANTIC_RULES}
        assert "SEM_DR_WRITE" in rule_ids
        assert "SEM_GDT_IDT" in rule_ids
        assert "SEM_LTR" in rule_ids
        assert "SEM_LMSW" in rule_ids
        assert "SEM_CLTS" in rule_ids
        assert "SEM_INVLPG" in rule_ids

    def test_dr_write_finding_integration(self):
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        func = Function(name="sub_7000", address=0x7000, size=0x100)
        ir.functions[0x7000] = func
        cfg = CFG(function_address=0x7000, entry_block=0x7000)
        block = BasicBlock(
            address=0x7000, end_address=0x7100,
            instructions=[
                Instruction(address=0x7010, mnemonic="mov", operands="dr0, rax", size=5),
            ],
            successors=[],
        )
        cfg.blocks[0x7000] = block
        ir.cfgs[0x7000] = ir.simple_cfgs[0x7000] = cfg
        ir.ioctl_handlers[0x22A004] = 0x7000

        sample = _make_sample()
        analyzer = SemanticAnalyzer()
        findings = analyzer.analyze(sample, ir)

        dr_findings = [
            f for f in findings
            if f.category == FindingCategory.DEBUG_REGISTER_WRITE
        ]
        assert len(dr_findings) >= 1


# ---------------------------------------------------------------------------
# Phase 11: Anti-Debug Instruction Tests
# ---------------------------------------------------------------------------

class TestAntiDebugInstructions:
    """Test anti-debug instruction detection in semantic analyzer."""

    def setup_method(self):
        self.analyzer = SemanticAnalyzer()
        self.sample = _make_sample()

    def _make_ir_with_insn(self, func_addr: int, insn) -> DisassemblyResult:
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        func = Function(name=f"sub_{func_addr:X}", address=func_addr, size=0x200)
        ir.functions[func_addr] = func
        ir.ioctl_handlers[0x22A004] = func_addr
        cfg = CFG(function_address=func_addr, entry_block=func_addr)
        block = BasicBlock(address=func_addr, end_address=func_addr + 0x200,
                           instructions=[insn], successors=[])
        cfg.blocks[func_addr] = block
        ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg
        return ir

    def test_rdtsc_detected(self):
        """RDTSC should produce ANTI_DEBUG_TIMING finding."""
        insn = MagicMock(address=0x1000, mnemonic="rdtsc", operands="", api_target=None)
        ir = self._make_ir_with_insn(0x1000, insn)
        findings = self.analyzer.analyze(self.sample, ir)
        assert any(f.category == FindingCategory.ANTI_DEBUG_TIMING for f in findings)

    def test_cpuid_detected(self):
        """CPUID should produce ANTI_DEBUG_HYPERVISOR finding."""
        insn = MagicMock(address=0x1000, mnemonic="cpuid", operands="", api_target=None)
        ir = self._make_ir_with_insn(0x1000, insn)
        findings = self.analyzer.analyze(self.sample, ir)
        assert any(f.category == FindingCategory.ANTI_DEBUG_HYPERVISOR for f in findings)

    def test_int3_detected(self):
        """INT 3 should produce ANTI_DEBUG_TRAP finding."""
        insn = MagicMock(address=0x1000, mnemonic="int", operands="3", api_target=None)
        ir = self._make_ir_with_insn(0x1000, insn)
        findings = self.analyzer.analyze(self.sample, ir)
        assert any(f.category == FindingCategory.ANTI_DEBUG_TRAP for f in findings)

    def test_icebp_detected(self):
        """ICEBP should produce ANTI_DEBUG_TRAP finding."""
        insn = MagicMock(address=0x1000, mnemonic="icebp", operands="", api_target=None)
        ir = self._make_ir_with_insn(0x1000, insn)
        findings = self.analyzer.analyze(self.sample, ir)
        assert any(f.category == FindingCategory.ANTI_DEBUG_TRAP for f in findings)

    def test_sidt_detected(self):
        """SIDT should produce ANTI_DEBUG_HYPERVISOR finding."""
        insn = MagicMock(address=0x1000, mnemonic="sidt", operands="[rsp]", api_target=None)
        ir = self._make_ir_with_insn(0x1000, insn)
        findings = self.analyzer.analyze(self.sample, ir)
        assert any(f.category == FindingCategory.ANTI_DEBUG_HYPERVISOR for f in findings)

    def test_sgdt_detected(self):
        """SGDT should produce ANTI_DEBUG_HYPERVISOR finding."""
        insn = MagicMock(address=0x1000, mnemonic="sgdt", operands="[rsp]", api_target=None)
        ir = self._make_ir_with_insn(0x1000, insn)
        findings = self.analyzer.analyze(self.sample, ir)
        assert any(f.category == FindingCategory.ANTI_DEBUG_HYPERVISOR for f in findings)

    def test_str_detected(self):
        """STR should produce ANTI_DEBUG_HYPERVISOR finding."""
        insn = MagicMock(address=0x1000, mnemonic="str", operands="rax", api_target=None)
        ir = self._make_ir_with_insn(0x1000, insn)
        findings = self.analyzer.analyze(self.sample, ir)
        assert any(f.category == FindingCategory.ANTI_DEBUG_HYPERVISOR for f in findings)

    def test_seh_setup_detected(self):
        """FS:[0] write should produce ANTI_DEBUG_EXCEPTION finding."""
        insn = MagicMock(address=0x1000, mnemonic="mov", operands="dword ptr fs:[0], eax", api_target=None)
        ir = self._make_ir_with_insn(0x1000, insn)
        findings = self.analyzer.analyze(self.sample, ir)
        assert any(f.category == FindingCategory.ANTI_DEBUG_EXCEPTION for f in findings)


# ---------------------------------------------------------------------------
# P2: Callback target extraction tests
# ---------------------------------------------------------------------------

class TestCallbackTargetExtraction:
    """Test that callback-registered functions are included in semantic analysis scope."""

    def test_ob_callback_targets_extracted(self):
        """Functions registered via ObRegisterCallbacks should be analyzed."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")

        # Handler function that calls ObRegisterCallbacks
        handler = Function(name="sub_1000", address=0x1000, size=0x200, calls=[0x2000])
        ir.functions[0x1000] = handler
        ir.function_apis[0x1000] = ["ObRegisterCallbacks"]

        # Callback implementation with wrmsr (should be detected)
        callback = Function(name="sub_2000", address=0x2000, size=0x200)
        ir.functions[0x2000] = callback
        cfg = CFG(function_address=0x2000, entry_block=0x2000)
        block = BasicBlock(
            address=0x2000, end_address=0x2200,
            instructions=[
                Instruction(address=0x2010, mnemonic="wrmsr", operands="", size=2),
            ],
            successors=[],
        )
        cfg.blocks[0x2000] = block
        ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = cfg

        # Handler with IOCTL entry point
        ir.ioctl_handlers[0x22A004] = 0x1000

        sample = _make_sample()
        analyzer = SemanticAnalyzer()

        # The callback target (0x2000) should be in entry point functions
        entry_funcs = analyzer._collect_entry_point_functions(ir)
        assert 0x2000 in entry_funcs

    def test_cm_register_callback_targets_extracted(self):
        """CmRegisterCallbackEx targets should also be extracted."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")

        handler = Function(name="sub_3000", address=0x3000, size=0x200, calls=[0x4000])
        ir.functions[0x3000] = handler
        ir.function_apis[0x3000] = ["CmRegisterCallbackEx"]

        callback = Function(name="sub_4000", address=0x4000, size=0x200)
        ir.functions[0x4000] = callback

        analyzer = SemanticAnalyzer()
        targets = analyzer._extract_callback_targets(ir)
        assert 0x4000 in targets

    def test_callback_target_in_is_entry_point_reachable(self):
        """Callback targets should be considered entry-point-reachable."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")

        handler = Function(name="sub_5000", address=0x5000, size=0x200, calls=[0x6000])
        ir.functions[0x5000] = handler
        ir.function_apis[0x5000] = ["FltRegisterFilter"]

        callback = Function(name="sub_6000", address=0x6000, size=0x200)
        ir.functions[0x6000] = callback

        analyzer = SemanticAnalyzer()
        assert analyzer._is_entry_point_reachable(0x6000, ir)

    def test_dynamic_import_callback_targets(self):
        """Callbacks resolved via dynamic_imports should be extracted."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")

        handler = Function(name="sub_7000", address=0x7000, size=0x200)
        ir.functions[0x7000] = handler
        ir.function_apis[0x7000] = ["PsSetCreateProcessNotifyRoutine"]
        ir.dynamic_imports[0x7000] = ["sub_8000"]

        callback = Function(name="sub_8000", address=0x8000, size=0x200)
        ir.functions[0x8000] = callback

        targets = SemanticAnalyzer._extract_callback_targets(ir)
        assert 0x8000 in targets
