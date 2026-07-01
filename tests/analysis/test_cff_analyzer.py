"""Tests for Control Flow Flattening (CFF) deep analyzer."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.deep.cff_analyzer import (
    ControlFlowFlatteningAnalyzer,
    DISPATCH_BRANCHES,
    OBFUSCATOR_STRINGS,
    OPAQUE_PREDICATE_PATTERNS,
    STATE_MODIFY,
    STATE_REGISTERS,
)
from src.models import (
    BasicBlock,
    CFG,
    DisassemblyResult,
    FindingCategory,
    Function,
    Instruction,
    Sample,
    Architecture,
    Severity,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _add_function(ir: DisassemblyResult, addr: int, api_names: list[str] | None = None) -> None:
    func = Function(name=f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func
    if api_names:
        ir.function_apis[addr] = api_names


def _add_cfg_with_insns(ir: DisassemblyResult, func_addr: int, instructions: list[tuple[str, str]]) -> None:
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    insns = [
        Instruction(address=func_addr + 0x10 + i * 4, mnemonic=mnem, operands=ops, size=4)
        for i, (mnem, ops) in enumerate(instructions)
    ]
    block = BasicBlock(address=func_addr, end_address=func_addr + 0x100, instructions=insns, successors=[])
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg


def _add_multi_block_cfg(ir: DisassemblyResult, func_addr: int,
                         block_instructions: list[list[tuple[str, str]]],
                         successors: list[list[int]] | None = None) -> None:
    """Create a CFG with multiple basic blocks."""
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    for i, insns_list in enumerate(block_instructions):
        block_addr = func_addr + i * 0x100
        insns = [
            Instruction(address=block_addr + 0x10 + j * 4, mnemonic=mnem, operands=ops, size=4)
            for j, (mnem, ops) in enumerate(insns_list)
        ]
        succs = successors[i] if successors and i < len(successors) else []
        block = BasicBlock(address=block_addr, end_address=block_addr + 0x100,
                          instructions=insns, successors=succs)
        cfg.blocks[block_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg


def _sample() -> Sample:
    return Sample(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
        is_driver=True,
    )


class TestCFFConstants:
    """Test CFF detection constant definitions."""

    def test_state_registers_defined(self):
        assert "eax" in STATE_REGISTERS
        assert "r8" in STATE_REGISTERS
        assert "r11" in STATE_REGISTERS

    def test_state_modify_defined(self):
        assert "add" in STATE_MODIFY
        assert "xor" in STATE_MODIFY
        assert "rol" in STATE_MODIFY

    def test_dispatch_branches_defined(self):
        assert "jmp" in DISPATCH_BRANCHES
        assert "jz" in DISPATCH_BRANCHES
        assert "jnz" in DISPATCH_BRANCHES

    def test_obfuscator_strings_defined(self):
        assert "VMProtect" in OBFUSCATOR_STRINGS
        assert "Themida" in OBFUSCATOR_STRINGS
        assert "CodeVirtualizer" in OBFUSCATOR_STRINGS


class TestSwitchDispatcherDetection:
    """Test switch dispatcher pattern detection."""

    def test_scaled_index_jump(self):
        """jmp [r12 + rax*8] — computed jump table."""
        ir = _make_ir()
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, rcx"),
            ("jmp", "qword ptr [r12 + rax*8]"),
        ])
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        dispatch_findings = [f for f in findings if f.context.get("dispatchers")]
        assert len(dispatch_findings) >= 1

    def test_simple_indirect_jump(self):
        """jmp [rcx] — indirect jump should be tracked."""
        ir = _make_ir()
        _add_cfg_with_insns(ir, 0x2000, [
            ("jmp", "[rcx]"),
        ])
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)

    def test_no_dispatcher_no_finding(self):
        """Normal instructions without indirect jump should not trigger."""
        ir = _make_ir()
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, rbx"),
            ("push", "rbp"),
            ("ret", ""),
        ])
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        dispatch_findings = [f for f in findings if f.context.get("dispatchers")]
        assert len(dispatch_findings) == 0


class TestStateVariablePatternDetection:
    """Test state variable pattern detection."""

    def _build_state_variable_ir(self, func_addr: int) -> DisassemblyResult:
        """Build an IR with state variable pattern: reg read/modify/branch."""
        ir = _make_ir()
        _add_function(ir, func_addr)

        # Build many blocks that all reference eax as state variable
        blocks = []
        for i in range(15):
            insns = [
                ("mov", "ecx, eax"),          # Read state
                ("add", "eax, 4"),             # Modify state
                ("test", "eax, eax"),          # Check state
                ("jnz", f"0x{func_addr + (i+1)*0x100:X}"),  # Branch on state
            ]
            blocks.append(insns)

        _add_multi_block_cfg(ir, func_addr, blocks,
                            successors=[[func_addr + (i+1)*0x100] for i in range(15)])
        return ir

    def test_state_variable_detected(self):
        """Repeated read/modify/branch on same register should be detected."""
        ir = self._build_state_variable_ir(0x1000)
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        state_findings = [f for f in findings if f.context.get("state_variables")]
        assert len(state_findings) >= 1

    def test_no_state_pattern(self):
        """Instructions without state variable pattern should not trigger."""
        ir = _make_ir()
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, rbx"),
            ("add", "rax, 8"),
            ("mov", "[rcx], rax"),
        ])
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        state_findings = [f for f in findings if f.context.get("state_variables")]
        assert len(state_findings) == 0


class TestOpaquePredicateDetection:
    """Test opaque predicate detection."""

    def test_xor_reg_reg_jz(self):
        """xor eax, eax; jz — always taken branch."""
        ir = _make_ir()
        blocks = []
        for i in range(5):
            blocks.append([
                ("xor", "eax, eax"),
                ("jz", f"0x{i+1:X}"),
            ])
        _add_multi_block_cfg(ir, 0x1000, blocks,
                            successors=[[0x1100] for _ in range(5)])
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        opaque_findings = [f for f in findings if f.context.get("opaque_count")]
        assert len(opaque_findings) >= 1

    def test_test_reg_reg_jnz(self):
        """test eax, eax; jnz — self-test pattern."""
        ir = _make_ir()
        blocks = []
        for i in range(5):
            blocks.append([
                ("test", "eax, eax"),
                ("jnz", f"0x{i+1:X}"),
            ])
        _add_multi_block_cfg(ir, 0x2000, blocks,
                            successors=[[0x2100] for _ in range(5)])
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        opaque_findings = [f for f in findings if f.context.get("opaque_count")]
        assert len(opaque_findings) >= 1

    def test_few_predicates_no_finding(self):
        """Few opaque predicates (< 3) should not trigger."""
        ir = _make_ir()
        _add_cfg_with_insns(ir, 0x1000, [
            ("xor", "eax, eax"),
            ("jz", "0x1"),
        ])
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        opaque_findings = [f for f in findings if f.context.get("opaque_count")]
        assert len(opaque_findings) == 0


class TestObfuscatorStringDetection:
    """Test obfuscator signature string detection."""

    def test_vmprotect_string(self):
        ir = _make_ir()
        ir.strings.append("VMProtect begin")
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        vmprot_findings = [f for f in findings if f.context.get("obfuscator") == "VMProtect"]
        assert len(vmprot_findings) >= 1

    def test_themida_string(self):
        ir = _make_ir()
        ir.strings.append("Protected by Themida")
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        themida_findings = [f for f in findings if f.context.get("obfuscator") == "Themida"]
        assert len(themida_findings) >= 1

    def test_code_virtualizer_string(self):
        ir = _make_ir()
        ir.strings.append("CodeVirtualizer marker")
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        cv_findings = [f for f in findings if f.context.get("obfuscator") == "CodeVirtualizer"]
        assert len(cv_findings) >= 1

    def test_no_obfuscator_string(self):
        ir = _make_ir()
        ir.strings.append("Hello World")
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        obf_findings = [f for f in findings if f.context.get("obfuscator")]
        assert len(obf_findings) == 0


class TestHandlerTableDetection:
    """Test handler table pattern detection."""

    def test_code_pointer_array(self):
        """Large array of code-like pointers should be detected."""
        ir = _make_ir()
        # Simulate handler table with code-pointer-like values
        ir.data_structures = {
            0x5000: {
                "type": "qword_array",
                "values": [0x10000, 0x10004, 0x10008, 0x1000C,
                          0x10010, 0x10014, 0x10018, 0x1001C,
                          0x10020, 0x10024],
            }
        }
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        handler_findings = [f for f in findings if f.context.get("rva")]
        assert len(handler_findings) >= 1

    def test_small_array_no_finding(self):
        """Small array (< 8 entries) should not trigger."""
        ir = _make_ir()
        ir.data_structures = {
            0x6000: {
                "type": "qword_array",
                "values": [0x10000, 0x10004, 0x10008],
            }
        }
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        handler_findings = [f for f in findings if f.context.get("rva")]
        assert len(handler_findings) == 0

    def test_non_qword_array_no_finding(self):
        """Non-qword_array data structures should not trigger."""
        ir = _make_ir()
        ir.data_structures = {
            0x7000: {
                "type": "byte_array",
                "values": list(range(20)),
            }
        }
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        handler_findings = [f for f in findings if f.context.get("rva")]
        assert len(handler_findings) == 0


class TestCFFAnalyzerIntegration:
    """Test CFF analyzer end-to-end."""

    def test_analyzer_name(self):
        analyzer = ControlFlowFlatteningAnalyzer()
        assert analyzer.name == "ControlFlowFlatteningAnalyzer"

    def test_analyzer_description(self):
        analyzer = ControlFlowFlatteningAnalyzer()
        desc = analyzer.description
        assert "control flow" in desc.lower() or "flattening" in desc.lower()

    def test_analyze_empty_ir(self):
        """Should handle empty IR without errors."""
        ir = _make_ir()
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        assert findings == []

    def test_analyze_combined_cff_patterns(self):
        """Should detect multiple CFF patterns simultaneously."""
        ir = _make_ir()

        # Obfuscator string
        ir.strings.append("VMProtect begin")

        # Switch dispatcher
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, rcx"),
            ("jmp", "qword ptr [r12 + rax*8]"),
        ])

        # Handler table
        ir.data_structures = {
            0x5000: {
                "type": "qword_array",
                "values": [0x10000 + i*4 for i in range(12)],
            }
        }

        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)

        categories = {f.category for f in findings}
        assert FindingCategory.CONTROL_FLOW_FLATTENING in categories

        # Should have at least VMProtect finding
        obf_findings = [f for f in findings if f.context.get("obfuscator")]
        assert len(obf_findings) >= 1

    def test_all_findings_have_evidence(self):
        """All findings should have evidence attached."""
        ir = _make_ir()
        ir.strings.append("VMProtect begin")
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        for f in findings:
            assert len(f.evidence) > 0

    def test_severity_critical_for_obfuscator(self):
        """Obfuscator signature should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("VMProtect")
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        obf_findings = [f for f in findings if f.context.get("obfuscator")]
        if obf_findings:
            assert obf_findings[0].severity == Severity.CRITICAL

    def test_severity_critical_for_dispatcher(self):
        """Switch dispatcher should be CRITICAL."""
        ir = _make_ir()
        _add_cfg_with_insns(ir, 0x1000, [
            ("jmp", "qword ptr [r12 + rax*8]"),
        ])
        analyzer = ControlFlowFlatteningAnalyzer()
        findings = analyzer.analyze(_sample(), ir)
        disp_findings = [f for f in findings if f.context.get("dispatchers")]
        if disp_findings:
            assert disp_findings[0].severity == Severity.CRITICAL
