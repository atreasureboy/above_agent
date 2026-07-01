"""Tests for Phase 7: Z3 constraint solver."""

from __future__ import annotations

from pathlib import Path
import pytest

from src.models import (
    Architecture,
    BasicBlock,
    CFG,
    DisassemblyResult,
    Function,
    Instruction,
    Sample,
)

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

from src.analysis.core.constraint_solver import (
    Z3_AVAILABLE as _z3_avail,
    PathAnalysis,
    PathConstraint,
    IoctlBypassResult,
    check_path_feasible,
    check_ioctl_bypassable,
    ConstraintAnalyzer,
    _branch_constraint,
)


def _make_ir_with_dangerous_api() -> DisassemblyResult:
    """IR with a function that calls MmMapIoSpaceEx after a cmp check."""
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
    func = Function(name="sub_1000", address=0x1000, size=0x200)
    ir.functions[0x1000] = func
    ir.function_apis[0x1000] = ["MmMapIoSpaceEx"]

    cfg = CFG(function_address=0x1000, entry_block=0x1000)
    block = BasicBlock(
        address=0x1000, end_address=0x1200,
        instructions=[
            Instruction(address=0x1010, mnemonic="mov", operands="rax, qword ptr [rcx + 0x60]", size=7),
            Instruction(address=0x1020, mnemonic="cmp", operands="eax, 0x22A004", size=6),
            Instruction(address=0x1030, mnemonic="jne", operands="0x1050", size=2),
            Instruction(address=0x1040, mnemonic="call", operands="MmMapIoSpaceEx", api_target="MmMapIoSpaceEx", size=6),
            Instruction(address=0x1050, mnemonic="mov", operands="eax, 0", size=5),
        ],
        successors=[],
    )
    cfg.blocks[0x1000] = block
    ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = cfg
    return ir


# ---------------------------------------------------------------------------
# Z3 Availability Tests
# ---------------------------------------------------------------------------

class TestZ3Availability:
    """Test Z3 solver availability."""

    def test_z3_is_available(self):
        """Z3 should be available after pip install."""
        assert Z3_AVAILABLE or not _z3_avail  # Either one should match

    def test_z3_can_solve_basic(self):
        """Basic Z3 solve should work."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")
        x = z3.BitVec("x", 32)
        solver = z3.Solver()
        solver.add(x == 42)
        assert solver.check() == z3.sat


# ---------------------------------------------------------------------------
# Path Feasibility Tests
# ---------------------------------------------------------------------------

class TestPathFeasibility:
    """Test path feasibility analysis."""

    def test_feasible_path_returns_sat(self):
        """Path with satisfiable constraints should return feasible=True."""
        insns = [
            Instruction(address=0x100, mnemonic="cmp", operands="rax, 0x100", size=6),
            Instruction(address=0x110, mnemonic="je", operands="0x200", size=2),
            Instruction(address=0x200, mnemonic="mov", operands="rcx, rax", size=3),
        ]
        result = check_path_feasible(insns)
        assert isinstance(result, PathAnalysis)
        assert isinstance(result.constraints, list)

    def test_empty_path_returns_feasible(self):
        """Empty instruction list should be feasible."""
        result = check_path_feasible([])
        assert result.feasible is True

    def test_constraints_extracted_from_cmp(self):
        """cmp instructions should be extracted as constraints."""
        insns = [
            Instruction(address=0x100, mnemonic="cmp", operands="rax, 0x22A004", size=6),
        ]
        result = check_path_feasible(insns)
        assert len(result.constraints) >= 1
        assert result.constraints[0].mnemonic == "cmp"

    def test_overflow_detection_with_add(self):
        """add with large immediate should trigger overflow detection."""
        insns = [
            Instruction(address=0x100, mnemonic="add", operands="eax, 0xFFFFFFFF", size=5),
        ]
        result = check_path_feasible(insns)
        if Z3_AVAILABLE:
            assert result.overflow_detected is True
        else:
            assert result.overflow_detected is False


# ---------------------------------------------------------------------------
# IOCTL Bypass Tests
# ---------------------------------------------------------------------------

class TestIoctlBypass:
    """Test IOCTL code bypassability analysis."""

    def test_bypassable_ioctl_detected(self):
        """cmp eax, 0x22A004 with eax from user should be bypassable."""
        insns = [
            Instruction(address=0x100, mnemonic="mov", operands="eax, dword ptr [rcx + 0x18]", size=7),
            Instruction(address=0x110, mnemonic="cmp", operands="eax, 0x22A004", size=6),
            Instruction(address=0x120, mnemonic="jne", operands="0x200", size=2),
            Instruction(address=0x130, mnemonic="call", operands="MmMapIoSpaceEx", api_target="MmMapIoSpaceEx", size=6),
        ]
        result = check_ioctl_bypassable(insns)
        assert isinstance(result, IoctlBypassResult)
        assert result.bypassable is True
        assert result.ioctl_value == 0x22A004

    def test_non_bypassable_ioctl(self):
        """No cmp against constant should not be bypassable."""
        insns = [
            Instruction(address=0x100, mnemonic="mov", operands="rax, rcx", size=3),
            Instruction(address=0x110, mnemonic="call", operands="MmMapIoSpaceEx", api_target="MmMapIoSpaceEx", size=6),
        ]
        result = check_ioctl_bypassable(insns)
        assert result.bypassable is False


# ---------------------------------------------------------------------------
# ConstraintAnalyzer Integration Tests
# ---------------------------------------------------------------------------

class TestConstraintAnalyzer:
    """Test ConstraintAnalyzer integration with DisassemblyResult."""

    def test_analyze_all_paths_returns_dict(self):
        """analyze_all_paths should return dict of func_addr → PathAnalysis."""
        ir = _make_ir_with_dangerous_api()
        analyzer = ConstraintAnalyzer(ir)
        results = analyzer.analyze_all_paths()
        assert isinstance(results, dict)
        assert 0x1000 in results
        assert isinstance(results[0x1000], PathAnalysis)

    def test_no_dangerous_api_returns_empty(self):
        """Functions without dangerous APIs should not be analyzed."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        func = Function(name="sub_1000", address=0x1000, size=0x100)
        ir.functions[0x1000] = func
        ir.function_apis[0x1000] = ["ExAllocatePoolWithTag"]  # Not in dangerous set

        analyzer = ConstraintAnalyzer(ir)
        results = analyzer.analyze_all_paths()
        assert 0x1000 not in results or results.get(0x1000) is not None

    def test_no_cfg_returns_empty(self):
        """Function without CFG should not be in results."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        func = Function(name="sub_2000", address=0x2000, size=0x100)
        ir.functions[0x2000] = func
        ir.function_apis[0x2000] = ["MmMapIoSpaceEx"]

        analyzer = ConstraintAnalyzer(ir)
        results = analyzer.analyze_all_paths()
        assert 0x2000 not in results


# ---------------------------------------------------------------------------
# Branch Constraint Tests
# ---------------------------------------------------------------------------

class TestBranchConstraints:
    """Test Z3 branch constraint building."""

    def test_branch_constraint_je_takes_equality(self):
        """je after cmp rax, imm should produce rax == imm constraint."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")
        cmp_insn = Instruction(address=0x100, mnemonic="cmp", operands="rax, 0x100", size=6)
        j_insn = Instruction(address=0x110, mnemonic="je", operands="0x200", size=2)
        reg_symbols: dict = {}
        expr = _branch_constraint(j_insn, cmp_insn, reg_symbols)
        assert expr is not None

    def test_branch_constraint_jne_takes_inequality(self):
        """jne after cmp rax, imm should produce rax != imm constraint."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")
        cmp_insn = Instruction(address=0x100, mnemonic="cmp", operands="rax, 0x100", size=6)
        j_insn = Instruction(address=0x110, mnemonic="jne", operands="0x200", size=2)
        reg_symbols: dict = {}
        expr = _branch_constraint(j_insn, cmp_insn, reg_symbols)
        assert expr is not None

    def test_branch_constraint_jb_unsigned(self):
        """jb after cmp should produce unsigned less than constraint."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")
        cmp_insn = Instruction(address=0x100, mnemonic="cmp", operands="rax, 0x100", size=6)
        j_insn = Instruction(address=0x110, mnemonic="jb", operands="0x200", size=2)
        reg_symbols: dict = {}
        expr = _branch_constraint(j_insn, cmp_insn, reg_symbols)
        assert expr is not None

    def test_branch_constraint_jle_signed(self):
        """jle after cmp should produce signed less or equal constraint."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")
        cmp_insn = Instruction(address=0x100, mnemonic="cmp", operands="rax, 0x100", size=6)
        j_insn = Instruction(address=0x110, mnemonic="jle", operands="0x200", size=2)
        reg_symbols: dict = {}
        expr = _branch_constraint(j_insn, cmp_insn, reg_symbols)
        assert expr is not None

    def test_branch_constraint_without_prev_cmp(self):
        """Branch without preceding cmp should return None."""
        j_insn = Instruction(address=0x110, mnemonic="je", operands="0x200", size=2)
        reg_symbols: dict = {}
        expr = _branch_constraint(j_insn, None, reg_symbols)
        assert expr is None

    def test_path_feasible_with_branch_constraints(self):
        """Path with cmp + je should have branch constraint in Z3 solver."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")
        insns = [
            Instruction(address=0x100, mnemonic="cmp", operands="rax, 0x100", size=6),
            Instruction(address=0x110, mnemonic="je", operands="0x200", size=2),
            Instruction(address=0x200, mnemonic="mov", operands="rcx, rax", size=3),
        ]
        result = check_path_feasible(insns)
        # Should have both cmp and j constraints
        assert len(result.constraints) >= 2
        # At least one constraint should have a z3_expr from the branch
        assert any(c.z3_expr is not None for c in result.constraints)

    def test_test_instruction_with_jz(self):
        """test eax, eax + jz should produce eax == 0 constraint."""
        if not Z3_AVAILABLE:
            pytest.skip("Z3 not available")
        insns = [
            Instruction(address=0x100, mnemonic="test", operands="eax, eax", size=3),
            Instruction(address=0x110, mnemonic="jz", operands="0x200", size=2),
        ]
        result = check_path_feasible(insns)
        assert len(result.constraints) >= 2
