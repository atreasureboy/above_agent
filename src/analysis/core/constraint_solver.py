"""
DriverScope — Constraint Solver.

Uses Z3 SMT solver to validate or refute CFG path feasibility.
Unlike full symbolic execution (which is impractical for kernel drivers),
this does **local** constraint solving on individual function paths:

1. **Path feasibility**: Given entry → sink path, is there any input
   that satisfies all branch conditions?
2. **IOCTL code bypassability**: If a driver checks IoControlCode with
   a simple comparison, can any user-provided IOCTL value trigger the
   dangerous path?
3. **Integer overflow detection**: Use Z3 BitVec to detect arithmetic
   that can overflow/underflow in size calculations.

Z3 is an optional dependency. If not installed, all functions degrade
to conservative (SAT) marking.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from src.models import (
    Confidence,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Instruction,
    Sample,
    Severity,
)

try:
    import z3
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constraint extraction from instructions
# ---------------------------------------------------------------------------

@dataclass
class PathConstraint:
    """A single constraint extracted from a branch instruction."""
    instruction_addr: int
    mnemonic: str
    operands: str
    # Z3 representation (built lazily)
    z3_expr: object | None = None


@dataclass
class PathAnalysis:
    """Result of analyzing a CFG path."""
    feasible: bool = True  # True if SAT, False if UNSAT
    constraints: list[PathConstraint] = field(default_factory=list)
    counter_example: str = ""  # Why infeasible (if UNSAT)
    overflow_detected: bool = False
    overflow_details: list[str] = field(default_factory=list)


def _parse_immediate(operand: str) -> int | None:
    """Extract an immediate value from an operand string."""
    operand = operand.strip()
    if operand.startswith("0x") or operand.startswith("0X"):
        try:
            return int(operand, 16)
        except ValueError:
            return None
    try:
        return int(operand)
    except ValueError:
        return None


def _constraint_from_cmp(insn: Instruction) -> z3.BoolRef | None:
    """Build a Z3 constraint from a cmp/test instruction.

    cmp rax, 0x22A004 → rax == 0x22A004
    test rax, rax → rax == 0 (for jz/jne after test)
    """
    if not Z3_AVAILABLE:
        return None

    operands = insn.operands.lower()
    parts = [p.strip() for p in operands.split(",")]
    if len(parts) != 2:
        return None

    left, right = parts
    # Clean up operands: strip ptr, size qualifiers
    left = re.sub(r'(?:byte|word|dword|qword)\s*ptr\s*', '', left).strip()
    right = re.sub(r'(?:byte|word|dword|qword)\s*ptr\s*', '', right).strip()

    if left == right:
        # cmp rax, rax → always equal, skip
        return None

    left_sym = z3.BitVec(_reg_name(left), 64) if re.match(r'^r[a-z0-9]+$', left) else None
    right_sym = z3.BitVec(_reg_name(right), 64) if re.match(r'^r[a-z0-9]+$', right) else None
    right_imm = _parse_immediate(right)

    if left_sym is not None:
        if right_sym is not None:
            return left_sym == right_sym
        if right_imm is not None:
            return left_sym == z3.BitVecVal(right_imm, 64)

    return None


def _build_comparison(left_name: str, right_name: str, right_imm: int | None,
                      op: str, reg_symbols: dict[str, z3.BitVecRef],
                      bit_width: int = 64) -> z3.BoolRef | None:
    """Build a Z3 comparison expression from operand names."""
    def _get_sym(name: str) -> z3.BitVecRef | z3.BitVecNumRef | None:
        name = name.strip().lower()
        if re.match(r'^r[a-z0-9]+$', name):
            if name not in reg_symbols:
                reg_symbols[name] = z3.BitVec(name, bit_width)
            return reg_symbols[name]
        imm = _parse_immediate(name)
        if imm is not None:
            return z3.BitVecVal(imm, bit_width)
        return None

    left_sym = _get_sym(left_name)
    right_val = _get_sym(right_name) if right_imm is None else z3.BitVecVal(right_imm, bit_width)

    if left_sym is None or right_val is None:
        return None

    # Signed comparisons use Python operators (z3 BitVec < is signed)
    # Unsigned comparisons use z3.ULT/ULE/UGT/UGE
    if op == "eq":
        return left_sym == right_val
    if op == "ne":
        return left_sym != right_val
    if op == "slt":
        return left_sym < right_val
    if op == "sle":
        return left_sym <= right_val
    if op == "sgt":
        return left_sym > right_val
    if op == "sge":
        return left_sym >= right_val
    if op == "ult":
        return z3.ULT(left_sym, right_val)
    if op == "ule":
        return z3.ULE(left_sym, right_val)
    if op == "ugt":
        return z3.UGT(left_sym, right_val)
    if op == "uge":
        return z3.UGE(left_sym, right_val)

    return None


def _branch_constraint(insn: Instruction, prev_cmp: Instruction | None,
                       reg_symbols: dict[str, z3.BitVecRef]) -> z3.BoolRef | None:
    """Build a Z3 constraint from a conditional jump.

    je/jz → condition is True (prev cmp was equal)
    jne/jnz → condition is False (prev cmp was not equal)
    jb → unsigned less than
    jle → signed less than or equal
    etc.

    Requires the preceding cmp/test instruction to know which register
    and value were compared.
    """
    if not Z3_AVAILABLE or prev_cmp is None:
        return None

    mnemonic = insn.mnemonic.lower()
    cmp_mnemonic = prev_cmp.mnemonic.lower()
    cmp_ops = prev_cmp.operands.lower()
    parts = [p.strip() for p in cmp_ops.split(",")]
    if len(parts) != 2:
        return None

    left, right = parts
    left = re.sub(r'(?:byte|word|dword|qword)\s*ptr\s*', '', left).strip()
    right = re.sub(r'(?:byte|word|dword|qword)\s*ptr\s*', '', right).strip()

    # test eax, eax → zero flag set means eax == 0
    if cmp_mnemonic == "test":
        left_sym_name = _reg_name(left)
        if left_sym_name not in reg_symbols:
            reg_symbols[left_sym_name] = z3.BitVec(left_sym_name, 64)
        zero_expr = reg_symbols[left_sym_name] == 0
        if mnemonic in ("je", "jz"):
            return zero_expr
        if mnemonic in ("jne", "jnz"):
            return z3.Not(zero_expr)
        return None

    # cmp left, right
    right_imm = _parse_immediate(right)
    right_is_reg = re.match(r'^r[a-z0-9]+$', right) is not None

    if mnemonic in ("je", "jz"):
        return _build_comparison(left, right, right_imm, "eq", reg_symbols)
    if mnemonic in ("jne", "jnz"):
        return _build_comparison(left, right, right_imm, "ne", reg_symbols)
    # Signed comparisons
    if mnemonic == "jle":
        return _build_comparison(left, right, right_imm, "sle", reg_symbols)
    if mnemonic == "jge":
        return _build_comparison(left, right, right_imm, "sge", reg_symbols)
    if mnemonic in ("jl", "jnge"):
        return _build_comparison(left, right, right_imm, "slt", reg_symbols)
    if mnemonic in ("jg", "jnle"):
        return _build_comparison(left, right, right_imm, "sgt", reg_symbols)
    # Unsigned comparisons
    if mnemonic in ("jb", "jnae", "jc"):
        return _build_comparison(left, right, right_imm, "ult", reg_symbols)
    if mnemonic in ("ja", "jnbe"):
        return _build_comparison(left, right, right_imm, "ugt", reg_symbols)
    if mnemonic in ("jae", "jnb", "jnc"):
        return _build_comparison(left, right, right_imm, "uge", reg_symbols)
    if mnemonic in ("jbe", "jna"):
        return _build_comparison(left, right, right_imm, "ule", reg_symbols)

    return None


def _reg_name(operand: str) -> str:
    """Normalize a register name to a valid Z3 identifier."""
    operand = operand.strip().lower()
    operand = re.sub(r'[\[\]ptr\s]', '', operand)
    if not operand.isidentifier():
        return "reg_" + operand.replace("0x", "h")
    return operand


# ---------------------------------------------------------------------------
# Path feasibility analysis
# ---------------------------------------------------------------------------

def check_path_feasible(
    path_insns: list[Instruction],
) -> PathAnalysis:
    """Use Z3 to check if a CFG path is feasible.

    Given a list of instructions on a path from entry to sink,
    extract all cmp/test/jcc constraints and check satisfiability.

    Returns PathAnalysis with feasibility result and overflow info.
    """
    analysis = PathAnalysis()

    if not Z3_AVAILABLE:
        analysis.constraints = [
            PathConstraint(instruction_addr=insn.address, mnemonic=insn.mnemonic, operands=insn.operands)
            for insn in path_insns
            if insn.mnemonic in ("cmp", "test")
        ]
        analysis.feasible = True  # Conservative: assume feasible without Z3
        analysis.counter_example = "Z3 not available, assuming feasible"
        return analysis

    solver = z3.Solver()
    reg_symbols: dict[str, z3.BitVecRef] = {}
    last_cmp_insn: Instruction | None = None

    def _get_reg_sym(name: str) -> z3.BitVecRef:
        name = _reg_name(name)
        if name not in reg_symbols:
            reg_symbols[name] = z3.BitVec(name, 64)
        return reg_symbols[name]

    for insn in path_insns:
        mnemonic = insn.mnemonic.lower()
        constraint = PathConstraint(
            instruction_addr=insn.address,
            mnemonic=insn.mnemonic,
            operands=insn.operands,
        )

        if mnemonic in ("cmp", "test"):
            expr = _constraint_from_cmp(insn)
            if expr is not None:
                constraint.z3_expr = expr
                solver.add(expr)
            analysis.constraints.append(constraint)
            last_cmp_insn = insn

        elif mnemonic.startswith("j") and len(insn.operands) > 0:
            # Conditional branch — the path taking this branch implies
            # the branch condition must be satisfied
            expr = _branch_constraint(insn, last_cmp_insn, reg_symbols)
            if expr is not None:
                constraint.z3_expr = expr
                solver.add(expr)
            analysis.constraints.append(constraint)

    result = solver.check()
    analysis.feasible = result == z3.sat

    if result == z3.unsat:
        analysis.counter_example = "Path is UNSAT — no input satisfies all branch constraints"

    # Check for integer overflows in arithmetic instructions
    _check_arithmetic_overflows(path_insns, analysis)

    return analysis


def _check_arithmetic_overflows(
    path_insns: list[Instruction],
    analysis: PathAnalysis,
) -> None:
    """Use Z3 BitVec to detect integer overflow in arithmetic operations."""
    if not Z3_AVAILABLE:
        return

    for insn in path_insns:
        mnemonic = insn.mnemonic.lower()
        if mnemonic not in ("add", "sub", "mul", "imul", "inc", "dec", "shl", "shr"):
            continue

        operands = insn.operands.lower()
        parts = [p.strip() for p in operands.split(",")]

        if mnemonic in ("add", "sub") and len(parts) == 2:
            left = parts[0]
            right = parts[1]
            right_imm = _parse_immediate(right)

            if right_imm is not None:
                reg_sym = z3.BitVec(_reg_name(left), 32)  # Check 32-bit overflow
                result_expr = reg_sym + right_imm if mnemonic == "add" else reg_sym - right_imm

                # Check if overflow is possible
                solver = z3.Solver()
                overflow = z3.UGE(result_expr, 0x100000000) if mnemonic == "add" else z3.ULT(result_expr, 0)
                solver.add(overflow)

                if solver.check() == z3.sat:
                    analysis.overflow_detected = True
                    analysis.overflow_details.append(
                        f"0x{insn.address:X}: {insn.mnemonic} {insn.operands} "
                        f"can overflow 32-bit boundary"
                    )


# ---------------------------------------------------------------------------
# IOCTL code bypassability
# ---------------------------------------------------------------------------

@dataclass
class IoctlBypassResult:
    """Result of IOCTL code bypassability analysis."""
    bypassable: bool = False
    ioctl_value: int = 0  # The value that bypasses the check
    check_instruction: Instruction | None = None
    details: str = ""


def check_ioctl_bypassable(
    path_insns: list[Instruction],
) -> IoctlBypassResult:
    """Check if an IOCTL code check can be bypassed.

    Looks for patterns like:
      cmp eax, 0x22A004
      jne skip_dangerous_path

    If the check exists but the compared value is user-controlled,
    the IOCTL is bypassable.
    """
    result = IoctlBypassResult()

    for insn in path_insns:
        if insn.mnemonic.lower() == "cmp":
            operands = insn.operands.lower()
            # Check if comparing against a constant IOCTL code
            parts = [p.strip() for p in operands.split(",")]
            if len(parts) == 2:
                right = parts[1].strip()
                imm = _parse_immediate(right)
                if imm is not None:
                    left = parts[0].strip()
                    # If the left side comes from IRP (IoControlCode), it's bypassable
                    if any(reg in left.lower() for reg in ("eax", "ax", "rcx", "ecx", "edx")):
                        result.bypassable = True
                        result.ioctl_value = imm
                        result.check_instruction = insn
                        result.details = (
                            f"IOCTL code 0x{imm:X} is compared against "
                            f"{left} — user can provide any IOCTL code value"
                        )
                        break

    return result


# ---------------------------------------------------------------------------
# Analyzer wrapper
# ---------------------------------------------------------------------------

class ConstraintAnalyzer:
    """Run constraint analysis on all entry-point functions.

    Not registered as an Analyzer (no findings produced directly),
    but provides utility methods for other analyzers to use.
    """

    def __init__(self, ir: DisassemblyResult):
        self.ir = ir

    def analyze_all_paths(self) -> dict[int, PathAnalysis]:
        """Check path feasibility for all functions with dangerous APIs."""
        results: dict[int, PathAnalysis] = {}

        dangerous_apis = {
            "MmMapIoSpace", "MmMapIoSpaceEx", "KeWriteMsr", "__writemsr",
            "MmCopyVirtualMemory", "ZwWriteVirtualMemory",
        }

        for func_addr, api_names in self.ir.function_apis.items():
            func = self.ir.functions.get(func_addr)
            if func is None:
                continue

            apis_hit = set(api_names) & dangerous_apis
            if not apis_hit:
                continue

            # Get instructions for this function
            cfg = self.ir.cfgs.get(func_addr) or self.ir.simple_cfgs.get(func_addr)
            if not cfg:
                continue

            all_insns = []
            for block in sorted(cfg.blocks.values(), key=lambda b: b.address):
                all_insns.extend(block.instructions)

            if all_insns:
                results[func_addr] = check_path_feasible(all_insns)

        return results
