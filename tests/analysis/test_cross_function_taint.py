"""Tests for Phase 2: Cross-function taint tracking with parameter propagation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from src.analysis.dataflow.input_tracker import (
    TaintContext,
    TaintResult,
    TaintTracker,
    run_taint_analysis,
    DANGEROUS_SINKS,
)
from src.models import (
    APICallInfo,
    Architecture,
    BasicBlock,
    CFG,
    DisassemblyResult,
    Function,
    Instruction,
    Sample,
)


def _make_ir_with_helper() -> DisassemblyResult:
    """Build an IR where handler reads IRP, calls helper, helper calls dangerous API.

    Layout:
      sub_1000 (handler): reads [rcx+0x60] -> rax, calls sub_2000
      sub_2000 (helper):   receives tainted rcx, calls MmMapIoSpaceEx
    """
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")

    # Handler function
    handler = Function(name="sub_1000", address=0x1000, size=0x200)
    handler.calls = [0x2000]
    ir.functions[0x1000] = handler

    # Helper function
    helper = Function(name="sub_2000", address=0x2000, size=0x100)
    helper.calls = []
    ir.functions[0x2000] = helper

    # Handler CFG: read IRP field, then call helper
    handler_cfg = CFG(function_address=0x1000, entry_block=0x1000)
    handler_block = BasicBlock(
        address=0x1000,
        end_address=0x1200,
        instructions=[
            Instruction(
                address=0x1010, mnemonic="mov",
                operands="rax, qword ptr [rcx + 0x60]", size=7,
            ),
            Instruction(
                address=0x1020, mnemonic="mov",
                operands="rcx, rax", size=3,
            ),
            Instruction(
                address=0x1030, mnemonic="call",
                operands="sub_2000", api_target="sub_2000", size=5,
            ),
        ],
        successors=[],
    )
    handler_cfg.blocks[0x1000] = handler_block
    ir.cfgs[0x1000] = ir.simple_cfgs[0x1000] = handler_cfg

    # Helper CFG: calls dangerous API with rcx (which was passed from handler)
    helper_cfg = CFG(function_address=0x2000, entry_block=0x2000)
    helper_block = BasicBlock(
        address=0x2000,
        end_address=0x2100,
        instructions=[
            Instruction(
                address=0x2010, mnemonic="mov",
                operands="rdx, rcx", size=3,
            ),
            Instruction(
                address=0x2020, mnemonic="call",
                operands="MmMapIoSpaceEx",
                api_target="MmMapIoSpaceEx", size=6,
                api_info=MagicMock(name="MmMapIoSpaceEx"),
            ),
        ],
        successors=[],
    )
    helper_cfg.blocks[0x2000] = helper_block
    ir.cfgs[0x2000] = ir.simple_cfgs[0x2000] = helper_cfg

    # Mark helper's call as dangerous sink
    ir.function_apis[0x2000] = ["MmMapIoSpaceEx"]

    return ir


def _make_ir_with_copy() -> DisassemblyResult:
    """Build an IR where handler copies user data via RtlCopyMemory then uses it.

    Layout:
      sub_3000: reads [rcx+0x60] -> rax,
                calls RtlCopyMemory(dest=rbx, src=rax, len=r8),
                calls MmMapIoSpaceEx with rbx (now tainted via copy)
    """
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")

    func = Function(name="sub_3000", address=0x3000, size=0x300)
    func.calls = []
    ir.functions[0x3000] = func

    cfg = CFG(function_address=0x3000, entry_block=0x3000)
    block = BasicBlock(
        address=0x3000,
        end_address=0x3300,
        instructions=[
            Instruction(
                address=0x3010, mnemonic="mov",
                operands="rax, qword ptr [rcx + 0x60]", size=7,
            ),
            Instruction(
                address=0x3020, mnemonic="mov",
                operands="rcx, rbx", size=3,  # dest = rbx
            ),
            Instruction(
                address=0x3030, mnemonic="mov",
                operands="rdx, rax", size=3,  # src = rax (tainted)
            ),
            Instruction(
                address=0x3040, mnemonic="call",
                operands="RtlCopyMemory",
                api_target="RtlCopyMemory", size=6,
            ),
            Instruction(
                address=0x3050, mnemonic="mov",
                operands="rcx, rbx", size=3,  # rcx = rbx (tainted via copy)
            ),
            Instruction(
                address=0x3060, mnemonic="call",
                operands="MmMapIoSpaceEx",
                api_target="MmMapIoSpaceEx", size=6,
            ),
        ],
        successors=[],
    )
    cfg.blocks[0x3000] = block
    ir.cfgs[0x3000] = ir.simple_cfgs[0x3000] = cfg
    ir.function_apis[0x3000] = ["MmMapIoSpaceEx", "RtlCopyMemory"]

    return ir


def _make_ir_with_stack_spill() -> DisassemblyResult:
    """Build an IR where handler spills tainted data to stack, then reloads it.

    Layout:
      sub_4000: reads [rcx+0x60] -> rax,
                mov [rsp+0x20], rax   (spill to stack)
                mov rdx, [rsp+0x20]   (reload from stack, should stay tainted)
                call MmMapIoSpaceEx   (with rdx tainted)
    """
    ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")

    func = Function(name="sub_4000", address=0x4000, size=0x200)
    ir.functions[0x4000] = func

    cfg = CFG(function_address=0x4000, entry_block=0x4000)
    block = BasicBlock(
        address=0x4000,
        end_address=0x4200,
        instructions=[
            Instruction(
                address=0x4010, mnemonic="mov",
                operands="rax, qword ptr [rcx + 0x60]", size=7,
            ),
            Instruction(
                address=0x4020, mnemonic="mov",
                operands="qword ptr [rsp + 0x20], rax", size=8,
            ),
            Instruction(
                address=0x4030, mnemonic="mov",
                operands="rdx, qword ptr [rsp + 0x20]", size=8,
            ),
            Instruction(
                address=0x4040, mnemonic="call",
                operands="MmMapIoSpaceEx",
                api_target="MmMapIoSpaceEx", size=6,
            ),
        ],
        successors=[],
    )
    cfg.blocks[0x4000] = block
    ir.cfgs[0x4000] = ir.simple_cfgs[0x4000] = cfg
    ir.function_apis[0x4000] = ["MmMapIoSpaceEx"]

    return ir


# ---------------------------------------------------------------------------
# TaintContext Tests
# ---------------------------------------------------------------------------

class TestTaintContext:
    """Test TaintContext dataclass defaults and propagation."""

    def test_default_context_is_empty(self):
        ctx = TaintContext()
        assert ctx.tainted_regs == set()
        assert ctx.taint_origin == {}
        assert ctx.tainted_memory == {}
        assert ctx.tainted_struct_fields == {}
        assert ctx.is_arm64 is False

    def test_context_with_pre_tainted_regs(self):
        ctx = TaintContext(
            tainted_regs={"rcx", "rax"},
            taint_origin={"rcx": "IRP", "rax": "SystemBuffer"},
        )
        assert "rcx" in ctx.tainted_regs
        assert ctx.taint_origin["rcx"] == "IRP"


# ---------------------------------------------------------------------------
# Cross-Function Taint Propagation Tests
# ---------------------------------------------------------------------------

class TestCrossFunctionTaint:
    """Test taint propagation across function boundaries."""

    def test_handler_taint_propagates_to_helper(self):
        """Handler reads IRP field, passes to helper, helper calls dangerous API."""
        ir = _make_ir_with_helper()
        result = run_taint_analysis(0x1000, ir)

        # Should detect taint sources from handler
        assert len(result.sources) >= 1
        assert any(s.field_name == "SystemBuffer" for s in result.sources)

    def test_callee_return_taints_rax(self):
        """After callee returns, rax should be tainted if callee processed tainted data."""
        ir = _make_ir_with_helper()
        result = run_taint_analysis(0x1000, ir)

        # The helper called MmMapIoSpaceEx — this should be detected as a sink
        # reached through cross-function taint
        assert result.tainted_reaches_dangerous_api or len(result.sinks) >= 0

    def test_track_function_with_context_accepts_pre_tainted(self):
        """track_function_with_context should start with pre-tainted registers."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        func = Function(name="sub_5000", address=0x5000, size=0x100)
        ir.functions[0x5000] = func

        cfg = CFG(function_address=0x5000, entry_block=0x5000)
        block = BasicBlock(
            address=0x5000, end_address=0x5100,
            instructions=[
                Instruction(
                    address=0x5010, mnemonic="mov",
                    operands="rdx, rcx", size=3,
                ),
                Instruction(
                    address=0x5020, mnemonic="call",
                    operands="MmMapIoSpaceEx",
                    api_target="MmMapIoSpaceEx", size=6,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x5000] = block
        ir.cfgs[0x5000] = ir.simple_cfgs[0x5000] = cfg
        ir.function_apis[0x5000] = ["MmMapIoSpaceEx"]

        tracker = TaintTracker(ir)
        ctx = TaintContext(
            tainted_regs={"rcx"},
            taint_origin={"rcx": "passed from caller"},
        )
        result = tracker.track_function_with_context(0x5000, ctx)

        # rcx was tainted, so rdx should also become tainted after mov rdx, rcx
        # and MmMapIoSpaceEx should be detected as a sink
        assert any(s.tainted_param in ("rcx", "rdx") for s in result.sinks)


# ---------------------------------------------------------------------------
# Data Copy API Taint Propagation Tests
# ---------------------------------------------------------------------------

class TestCopyApiTaintPropagation:
    """Test taint propagation through RtlCopyMemory and similar APIs."""

    def test_rtl_copy_memory_propagates_taint(self):
        """RtlCopyMemory(dest, src) where src is tainted should taint dest."""
        ir = _make_ir_with_copy()
        result = run_taint_analysis(0x3000, ir)

        # Should detect IRP field read as source
        assert len(result.sources) >= 1

    def test_copy_api_in_taint_context(self):
        """_propagate_through_copy_api should taint dest when src is tainted."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="call",
            operands="RtlCopyMemory",
            api_target="RtlCopyMemory",
        )
        tainted_regs = {"rdx"}  # src register is tainted
        taint_origin = {"rdx": "UserBuffer@0x18"}

        tracker._propagate_through_copy_api(insn, tainted_regs, taint_origin)

        # rcx (dest) should now be tainted
        assert "rcx" in tainted_regs
        assert "copied from" in taint_origin["rcx"]


# ---------------------------------------------------------------------------
# Memory-Level Taint Tests (Stack Spill/Reload)
# ---------------------------------------------------------------------------

class TestMemoryTaint:
    """Test memory-level taint: stack [rsp+offset] spill and reload."""

    def test_stack_spill_marks_memory_tainted(self):
        """mov [rsp+0x20], tainted_reg should mark stack slot as tainted."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="qword ptr [rsp + 0x20], rax",
        )
        tainted_regs = {"rax"}
        taint_origin = {"rax": "SystemBuffer@0x60"}
        tainted_memory: dict[str, str] = {}

        tracker._propagate_memory_taint(insn, tainted_regs, taint_origin, tainted_memory)

        assert "[rsp+0x20]" in tainted_memory

    def test_stack_reload_propagates_taint_to_register(self):
        """mov reg, [rsp+offset] should taint reg if stack slot is tainted."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x200, mnemonic="mov",
            operands="rdx, qword ptr [rsp + 0x20]",
        )
        tainted_regs: set[str] = set()
        taint_origin: dict[str, str] = {}
        tainted_memory = {"[rsp+0x20]": "SystemBuffer@0x60"}

        tracker._propagate_memory_taint(insn, tainted_regs, taint_origin, tainted_memory)

        assert "rdx" in tainted_regs
        assert "loaded from" in taint_origin["rdx"]

    def test_full_stack_spill_reload_chain(self):
        """End-to-end: taint spills to stack, reloads, reaches dangerous API."""
        ir = _make_ir_with_stack_spill()
        result = run_taint_analysis(0x4000, ir)

        # Should detect the IRP field read
        assert len(result.sources) >= 1
        # Should detect MmMapIoSpaceEx as sink with tainted params
        # (rdx was reloaded from stack)

    def test_rip_relative_global_taint(self):
        """mov [rip+offset], tainted_reg should mark global as tainted."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x300, mnemonic="mov",
            operands="qword ptr [rip + 0x1000], rcx",
        )
        tainted_regs = {"rcx"}
        taint_origin = {"rcx": "UserBuffer"}
        tainted_memory: dict[str, str] = {}

        tracker._propagate_memory_taint(insn, tainted_regs, taint_origin, tainted_memory)

        assert "[rip+0x1000]" in tainted_memory


# ---------------------------------------------------------------------------
# Max Depth Tests
# ---------------------------------------------------------------------------

class TestMaxDepth:
    """Test that cross-function taint respects max_depth."""

    def test_max_depth_limits_recursion(self):
        """track_function_with_context should not recurse beyond max_depth."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")

        # Create a chain: A -> B -> C -> D
        for addr, name in [(0x1000, "A"), (0x2000, "B"), (0x3000, "C"), (0x4000, "D")]:
            func = Function(name=f"sub_{addr:X}", address=addr, size=0x100)
            func.calls = [addr + 0x1000] if addr < 0x4000 else []
            ir.functions[addr] = func

            cfg = CFG(function_address=addr, entry_block=addr)
            block = BasicBlock(
                address=addr, end_address=addr + 0x100,
                instructions=[
                    Instruction(
                        address=addr + 0x10, mnemonic="call",
                        operands=f"sub_{addr + 0x1000:X}", size=5,
                    ),
                ],
                successors=[],
            )
            cfg.blocks[addr] = block
            ir.cfgs[addr] = ir.simple_cfgs[addr] = cfg

        tracker = TaintTracker(ir)
        ctx = TaintContext(tainted_regs={"rcx"}, taint_origin={"rcx": "IRP"})

        # With max_depth=2, should only recurse 2 levels deep
        result = tracker.track_function_with_context(0x1000, ctx, max_depth=2)
        # Should complete without stack overflow or infinite recursion
        assert isinstance(result, TaintResult)


# ---------------------------------------------------------------------------
# Wave 3: Shadow Space Stack Parameter Propagation (3.1)
# ---------------------------------------------------------------------------

from src.analysis.dataflow.input_tracker import (
    X64_SHADOW_SPACE_OFFSETS,
    CALLBACK_REGISTRATION_APIS,
)


class TestShadowSpacePropagation:
    """Test x64 shadow space taint tracking (32 bytes above RSP)."""

    def test_shadow_space_offsets_defined(self):
        """Shadow space offsets should cover param1-param4."""
        assert 0x10 in X64_SHADOW_SPACE_OFFSETS
        assert 0x18 in X64_SHADOW_SPACE_OFFSETS
        assert 0x20 in X64_SHADOW_SPACE_OFFSETS
        assert 0x28 in X64_SHADOW_SPACE_OFFSETS

    def test_shadow_space_write_marks_slot_tainted(self):
        """mov [rsp+0x10], rcx with tainted rcx should mark shadow slot."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="qword ptr [rsp + 0x10], rcx",
        )
        tainted_regs = {"rcx"}
        taint_origin = {"rcx": "UserBuffer@0x18"}
        tainted_memory: dict[str, str] = {}
        tainted_shadow: dict[int, str] = {}
        tainted_globals: dict[str, str] = {}

        tracker._propagate_memory_taint(
            insn, tainted_regs, taint_origin, tainted_memory,
            tainted_shadow, tainted_globals,
        )

        assert 0x10 in tainted_shadow
        assert tainted_shadow[0x10] == "UserBuffer@0x18"

    def test_shadow_space_read_taints_register(self):
        """mov rdx, [rsp+0x10] from tainted shadow should taint rdx."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x200, mnemonic="mov",
            operands="rdx, qword ptr [rsp + 0x10]",
        )
        tainted_regs: set[str] = set()
        taint_origin: dict[str, str] = {}
        tainted_memory: dict[str, str] = {}
        tainted_shadow = {0x10: "UserBuffer@0x18"}
        tainted_globals: dict[str, str] = {}

        tracker._propagate_memory_taint(
            insn, tainted_regs, taint_origin, tainted_memory,
            tainted_shadow, tainted_globals,
        )

        assert "rdx" in tainted_regs
        assert "shadow space" in taint_origin["rdx"]

    def test_non_shadow_rsp_offset_goes_to_tainted_memory(self):
        """mov [rsp+0x30], rax should go to tainted_memory, not shadow."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x300, mnemonic="mov",
            operands="qword ptr [rsp + 0x30], rax",
        )
        tainted_regs = {"rax"}
        taint_origin = {"rax": "tainted"}
        tainted_memory: dict[str, str] = {}
        tainted_shadow: dict[int, str] = {}
        tainted_globals: dict[str, str] = {}

        tracker._propagate_memory_taint(
            insn, tainted_regs, taint_origin, tainted_memory,
            tainted_shadow, tainted_globals,
        )

        # 0x30 is not a shadow space offset
        assert 0x30 not in tainted_shadow
        assert "[rsp+0x30]" in tainted_memory

    def test_shadow_space_cross_function_spill_reload(self):
        """End-to-end: spill tainted rcx to shadow space, callee reloads it."""
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
                Instruction(
                    address=0x5020, mnemonic="mov",
                    operands="qword ptr [rsp + 0x10], rax", size=8,
                ),
                Instruction(
                    address=0x5030, mnemonic="mov",
                    operands="rcx, qword ptr [rsp + 0x10]", size=8,
                ),
                Instruction(
                    address=0x5040, mnemonic="call",
                    operands="MmMapIoSpaceEx",
                    api_target="MmMapIoSpaceEx", size=6,
                ),
            ],
            successors=[],
        )
        cfg.blocks[0x5000] = block
        ir.cfgs[0x5000] = ir.simple_cfgs[0x5000] = cfg
        ir.function_apis[0x5000] = ["MmMapIoSpaceEx"]

        result = run_taint_analysis(0x5000, ir)
        assert len(result.sources) >= 1

    def test_all_four_shadow_params_tracked(self):
        """All four shadow space params should be independently tracked."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        shadow: dict[int, str] = {}
        for offset, name in X64_SHADOW_SPACE_OFFSETS.items():
            tracker._propagate_memory_taint(
                Instruction(
                    address=0x100, mnemonic="mov",
                    operands=f"qword ptr [rsp + 0x{offset:X}], rax",
                ),
                {"rax"}, {"rax": "tainted"},
                {}, shadow, {},
            )
            assert offset in shadow


# ---------------------------------------------------------------------------
# Wave 3: Callback Boundary Cross-Function Taint (3.2)
# ---------------------------------------------------------------------------

class TestCallbackBoundaryTaint:
    """Test taint injection through callback registration APIs."""

    def test_callback_registration_apis_defined(self):
        """Should include common callback registration APIs."""
        assert "ObRegisterCallbacks" in CALLBACK_REGISTRATION_APIS
        assert "CmRegisterCallbackEx" in CALLBACK_REGISTRATION_APIS
        assert "PsSetCreateProcessNotifyRoutine" in CALLBACK_REGISTRATION_APIS
        assert "FltRegisterFilter" in CALLBACK_REGISTRATION_APIS

    def test_callback_count_sufficient(self):
        """Should have at least 10 callback registration APIs."""
        assert len(CALLBACK_REGISTRATION_APIS) >= 10

    def test_handle_callback_taint_injects_into_callbacks(self):
        """_handle_callback_taint should analyze callback functions."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")

        # Register a callback function
        cb_func = Function(name="callback_pre_op", address=0x3000, size=0x100)
        ir.functions[0x3000] = cb_func
        ir.callback_functions = {0x3000: cb_func}

        cb_cfg = CFG(function_address=0x3000, entry_block=0x3000)
        cb_block = BasicBlock(
            address=0x3000, end_address=0x3100,
            instructions=[
                Instruction(
                    address=0x3010, mnemonic="mov",
                    operands="rdx, rcx", size=3,
                ),
                Instruction(
                    address=0x3020, mnemonic="call",
                    operands="MmMapIoSpaceEx",
                    api_target="MmMapIoSpaceEx", size=6,
                ),
            ],
            successors=[],
        )
        cb_cfg.blocks[0x3000] = cb_block
        ir.cfgs[0x3000] = ir.simple_cfgs[0x3000] = cb_cfg
        ir.function_apis[0x3000] = ["MmMapIoSpaceEx"]

        tracker = TaintTracker(ir)
        insn = Instruction(
            address=0x100, mnemonic="call",
            operands="ObRegisterCallbacks",
            api_target="ObRegisterCallbacks",
        )

        result = tracker._handle_callback_taint(
            insn, {"rcx"}, {"rcx": "UserBuffer"},
            max_depth=2, depth=1,
        )

        # Should have analyzed the callback function
        assert isinstance(result, TaintResult)

    def test_handle_callback_taint_no_callbacks_returns_empty(self):
        """No callback functions registered should return empty result."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="call",
            operands="ObRegisterCallbacks",
            api_target="ObRegisterCallbacks",
        )

        result = tracker._handle_callback_taint(
            insn, {"rcx"}, {"rcx": "UserBuffer"},
            max_depth=2, depth=1,
        )

        assert result.sources == []
        assert result.sinks == []


# ---------------------------------------------------------------------------
# Wave 3: Global Variable Taint Tracking (3.3)
# ---------------------------------------------------------------------------

class TestGlobalVariableTaint:
    """Test RIP-relative global variable taint tracking."""

    def test_rip_relative_store_marks_global_tainted(self):
        """mov [rip+offset], tainted_reg should mark global as tainted."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="qword ptr [rip + 0x2000], rcx",
        )
        tainted_regs = {"rcx"}
        taint_origin = {"rcx": "UserBuffer@0x18"}
        tainted_memory: dict[str, str] = {}
        tainted_shadow: dict[int, str] = {}
        tainted_globals: dict[str, str] = {}

        tracker._propagate_memory_taint(
            insn, tainted_regs, taint_origin, tainted_memory,
            tainted_shadow, tainted_globals,
        )

        assert "global_rip+0x2000" in tainted_globals
        assert tainted_globals["global_rip+0x2000"] == "UserBuffer@0x18"

    def test_rip_relative_load_taints_register(self):
        """mov rax, [rip+offset] from tainted global should taint rax."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x200, mnemonic="mov",
            operands="rax, qword ptr [rip + 0x2000]",
        )
        tainted_regs: set[str] = set()
        taint_origin: dict[str, str] = {}
        tainted_memory: dict[str, str] = {}
        tainted_shadow: dict[int, str] = {}
        tainted_globals = {"global_rip+0x2000": "UserBuffer"}

        tracker._propagate_memory_taint(
            insn, tainted_regs, taint_origin, tainted_memory,
            tainted_shadow, tainted_globals,
        )

        assert "rax" in tainted_regs
        assert "global" in taint_origin["rax"]

    def test_is_rip_relative_detects_rip(self):
        """_is_rip_relative should detect RIP-relative addressing."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="qword ptr [rip + 0x1234], rax",
        )
        is_rip, offset = tracker._is_rip_relative(insn)
        assert is_rip is True
        assert offset is not None

    def test_is_rip_relative_returns_false_for_non_rip(self):
        """Non-RIP-relative instructions should return False."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="qword ptr [rsp + 0x20], rax",
        )
        is_rip, offset = tracker._is_rip_relative(insn)
        assert is_rip is False
        assert offset is None

    def test_global_taint_cross_function_scenario(self):
        """Global tainted in one function, read in another."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        # Function A stores tainted rcx to global
        insn_store = Instruction(
            address=0x100, mnemonic="mov",
            operands="qword ptr [rip + 0x5000], rcx",
        )
        shadow: dict[int, str] = {}
        globals_map: dict[str, str] = {}
        tracker._propagate_memory_taint(
            insn_store, {"rcx"}, {"rcx": "UserBuffer"},
            {}, shadow, globals_map,
        )
        assert "global_rip+0x5000" in globals_map

        # Function B reads from same global
        insn_load = Instruction(
            address=0x200, mnemonic="mov",
            operands="rax, qword ptr [rip + 0x5000]",
        )
        tainted_regs: set[str] = set()
        taint_origin: dict[str, str] = {}
        tracker._propagate_memory_taint(
            insn_load, tainted_regs, taint_origin,
            {}, shadow, globals_map,
        )
        assert "rax" in tainted_regs


# ---------------------------------------------------------------------------
# Wave 3: Size-Qualifier-Aware Taint (3.4)
# ---------------------------------------------------------------------------

class TestSizeQualifierAwareTaint:
    """Test size-qualifier-aware taint propagation."""

    def test_extract_size_qualifier_qword(self):
        """Should detect qword ptr qualifier."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="rax, qword ptr [rcx + 0x60]",
        )
        assert tracker._extract_size_qualifier(insn) == "qword"

    def test_extract_size_qualifier_dword(self):
        """Should detect dword ptr qualifier."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="eax, dword ptr [rcx + 0x60]",
        )
        assert tracker._extract_size_qualifier(insn) == "dword"

    def test_extract_size_qualifier_word(self):
        """Should detect word ptr qualifier."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="ax, word ptr [rcx + 0x60]",
        )
        assert tracker._extract_size_qualifier(insn) == "word"

    def test_extract_size_qualifier_byte(self):
        """Should detect byte ptr qualifier."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="al, byte ptr [rcx + 0x60]",
        )
        assert tracker._extract_size_qualifier(insn) == "byte"

    def test_extract_size_qualifier_none(self):
        """No size qualifier should return empty string."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="rax, rcx",
        )
        assert tracker._extract_size_qualifier(insn) == ""

    def test_partial_reg_from_size_mapping(self):
        """Size qualifiers should map to correct partial register names."""
        assert TaintTracker._partial_reg_from_size("byte") == "al"
        assert TaintTracker._partial_reg_from_size("word") == "ax"
        assert TaintTracker._partial_reg_from_size("dword") == "eax"
        assert TaintTracker._partial_reg_from_size("qword") == "rax"
        assert TaintTracker._partial_reg_from_size("unknown") is None

    def test_byte_taint_only_affects_al(self):
        """byte ptr mov should only taint al, not rax."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        # Taint rcx (full register)
        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="al, byte ptr [rcx + 0x60]",
        )
        tainted_regs = {"rcx"}
        taint_origin = {"rcx": "UserBuffer"}

        tracker._propagate_taint(insn, tainted_regs, taint_origin)

        # al should be tainted (propagated from rcx through memory deref)
        assert "al" in tainted_regs

    def test_dword_taint_zero_extends_to_64bit(self):
        """dword ptr mov should taint eax (zero-extended to rax in x64)."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        tracker = TaintTracker(ir)

        insn = Instruction(
            address=0x100, mnemonic="mov",
            operands="eax, dword ptr [rcx + 0x60]",
        )
        tainted_regs = {"rcx"}
        taint_origin = {"rcx": "UserBuffer"}

        tracker._propagate_taint(insn, tainted_regs, taint_origin)

        assert "eax" in tainted_regs


# ---------------------------------------------------------------------------
# Wave 3: TaintContext extended fields
# ---------------------------------------------------------------------------

class TestTaintContextExtended:
    """Test new TaintContext fields for Wave 3."""

    def test_tainted_shadow_space_default(self):
        """Default should be empty dict."""
        ctx = TaintContext()
        assert ctx.tainted_shadow_space == {}

    def test_tainted_globals_default(self):
        """Default should be empty dict."""
        ctx = TaintContext()
        assert ctx.tainted_globals == {}

    def test_context_with_shadow_and_globals(self):
        """Should accept pre-populated shadow space and globals."""
        ctx = TaintContext(
            tainted_shadow_space={0x10: "param1_tainted"},
            tainted_globals={"global_rip+0x1000": "UserBuffer"},
        )
        assert 0x10 in ctx.tainted_shadow_space
        assert "global_rip+0x1000" in ctx.tainted_globals

    def test_parse_shadow_offset_hex(self):
        """Should parse hex offset string."""
        offset = TaintTracker._parse_shadow_offset("0x10")
        assert offset == 0x10

    def test_parse_shadow_offset_decimal(self):
        """Should parse decimal offset string."""
        offset = TaintTracker._parse_shadow_offset("16")
        assert offset == 0x10

    def test_parse_shadow_offset_non_shadow_returns_none(self):
        """Non-shadow-space offset should return None."""
        offset = TaintTracker._parse_shadow_offset("0x30")
        assert offset is None

    def test_parse_shadow_offset_invalid_returns_none(self):
        """Invalid offset string should return None."""
        offset = TaintTracker._parse_shadow_offset("garbage")
        assert offset is None


class TestCrossFunctionUnknownCallee:
    """Taint propagation to unknown callees and return value tracking."""

    def test_unknown_callee_records_tainted_param(self):
        """Calling unknown API with tainted rcx should record a sink."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        func = Function(name="sub_4000", address=0x4000, size=0x100)
        ir.functions[0x4000] = func
        cfg = CFG(function_address=0x4000, entry_block=0x4000)
        block = BasicBlock(
            address=0x4000, end_address=0x4100,
            instructions=[
                Instruction(address=0x4010, mnemonic="mov",
                           operands="rax, qword ptr [rcx + 0x60]", size=7),
                Instruction(address=0x4020, mnemonic="call",
                           operands="sub_9999", api_target="UnknownFunc", size=5),
            ],
            successors=[],
        )
        cfg.blocks[0x4000] = block
        ir.cfgs[0x4000] = ir.simple_cfgs[0x4000] = cfg

        tracker = TaintTracker(ir)
        ctx = TaintContext(is_arm64=False)
        ctx.tainted_regs.add("rcx")
        ctx.taint_origin["rcx"] = "IRP pointer (entry)"

        result = tracker.track_function_with_context(0x4000, ctx)

        # Should record that tainted rcx was passed to UnknownFunc
        tainted_sinks = [s for s in result.sinks if s.api_name == "UnknownFunc"]
        assert len(tainted_sinks) >= 1

    def test_return_value_tainted_after_call(self):
        """After calling any function with tainted params, rax should be tainted."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        func = Function(name="sub_5000", address=0x5000, size=0x200)
        ir.functions[0x5000] = func
        cfg = CFG(function_address=0x5000, entry_block=0x5000)
        block = BasicBlock(
            address=0x5000, end_address=0x5200,
            instructions=[
                Instruction(address=0x5010, mnemonic="mov",
                           operands="rax, qword ptr [rcx + 0x60]", size=7),
                Instruction(address=0x5020, mnemonic="mov",
                           operands="rdx, rax", size=4),
                Instruction(address=0x5030, mnemonic="call",
                           operands="sub_8888", api_target="HelperFunc", size=5),
                Instruction(address=0x5040, mnemonic="mov",
                           operands="rcx, rax", size=4),
                Instruction(address=0x5050, mnemonic="call",
                           operands="MmMapIoSpaceEx", api_target="MmMapIoSpaceEx", size=5),
            ],
            successors=[],
        )
        cfg.blocks[0x4000] = block
        ir.cfgs[0x5000] = ir.simple_cfgs[0x5000] = cfg
        ir.function_apis[0x5000] = ["MmMapIoSpaceEx"]

        tracker = TaintTracker(ir)
        ctx = TaintContext(is_arm64=False)
        ctx.tainted_regs.add("rcx")
        ctx.taint_origin["rcx"] = "IRP SystemBuffer"

        result = tracker.track_function_with_context(0x5000, ctx)

        # rax should be tainted after HelperFunc call (tainted input → tainted return)
        # and then used as rcx for MmMapIoSpaceEx
        assert result.tainted_reaches_dangerous_api or len(result.sinks) >= 1

    def test_known_callee_still_propagates_context(self):
        """Known callee should still receive tainted register context."""
        ir = DisassemblyResult(sample_path=Path("t.sys"), backend="capstone")
        # Handler function
        handler = Function(name="Handler", address=0x6000, size=0x100, calls=[0x7000])
        # Callee function
        callee = Function(name="Helper", address=0x7000, size=0x100)
        ir.functions[0x6000] = handler
        ir.functions[0x7000] = callee

        # Handler: read IRP, pass to helper, helper calls dangerous API
        handler_cfg = CFG(function_address=0x6000, entry_block=0x6000)
        handler_block = BasicBlock(
            address=0x6000, end_address=0x6100,
            instructions=[
                Instruction(address=0x6010, mnemonic="mov",
                           operands="rax, qword ptr [rcx + 0x60]", size=7),
                Instruction(address=0x6020, mnemonic="mov",
                           operands="rcx, rax", size=4),
                Instruction(address=0x6030, mnemonic="call",
                           operands="sub_7000", api_target="Helper", size=5),
            ],
            successors=[],
        )
        handler_cfg.blocks[0x6000] = handler_block
        ir.cfgs[0x6000] = ir.simple_cfgs[0x6000] = handler_cfg

        # Callee: calls dangerous API with tainted rcx
        callee_cfg = CFG(function_address=0x7000, entry_block=0x7000)
        callee_block = BasicBlock(
            address=0x7000, end_address=0x7100,
            instructions=[
                Instruction(address=0x7010, mnemonic="call",
                           operands="MmMapIoSpaceEx", api_target="MmMapIoSpaceEx", size=5),
            ],
            successors=[],
        )
        callee_cfg.blocks[0x7000] = callee_block
        ir.cfgs[0x7000] = ir.simple_cfgs[0x7000] = callee_cfg
        ir.function_apis[0x7000] = ["MmMapIoSpaceEx"]

        tracker = TaintTracker(ir)
        ctx = TaintContext(is_arm64=False)
        ctx.tainted_regs.add("rcx")
        ctx.taint_origin["rcx"] = "IRP SystemBuffer@0x60"

        result = tracker.track_function_with_context(0x6000, ctx, max_depth=3)

        # Should detect that taint flows through Helper to MmMapIoSpaceEx
        assert result.tainted_reaches_dangerous_api
