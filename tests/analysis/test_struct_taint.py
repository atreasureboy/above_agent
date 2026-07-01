"""Tests for Phase 9: Struct field-level taint tracking."""

from __future__ import annotations

import pytest

from src.analysis.dataflow.struct_tracker import (
    KERNEL_STRUCTS,
    HIGH_RISK_FIELDS,
    BUFFERED_FIELDS,
    FieldTaint,
    StructTaintState,
    _find_struct_field,
    _get_risk_level,
    track_struct_field_taint,
    get_field_taint_for_register,
    has_high_risk_taint,
    enhance_taint_result_with_struct_info,
)


# ---------------------------------------------------------------------------
# Struct Definitions Tests
# ---------------------------------------------------------------------------

class TestStructDefinitions:
    """Test kernel struct offset definitions."""

    def test_irp_has_userbuffer_at_0x18(self):
        assert KERNEL_STRUCTS["IRP"][0x18] == "UserBuffer"

    def test_irp_has_systembuffer_at_0x60(self):
        assert KERNEL_STRUCTS["IRP"][0x60] == "SystemBuffer"

    def test_irp_has_currentstacklocation(self):
        assert "Tail.Overlay.CurrentStackLocation" in KERNEL_STRUCTS["IRP"].values()

    def test_io_stack_location_has_majorfunction(self):
        assert KERNEL_STRUCTS["IO_STACK_LOCATION"][0x00] == "MajorFunction"

    def test_userbuffer_is_high_risk(self):
        assert "UserBuffer" in HIGH_RISK_FIELDS

    def test_systembuffer_is_buffered(self):
        assert "SystemBuffer" in BUFFERED_FIELDS


# ---------------------------------------------------------------------------
# Field Lookup Tests
# ---------------------------------------------------------------------------

class TestFieldLookup:
    """Test struct field lookup by offset."""

    def test_find_struct_field_0x18(self):
        results = _find_struct_field(0x18)
        assert any(name == "IRP" and field == "UserBuffer" for name, field in results)

    def test_find_struct_field_0x60(self):
        results = _find_struct_field(0x60)
        assert any(name == "IRP" and field == "SystemBuffer" for name, field in results)

    def test_find_struct_field_unknown_offset(self):
        results = _find_struct_field(0xFFFF)
        assert len(results) == 0

    def test_risk_level_high(self):
        assert _get_risk_level("UserBuffer") == "HIGH"

    def test_risk_level_medium(self):
        assert _get_risk_level("SystemBuffer") == "MEDIUM"

    def test_risk_level_low(self):
        assert _get_risk_level("Type") == "LOW"


# ---------------------------------------------------------------------------
# Taint Propagation Tests
# ---------------------------------------------------------------------------

class TestTaintPropagation:
    """Test struct field taint propagation through instructions."""

    def test_irp_field_read_labels_register(self):
        """mov rax, [rcx+0x18] should label rax with IRP.UserBuffer."""
        state = StructTaintState()
        track_struct_field_taint("mov", "rax, qword ptr [rcx + 0x18]", state)

        assert "rax" in state.reg_field_taint
        assert state.reg_field_taint["rax"].field_name == "UserBuffer"
        assert state.reg_field_taint["rax"].field_offset == 0x18

    def test_register_to_register_propagation(self):
        """mov rdx, rax should propagate field taint from rax to rdx."""
        state = StructTaintState()
        state.reg_field_taint["rax"] = FieldTaint(
            struct_name="IRP", field_name="UserBuffer",
            field_offset=0x18, source_description="HIGH risk",
        )
        track_struct_field_taint("mov", "rdx, rax", state)

        assert "rdx" in state.reg_field_taint
        assert state.reg_field_taint["rdx"].field_name == "UserBuffer"

    def test_store_to_memory_propagates_taint(self):
        """mov [rsp+0x20], rax should propagate field taint to memory."""
        state = StructTaintState()
        state.reg_field_taint["rax"] = FieldTaint(
            struct_name="IRP", field_name="UserBuffer",
            field_offset=0x18, source_description="HIGH risk",
        )
        track_struct_field_taint("mov", "qword ptr [rsp + 0x20], rax", state)

        assert "[rsp+0x20]" in state.mem_field_taint
        assert state.mem_field_taint["[rsp+0x20]"].field_name == "UserBuffer"

    def test_systembuffer_has_lower_risk(self):
        """mov rax, [rcx+0x60] should label with SystemBuffer (MEDIUM risk)."""
        state = StructTaintState()
        track_struct_field_taint("mov", "rax, qword ptr [rcx + 0x60]", state)

        assert "rax" in state.reg_field_taint
        assert state.reg_field_taint["rax"].field_name == "SystemBuffer"
        assert _get_risk_level(state.reg_field_taint["rax"].field_name) == "MEDIUM"

    def test_unknown_offset_no_taint(self):
        """mov rax, [rcx+0x999] should not produce field taint."""
        state = StructTaintState()
        track_struct_field_taint("mov", "rax, qword ptr [rcx + 0x999]", state)

        assert "rax" not in state.reg_field_taint

    def test_non_irp_base_no_taint(self):
        """mov rax, [rdi+0x18] should not produce field taint (rdi != rcx)."""
        state = StructTaintState()
        track_struct_field_taint("mov", "rax, qword ptr [rdi + 0x18]", state)

        assert "rax" not in state.reg_field_taint

    def test_non_irp_base_with_irp_taint_propagates(self):
        """mov rax, [rdi+0x18] where rdi carries IRP taint should work."""
        state = StructTaintState()
        state.reg_field_taint["rdi"] = FieldTaint(
            struct_name="IRP", field_name="IRP pointer",
            field_offset=0, source_description="base",
        )
        track_struct_field_taint("mov", "rax, qword ptr [rdi + 0x18]", state)

        assert "rax" in state.reg_field_taint


# ---------------------------------------------------------------------------
# High Risk Detection Tests
# ---------------------------------------------------------------------------

class TestHighRiskDetection:
    """Test high-risk field taint detection."""

    def test_high_risk_param_detected(self):
        """rcx tainted with UserBuffer should be high risk."""
        state = StructTaintState()
        state.reg_field_taint["rcx"] = FieldTaint(
            struct_name="IRP", field_name="UserBuffer",
            field_offset=0x18, source_description="HIGH risk",
        )
        risks = has_high_risk_taint(["rcx"], state)
        assert len(risks) == 1
        assert risks[0].field_name == "UserBuffer"

    def test_low_risk_param_not_flagged(self):
        """rcx tainted with SystemBuffer should NOT be high risk."""
        state = StructTaintState()
        state.reg_field_taint["rcx"] = FieldTaint(
            struct_name="IRP", field_name="SystemBuffer",
            field_offset=0x60, source_description="MEDIUM risk",
        )
        risks = has_high_risk_taint(["rcx"], state)
        assert len(risks) == 0

    def test_no_taint_returns_empty(self):
        """Register with no field taint should return empty."""
        state = StructTaintState()
        risks = has_high_risk_taint(["rax"], state)
        assert len(risks) == 0


# ---------------------------------------------------------------------------
# Dataclass Tests
# ---------------------------------------------------------------------------

class TestDataclasses:
    """Test dataclass defaults."""

    def test_field_taint_creation(self):
        ft = FieldTaint(
            struct_name="IRP", field_name="UserBuffer",
            field_offset=0x18, source_description="HIGH risk",
        )
        assert ft.struct_name == "IRP"
        assert ft.field_name == "UserBuffer"
        assert ft.field_offset == 0x18

    def test_struct_taint_state_defaults(self):
        state = StructTaintState()
        assert state.reg_field_taint == {}
        assert state.mem_field_taint == {}
        assert state.all_taints == []
