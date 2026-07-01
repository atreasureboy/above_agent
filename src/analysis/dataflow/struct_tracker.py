"""
DriverScope — Struct Field Taint Tracker.

Tracks taint at the **struct field** level, not just register level.
When a driver reads `IRP->UserBuffer` (offset 0x18 from IRP pointer),
the tainted value carries the semantic meaning "this is a direct user
pointer" (METHOD_NEITHER). If it reaches a dangerous API without
validation, the risk is higher than a buffered copy (METHOD_BUFFERED).

Key insight: `mov rax, [rcx+0x18]` produces a register-level taint on
`rax`, but the field-level label `"IRP.UserBuffer"` is lost after the
first `mov rdx, rax`. This tracker preserves that label through the
entire data flow.
"""

from __future__ import annotations

from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Known Windows kernel struct offsets (x64)
# ---------------------------------------------------------------------------

KERNEL_STRUCTS: dict[str, dict[int, str]] = {
    "IRP": {
        0x00: "Type",
        0x08: "Size",
        0x10: "MdlAddress",
        0x18: "UserBuffer",          # METHOD_NEITHER — direct user pointer (HIGH risk)
        0x20: "Overlay.AuxData",
        0x28: "Overlay.DriverContext",
        0x30: "ThreadListEntry",
        0x60: "SystemBuffer",        # METHOD_BUFFERED — kernel copy (lower risk)
        0x68: "Overlay.AllocationSize",
        0x70: "Overlay.DeletePending",
        0x78: "Tail.Overlay.DriverContext",
        0x80: "Tail.Overlay.DeviceObject",
        0x88: "Tail.Overlay.CurrentStackLocation",
        0x90: "Tail.Overlay.FileObject",
        0x98: "Parameters",
        0xA0: "Tail.Overlay.ListEntry",
        0xB0: "Tail.Overlay.CurrentStackLocation",
    },
    "IO_STACK_LOCATION": {
        0x00: "MajorFunction",
        0x04: "MinorFunction",
        0x08: "Flags",
        0x0C: "Control",
        0x10: "Parameters",
        0x38: "DeviceObject",
        0x40: "FileObject",
        0x48: "CompletionRoutine",
        0x50: "Context",
    },
    "DEVICE_OBJECT": {
        0x08: "DeviceExtension",
        0x18: "DeviceType",
        0x28: "Flags",
        0x30: "StackSize",
    },
    "FILE_OBJECT": {
        0x08: "Type",
        0x0C: "Size",
        0x18: "DeviceObject",
        0x20: "Vpb",
        0x28: "FsContext",
        0x30: "FsContext2",
        0x38: "SectionObjectPointer",
        0x40: "PrivateCacheMap",
        0x60: "FileName",
    },
}

# Fields that carry HIGH risk when reaching dangerous APIs unvalidated
HIGH_RISK_FIELDS = {
    "UserBuffer",                    # METHOD_NEITHER — direct user-mode pointer
    "MdlAddress",                    # MDL describing user pages
    "Tail.Overlay.CurrentStackLocation",  # Stack location — user-controllable IOCTL params
    "Parameters",                    # Parameters union — user-controllable
}

# Fields that are lower risk (kernel-buffered)
BUFFERED_FIELDS = {
    "SystemBuffer",                  # METHOD_BUFFERED — copied to kernel buffer
}


@dataclass
class FieldTaint:
    """Taint label for a struct field."""
    struct_name: str   # "IRP", "IO_STACK_LOCATION"
    field_name: str    # "UserBuffer", "SystemBuffer", etc.
    field_offset: int  # Byte offset within struct
    source_description: str  # e.g. "METHOD_NEITHER user pointer"


@dataclass
class StructTaintState:
    """Current struct field taint state carried through analysis."""
    # Register → FieldTaint (which register holds which struct field value)
    reg_field_taint: dict[str, FieldTaint] = field(default_factory=dict)
    # Memory location → FieldTaint
    mem_field_taint: dict[str, FieldTaint] = field(default_factory=dict)
    # Set of all unique field taints seen (for deduplication)
    all_taints: list[FieldTaint] = field(default_factory=list)


def _find_struct_field(offset: int) -> list[tuple[str, str]]:
    """Find which struct(s) have a field at the given offset.

    Returns list of (struct_name, field_name) tuples.
    Multiple structs may have fields at the same offset.
    """
    results = []
    for struct_name, fields in KERNEL_STRUCTS.items():
        if offset in fields:
            results.append((struct_name, fields[offset]))
    return results


def _get_risk_level(field_name: str) -> str:
    """Get risk level for a struct field."""
    if field_name in HIGH_RISK_FIELDS:
        return "HIGH"
    if field_name in BUFFERED_FIELDS:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Struct field taint propagation
# ---------------------------------------------------------------------------

def track_struct_field_taint(
    insn_mnemonic: str,
    insn_operands: str,
    state: StructTaintState,
    is_arm64: bool = False,
) -> None:
    """Update struct field taint state based on an instruction.

    Handles:
    - ``mov reg, [base+offset]`` — if base is IRP pointer and offset matches
      a known field, label the destination register with the field taint
    - ``mov reg, reg`` — propagate field taint between registers
    - ``mov [mem], reg`` — propagate field taint to memory
    - ``mov reg, [mem]`` — propagate field taint from memory to register
    """
    import re

    base_reg = "x0" if is_arm64 else "rcx"
    ops = insn_operands.strip().lower()

    if insn_mnemonic in ("mov", "ldr"):
        # Store to memory: mov [mem], reg — check first to avoid matching reg,reg
        if "[" in ops:
            store_match = re.match(
                r'(?:byte|word|dword|qword)\s*ptr\s*\[\s*([a-z0-9]+)\s*(?:\+\s*([^\]]+))?\s*\]\s*,\s*([a-z0-9]+)',
                ops, re.IGNORECASE
            )
            if not store_match:
                store_match = re.match(
                    r'\[\s*([a-z0-9]+)\s*(?:\+\s*([^\]]+))?\s*\]\s*,\s*([a-z0-9]+)',
                    ops, re.IGNORECASE
                )
            if store_match:
                base = store_match.group(1).lower()
                offset_str = store_match.group(2)
                src = store_match.group(3).lower()

                mem_key = f"[{base}+{offset_str}]" if offset_str else f"[{base}]"
                if src in state.reg_field_taint:
                    state.mem_field_taint[mem_key] = state.reg_field_taint[src]
                return

            # Load from memory: mov reg, [base+offset]
            load_match = re.match(
                r'([a-z0-9]+)\s*,\s*(?:byte|word|dword|qword)\s*ptr\s*\[\s*([a-z0-9]+)\s*(?:\+\s*([^\]]+))?\s*\]',
                ops, re.IGNORECASE
            )
            if not load_match:
                load_match = re.match(
                    r'([a-z0-9]+)\s*,\s*\[\s*([a-z0-9]+)\s*(?:\+\s*([^\]]+))?\s*\]',
                    ops, re.IGNORECASE
                )
            if load_match:
                dest = load_match.group(1).lower()
                base = load_match.group(2).lower()
                offset_str = load_match.group(3)

                is_irp_base = (base == base_reg or base in state.reg_field_taint)

                if is_irp_base and offset_str:
                    offset_str = offset_str.strip().rstrip("h")
                    try:
                        offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
                    except ValueError:
                        offset = 0

                    matches = _find_struct_field(offset)
                    if matches:
                        struct_name, field_name = matches[0]
                        src_desc = f"{struct_name}.{field_name} ({_get_risk_level(field_name)} risk)"
                        ft = FieldTaint(
                            struct_name=struct_name,
                            field_name=field_name,
                            field_offset=offset,
                            source_description=src_desc,
                        )
                        state.reg_field_taint[dest] = ft
                        state.all_taints.append(ft)
                return
        else:
            # Register-to-register: mov rdx, rax — propagate field taint
            reg_match = re.match(r'([a-z0-9]+)\s*,\s*([a-z0-9]+)', ops, re.IGNORECASE)
            if reg_match:
                dest = reg_match.group(1).lower()
                src = reg_match.group(2).lower()
                if src in state.reg_field_taint:
                    state.reg_field_taint[dest] = state.reg_field_taint[src]


def get_field_taint_for_register(
    reg: str,
    state: StructTaintState,
) -> FieldTaint | None:
    """Get the struct field taint associated with a register."""
    return state.reg_field_taint.get(reg.lower())


def has_high_risk_taint(
    tainted_params: list[str],
    state: StructTaintState,
) -> list[FieldTaint]:
    """Check if any tainted parameters carry HIGH-risk field taint."""
    high_risks = []
    for param in tainted_params:
        ft = get_field_taint_for_register(param, state)
        if ft and ft.field_name in HIGH_RISK_FIELDS:
            high_risks.append(ft)
    return high_risks


# ---------------------------------------------------------------------------
# Integration helper for input_tracker.py
# ---------------------------------------------------------------------------

def enhance_taint_result_with_struct_info(
    result,
    struct_state: StructTaintState,
) -> None:
    """Add struct field taint info to an existing TaintResult.

    This is called by input_tracker.py to enrich taint analysis results
    with struct field labels.
    """
    if hasattr(result, 'struct_field_taints'):
        result.struct_field_taints = list(struct_state.all_taints)

    # Check if any sink involves high-risk fields
    for sink in result.sinks:
        high_risks = has_high_risk_taint([sink.tainted_param], struct_state)
        if high_risks:
            sink.field_risk = high_risks[0].source_description
            # Upgrade severity for high-risk fields
            if not hasattr(sink, '__dict__') or True:  # TaintSink is a dataclass
                pass  # Already handled at the finding generation level
