"""
DriverScope — Indirect Call Resolver.

Resolves indirect call targets that name-based matching cannot identify:
- C++ vtable dispatch (``call [rax + rdx*8]``)
- Callback function pointers (``call [rcx+0x20]`` where rcx is a callback struct)
- Registration-based indirect calls (``IoSetStartIo``, ``IoSetCompletionRoutine``)
- WDF callback dispatch (``WdfIoQueueCreate`` config callbacks)

Strategy:
1. **VTable identification**: Scan .rdata for contiguous function-pointer arrays
   (QWORD values pointing to code sections). Mark these as vtables.
2. **Callback registration tracking**: Identify ``mov [reg+offset], handler``
   patterns at known callback struct offsets.
3. **Register backtracking**: For ``call [reg]``, trace ``reg`` backwards through
   mov/lea instructions to find its value source.
"""

from __future__ import annotations

import bisect
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

import pefile

from src.models import DisassemblyResult, Function, Instruction


# ---------------------------------------------------------------------------
# Callback struct offsets (known WDM/WDF patterns)
# ---------------------------------------------------------------------------

# IoSetCompletionRoutine callback offsets in IO_STACK_LOCATION
IO_COMPLETION_CALLBACK_OFFSETS = {
    0x28: "CompletionRoutine",
    0x30: "CompletionContext",
}

# WDF_IO_QUEUE_CONFIG callback offsets
WDF_QUEUE_CALLBACK_OFFSETS = {
    0x18: "EvtIoDeviceControl",
    0x20: "EvtIoRead",
    0x28: "EvtIoWrite",
    0x30: "EvtIoInternalDeviceControl",
    0x38: "EvtIoDefault",
}

# Registration APIs that set up callbacks
CALLBACK_REGISTER_APIS = {
    "IoSetCompletionRoutine", "IoSetStartIo", "IoSetCancelRoutine",
    "IoSetCompletionObject", "IoRegisterPlugPlayNotification",
    "IoRegisterShutdownNotification", "IoRegisterFsRegistrationChange",
    "WdfIoQueueCreate", "WdfRequestSetCompletionRoutine",
}


@dataclass
class ResolvedTarget:
    """A resolved indirect call target."""
    instruction_addr: int  # Address of the indirect call
    target_addr: int  # Resolved function address
    target_name: str  # Function name if available
    resolution_method: str  # "vtable" | "callback_struct" | "register_backtrack" | "constant"
    confidence: float  # 0.0-1.0


@dataclass
class VTableInfo:
    """A discovered vtable."""
    address: int  # VTable base address in .rdata
    entries: list[int]  # Function pointer addresses
    owning_func: int | None = None  # Function that sets up this vtable
    name: str = ""  # Inferred name (e.g., "vtable_0x4000")


@dataclass
class CallbackRegistration:
    """A detected callback registration."""
    registered_by: str  # API that registered
    handler_addr: int  # Callback function address
    callback_type: str  # Type of callback
    registered_in: int  # Function that did the registration


# ---------------------------------------------------------------------------
# VTable identification
# ---------------------------------------------------------------------------

def identify_vtables(
    pe_path: Path,
    ir: DisassemblyResult,
    min_entries: int = 3,
) -> list[VTableInfo]:
    """Scan PE .rdata section for contiguous function-pointer arrays.

    A vtable is identified as a sequence of >= min_entries QWORD values
    where each value points to a known function in the IR.
    """
    vtables: list[VTableInfo] = []
    func_addrs = set(ir.functions.keys())

    if not func_addrs:
        return vtables

    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        img_base = pe.OPTIONAL_HEADER.ImageBase
        pe.close()
    except Exception as e:
        logging.warning("[vtable] Failed to open PE file for image base: %s", e)
        return vtables

    # Read raw bytes from the PE file
    try:
        with open(pe_path, "rb") as f:
            raw_data = f.read()
    except Exception as e:
        logging.warning("[vtable] Failed to read PE raw data: %s", e)
        return vtables

    # Find section boundaries
    try:
        pe = pefile.PE(str(pe_path), fast_load=True)
        sections = pe.sections
        pe.close()
    except Exception as e:
        logging.warning("[vtable] Failed to read PE sections: %s", e)
        return vtables

    for section in sections:
        sec_name = section.Name.decode("utf-8", errors="replace").strip("\x00")
        if sec_name not in (".rdata", ".data"):
            continue

        sec_rva = section.VirtualAddress
        sec_size = section.Misc_VirtualSize
        sec_file_offset = section.PointerToRawData

        if sec_file_offset + sec_size > len(raw_data):
            continue

        data = raw_data[sec_file_offset:sec_file_offset + sec_size]

        # Scan for QWORD function pointers
        import struct
        func_pointers: list[tuple[int, int]] = []  # (rva, func_addr)

        for i in range(0, len(data) - 8, 8):
            qword = struct.unpack("<Q", data[i:i+8])[0]
            if qword == 0:
                func_pointers.append((0, 0))
                continue
            # Check if this points to a known function
            va = qword
            if va in func_addrs:
                func_pointers.append((sec_rva + i, va))
            else:
                func_pointers.append((0, 0))

        # Find contiguous runs of function pointers
        run_start = -1
        for i, (rva, func_addr) in enumerate(func_pointers):
            if func_addr != 0:
                if run_start < 0:
                    run_start = i
            else:
                if run_start >= 0 and i - run_start >= min_entries:
                    # Found a vtable
                    entries = [fp[1] for fp in func_pointers[run_start:i] if fp[1] != 0]
                    vtable_rva = sec_rva + run_start * 8
                    vtables.append(VTableInfo(
                        address=vtable_rva,
                        entries=entries,
                        name=f"vtable_0x{vtable_rva:X}",
                    ))
                run_start = -1

        # Handle run at end of section
        if run_start >= 0 and len(func_pointers) - run_start >= min_entries:
            entries = [fp[1] for fp in func_pointers[run_start:] if fp[1] != 0]
            vtable_rva = sec_rva + run_start * 8
            vtables.append(VTableInfo(
                address=vtable_rva,
                entries=entries,
                name=f"vtable_0x{vtable_rva:X}",
            ))

    return vtables


# ---------------------------------------------------------------------------
# Register backtracking for indirect calls
# ---------------------------------------------------------------------------

def resolve_indirect_call(
    insn: Instruction,
    all_instructions: dict[int, Instruction],
    ir: DisassemblyResult,
    vtables: list[VTableInfo] | None = None,
) -> ResolvedTarget | None:
    """Attempt to resolve an indirect call target.

    Handles:
    - call rax → trace rax backwards
    - call [reg+offset] → trace reg backwards
    - call [rip+offset] → direct data reference
    """
    if insn.mnemonic.lower() != "call":
        return None

    operands = insn.operands.strip()

    # Direct RIP-relative indirect call: call qword ptr [rip+offset]
    # Handles: [rip+0x60], [rip+60h], [rip + 0x60], [RIP + 60]
    rip_match = re.search(r'\[\s*(?:rip|RIP)\s*\+\s*(?:0x)?([0-9a-fA-F]+)\s*h?\s*\]', operands, re.IGNORECASE)
    if rip_match:
        offset = int(rip_match.group(1), 16)
        insn_size = insn.size if insn.size else 7  # Default 7 for x64 call
        target_rva = insn.address + insn_size + offset
        # Check if this points to a known function
        if target_rva in ir.functions:
            func = ir.functions[target_rva]
            return ResolvedTarget(
                instruction_addr=insn.address,
                target_addr=target_rva,
                target_name=func.name,
                resolution_method="constant",
                confidence=0.9,
            )

    # Register indirect: call rax, call rcx, etc.
    reg_match = re.match(r'^(r[a-z0-9]+)$', operands, re.IGNORECASE)
    if reg_match:
        reg = reg_match.group(1).lower()
        return _trace_register_to_target(reg, insn.address, all_instructions, ir, vtables)

    # Memory indirect: call qword ptr [reg+offset]
    mem_match = re.search(r'\[\s*(r[a-z0-9]+)\s*(?:\+\s*([^\]]+))?\s*\]', operands, re.IGNORECASE)
    if mem_match:
        base_reg = mem_match.group(1).lower()
        offset_str = mem_match.group(2)

        # Check if this matches a known callback struct
        if offset_str:
            offset_str = offset_str.strip().rstrip("h")
            try:
                offset = int(offset_str, 16) if offset_str.startswith("0x") else int(offset_str)
            except ValueError:
                offset = 0

            if offset != 0:
                cb_result = _check_callback_struct(base_reg, offset, ir)
                if cb_result:
                    return cb_result

        # Trace the base register backwards
        return _trace_register_to_target(base_reg, insn.address, all_instructions, ir, vtables)

    return None


def _trace_register_to_target(
    reg: str,
    call_addr: int,
    all_instructions: dict[int, Instruction],
    ir: DisassemblyResult,
    vtables: list[VTableInfo] | None,
    max_back: int = 30,
) -> ResolvedTarget | None:
    """Trace a register backwards to find its value source."""
    sorted_addrs = sorted(all_instructions.keys())
    idx = bisect.bisect_left(sorted_addrs, call_addr)

    for i in range(idx - 1, max(-1, idx - max_back - 1), -1):
        cur_addr = sorted_addrs[i]
        if call_addr - cur_addr > 0x200:
            break

        cur = all_instructions[cur_addr]

        # mov reg, immediate → constant target
        if cur.mnemonic == "mov":
            dest_match = re.match(r'^' + re.escape(reg) + r'\s*,\s*0x([0-9a-fA-F]+)$',
                                  cur.operands.strip(), re.IGNORECASE)
            if dest_match:
                target_va = int(dest_match.group(1), 16)
                if target_va in ir.functions:
                    func = ir.functions[target_va]
                    return ResolvedTarget(
                        instruction_addr=call_addr,
                        target_addr=target_va,
                        target_name=func.name,
                        resolution_method="constant",
                        confidence=0.95,
                    )

        # lea reg, [rip+offset] → data reference (possibly vtable pointer)
        if cur.mnemonic == "lea":
            dest_match = re.match(r'^' + re.escape(reg) + r'\s*,\s*\[\s*rip\s*\+\s*0x([0-9a-fA-F]+)\s*\]',
                                  cur.operands.strip(), re.IGNORECASE)
            if dest_match:
                offset = int(dest_match.group(1), 16)
                data_rva = cur_addr + (cur.size or 7) + offset
                # Check if this is a vtable address
                if vtables:
                    for vt in vtables:
                        if abs(vt.address - data_rva) < 0x10:
                            return ResolvedTarget(
                                instruction_addr=call_addr,
                                target_addr=vt.entries[0] if vt.entries else 0,
                                target_name=vt.name,
                                resolution_method="vtable",
                                confidence=0.7,
                            )

        # mov reg, other_reg → follow the chain
        if cur.mnemonic == "mov":
            src_match = re.match(r'^' + re.escape(reg) + r'\s*,\s*(r[a-z0-9]+)$',
                                 cur.operands.strip(), re.IGNORECASE)
            if src_match:
                reg = src_match.group(1).lower()
                continue

        # Register overwritten with unknown value → stop
        if re.match(r'^' + re.escape(reg) + r'\b', cur.operands.strip(), re.IGNORECASE):
            break

    return None


def _check_callback_struct(
    reg: str,
    offset: int,
    ir: DisassemblyResult,
) -> ResolvedTarget | None:
    """Check if [reg+offset] matches a known callback struct field."""
    # IO_STACK_LOCATION completion callback
    if offset in IO_COMPLETION_CALLBACK_OFFSETS:
        return None  # Needs runtime context to resolve

    # WDF queue callbacks
    if offset in WDF_QUEUE_CALLBACK_OFFSETS:
        return None  # Needs WDF context

    return None


# ---------------------------------------------------------------------------
# IR population
# ---------------------------------------------------------------------------

def populate_indirect_calls(
    ir: DisassemblyResult,
    all_instructions: dict[int, Instruction],
    pe_path: Path | None = None,
) -> None:
    """Scan all indirect calls in the IR and attempt to resolve targets.

    Populates:
    - ir.resolved_indirect_calls: {insn_addr: [target_addrs]}
    - ir.vtables: {vtable_addr: [func_addrs]}
    - ir.callback_registrations: [{type, handler_addr, registered_by}]
    """
    # Initialize new IR fields (Phase 8 extension)
    if not hasattr(ir, 'resolved_indirect_calls'):
        ir.resolved_indirect_calls = {}
    if not hasattr(ir, 'vtables'):
        ir.vtables = {}
    if not hasattr(ir, 'callback_registrations'):
        ir.callback_registrations = []

    # Identify vtables
    vtables: list[VTableInfo] = []
    if pe_path and pe_path.exists():
        vtables = identify_vtables(pe_path, ir)
        for vt in vtables:
            ir.vtables[vt.address] = vt.entries

    # Scan all indirect calls
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if not cfg:
            continue

        for block in cfg.blocks.values():
            for insn in block.instructions:
                if insn.mnemonic.lower() != "call":
                    continue
                # Check if indirect
                if not insn.api_target and ("[" in insn.operands or
                                            re.match(r'^(r[a-z0-9]+)$', insn.operands.strip(), re.IGNORECASE)):
                    target = resolve_indirect_call(insn, all_instructions, ir, vtables)
                    if target:
                        ir.resolved_indirect_calls.setdefault(insn.address, []).append(
                            target.target_addr
                        )

    # Detect callback registrations
    _detect_callback_registrations(ir)


def _detect_callback_registrations(ir: DisassemblyResult) -> None:
    """Detect callback registration patterns in function API calls."""
    for func_addr, api_names in ir.function_apis.items():
        func = ir.functions.get(func_addr)
        if func is None:
            continue

        cb_apis = set(api_names) & CALLBACK_REGISTER_APIS
        for api in cb_apis:
            # The callback handler is typically passed as a function pointer argument
            # We can't resolve the exact handler without more context, but we mark
            # the registration for further analysis
            ir.callback_registrations.append({
                "registered_by": api,
                "registered_in": func_addr,
                "callback_type": api,
                "handler_addr": 0,  # Requires deeper analysis
            })
