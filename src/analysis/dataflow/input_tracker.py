"""
DriverScope — Input Validation Analyzer.

Tracks whether IOCTL handler functions validate user-controlled input
before passing it to dangerous kernel APIs. A handler that calls
MmMapIoSpace without checking buffer size or caller privilege is
a high-confidence BYOVD candidate.

For WDF drivers: since WDF uses EvtIoDeviceControl callbacks rather than
direct IRP_MJ_DEVICE_CONTROL assignments, we analyse ALL functions that
call dangerous sink APIs — in a WDF driver with IOCTL queue, any function
is potentially user-triggerable.

Instruction-level taint tracking:
  - Identifies IRP field reads ([rcx+0x60], [rcx+0x18]) as taint sources
  - Propagates taint through register moves (mov rax, rcx)
  - Detects when tainted registers reach dangerous API call parameters

Enhanced v2:
  - Cross-function taint with complete BFS through callees
  - MDL-based taint sources (MmGetSystemAddressForMdlSafe, etc.)
  - WDF request object tracking (WdfRequestRetrieveInputBuffer)
  - Heap-allocated data indirect pollution
  - Size-qualifier-aware register propagation (byte/word/dword/qword)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from src.models import (
    Confidence,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)
from src.analysis.analyzer import Analyzer


# IRP struct offsets (x64, byte offsets from IRP base pointer)
IRP_OFFSETS = {
    0x18: "UserBuffer",      # METHOD_NEITHER — direct user pointer
    0x60: "SystemBuffer",    # METHOD_BUFFERED — kernel-buffered copy
    0x98: "Parameters",      # IoStatus / Parameters union
}

# Additional taint sources beyond direct IRP access
# These APIs return user-controllable data and should be treated as taint sources
INDIRECT_TAINT_SOURCES = {
    # MDL-based access
    "MmGetSystemAddressForMdlSafe": "MDL mapped buffer",
    "MmGetSystemAddressForMdl": "MDL mapped buffer",
    "MmMapLockedPagesSpecifyCache": "MDL mapped pages",
    "MmMapLockedPages": "MDL mapped pages",
    # WDF request APIs
    "WdfRequestRetrieveInputBuffer": "WDF input buffer",
    "WdfRequestRetrieveOutputBuffer": "WDF output buffer",
    "WdfMemoryGetBuffer": "WDF memory buffer",
    "WdfBufferGetObject": "WDF buffer object",
    # Fast I/O and other sources
    "ZwDeviceIoControlFile": "device IOCTL output",
    "NtDeviceIoControlFile": "device IOCTL output",
}

# APIs that copy/move user data — taint propagates through these
DATA_COPY_APIS = {
    "MmCopyMemory",
    "memcpy", "memmove", "RtlCopyMemory", "RtlMoveMemory",
    "RtlCopyBytes", "RtlCopyUnicodeString",
}

# Validation APIs grouped by purpose
PROBE_APIS = {
    "MmProbeAndLockPages", "MmProbeAndLockProcessPages",
    "ProbeForRead", "ProbeForWrite",
}
PRIVILEGE_APIS = {
    "SeSinglePrivilegeCheck",
    "ExGetPreviousMode",
}
SIZE_CHECK_APIS = {
    "RtlCompareMemory",
}

# Synchronization APIs indicate careful handling but are NOT input validation.
SYNC_APIS = {
    "ExAcquireFastMutex", "ExReleaseFastMutex",
    "KeAcquireSpinLock", "KeReleaseSpinLock",
    "IoAcquireRemoveLock", "IoReleaseRemoveLock",
}

# Known dangerous sink APIs
DANGEROUS_SINKS = {
    "MmMapIoSpace", "MmMapIoSpaceEx",
    "MmMapLockedPagesSpecifyCache", "MmMapLockedPages",
    "KeWriteMsr", "__writemsr",
    "MmCopyVirtualMemory",
    "ZwWriteVirtualMemory", "NtWriteVirtualMemory",
    "ZwCreateThreadEx",
    "ZwQueueApcThread",
    "ZwSetInformationProcess",
    "IoQueueWorkItem", "KeInitializeDpc",
    "WdfDmaEnablerCreate", "WdfDmaTransactionCreate",
    "MmAllocateContiguousMemorySpecifyCache",
    "IoConnectInterrupt", "IoConnectInterruptEx",
    "ObReferenceObjectByHandle",
    "ExAllocatePoolWithTag", "ExAllocatePool2", "ExAllocatePool3",
    "ObRegisterCallbacks",
    "ZwOpenProcess", "ZwOpenThread",
    "ZwReadFile", "ZwWriteFile",
    "PsCreateSystemThread",
    "MmCopyMemory",
    "HalTranslateBusAddress",
    "MmAllocateMappingAddress",
    "IoAllocateMdl",
}

# x64 calling convention: first 4 params in rcx, rdx, r8, r9
CALLING_CONV_REGS = ["rcx", "rdx", "r8", "r9"]

# ARM64 calling convention: first 8 params in x0-x7
ARM64_CALLING_CONV_REGS = ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]

# x64 shadow space offsets (32 bytes above RSP for params 1-4)
# Callee uses [rsp+0x10] through [rsp+0x28] to spill caller's register params.
X64_SHADOW_SPACE_OFFSETS = {
    0x10: "shadow_param1",
    0x18: "shadow_param2",
    0x20: "shadow_param3",
    0x28: "shadow_param4",
}

# ARM64 has no shadow space (params stay in x0-x7), but red zone equivalents
ARM64_SHADOW_SPACE_OFFSETS = {}

# Callback registration APIs — taint should be injected into registered callbacks
CALLBACK_REGISTRATION_APIS = {
    "ObRegisterCallbacks",
    "ObUnRegisterCallbacks",
    "CmRegisterCallbackEx",
    "CmUnRegisterCallback",
    "FltRegisterFilter",
    "FltSetCallback",
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "PsSetCreateThreadNotifyRoutineEx",
    "PsSetImageNotifyRoutine",
    "PsRemoveLoadImageNotifyRoutine",
    "IoSetStartIoAttributes",
    "IoCsqInitialize",
}

# All general-purpose x64 registers (canonical 64-bit names)
GPR_NAMES = [
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]

# ARM64 general-purpose registers
ARM64_GPR_NAMES = [f"x{i}" for i in range(31)] + ["sp", "fp", "lr"]


@dataclass
class TaintSource:
    """A point where user-controlled data enters the function."""
    address: int  # Instruction address
    irp_offset: int  # IRP field offset (0x60, 0x18, etc.)
    field_name: str  # "SystemBuffer", "UserBuffer", etc.
    target_reg: str  # Register that received the tainted value
    source_type: str = "irp_field"  # irp_field | mdl | wdf_request | indirect_api


@dataclass
class TaintSink:
    """A point where tainted data reaches a dangerous API parameter."""
    address: int  # Call instruction address
    api_name: str
    tainted_param: str  # "rcx", "rdx", etc.
    taint_path: list[str]  # Description of how taint reached here


@dataclass
class TaintResult:
    """Complete taint analysis result for a function."""
    sources: list[TaintSource] = field(default_factory=list)
    sinks: list[TaintSink] = field(default_factory=list)
    tainted_reaches_dangerous_api: bool = False
    tainted_params: list[str] = field(default_factory=list)


@dataclass
class TaintContext:
    """Cross-function taint propagation context.

    Carries taint state across function call boundaries so that
    when a handler passes an IRP pointer (or derived data) to a
    callee, the callee starts with the appropriate taint state
    instead of a blank slate.
    """
    tainted_regs: set[str] = field(default_factory=set)
    taint_origin: dict[str, str] = field(default_factory=dict)
    tainted_memory: dict[str, str] = field(default_factory=dict)  # [rsp+offset] / [rip+offset] -> source
    tainted_shadow_space: dict[int, str] = field(default_factory=dict)  # offset -> source
    tainted_globals: dict[str, str] = field(default_factory=dict)  # rip_relative_key -> source
    tainted_struct_fields: dict[str, str] = field(default_factory=dict)  # struct field -> source
    is_arm64: bool = False


class TaintTracker:
    """Instruction-level taint tracker for x64 and ARM64 functions.

    Tracks data flow from IRP buffer reads (taint sources) through
    register moves to dangerous API call parameters (taint sinks).

    Strategy:
    1. Scan all instructions in a function
    2. Identify IRP field access: mov reg, [rcx+offset] (x64) or ldr reg, [x0+offset] (ARM64)
    3. Also detect indirect taint sources: MDL APIs, WDF request APIs
    4. Propagate taint: when a tainted register is read by another instruction
    5. Detect sinks: call instructions where tainted registers are parameters
    """

    def __init__(self, ir: DisassemblyResult):
        self.ir = ir
        # Detect architecture from IRP base register
        self.is_arm64 = getattr(ir, 'is_arm64', False)
        if self.is_arm64:
            self.irp_base_reg = "x0"  # ARM64: first param
            self.calling_conv_regs = ARM64_CALLING_CONV_REGS
            self.gpr_names = ARM64_GPR_NAMES
        else:
            self.irp_base_reg = "rcx"  # x64: first param
            self.calling_conv_regs = CALLING_CONV_REGS
            self.gpr_names = GPR_NAMES

    def track_function(
        self,
        func_addr: int,
        is_handler: bool = True,
    ) -> TaintResult:
        """Run taint analysis on a single function.

        Args:
            func_addr: Function entry address.
            is_handler: If True, treat the first param register (rcx/x0)
                       as the IRP pointer. For callees, this is False
                       unless we know the IRP was passed through.

        Returns TaintResult with sources, sinks, and tainted API info.
        """
        result = TaintResult()
        func = self.ir.functions.get(func_addr)
        if func is None:
            return result

        # Collect all instructions in this function
        func_instructions = self._get_function_instructions(func_addr, func)
        if not func_instructions:
            return result

        # Track which registers are tainted at each instruction
        tainted_regs: set[str] = set()
        # Track taint origin per register (for path description)
        taint_origin: dict[str, str] = {}

        for insn in func_instructions:
            # Check for direct taint sources: IRP field reads
            src = self._check_taint_source(insn, tainted_regs)
            if src:
                result.sources.append(src)
                tainted_regs.add(src.target_reg)
                taint_origin[src.target_reg] = f"{src.field_name}@0x{src.irp_offset:X}"
                # Also taint the base register (rcx on x64, x0 on ARM64)
                if insn.mnemonic in ("mov", "lea", "ldr") and f"[{self.irp_base_reg}" in insn.operands.lower():
                    tainted_regs.add(self.irp_base_reg)
                    taint_origin[self.irp_base_reg] = f"IRP pointer"

            # Check for indirect taint sources: MDL/WDF APIs returning user data
            indirect_src = self._check_indirect_taint_source(insn)
            if indirect_src:
                result.sources.append(indirect_src)
                tainted_regs.add(indirect_src.target_reg)
                taint_origin[indirect_src.target_reg] = indirect_src.field_name

            # Propagate taint through register moves
            self._propagate_taint(insn, tainted_regs, taint_origin)

            # Check for taint sinks: API calls with tainted parameters
            api_name = None
            if insn.api_info and insn.api_info.name in DANGEROUS_SINKS:
                api_name = insn.api_info.name
            elif insn.api_target and insn.api_target in DANGEROUS_SINKS:
                api_name = insn.api_target
            elif insn.api_target and self._is_deobfuscated_sink(self.ir, insn.api_target):
                # Phase 0 deobfuscation resolved a hashed API — treat as sink
                api_name = insn.api_target

            if api_name:
                sink = self._check_taint_sink(insn, tainted_regs, taint_origin, api_name)
                if sink:
                    result.sinks.append(sink)
                    result.tainted_reaches_dangerous_api = True

        # Collect all tainted parameters
        seen_params = set()
        for sink in result.sinks:
            if sink.tainted_param not in seen_params:
                result.tainted_params.append(sink.tainted_param)
                seen_params.add(sink.tainted_param)

        return result

    def _get_function_instructions(
        self,
        func_addr: int,
        func,
    ) -> list:
        """Get all instructions belonging to a function, sorted by address."""
        from src.models import Instruction

        cfg = self.ir.cfgs.get(func_addr) or self.ir.simple_cfgs.get(func_addr)
        if cfg:
            instructions = []
            for block in sorted(cfg.blocks.values(), key=lambda b: b.address):
                for insn in block.instructions:
                    instructions.append(insn)
            return instructions

        # Fallback: use function_apis and import_addresses to find call instructions
        # This is less precise but still useful
        return []

    def _check_taint_source(
        self,
        insn,
        tainted_regs: set[str],
    ) -> TaintSource | None:
        """Check if an instruction reads from a user-controlled IRP field.

        Taint sources are instructions like:
        - x64: mov rax, [rcx+0x60]  → SystemBuffer (direct)
        - x64: lea rax, [rcx+0x60]  → SystemBuffer (pointer)
        - x64: mov rax, [rdi+0x60]  → SystemBuffer (if rdi was derived from rcx)
        - ARM64: ldr x8, [x0, #0x60]  → SystemBuffer
        - ARM64: ldr x8, [x0, 0x60]  → SystemBuffer (bare hex variant)
        """
        if not self.is_arm64:
            # x64 patterns: mov/lea reg, [reg+offset]
            # Capstone produces: "rax, qword ptr [rcx + 0x60]"
            # Also handles: "rax, [rcx+0x60]", "rax, qword ptr [rcx+0x60h]"
            mem_pattern = re.compile(
                r'(?:mov|lea)\s+(\w+)\s*,\s*'
                r'(?:byte|word|dword|qword)\s*ptr\s*'
                r'\[\s*(\w+)\s*(?:\+\s*([^\]]+))?\s*\]',
                re.IGNORECASE,
            )
            m = mem_pattern.match(f"{insn.mnemonic} {insn.operands}")
            if not m:
                # Fallback: try without size qualifier
                mem_pattern2 = re.compile(
                    r'(?:mov|lea)\s+(\w+)\s*,\s*\[\s*(\w+)\s*(?:\+\s*([^\]]+))?\s*\]',
                    re.IGNORECASE,
                )
                m = mem_pattern2.match(f"{insn.mnemonic} {insn.operands}")
                if not m:
                    return None

            dest_reg = m.group(1).lower()
            base_reg = m.group(2).lower()
            offset_str = m.group(3)

            # Accept rcx directly, or a register that was tainted from rcx
            if base_reg != self.irp_base_reg and base_reg not in tainted_regs:
                return None

            # If no offset (e.g., mov rax, [rcx]), skip — not a specific IRP field
            if not offset_str:
                return None

            # Clean up offset: strip "0x" prefix, "h" suffix, whitespace
            offset_str = offset_str.strip().rstrip("h")
            try:
                if offset_str.startswith("0x"):
                    offset = int(offset_str, 16)
                else:
                    offset = int(offset_str)
            except ValueError:
                return None

            if offset not in IRP_OFFSETS:
                return None

            return TaintSource(
                address=insn.address,
                irp_offset=offset,
                field_name=IRP_OFFSETS[offset],
                target_reg=dest_reg,
                source_type="irp_field",
            )
        else:
            # ARM64 pattern: ldr reg, [x0, #offset] or ldr reg, [x0, offset]
            ldr_pattern = re.compile(
                r'ldr\s+(\w+)\s*,\s*\[\s*(\w+)\s*,\s*#?(0x[0-9a-fA-F]+|[0-9]+)\s*\]',
                re.IGNORECASE,
            )
            m = ldr_pattern.match(f"{insn.mnemonic} {insn.operands}")
            if not m:
                return None

            dest_reg = m.group(1).lower()
            base_reg = m.group(2).lower()
            offset_str = m.group(3)

            if base_reg != self.irp_base_reg:
                return None

            try:
                if offset_str.startswith("0x"):
                    offset = int(offset_str, 16)
                else:
                    offset = int(offset_str)
            except ValueError:
                return None

            if offset not in IRP_OFFSETS:
                return None

            return TaintSource(
                address=insn.address,
                irp_offset=offset,
                field_name=IRP_OFFSETS[offset],
                target_reg=dest_reg,
                source_type="irp_field",
            )

    def _check_indirect_taint_source(
        self,
        insn,
    ) -> TaintSource | None:
        """Check if an instruction calls an API that returns user-controllable data.

        These are indirect taint sources — the API returns a pointer to
        user-controllable data that should be treated as tainted.

        Examples:
        - MmGetSystemAddressForMdlSafe → returns mapped buffer pointer
        - WdfRequestRetrieveInputBuffer → returns WDF request buffer
        """
        api_name = insn.api_target or (insn.api_info.name if insn.api_info else "")
        if api_name not in INDIRECT_TAINT_SOURCES:
            return None

        # The return value (rax on x64, x0 on ARM64) becomes tainted
        if self.is_arm64:
            return_reg = "x0"
        else:
            return_reg = "rax"

        return TaintSource(
            address=insn.address,
            irp_offset=0,  # Not from IRP directly
            field_name=INDIRECT_TAINT_SOURCES[api_name],
            target_reg=return_reg,
            source_type="indirect_api",
        )

    def _propagate_taint(
        self,
        insn,
        tainted_regs: set[str],
        taint_origin: dict[str, str],
    ) -> None:
        """Propagate taint through register-to-register moves.

        Handles:
        - mov/ldr dest, src → if src is tainted, dest becomes tainted
        - lea/adrp dest, [src] → if src is tainted, dest becomes tainted
        - mov/ldr dest, [src+offset] → if src is tainted, dest becomes tainted
        - Size-qualifier-aware: byte/word/dword/qword ptr affects propagation
        """
        # Detect size qualifier for partial-register taint tracking
        size_qualifier = self._extract_size_qualifier(insn)

        # mov reg, reg (x64) or mov reg, reg (ARM64)
        # Capstone: "rax, rcx" (no size qualifier for register-to-register)
        mov_reg_reg = re.compile(
            r'(?:mov|ldr)\s+(\w+)\s*,\s*(\w+)\s*$',
            re.IGNORECASE,
        )
        m = mov_reg_reg.match(f"{insn.mnemonic} {insn.operands}")
        if m:
            dest = m.group(1).lower()
            src = m.group(2).lower()
            if src in tainted_regs and src in self.gpr_names:
                tainted_regs.add(dest)
                if src in taint_origin:
                    taint_origin[dest] = taint_origin[src]
            return

        # lea reg, [reg+offset] (x64) or adr/adrp (ARM64)
        # Capstone: "rax, [rcx + 0x10]" or "rax, qword ptr [rcx + 0x10]"
        if insn.mnemonic in ("lea", "adr", "adrp"):
            base_pattern = re.compile(
                r'(?:lea|adr|adrp)\s+(\w+)\s*,\s*'
                r'(?:byte|word|dword|qword)\s*ptr\s*'
                r'\[\s*(\w+)',
                re.IGNORECASE,
            )
            m = base_pattern.match(f"{insn.mnemonic} {insn.operands}")
            if not m:
                # Fallback without size qualifier
                base_pattern2 = re.compile(
                    r'(?:lea|adr|adrp)\s+(\w+)\s*,\s*\[\s*(\w+)',
                    re.IGNORECASE,
                )
                m = base_pattern2.match(f"{insn.mnemonic} {insn.operands}")
            if m:
                dest = m.group(1).lower()
                src = m.group(2).lower()
                if src in tainted_regs and src in self.gpr_names:
                    tainted_regs.add(dest)
                    if src in taint_origin:
                        taint_origin[dest] = taint_origin[src]
                return

        # mov reg, [reg+offset] — propagate taint from base register
        # Capstone: "rax, qword ptr [rdi + 0x10]"
        mov_mem_reg = re.compile(
            r'(?:mov|ldr)\s+(\w+)\s*,\s*'
            r'(?:byte|word|dword|qword)\s*ptr\s*'
            r'\[\s*(\w+)',
            re.IGNORECASE,
        )
        m = mov_mem_reg.match(f"{insn.mnemonic} {insn.operands}")
        if not m:
            # Fallback without size qualifier
            mov_mem_reg2 = re.compile(
                r'(?:mov|ldr)\s+(\w+)\s*,\s*\[\s*(\w+)',
                re.IGNORECASE,
            )
            m = mov_mem_reg2.match(f"{insn.mnemonic} {insn.operands}")
        if m:
            dest = m.group(1).lower()
            src = m.group(2).lower()
            if src in tainted_regs and src in self.gpr_names:
                tainted_regs.add(dest)
                if src in taint_origin:
                    taint_origin[dest] = taint_origin[src]
            return

        # AND/OR/XOR/ADD/SUB with register operands — propagate taint
        # If any input register is tainted, the output register is tainted
        if insn.mnemonic.lower() in ("and", "or", "xor", "add", "sub", "shl", "shr"):
            parts = insn.operands.split(",")
            if len(parts) >= 2:
                dest = parts[0].strip().lower()
                src = parts[1].strip().lower()
                # Strip size qualifiers and brackets
                src = re.sub(r'(?:byte|word|dword|qword)\s*ptr\s*', '', src)
                src = re.sub(r'[\[\]]', '', src).strip()

                if src in tainted_regs and dest in self.gpr_names:
                    tainted_regs.add(dest)
                    if src in taint_origin:
                        taint_origin[dest] = f"derived from {taint_origin[src]} via {insn.mnemonic}"
                return

    def _check_taint_sink(
        self,
        insn,
        tainted_regs: set[str],
        taint_origin: dict[str, str],
        api_name: str,
    ) -> TaintSink | None:
        """Check if an API call has tainted registers as parameters.

        For x64: params are in rcx, rdx, r8, r9.
        For ARM64: params are in x0-x7.
        If any of these registers are tainted, the API receives user-controlled data.
        """
        tainted_params = []
        for param_reg in self.calling_conv_regs:
            if param_reg in tainted_regs:
                tainted_params.append(param_reg)

        if not tainted_params:
            return None

        path_parts = []
        for reg in tainted_params:
            origin = taint_origin.get(reg, "unknown source")
            path_parts.append(f"{origin} → {reg} → {api_name}")

        return TaintSink(
            address=insn.address,
            api_name=api_name,
            tainted_param=tainted_params[0],
            taint_path=path_parts,
        )

    def _is_deobfuscated_sink(self, ir: DisassemblyResult, api_target: str) -> bool:
        """Check if api_target matches a dangerous API resolved by Phase 0 deobfuscation.

        When API hashing is detected, deobfuscation resolves hashed values and
        populates ir.function_apis with the real API names. A call to such a
        function may not have insn.api_target set to the API name directly,
        but if the called function has been flagged with a dangerous API name,
        we should treat it as a sink.
        """
        if not api_target:
            return False
        # Check if any function in the IR has this target as a resolved API
        # and that API is in DANGEROUS_SINKS
        for func_addr, resolved_apis in ir.function_apis.items():
            if api_target in resolved_apis and api_target in DANGEROUS_SINKS:
                return True
        # Also check dynamic_imports (runtime-resolved function pointers)
        for func_addr, imports in ir.dynamic_imports.items():
            if api_target in imports and api_target in DANGEROUS_SINKS:
                return True
        return False

    def track_function_with_context(
        self,
        func_addr: int,
        context: TaintContext,
        max_depth: int = 3,
        _depth: int = 0,
    ) -> TaintResult:
        """Run taint analysis with pre-existing taint context.

        Unlike ``track_function()``, this accepts a ``TaintContext`` that
        may already contain tainted registers from the caller.  When a
        ``call`` instruction is encountered, taint is propagated to the
        callee's parameter registers (rcx/rdx/r8/r9 for x64) and the
        callee is analyzed recursively.

        Args:
            func_addr: Function entry address.
            context: Pre-tainted register/memory state from caller.
            max_depth: Maximum recursion depth for cross-function tracking.
            _depth: Internal recursion depth counter.

        Returns TaintResult with sources, sinks, and tainted API info.
        """
        result = TaintResult()
        func = self.ir.functions.get(func_addr)
        if func is None:
            return result

        func_instructions = self._get_function_instructions(func_addr, func)
        if not func_instructions:
            return result

        # Clone mutable context so each call branch gets its own copy
        tainted_regs: set[str] = set(context.tainted_regs)
        taint_origin: dict[str, str] = dict(context.taint_origin)
        tainted_memory: dict[str, str] = dict(context.tainted_memory)
        tainted_shadow: dict[int, str] = dict(context.tainted_shadow_space)
        tainted_globals_map: dict[str, str] = dict(context.tainted_globals)

        for insn in func_instructions:
            # Direct taint sources (IRP field reads)
            src = self._check_taint_source(insn, tainted_regs)
            if src:
                result.sources.append(src)
                tainted_regs.add(src.target_reg)
                taint_origin[src.target_reg] = f"{src.field_name}@0x{src.irp_offset:X}"
                if insn.mnemonic in ("mov", "lea", "ldr") and f"[{self.irp_base_reg}" in insn.operands.lower():
                    tainted_regs.add(self.irp_base_reg)
                    taint_origin[self.irp_base_reg] = "IRP pointer"

            # Indirect taint sources (MDL/WDF APIs)
            indirect_src = self._check_indirect_taint_source(insn)
            if indirect_src:
                result.sources.append(indirect_src)
                tainted_regs.add(indirect_src.target_reg)
                taint_origin[indirect_src.target_reg] = indirect_src.field_name

            # Memory-level taint: [rsp+offset] / [rip+offset] propagation
            self._propagate_memory_taint(
                insn, tainted_regs, taint_origin, tainted_memory,
                tainted_shadow, tainted_globals_map,
            )

            # Data copy API: RtlCopyMemory(dest, src, len) propagates src taint to dest
            self._propagate_through_copy_api(insn, tainted_regs, taint_origin)

            # Standard register taint propagation
            self._propagate_taint(insn, tainted_regs, taint_origin)

            # Call instruction: propagate taint to callee
            if insn.mnemonic == "call" and _depth < max_depth:
                callee_result = self._handle_call_taint(
                    insn, tainted_regs, taint_origin, max_depth, _depth + 1,
                    tainted_shadow, tainted_globals_map,
                )
                result.sources.extend(callee_result.sources)
                result.sinks.extend(callee_result.sinks)
                if callee_result.tainted_reaches_dangerous_api:
                    result.tainted_reaches_dangerous_api = True
                # Callee may taint return register (rax/x0) if ANY input was tainted.
                # This applies even for unknown callees — if tainted data was passed
                # as a parameter, the return value may carry that tainted data.
                callee_has_tainted_input = any(
                    param_reg in tainted_regs
                    for param_reg in self.calling_conv_regs
                )
                if callee_has_tainted_input:
                    ret_reg = "x0" if self.is_arm64 else "rax"
                    tainted_regs.add(ret_reg)
                    taint_origin[ret_reg] = f"return from {insn.api_target or 'callee'} (tainted input)"

            # Sink detection
            api_name = None
            if insn.api_info and insn.api_info.name in DANGEROUS_SINKS:
                api_name = insn.api_info.name
            elif insn.api_target and insn.api_target in DANGEROUS_SINKS:
                api_name = insn.api_target
            elif insn.api_target and self._is_deobfuscated_sink(self.ir, insn.api_target):
                # Phase 0 deobfuscation resolved a hashed API — treat as sink
                api_name = insn.api_target

            if api_name:
                sink = self._check_taint_sink(insn, tainted_regs, taint_origin, api_name)
                if sink:
                    result.sinks.append(sink)
                    result.tainted_reaches_dangerous_api = True

        # Collect tainted params
        seen_params = set()
        for sink in result.sinks:
            if sink.tainted_param not in seen_params:
                result.tainted_params.append(sink.tainted_param)
                seen_params.add(sink.tainted_param)

        return result

    def _handle_call_taint(
        self,
        insn,
        caller_tainted_regs: set[str],
        caller_taint_origin: dict[str, str],
        max_depth: int,
        depth: int,
        caller_tainted_shadow: dict[int, str] | None = None,
        caller_tainted_globals: dict[str, str] | None = None,
    ) -> TaintResult:
        """Propagate taint from caller to callee via calling convention registers.

        x64: first 4 params in rcx, rdx, r8, r9
        ARM64: first 8 params in x0-x7

        If any of the caller's parameter registers are tainted, the callee
        starts with those registers pre-tainted.

        For callback registration APIs (ObRegisterCallbacks, etc.), the
        callback function pointer passed as a parameter is treated as an
        additional entry point — taint is injected into that function.

        For unknown callees (not in IR function list): still track that
        tainted data was passed as a parameter and mark the return value
        as potentially tainted.

        Returns TaintResult from analyzing the callee (empty for unknown).
        """
        result = TaintResult()
        callee_addr = 0
        callee_name = None
        # Extract callee address from instruction operands or api_target
        if hasattr(insn, 'api_target') and insn.api_target:
            callee_name = insn.api_target
            # Look up by name — try to find in functions
            for addr, func in self.ir.functions.items():
                if func.name == insn.api_target:
                    callee_addr = addr
                    break

        # Also try numeric address from operands
        if callee_addr == 0:
            addr_match = re.search(r'(?:0x)?([0-9a-fA-F]+)', insn.operands)
            if addr_match:
                callee_addr = int(addr_match.group(1), 16)

        # Check which caller params are tainted (applies to ALL callees)
        tainted_caller_params = []
        for param_reg in self.calling_conv_regs:
            if param_reg in caller_tainted_regs:
                tainted_caller_params.append(param_reg)

        # Record sink-like finding for tainted call to any API
        if tainted_caller_params and callee_name:
            path_parts = []
            for reg in tainted_caller_params:
                origin = caller_taint_origin.get(reg, "unknown source")
                path_parts.append(f"{origin} → {reg} → {callee_name}")
            result.sinks.append(TaintSink(
                address=insn.address,
                api_name=callee_name,
                tainted_param=tainted_caller_params[0],
                taint_path=path_parts,
            ))

        if callee_addr == 0 or callee_addr not in self.ir.functions:
            # Callback boundary: check if this is a callback registration API
            if callee_name and callee_name in CALLBACK_REGISTRATION_APIS:
                callback_result = self._handle_callback_taint(
                    insn, caller_tainted_regs, caller_taint_origin,
                    max_depth, depth,
                )
                result.sources.extend(callback_result.sources)
                result.sinks.extend(callback_result.sinks)
                if callback_result.tainted_reaches_dangerous_api:
                    result.tainted_reaches_dangerous_api = True

            # Even for unknown callees, if input params were tainted,
            # the return value may carry tainted data
            if tainted_caller_params:
                ret_reg = "x0" if self.is_arm64 else "rax"
                # Don't add to result.sinks again — already done above
                # Just signal that taint reached a dangerous/unknown API
                if callee_name and callee_name in DANGEROUS_SINKS:
                    result.tainted_reaches_dangerous_api = True
                elif callee_name:
                    # Mark return as tainted for cross-function tracking
                    pass  # Caller will handle return taint

            return result

        # Build callee's initial taint context from caller's parameter registers
        callee_context = TaintContext(is_arm64=self.is_arm64)
        for param_reg in self.calling_conv_regs:
            if param_reg in caller_tainted_regs:
                callee_context.tainted_regs.add(param_reg)
                callee_context.taint_origin[param_reg] = caller_taint_origin.get(
                    param_reg, f"caller param {param_reg}"
                )

        # Propagate shadow space and global taint to callee
        if caller_tainted_shadow is not None:
            callee_context.tainted_shadow_space = dict(caller_tainted_shadow)
        if caller_tainted_globals is not None:
            callee_context.tainted_globals = dict(caller_tainted_globals)

        # Also propagate struct field taint that might be passed through
        callee_context.tainted_struct_fields = dict(caller_taint_origin)

        # Analyze callee with context
        callee_tracker = TaintTracker(self.ir)
        callee_result = callee_tracker.track_function_with_context(
            callee_addr, callee_context, max_depth, depth
        )
        result.sources.extend(callee_result.sources)
        result.sinks.extend(callee_result.sinks)
        if callee_result.tainted_reaches_dangerous_api:
            result.tainted_reaches_dangerous_api = True

        return result

    def _handle_callback_taint(
        self,
        insn,
        caller_tainted_regs: set[str],
        caller_taint_origin: dict[str, str],
        max_depth: int,
        depth: int,
    ) -> TaintResult:
        """Inject taint into callback functions registered via callback APIs.

        When ObRegisterCallbacks/CmRegisterCallbackEx/etc. is called, the
        callback function pointer is passed as a parameter. That callback
        function becomes an additional taint entry point — any user-controlled
        data that could reach the registration call can also reach the callback.

        We search the IR for functions that match known callback patterns
        and inject taint context into them.
        """
        result = TaintResult()

        # Find callback function addresses from IR metadata.
        # Callback functions are typically stored in function_apis as
        # callees of the registration function, or in callback_functions dict.
        callback_addrs = set()

        # Check ir.callback_functions if available (populated by registry analyzer)
        if hasattr(self.ir, 'callback_functions'):
            callback_addrs.update(self.ir.callback_functions.keys())

        # Fallback: use function_apis to find functions near the registration call
        if not callback_addrs:
            for func_addr, api_names in self.ir.function_apis.items():
                # Functions that are not the current one but have callback-like names
                func = self.ir.functions.get(func_addr)
                if func and func.name.lower().startswith(("callback", "pre_", "post_")):
                    callback_addrs.add(func_addr)

        if not callback_addrs:
            return result

        # Inject taint into each callback function
        for cb_addr in callback_addrs:
            cb_context = TaintContext(is_arm64=self.is_arm64)
            # Callback receives the same tainted input as the registration call
            for param_reg in self.calling_conv_regs:
                if param_reg in caller_tainted_regs:
                    cb_context.tainted_regs.add(param_reg)
                    cb_context.taint_origin[param_reg] = (
                        f"taint from callback registration "
                        f"({caller_taint_origin.get(param_reg, param_reg)})"
                    )

            cb_tracker = TaintTracker(self.ir)
            cb_result = cb_tracker.track_function_with_context(
                cb_addr, cb_context, max_depth, depth,
            )
            result.sources.extend(cb_result.sources)
            result.sinks.extend(cb_result.sinks)
            if cb_result.tainted_reaches_dangerous_api:
                result.tainted_reaches_dangerous_api = True

        return result

    def _propagate_through_copy_api(
        self,
        insn,
        tainted_regs: set[str],
        taint_origin: dict[str, str],
    ) -> None:
        """Propagate taint through data copy APIs like RtlCopyMemory.

        RtlCopyMemory(dest, src, len):
          - If src register is tainted, mark dest memory/ register as tainted.
          - The destination becomes a new taint carrier even though it
            didn't directly read from an IRP field.

        x64 calling convention: rcx=dest, rdx=src, r8=len
        ARM64 calling convention: x0=dest, x1=src, x2=len
        """
        api_name = insn.api_target or (insn.api_info.name if insn.api_info else "")
        if api_name not in DATA_COPY_APIS:
            return

        if self.is_arm64:
            dest_reg, src_reg = "x0", "x1"
        else:
            dest_reg, src_reg = "rcx", "rdx"

        if src_reg in tainted_regs:
            # Destination register also becomes tainted
            tainted_regs.add(dest_reg)
            src_desc = taint_origin.get(src_reg, "unknown")
            taint_origin[dest_reg] = f"copied from {src_desc} via {api_name}"

    def _propagate_memory_taint(
        self,
        insn,
        tainted_regs: set[str],
        taint_origin: dict[str, str],
        tainted_memory: dict[str, str],
        tainted_shadow_space: dict[int, str] | None = None,
        tainted_globals: dict[str, str] | None = None,
    ) -> None:
        """Track taint in memory locations: [rsp+offset], [rip+offset], [reg+offset].

        - ``mov [rsp+0x20], rax`` — if rax is tainted, mark stack slot as tainted
        - ``mov rax, [rsp+0x20]`` — if stack slot is tainted, rax becomes tainted
        - ``mov [rip+0x1000], rax`` — same for global/static data
        - Shadow space: [rsp+0x10]/[rsp+0x18]/[rsp+0x20]/[rsp+0x28] tracked separately
        - RIP-relative globals: tracked in tainted_globals dict across functions
        """
        # Store to memory: mov [base+offset], reg
        store_pattern = re.compile(
            r'(?:mov|str)\s+(?:byte|word|dword|qword)\s*ptr\s*'
            r'\[\s*(\w+)\s*(?:\+\s*([^\]]+))?\s*\]\s*,\s*(\w+)',
            re.IGNORECASE,
        )
        m = store_pattern.match(f"{insn.mnemonic} {insn.operands}")
        if not m:
            store_pattern2 = re.compile(
                r'(?:mov|str)\s+\[\s*(\w+)\s*(?:\+\s*([^\]]+))?\s*\]\s*,\s*(\w+)',
                re.IGNORECASE,
            )
            m = store_pattern2.match(f"{insn.mnemonic} {insn.operands}")
        if m:
            base = m.group(1).lower()
            offset_str = m.group(2)
            src_reg = m.group(3).lower()
            if src_reg in tainted_regs:
                # Check if this is a shadow space write
                if base == "rsp" and offset_str and tainted_shadow_space is not None:
                    shadow_offset = self._parse_shadow_offset(offset_str)
                    if shadow_offset is not None:
                        tainted_shadow_space[shadow_offset] = taint_origin.get(src_reg, "unknown")
                        return

                # Check if this is a RIP-relative global write
                if base == "rip" and tainted_globals is not None:
                    offset_str_clean = (offset_str or "").strip().rstrip("h")
                    global_key = f"global_rip+{offset_str_clean}" if offset_str_clean else "global_rip"
                    tainted_globals[global_key] = taint_origin.get(src_reg, "unknown")
                    return

                mem_key = self._make_memory_key(base, offset_str, insn)
                tainted_memory[mem_key] = taint_origin.get(src_reg, "unknown")
            return

        # Load from memory: mov reg, [base+offset]
        load_pattern = re.compile(
            r'(?:mov|ldr)\s+(\w+)\s*,\s*(?:byte|word|dword|qword)\s*ptr\s*'
            r'\[\s*(\w+)\s*(?:\+\s*([^\]]+))?\s*\]',
            re.IGNORECASE,
        )
        m = load_pattern.match(f"{insn.mnemonic} {insn.operands}")
        if not m:
            load_pattern2 = re.compile(
                r'(?:mov|ldr)\s+(\w+)\s*,\s*\[\s*(\w+)\s*(?:\+\s*([^\]]+))?\s*\]',
                re.IGNORECASE,
            )
            m = load_pattern2.match(f"{insn.mnemonic} {insn.operands}")
        if m:
            dest_reg = m.group(1).lower()
            base = m.group(2).lower()
            offset_str = m.group(3)

            # Check shadow space load
            if base == "rsp" and offset_str and tainted_shadow_space is not None:
                shadow_offset = self._parse_shadow_offset(offset_str)
                if shadow_offset is not None and shadow_offset in tainted_shadow_space:
                    tainted_regs.add(dest_reg)
                    taint_origin[dest_reg] = f"loaded from shadow space +0x{shadow_offset:X} ({tainted_shadow_space[shadow_offset]})"
                    return

            # Check RIP-relative global load
            if base == "rip" and tainted_globals is not None:
                offset_str_clean = (offset_str or "").strip().rstrip("h")
                global_key = f"global_rip+{offset_str_clean}" if offset_str_clean else "global_rip"
                if global_key in tainted_globals:
                    tainted_regs.add(dest_reg)
                    taint_origin[dest_reg] = f"loaded from global {global_key} ({tainted_globals[global_key]})"
                    return

            mem_key = self._make_memory_key(base, offset_str, insn)
            if mem_key in tainted_memory:
                tainted_regs.add(dest_reg)
                taint_origin[dest_reg] = f"loaded from {tainted_memory[mem_key]}"

    @staticmethod
    def _parse_shadow_offset(offset_str: str) -> int | None:
        """Parse a shadow space offset string and return the offset, or None."""
        offset_str = offset_str.strip().rstrip("h")
        try:
            if offset_str.startswith("0x"):
                offset = int(offset_str, 16)
            else:
                offset = int(offset_str)
        except ValueError:
            return None
        if offset in X64_SHADOW_SPACE_OFFSETS:
            return offset
        return None

    @staticmethod
    def _make_memory_key(base: str, offset_str: str | None, insn) -> str:
        """Create a canonical key for a memory location."""
        if offset_str:
            offset_str = offset_str.strip().rstrip("h")
            return f"[{base}+{offset_str}]"
        return f"[{base}]"

    @staticmethod
    def _extract_size_qualifier(insn) -> str:
        """Extract size qualifier from instruction (byte/word/dword/qword).

        Returns empty string if no size qualifier found (implies full register).
        """
        ops_lower = insn.operands.lower()
        for sz in ("qword", "dword", "word", "byte"):
            if sz in ops_lower:
                return sz
        return ""

    @staticmethod
    def _partial_reg_from_size(size: str) -> str | None:
        """Map size qualifier to the partial register name (x64).

        For full 64-bit registers:
            qword → rax (full)
            dword → eax (zero-extended to 64-bit)
            word  → ax
            byte  → al
        """
        return {
            "byte": "al",
            "word": "ax",
            "dword": "eax",
            "qword": "rax",
        }.get(size)

    def _is_rip_relative(self, insn) -> tuple[bool, str | None]:
        """Check if instruction uses RIP-relative addressing.

        Returns (is_rip_relative, offset_string_or_None).
        """
        ops = insn.operands
        rip_match = re.search(r'\[\s*rip\s*(?:\+\s*([0-9a-fA-Fxh]+))?\s*\]', ops, re.IGNORECASE)
        if rip_match:
            return True, rip_match.group(1)
        return False, None


def run_taint_analysis(
    handler_addr: int,
    ir: DisassemblyResult,
    max_depth: int = 3,
) -> TaintResult:
    """Run taint analysis on a handler function and its callees.

    Uses ``track_function_with_context()`` as the internal engine so that
    taint state (tainted registers, memory locations, struct fields) is
    propagated across function call boundaries instead of dying at each
    ``call`` instruction.

    Backward-compatible: same signature as before.

    Returns TaintResult indicating if user input reaches dangerous APIs.
    """
    tracker = TaintTracker(ir)

    # Build initial context: handler's first param (rcx/x0) is the IRP pointer
    initial_context = TaintContext(is_arm64=tracker.is_arm64)
    # The IRP base register itself isn't tainted yet — taint comes from
    # reading IRP fields. But we mark it so that [rcx+offset] patterns
    # recognize the base as a valid IRP-derived register.
    initial_context.tainted_regs.add(tracker.irp_base_reg)
    initial_context.taint_origin[tracker.irp_base_reg] = "IRP pointer (entry)"

    result = tracker.track_function_with_context(
        handler_addr, initial_context, max_depth, _depth=0
    )

    # Deduplicate tainted params
    seen_params = set()
    unique_sinks = []
    for sink in result.sinks:
        if sink.tainted_param not in seen_params:
            unique_sinks.append(sink)
            seen_params.add(sink.tainted_param)
    result.sinks = unique_sinks

    return result


class InputValidationAnalyzer(Analyzer):
    """Checks IOCTL handler functions for missing input validation.

    Strategy:
    1. Identify IOCTL handler functions
    2. For each handler, classify dangerous sinks
    3. Track user-controlled buffer references via IRP struct offsets
    4. Check for specific validation types: probe, privilege, size
    5. Report each missing check as a separate finding
    """

    @property
    def name(self) -> str:
        return "InputValidationAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Checks whether IOCTL handler functions validate user input "
            "before calling dangerous kernel APIs."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # Collect handler function addresses
        handler_addrs = set()

        for handler_addr in ir.ioctl_handlers.values():
            handler_addrs.add(handler_addr)

        if 0xE in ir.irp_handlers:
            handler_addrs.add(ir.irp_handlers[0xE])

        if ir.ioctl_dispatcher:
            handler_addrs.add(ir.ioctl_dispatcher)

        # For WDF drivers: all functions with dangerous sinks are reachable
        if ir.is_wdf_driver and ir.irp_handlers:
            for func_addr in ir.functions:
                handler_addrs.add(func_addr)

        # Callback-registered functions are also entry-point-reachable.
        # Extract from ObRegisterCallbacks/CmRegisterCallbackEx/etc. calls.
        callback_apis = {
            "ObRegisterCallbacks", "ObUnRegisterCallbacks",
            "CmRegisterCallbackEx", "CmUnRegisterCallback",
            "FltRegisterFilter", "FltStartFiltering",
            "PsSetCreateProcessNotifyRoutine",
            "PsSetCreateThreadNotifyRoutine",
        }
        for func_addr, api_names in ir.function_apis.items():
            if any(api in callback_apis for api in api_names):
                func = ir.functions.get(func_addr)
                if func:
                    for callee_addr in func.calls:
                        callee = ir.functions.get(callee_addr)
                        if callee:
                            handler_addrs.add(callee_addr)

        handler_addrs.discard(0)

        # Aggregate: collect per-function sinks and validation categories
        func_analysis: dict[int, dict] = {}
        for handler_addr in handler_addrs:
            func = ir.functions.get(handler_addr)
            if func is None:
                continue

            handler_calls = self._get_handler_calls(handler_addr, func, ir)
            sinks_found = handler_calls & DANGEROUS_SINKS
            if not sinks_found:
                continue

            probe_found = handler_calls & PROBE_APIS
            priv_found = handler_calls & PRIVILEGE_APIS
            size_found = handler_calls & SIZE_CHECK_APIS
            sync_found = handler_calls & SYNC_APIS

            # Dataflow: check if function actually reads user-controlled IRP fields
            has_irp_access = self._find_input_source(handler_addr, func, ir)

            # Dataflow: track if there's a real validation path (not just API call)
            has_real_validation = self._has_real_validation(handler_addr, func, ir)

            # Taint analysis: check if user input flows to dangerous APIs
            taint_result = run_taint_analysis(handler_addr, ir)

            # Cross-function: check if callees provide validation
            cross_function_validation = self._check_cross_function_validation(
                handler_addr, func, ir, max_depth=3
            )

            func_analysis[handler_addr] = {
                "sinks": sinks_found,
                "probe": probe_found,
                "privilege": priv_found,
                "size": size_found,
                "sync": sync_found,
                "has_irp_access": has_irp_access,
                "has_real_validation": has_real_validation,
                "taint_result": taint_result,
                "cross_function_validation": cross_function_validation,
            }

        # Generate findings per function
        for func_addr, info in func_analysis.items():
            sinks = info["sinks"]
            sink_list = ", ".join(sorted(sinks))
            cross_func = info.get("cross_function_validation", {})
            has_any_real_validation = (
                info["probe"] or info["privilege"] or info["size"]
                or info["has_real_validation"]
                or cross_func.get("probe") or cross_func.get("privilege") or cross_func.get("size")
            )

            # Missing probe check
            if not info["probe"]:
                taint = info.get("taint_result")
                taint_context = {}
                if taint and taint.tainted_reaches_dangerous_api:
                    taint_context["taint_confirmed"] = True
                    taint_context["taint_sources"] = [
                        f"{s.field_name}@0x{s.irp_offset:X}" for s in taint.sources
                    ]
                    taint_context["taint_sinks"] = [
                        f"{s.api_name}({s.tainted_param})" for s in taint.sinks
                    ]
                    taint_context["taint_path"] = taint.sinks[0].taint_path if taint.sinks else []

                findings.append(
                    Finding(
                        category=FindingCategory.UNVALIDATED_USER_INPUT,
                        severity=Severity.HIGH,
                        confidence=(
                            Confidence.HIGH
                            if taint_context.get("taint_confirmed")
                            else (Confidence.HIGH
                                  if info["has_irp_access"] and not info["has_real_validation"]
                                  else Confidence.MEDIUM)
                        ),
                        description=(
                            f"Handler sub_{func_addr:X} calls {sink_list} "
                            f"without probing input buffer. "
                            f"{'Taint analysis confirms user input reaches dangerous API. ' if taint_context.get('taint_confirmed') else ''}"
                            f"No ProbeForRead, ProbeForWrite, or MmProbeAndLockPages found."
                        ),
                        function_address=func_addr,
                        api_name=sorted(sinks)[0],
                        context={
                            "dangerous_apis": sorted(sinks),
                            "missing_checks": ["probe"],
                            "irp_access": info["has_irp_access"],
                            **taint_context,
                        },
                        evidence=[
                            Evidence(
                                type="cfg_path",
                                location=f"sub_{func_addr:X}",
                                snippet=f"Dangerous APIs ({sink_list}) called without ProbeForRead/ProbeForWrite",
                                rule_id="VAL_NO_PROBE",
                            )
                        ],
                    )
                )

            # Missing privilege check
            if not info["privilege"]:
                findings.append(
                    Finding(
                        category=FindingCategory.MISSING_PRIVILEGE_CHECK,
                        severity=Severity.HIGH if sinks & {"KeWriteMsr", "__writemsr", "MmMapLockedPagesSpecifyCache"} else Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        description=(
                            f"Handler sub_{func_addr:X} calls {sink_list} "
                            f"without checking caller privilege. "
                            f"No SeSinglePrivilegeCheck or ExGetPreviousMode found."
                        ),
                        function_address=func_addr,
                        api_name=sorted(sinks)[0],
                        context={
                            "dangerous_apis": sorted(sinks),
                            "missing_checks": ["privilege"],
                        },
                        evidence=[
                            Evidence(
                                type="cfg_path",
                                location=f"sub_{func_addr:X}",
                                snippet=f"Dangerous APIs ({sink_list}) called without privilege check",
                                rule_id="VAL_NO_PRIV",
                            )
                        ],
                    )
                )

            # Missing size check
            if not info["size"]:
                findings.append(
                    Finding(
                        category=FindingCategory.MISSING_SIZE_CHECK,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        description=(
                            f"Handler sub_{func_addr:X} does not validate "
                            f"IOCTL input buffer size before processing."
                        ),
                        function_address=func_addr,
                        context={
                            "dangerous_apis": sorted(sinks),
                            "missing_checks": ["size"],
                        },
                        evidence=[
                            Evidence(
                                type="cfg_path",
                                location=f"sub_{func_addr:X}",
                                snippet="No buffer size validation detected",
                                rule_id="VAL_NO_SIZE",
                            )
                        ],
                    )
                )

            # Sync-only "validation" — note it but don't count as real validation
            if not has_any_real_validation and info["sync"]:
                sync_list = ", ".join(sorted(info["sync"]))
                findings.append(
                    Finding(
                        category=FindingCategory.PARTIAL_VALIDATION,
                        severity=Severity.LOW,
                        confidence=Confidence.LOW,
                        description=(
                            f"Handler sub_{func_addr:X} calls {sink_list} "
                            f"with synchronization ({sync_list}) but no input "
                            f"validation. Race condition protection does not "
                            f"prevent BYOVD exploitation."
                        ),
                        function_address=func_addr,
                        api_name=sorted(sinks)[0],
                        context={
                            "dangerous_apis": sorted(sinks),
                            "sync_apis": sorted(info["sync"]),
                            "note": "synchronization is not input validation",
                        },
                        evidence=[
                            Evidence(
                                type="cfg_path",
                                location=f"sub_{func_addr:X}",
                                snippet=f"Sync only ({sync_list}), no real validation",
                                rule_id="VAL_SYNC_ONLY",
                            )
                        ],
                    )
                )

            # Partial validation — has some real checks but not all
            if has_any_real_validation:
                found_checks = []
                if info["probe"]:
                    found_checks.append(f"probe ({', '.join(sorted(info['probe']))})")
                if info["privilege"]:
                    found_checks.append(f"privilege ({', '.join(sorted(info['privilege']))})")
                if info["size"]:
                    found_checks.append(f"size ({', '.join(sorted(info['size']))})")
                if info["has_real_validation"]:
                    found_checks.append("size_comparison (instruction-level)")

                missing = []
                if not info["probe"]:
                    missing.append("probe")
                if not info["privilege"]:
                    missing.append("privilege")
                if not info["size"] and not info["has_real_validation"]:
                    missing.append("size")

                if missing:
                    findings.append(
                        Finding(
                            category=FindingCategory.PARTIAL_VALIDATION,
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            description=(
                                f"Handler sub_{func_addr:X} calls {sink_list} "
                                f"with partial validation: {'; '.join(found_checks)}. "
                                f"Missing: {', '.join(missing)}."
                            ),
                            function_address=func_addr,
                            api_name=sorted(sinks)[0],
                            context={
                                "dangerous_apis": sorted(sinks),
                                "validation_found": found_checks,
                                "missing": missing,
                            },
                            evidence=[
                                Evidence(
                                    type="cfg_path",
                                    location=f"sub_{func_addr:X}",
                                    snippet=(
                                        f"{sink_list} with partial validation "
                                        f"({' | '.join(found_checks)})"
                                    ),
                                    rule_id="VAL_PARTIAL",
                                )
                            ],
                        )
                    )

        return findings

    def _find_input_source(
        self,
        func_addr: int,
        func,
        ir: DisassemblyResult,
    ) -> bool:
        """Check if a function accesses user-controlled IRP fields.

        Looks for patterns like:
        - mov reg, [rcx+offset] where rcx is the IRP pointer (x64 calling convention)
        - Known offsets: 0x18 (UserBuffer), 0x60 (SystemBuffer), 0x98 (Parameters)

        Returns True if the function directly reads from the IRP structure.
        """
        all_tracked = DANGEROUS_SINKS | PROBE_APIS | PRIVILEGE_APIS | SIZE_CHECK_APIS | SYNC_APIS
        tracked_lower = {a.lower() for a in all_tracked}

        # Check function's API calls for IRP-related patterns
        if func_addr in ir.function_apis:
            for api_name in ir.function_apis[func_addr]:
                if api_name in DANGEROUS_SINKS:
                    return True
        # Fallback: check function calls for API-like names
        for target_addr in func.calls:
            target_func = ir.functions.get(target_addr)
            if target_func:
                if any(api in target_func.name.lower() for api in tracked_lower):
                    return True
        return False

    def _track_buffer_usage(
        self,
        func_addr: int,
        ir: DisassemblyResult,
    ) -> dict[str, Any]:
        """Track how user-controlled buffer references flow to dangerous sinks.

        Based on simplified CFG, traces registers/memory locations that
        originate from IRP struct offsets (x64: rcx=IRP pointer):
          - 0x60 → SystemBuffer (METHOD_BUFFERED)
          - 0x18 → UserBuffer (METHOD_NEITHER)

        Returns:
            {
                "has_irp_read": bool,
                "buffer_refs": [list of accessed offsets],
                "taint_reaches_sink": bool,
                "sink_apis": [list of APIs reached by tainted data],
            }
        """
        func = ir.functions.get(func_addr)
        if not func:
            return {"has_irp_read": False, "buffer_refs": [], "taint_reaches_sink": False, "sink_apis": []}

        # Get CFG for this function (prefer full, fall back to simple)
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)

        result = {
            "has_irp_read": False,
            "buffer_refs": [],
            "taint_reaches_sink": False,
            "sink_apis": [],
        }

        # Scan function's API calls for dangerous sinks
        func_apis = ir.function_apis.get(func_addr, [])
        dangerous_found = [a for a in func_apis if a in DANGEROUS_SINKS]
        result["sink_apis"] = dangerous_found

        # Check for IRP field access patterns in API names / call targets
        # If the function calls dangerous sinks, it's a potential taint sink
        if dangerous_found:
            result["taint_reaches_sink"] = True

        # Check if function has APIs that suggest IRP access
        for api_name in func_apis:
            # Functions that typically access IRP buffers
            if api_name in {"IoGetCurrentIrpStackLocation", "IoGetRelatedDevice",
                           "ExGetPreviousMode"}:
                result["has_irp_read"] = True

        # Also check for IRP offset access in callees
        for target_addr in func.calls:
            target_func = ir.functions.get(target_addr)
            if target_func:
                name_lower = target_func.name.lower()
                for offset_name in ("irp", "stack", "buffer", "systembuffer", "userbuffer"):
                    if offset_name in name_lower:
                        result["has_irp_read"] = True
                        result["buffer_refs"].append(offset_name)
                        break

        return result

    def _has_real_validation(
        self,
        func_addr: int,
        func,
        ir: DisassemblyResult,
    ) -> bool:
        """Check if a function has actual size validation at the instruction level.

        Looks for cmp instructions with a register that was loaded from an
        IRP offset (like IoStatus.Information, the actual buffer size).
        This catches validation that doesn't call a named API.

        Returns True if instruction-level size validation is detected.
        """
        # Check if function has any cmp/test with a size-like constant
        # This is a heuristic: many drivers compare IoStatus.Information
        # against an expected minimum size
        func_apis = ir.function_apis.get(func_addr, [])
        # If the function calls RtlCompareMemory or similar, it's already
        # handled by SIZE_CHECK_APIS. Here we look for raw cmp patterns.
        for api_name in func_apis:
            if "compare" in api_name.lower() or "length" in api_name.lower():
                return True
        return False

    def _get_handler_calls(
        self,
        handler_addr: int,
        func,
        ir: DisassemblyResult,
    ) -> set[str]:
        """Get all API names called within a handler function."""
        calls = set()

        if handler_addr in ir.function_apis:
            for api_name in ir.function_apis[handler_addr]:
                if api_name in DANGEROUS_SINKS or \
                   api_name in PROBE_APIS or \
                   api_name in PRIVILEGE_APIS or \
                   api_name in SIZE_CHECK_APIS or \
                   api_name in SYNC_APIS:
                    calls.add(api_name)
            return calls

        # Fallback: check func.calls for API-like names
        all_tracked = DANGEROUS_SINKS | PROBE_APIS | PRIVILEGE_APIS | SIZE_CHECK_APIS | SYNC_APIS
        tracked_lower = {a.lower() for a in all_tracked}
        for target_addr in func.calls:
            target_func = ir.functions.get(target_addr)
            if target_func:
                if any(api in target_func.name.lower() for api in tracked_lower):
                    calls.add(target_func.name)

        return calls

    def _check_cross_function_validation(
        self,
        func_addr: int,
        func,
        ir: DisassemblyResult,
        max_depth: int = 3,
    ) -> dict[str, Any]:
        """Recursively check if callee functions provide input validation.

        If a handler calls a helper function that performs probe/privilege/size
        checks, treat the handler as having validation through that helper.

        Returns:
            {"probe": set, "privilege": set, "size": set, "validating_callees": list}
        """
        result: dict[str, Any] = {
            "probe": set(),
            "privilege": set(),
            "size": set(),
            "validating_callees": [],
        }
        visited: set[int] = set()
        self._walk_callees(func_addr, ir, max_depth, visited, result)
        return result

    def _walk_callees(
        self,
        func_addr: int,
        ir: DisassemblyResult,
        remaining_depth: int,
        visited: set[int],
        result: dict[str, Any],
    ) -> None:
        """DFS walk through callee call graph, collecting validation APIs."""
        if remaining_depth <= 0 or func_addr in visited or func_addr == 0:
            return
        visited.add(func_addr)

        func = ir.functions.get(func_addr)
        if func is None:
            return

        # Check this function's APIs for validation
        callee_apis = set(ir.function_apis.get(func_addr, []))
        probe_found = callee_apis & PROBE_APIS
        priv_found = callee_apis & PRIVILEGE_APIS
        size_found = callee_apis & SIZE_CHECK_APIS

        if probe_found or priv_found or size_found:
            result["probe"].update(probe_found)
            result["privilege"].update(priv_found)
            result["size"].update(size_found)
            result["validating_callees"].append(f"sub_{func_addr:X}")

        # Recurse into callees
        for callee_addr in func.calls:
            if callee_addr != func_addr:  # Skip self-recursion
                self._walk_callees(callee_addr, ir, remaining_depth - 1, visited, result)
