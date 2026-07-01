"""
DriverScope — Semantic Primitive Analyzer.

Detects dangerous kernel primitives that do NOT use standard named APIs.
API-name matching alone misses:
- Direct MSR writes via ``wrmsr`` instruction (not ``KeWriteMsr``)
- Control register writes via ``mov cr0/cr4, reg``
- Custom physical memory mapping through bit-shift arithmetic
- Indirect code execution via user-controlled function pointers
- Direct port I/O (``in``/``out``) for PCI config space access

These are semantically equivalent to known dangerous APIs but bypass
name-based detection entirely.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from src.analysis.analyzer import Analyzer
from src.analysis.dataflow.input_tracker import DANGEROUS_SINKS
from src.models import (
    Confidence,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)


# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

@dataclass
class SemanticRule:
    """A single semantic detection rule."""
    rule_id: str
    category: FindingCategory
    severity: Severity
    confidence: Confidence
    description: str
    check: callable  # (ir, func_addr, insn) -> bool


def _check_wrmsr(ir, func_addr, insn) -> bool:
    return insn.mnemonic.lower() in ("wrmsr",)


def _check_cr_write(ir, func_addr, insn) -> bool:
    ops = insn.operands.lower()
    return insn.mnemonic.lower() == "mov" and any(
        f"cr{i}" in ops for i in (0, 2, 3, 4, 8)
    )


def _check_indirect_call(ir, func_addr, insn) -> bool:
    """Indirect call/jmp through memory or register (not a direct target).

    Patterns:
      call [reg+offset]   — function pointer from struct
      call [rip+offset]   — global function pointer
      jmp [reg]
      call qword ptr [...]
    """
    if insn.mnemonic.lower() not in ("call", "jmp"):
        return False
    ops = insn.operands
    # Indirect through memory: [reg+offset], [rip+offset], qword ptr [...]
    if "[" in ops and "]" in ops:
        # Filter out direct API calls
        if not insn.api_target:
            return True
    return False


def _check_port_io(ir, func_addr, insn) -> bool:
    """Direct port I/O: in/out instructions."""
    return insn.mnemonic.lower() in ("in", "out", "ins", "outs", "insb", "outsb")


def _check_pci_config_port(ir, func_addr, insn) -> bool:
    """Port I/O to PCI config space ports 0xCF8/0xCFC."""
    if insn.mnemonic.lower() not in ("in", "out"):
        return False
    ops = insn.operands.lower()
    return "0xcf8" in ops.replace(" ", "") or "0xcfc" in ops.replace(" ", "")


def _check_physical_addr_shift(ir, func_addr, insn) -> bool:
    """Bit-shifting that suggests physical address construction.

    Pattern: ``shl reg, 0xC`` (page-align, shift by 12) followed by
    ``shr reg, 0xC`` or similar — typical of drivers that construct
    physical addresses from user input without using MmMapIoSpace.

    This is a heuristic; we flag it at the instruction level and
    aggregate at the function level.
    """
    if insn.mnemonic.lower() not in ("shl", "shr", "sal", "sar"):
        return False
    ops = insn.operands.lower()
    # Shift by 12 (page size) or by large values suggesting physical addr
    for val in ("0xc", "12", "0x10", "16", "0x20", "32", "0x30", "48"):
        if val in ops:
            return True
    return False


def _check_dr_write(ir, func_addr, insn) -> bool:
    """Direct debug register write: mov dr0-dr7, reg."""
    if insn.mnemonic.lower() != "mov":
        return False
    ops = insn.operands.lower()
    return any(f"dr{i}" in ops for i in range(8))


def _check_gdt_idt(ir, func_addr, insn) -> bool:
    """GDT/IDT modification: lgdt, lidt."""
    return insn.mnemonic.lower() in ("lgdt", "lidt")


def _check_ltr(ir, func_addr, insn) -> bool:
    """Load task register: ltr."""
    return insn.mnemonic.lower() == "ltr"


def _check_lmsw(ir, func_addr, insn) -> bool:
    """Load machine status word: lmsw."""
    return insn.mnemonic.lower() == "lmsw"


def _check_clts(ir, func_addr, insn) -> bool:
    """Clear task switched flag: clts."""
    return insn.mnemonic.lower() == "clts"


def _check_invlpg(ir, func_addr, insn) -> bool:
    """Invalidate TLB entry: invlpg."""
    return insn.mnemonic.lower() == "invlpg"


# --- Anti-Debug & Anti-Reversing detection rules ---

def _check_rdtsc(ir, func_addr, insn) -> bool:
    """RDTSC timing check — common anti-debug technique."""
    return insn.mnemonic.lower() == "rdtsc"


def _check_cpuid(ir, func_addr, insn) -> bool:
    """CPUID — used for hypervisor detection (anti-VM)."""
    return insn.mnemonic.lower() == "cpuid"


def _check_icebp(ir, func_addr, insn) -> bool:
    """ICEBP/F1 — undocumented single-step trap, anti-debug."""
    return insn.mnemonic.lower() in ("icebp", "f1")


def _check_int3(ir, func_addr, insn) -> bool:
    """INT 3 — software breakpoint, sometimes used in anti-debug SEH traps."""
    return insn.mnemonic.lower() == "int" and "3" in insn.operands


def _check_sidt_sgdt_str(ir, func_addr, insn) -> bool:
    """SIDT/SGDT/STR — Red Pill hypervisor detection."""
    return insn.mnemonic.lower() in ("sidt", "sgdt", "str")


def _check_nmi_callbacks(ir, func_addr, insn) -> bool:
    """KeRegisterNmiCallback — may be used for anti-debug persistence."""
    # This is detected via API name, not instruction, so we skip here
    return False


def _check_nmi_callback_api(ir, func_addr, insn) -> bool:
    """NMI callback registration — may manipulate debugger detection."""
    if insn.api_target and "KeRegisterNmiCallback" in str(insn.api_target):
        return True
    return False


def _check_seh_setup(ir, func_addr, insn) -> bool:
    """FS:[0] write — sets up SEH handler, often used in anti-debug traps."""
    if insn.mnemonic.lower() == "mov":
        ops = insn.operands.lower()
        # Pattern: mov large dword ptr fs:[0], reg
        if "fs:[0]" in ops.replace(" ", "") or "gs:[0]" in ops.replace(" ", ""):
            return True
    return False


def _check_kd_disable(ir, func_addr, insn) -> bool:
    """KdDisableDebugger or KdRefreshDebuggerHidden — kernel debugger manipulation."""
    if insn.api_target:
        api = str(insn.api_target)
        if "KdDisableDebugger" in api or "KdRefreshDebuggerHidden" in api:
            return True
    return False


def _check_nt_set_info_thread(ir, func_addr, insn) -> bool:
    """NtSetInformationThread with ThreadHideFromDebugger (0x11)."""
    if insn.api_target:
        api = str(insn.api_target)
        if "NtSetInformationThread" in api or "ZwSetInformationThread" in api:
            return True
    return False


def _check_nt_close(ir, func_addr, insn) -> bool:
    """NtClose/ZwClose — may be used as invalid-handle anti-debug trap."""
    if insn.api_target:
        api = str(insn.api_target)
        if api in ("NtClose", "ZwClose"):
            return True
    return False


def _check_nt_query_info_process(ir, func_addr, insn) -> bool:
    """NtQueryInformationProcess — may query ProcessDebugPort/DebugFlags/DebugObjectHandle."""
    if insn.api_target:
        api = str(insn.api_target)
        if "NtQueryInformationProcess" in api or "ZwQueryInformationProcess" in api:
            return True
    return False


def _check_nt_create_debug_object(ir, func_addr, insn) -> bool:
    """NtCreateDebugObject/NtRemoveProcessDebug — debugger object manipulation."""
    if insn.api_target:
        api = str(insn.api_target)
        if "NtCreateDebugObject" in api or "NtRemoveProcessDebug" in api:
            return True
    return False


def _check_ob_register_callbacks(ir, func_addr, insn) -> bool:
    """ObRegisterCallbacks — may be used to block debugger attachment."""
    if insn.api_target:
        api = str(insn.api_target)
        if "ObRegisterCallbacks" in api or "ObUnRegisterCallbacks" in api:
            return True
    return False


def _check_system_debug_control(ir, func_addr, insn) -> bool:
    """ZwSystemDebugControl — direct system debug control."""
    if insn.api_target:
        api = str(insn.api_target)
        if "ZwSystemDebugControl" in api or "NtSystemDebugControl" in api:
            return True
    return False


def _check_psp_cid_table(ir, func_addr, insn) -> bool:
    """PspCidTable access — process/thread enumeration for debugger detection."""
    if insn.api_target:
        api = str(insn.api_target)
        if "PspCidTable" in api:
            return True
    return False


SEMANTIC_RULES = [
    SemanticRule(
        rule_id="SEM_WRMSR",
        category=FindingCategory.DIRECT_MSR_WRITE,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Direct MSR write via wrmsr instruction (not KeWriteMsr API)",
        check=_check_wrmsr,
    ),
    SemanticRule(
        rule_id="SEM_CR_WRITE",
        category=FindingCategory.DIRECT_CR_WRITE,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Direct control register write (mov cr0/cr4, reg)",
        check=_check_cr_write,
    ),
    SemanticRule(
        rule_id="SEM_INDIRECT_CALL",
        category=FindingCategory.CUSTOM_CODE_EXECUTION,
        severity=Severity.LOW,
        confidence=Confidence.LOW,
        description="Indirect call/jmp through function pointer (potential user-controlled code execution)",
        check=_check_indirect_call,
    ),
    SemanticRule(
        rule_id="SEM_PORT_IO",
        category=FindingCategory.DIRECT_PORT_IO,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Direct port I/O instruction (in/out)",
        check=_check_port_io,
    ),
    SemanticRule(
        rule_id="SEM_PCI_CONFIG",
        category=FindingCategory.PCI_CONFIG_ACCESS,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="PCI configuration space access via port 0xCF8/0xCFC",
        check=_check_pci_config_port,
    ),
    SemanticRule(
        rule_id="SEM_PHYS_SHIFT",
        category=FindingCategory.CUSTOM_PHYSICAL_MEMORY_MAPPING,
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        description="Bit-shift pattern suggesting custom physical address mapping",
        check=_check_physical_addr_shift,
    ),
    SemanticRule(
        rule_id="SEM_DR_WRITE",
        category=FindingCategory.DEBUG_REGISTER_WRITE,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="Direct debug register write (mov drX, reg)",
        check=_check_dr_write,
    ),
    SemanticRule(
        rule_id="SEM_GDT_IDT",
        category=FindingCategory.GDT_IDT_MODIFICATION,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="GDT/IDT modification (lgdt/lidt)",
        check=_check_gdt_idt,
    ),
    SemanticRule(
        rule_id="SEM_LTR",
        category=FindingCategory.PROCESSOR_STATE_MANIPULATION,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Load task register (ltr)",
        check=_check_ltr,
    ),
    SemanticRule(
        rule_id="SEM_LMSW",
        category=FindingCategory.PROCESSOR_STATE_MANIPULATION,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="Load machine status word (lmsw)",
        check=_check_lmsw,
    ),
    SemanticRule(
        rule_id="SEM_CLTS",
        category=FindingCategory.PROCESSOR_STATE_MANIPULATION,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description="Clear task switched flag (clts)",
        check=_check_clts,
    ),
    SemanticRule(
        rule_id="SEM_INVLPG",
        category=FindingCategory.TLB_INVALIDATION,
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description="Invalidate TLB entry (invlpg)",
        check=_check_invlpg,
    ),
    # Anti-Debug & Anti-Reversing rules
    SemanticRule(
        rule_id="SEM_RDTSC",
        category=FindingCategory.ANTI_DEBUG_TIMING,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="RDTSC timing check — potential anti-debug technique",
        check=_check_rdtsc,
    ),
    SemanticRule(
        rule_id="SEM_CPUID",
        category=FindingCategory.ANTI_DEBUG_HYPERVISOR,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="CPUID instruction — potential hypervisor/VM detection",
        check=_check_cpuid,
    ),
    SemanticRule(
        rule_id="SEM_INT3",
        category=FindingCategory.ANTI_DEBUG_TRAP,
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description="INT 3 trap — potential anti-debug SEH trap",
        check=_check_int3,
    ),
    SemanticRule(
        rule_id="SEM_ICEBP",
        category=FindingCategory.ANTI_DEBUG_TRAP,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="ICEBP (F1) undocumented trap — anti-debug technique",
        check=_check_icebp,
    ),
    SemanticRule(
        rule_id="SEM_SIDT_SGDT_STR",
        category=FindingCategory.ANTI_DEBUG_HYPERVISOR,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="SIDT/SGDT/STR — Red Pill hypervisor detection",
        check=_check_sidt_sgdt_str,
    ),
    SemanticRule(
        rule_id="SEM_SEH_SETUP",
        category=FindingCategory.ANTI_DEBUG_EXCEPTION,
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="FS:[0]/GS:[0] write — SEH handler setup, potential anti-debug trap",
        check=_check_seh_setup,
    ),
    # API-based anti-debug detection
    SemanticRule(
        rule_id="SEM_KD_DISABLE",
        category=FindingCategory.ANTI_DEBUG_NMI,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="KdDisableDebugger/KdRefreshDebuggerHidden — kernel debugger manipulation",
        check=_check_kd_disable,
    ),
    SemanticRule(
        rule_id="SEM_NT_SET_INFO_THREAD",
        category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG,
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        description="NtSetInformationThread — potential ThreadHideFromDebugger (0x11)",
        check=_check_nt_set_info_thread,
    ),
    SemanticRule(
        rule_id="SEM_NT_CLOSE",
        category=FindingCategory.ANTI_DEBUG_TRAP,
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="NtClose/ZwClose — potential invalid-handle anti-debug trap",
        check=_check_nt_close,
    ),
    SemanticRule(
        rule_id="SEM_NT_QUERY_INFO_PROCESS",
        category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="NtQueryInformationProcess — potential ProcessDebugPort/DebugFlags query",
        check=_check_nt_query_info_process,
    ),
    SemanticRule(
        rule_id="SEM_NT_DEBUG_OBJECT",
        category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="NtCreateDebugObject/NtRemoveProcessDebug — debugger object manipulation",
        check=_check_nt_create_debug_object,
    ),
    SemanticRule(
        rule_id="SEM_OB_CALLBACKS",
        category=FindingCategory.ANTI_DEBUG_EXCEPTION,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="ObRegisterCallbacks — may block debugger attachment",
        check=_check_ob_register_callbacks,
    ),
    SemanticRule(
        rule_id="SEM_SYS_DEBUG_CONTROL",
        category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        description="ZwSystemDebugControl — direct system debug control",
        check=_check_system_debug_control,
    ),
    SemanticRule(
        rule_id="SEM_PSP_CID_TABLE",
        category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG,
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description="PspCidTable access — process/thread enumeration for debugger detection",
        check=_check_psp_cid_table,
    ),
]


class SemanticAnalyzer(Analyzer):
    """Detect dangerous kernel primitives via instruction semantics, not API names.

    Runs on all functions that are reachable from any entry point
    (IOCTL, FastIO, MiniFilter, WMI, PnP/Power).
    """

    @property
    def name(self) -> str:
        return "SemanticAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Detects custom kernel primitives via instruction-level semantic "
            "analysis: wrmsr, mov crX, indirect calls, port I/O, PCI config, "
            "physical address bit-shifts."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # Determine which functions to scan: all entry-point-reachable functions
        entry_funcs = self._collect_entry_point_functions(ir)
        if not entry_funcs:
            # If no entry points detected, scan all functions
            entry_funcs = set(ir.functions.keys())

        # Aggregate per-function semantic findings
        func_semantics: dict[int, dict[str, list]] = {}

        for func_addr in entry_funcs:
            func = ir.functions.get(func_addr)
            if func is None:
                continue

            instructions = self._get_function_instructions(func_addr, ir)
            if not instructions:
                continue

            func_semantics[func_addr] = {}

            for insn in instructions:
                for rule in SEMANTIC_RULES:
                    try:
                        if rule.check(ir, func_addr, insn):
                            rule_id = rule.rule_id
                            if rule_id not in func_semantics[func_addr]:
                                func_semantics[func_addr][rule_id] = []
                            func_semantics[func_addr][rule_id].append(insn)
                    except Exception:
                        continue

        # Deduplicate and generate findings per function per rule
        for func_addr, rule_matches in func_semantics.items():
            for rule_id, insns in rule_matches.items():
                rule = next(r for r in SEMANTIC_RULES if r.rule_id == rule_id)
                # Deduplicate by instruction address
                seen_addrs = set()
                unique_insns = []
                for insn in insns:
                    if insn.address not in seen_addrs:
                        seen_addrs.add(insn.address)
                        unique_insns.append(insn)

                if not unique_insns:
                    continue

                addr_list = ", ".join(f"0x{i.address:X}" for i in unique_insns[:5])
                if len(unique_insns) > 5:
                    addr_list += f" (+{len(unique_insns) - 5} more)"

                # For indirect calls, check if the function is entry-point reachable
                if rule_id == "SEM_INDIRECT_CALL":
                    if not self._is_entry_point_reachable(func_addr, ir):
                        continue

                findings.append(
                    Finding(
                        category=rule.category,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        description=(
                            f"Function sub_{func_addr:X}: {rule.description}. "
                            f"Instructions at: {addr_list}"
                        ),
                        function_address=func_addr,
                        instruction_address=unique_insns[0].address,
                        context={
                            "rule_id": rule_id,
                            "instruction_count": len(unique_insns),
                            "addresses": sorted(seen_addrs),
                        },
                        evidence=[
                            Evidence(
                                type="instruction_pattern",
                                location=f"sub_{func_addr:X}",
                                snippet=f"{rule.description} at {addr_list}",
                                rule_id=rule_id,
                            )
                        ],
                    )
                )

        return findings

    def _collect_entry_point_functions(self, ir: DisassemblyResult) -> set[int]:
        """Collect all functions reachable from any entry point."""
        entry_addrs = set()

        # IOCTL handlers
        entry_addrs.update(ir.ioctl_handlers.values())
        entry_addrs.update(ir.irp_handlers.values())

        # FastIO handlers
        entry_addrs.update(ir.fastio_handlers.values())

        # MiniFilter callbacks
        entry_addrs.update(ir.minifilter_handlers.values())

        # Callback-registered functions: extract callee addresses from
        # ObRegisterCallbacks/CmRegisterCallbackEx/FltRegisterFilter calls.
        # These functions are invoked by the kernel at runtime and must be
        # treated as entry points for semantic analysis.
        callback_targets = self._extract_callback_targets(ir)
        entry_addrs.update(callback_targets)

        # Also walk callees from entry points
        visited: set[int] = set()
        queue = list(entry_addrs)

        while queue:
            addr = queue.pop(0)
            if addr in visited or addr == 0:
                continue
            visited.add(addr)
            func = ir.functions.get(addr)
            if func:
                for callee in func.calls:
                    if callee not in visited:
                        queue.append(callee)

        return visited

    @staticmethod
    def _extract_callback_targets(ir: DisassemblyResult) -> set[int]:
        """Extract function addresses registered via callback APIs.

        Patterns:
          - ObRegisterCallbacks: callback struct passed in rcx, contains
            function pointers for Pre/Post operation callbacks
          - CmRegisterCallbackEx: callback function pointer in rcx
          - FltRegisterFilter: callback struct with function pointers
          - PsSetCreateProcessNotifyRoutine: callback function pointer
        """
        targets: set[int] = set()
        callback_apis = {
            "ObRegisterCallbacks", "ObUnRegisterCallbacks",
            "CmRegisterCallbackEx", "CmUnRegisterCallback",
            "FltRegisterFilter", "FltStartFiltering",
            "PsSetCreateProcessNotifyRoutine",
            "PsSetCreateThreadNotifyRoutine",
            "IoRegisterShutdownNotification",
            "IoRegisterDeviceInterface",
            "KeRegisterNmiCallback",
        }

        for func_addr, api_names in ir.function_apis.items():
            if any(api in callback_apis for api in api_names):
                # The callback struct or function pointer is passed as a
                # parameter. We approximate by looking at callees of the
                # registering function — the first-level callees that are
                # not known APIs are likely the callback implementations.
                func = ir.functions.get(func_addr)
                if func:
                    for callee_addr in func.calls:
                        callee = ir.functions.get(callee_addr)
                        if callee and callee_addr not in ir.function_apis.get(callee_addr, []):
                            # Not a known imported API — likely a callback impl
                            targets.add(callee_addr)

                # Also check if the callback function is registered via
                # dynamic_imports (runtime-resolved function pointers)
                if func_addr in ir.dynamic_imports:
                    for import_name in ir.dynamic_imports[func_addr]:
                        # Try to match by name to a known function
                        for addr, f in ir.functions.items():
                            if f.name == import_name:
                                targets.add(addr)

        return targets

    def _is_entry_point_reachable(self, func_addr: int, ir: DisassemblyResult) -> bool:
        """Check if a function is reachable from any known entry point."""
        entry_points = set()
        entry_points.update(ir.ioctl_handlers.values())
        entry_points.update(ir.irp_handlers.values())
        entry_points.update(ir.fastio_handlers.values())
        entry_points.update(ir.minifilter_handlers.values())
        entry_points.update(self._extract_callback_targets(ir))

        # BFS from entry points
        visited: set[int] = set()
        queue = list(entry_points)
        while queue:
            addr = queue.pop(0)
            if addr == func_addr:
                return True
            if addr in visited or addr == 0:
                continue
            visited.add(addr)
            func = ir.functions.get(addr)
            if func:
                for callee in func.calls:
                    if callee not in visited:
                        queue.append(callee)
        return False

    @staticmethod
    def _get_function_instructions(func_addr: int, ir: DisassemblyResult) -> list:
        """Get all instructions in a function, sorted by address."""
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg:
            instructions = []
            for block in sorted(cfg.blocks.values(), key=lambda b: b.address):
                for insn in block.instructions:
                    instructions.append(insn)
            return instructions
        return []
