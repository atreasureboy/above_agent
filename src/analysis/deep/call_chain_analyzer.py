"""
DriverScope — Call Chain Analyzer.

Traces from IOCTL handlers through the call graph to identify:
- Dangerous API calls reachable from unprivileged IOCTLs
- Callback registration points (ObRegisterCallbacks, PsSetCreateProcessNotifyRoutine, etc.)
- Whitelist/blacklist data table access on reachable paths
- Capability surface exposed by each IOCTL

Reuses the call graph (Function.calls/called_by) populated by CapstoneBackend.
"""

from __future__ import annotations

from collections import deque
from typing import Any

from src.analysis.analyzer import Analyzer
from src.models import (
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)

# Dangerous APIs grouped by capability
DANGEROUS_API_GROUPS: dict[str, set[str]] = {
    "memory_primitive": {
        "MmMapIoSpaceEx", "MmMapLockedPagesSpecifyCache",
        "MmMapLockedPages", "MmBuildMdlForNonPagedPool",
        "MmProbeAndLockPages", "ZwMapViewOfSection",
        "NtMapViewOfSection",
    },
    "process_control": {
        "ZwTerminateProcess", "NtTerminateProcess",
        "PsTerminateSystemThread", "ZwOpenProcess",
        "ZwCreateThreadEx", "NtCreateThreadEx",
    },
    "token_manipulation": {
        "SeImpersonateClient", "PsReferenceImpersonationToken",
        "SeAssignSecurity", "ZwAdjustPrivilegesToken",
        "NtAdjustPrivilegesToken",
    },
    "kernel_callback": {
        "ObRegisterCallbacks", "PsSetCreateProcessNotifyRoutine",
        "PsSetCreateProcessNotifyRoutineEx", "PsSetCreateThreadNotifyRoutine",
        "PsSetLoadImageNotifyRoutine", "CmRegisterCallback",
        "CmRegisterCallbackEx", "IoRegisterFsRegistrationChange",
        "IoRegisterFsRegistrationChangeEx", "IoRegisterShutdownNotification",
        "ExRegisterCallback", "KeRegisterBoundCallback",
    },
    "hardware_access": {
        "HalTranslateBusAddress", "READ_PORT_UCHAR", "WRITE_PORT_UCHAR",
        "READ_REGISTER_UCHAR", "WRITE_REGISTER_UCHAR",
    },
    "code_execution": {
        "ZwCreateSection", "NtCreateSection",
        "ZwQueueApcThread", "NtQueueApcThread",
        "KeInitializeApc", "KeInsertQueueApc",
    },
}

# APIs that indicate security/validation
VALIDATION_APIS: set[str] = {
    "ExGetPreviousMode", "SeSinglePrivilegeCheck",
    "SeAccessCheck", "ObOpenObjectByPointer",
    "PsGetCurrentProcess", "PsGetProcessId",
    "PsGetCurrentThread", "PsGetCurrentProcessId",
    "PsReferencePrimaryToken",
}


class CallChainAnalyzer(Analyzer):
    """Trace IOCTL handlers through call graph to identify reachable dangerous capabilities."""

    name = "CallChainAnalyzer"
    description = "IOCTL-to-dangerous-API call chain tracing"

    @property
    def is_correlator(self) -> bool:
        """Needs all analyzers to have populated ir.function_apis first."""
        return True

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        if not ir.ioctl_handlers and not ir.ioctl_codes:
            return findings

        # Build reachable function sets for each IOCTL handler
        for ioctl_code, handler_addr in ir.ioctl_handlers.items():
            reachable = self._bfs_reachable(handler_addr, ir.functions)

            # Check for dangerous API groups
            for group_name, api_set in DANGEROUS_API_GROUPS.items():
                found_apis = self._find_apis_in_set(
                    reachable, ir.function_apis, api_set, ir.dynamic_imports
                )
                if found_apis:
                    findings.append(self._make_chain_finding(
                        ioctl_code, handler_addr, reachable,
                        group_name, found_apis, ir
                    ))

            # Check for validation (reduces severity)
            validation_apis = self._find_apis_in_set(
                reachable, ir.function_apis, VALIDATION_APIS, ir.dynamic_imports
            )

            # Check for data table access
            data_access = self._find_data_table_access(
                reachable, ir.data_references, ir.comparison_traces
            )

        # Also check for callback registration reachable from any entry point
        entry_reachable = self._bfs_all_entry_points(ir)
        callback_findings = self._find_callback_registrations(
            entry_reachable, ir.function_apis, ir
        )
        findings.extend(callback_findings)

        return findings

    # ------------------------------------------------------------------
    # BFS call graph traversal
    # ------------------------------------------------------------------

    @staticmethod
    def _bfs_reachable(start_addr: int, functions: dict) -> set[int]:
        """BFS from start_addr through Function.calls graph. Returns set of reachable addresses."""
        visited: set[int] = set()
        queue = deque([start_addr])

        while queue:
            addr = queue.popleft()
            if addr in visited:
                continue
            visited.add(addr)

            func = functions.get(addr)
            if func:
                for callee in func.calls:
                    if callee not in visited and callee in functions:
                        queue.append(callee)

        visited.discard(start_addr)  # Don't count the handler itself
        return visited

    @staticmethod
    def _bfs_all_entry_points(ir: DisassemblyResult) -> set[int]:
        """BFS from all entry points (IOCTL handlers, IRP handlers, etc.)."""
        entry_points: set[int] = set()

        for addr in ir.ioctl_handlers.values():
            entry_points.add(addr)
        for addr in ir.irp_handlers.values():
            entry_points.add(addr)
        if hasattr(ir, "fastio_handlers") and ir.fastio_handlers:
            for addr in ir.fastio_handlers.values():
                entry_points.add(addr)
        if hasattr(ir, "minifilter_handlers") and ir.minifilter_handlers:
            for addrs in ir.minifilter_handlers.values():
                if isinstance(addrs, list):
                    entry_points.update(addrs)

        all_reachable: set[int] = set()
        for ep in entry_points:
            visited = CallChainAnalyzer._bfs_reachable(ep, ir.functions)
            all_reachable.update(visited)

        return all_reachable

    # ------------------------------------------------------------------
    # API detection in reachable set
    # ------------------------------------------------------------------

    @staticmethod
    def _find_apis_in_set(
        reachable: set[int],
        function_apis: dict,
        api_set: set[str],
        dynamic_imports: dict | None = None,
    ) -> list[tuple[int, str]]:
        """Find which APIs from api_set are called by any reachable function.

        Also checks dynamic_imports for dynamically resolved API names.
        """
        found = []
        for addr in reachable:
            apis = function_apis.get(addr, [])
            for api in apis:
                if api in api_set:
                    found.append((addr, api))
            if dynamic_imports:
                for api in dynamic_imports.get(addr, []):
                    if api in api_set:
                        entry = (addr, api)
                        if entry not in found:
                            found.append(entry)
        return found

    # ------------------------------------------------------------------
    # Data table access on reachable paths
    # ------------------------------------------------------------------

    @staticmethod
    def _find_data_table_access(
        reachable: set[int],
        data_references: list,
        comparison_traces: list,
    ) -> list[dict]:
        """Check if any reachable function accesses known data tables."""
        results = []

        # Check data references
        for ref in data_references:
            func_addr = ref.get("func_addr")
            if func_addr in reachable:
                results.append({
                    "type": "data_reference",
                    "func_addr": func_addr,
                    "rva": ref.get("rva"),
                    "access_type": ref.get("access_type"),
                })

        # Check comparison traces
        for trace in comparison_traces:
            # Find which function this trace belongs to by checking insn_addr
            # against function boundaries (approximate: match func_addr if available)
            if "func_addr" in trace and trace["func_addr"] in reachable:
                results.append({
                    "type": "comparison",
                    "func_addr": trace["func_addr"],
                    "data_rva": trace.get("data_rva"),
                    "is_whitelist": trace.get("is_whitelist_check"),
                    "is_blacklist": trace.get("is_blacklist_check"),
                })

        return results

    # ------------------------------------------------------------------
    # Callback registration detection
    # ------------------------------------------------------------------

    @staticmethod
    def _find_callback_registrations(
        reachable: set[int],
        function_apis: dict,
        ir: DisassemblyResult,
    ) -> list[Finding]:
        """Find callback registration APIs called from entry-point-reachable functions."""
        findings = []

        callback_api_groups: dict[str, set[str]] = {
            "object_callback": {"ObRegisterCallbacks"},
            "process_notify": {
                "PsSetCreateProcessNotifyRoutine",
                "PsSetCreateProcessNotifyRoutineEx",
            },
            "thread_notify": {"PsSetCreateThreadNotifyRoutine"},
            "image_notify": {"PsSetLoadImageNotifyRoutine"},
            "registry_callback": {"CmRegisterCallback", "CmRegisterCallbackEx"},
            "fs_callback": {
                "IoRegisterFsRegistrationChange",
                "IoRegisterFsRegistrationChangeEx",
            },
            "minifilter": {"FltRegisterFilter", "FltStartFiltering"},
        }

        for group_name, api_set in callback_api_groups.items():
            found = CallChainAnalyzer._find_apis_in_set(
                reachable, function_apis, api_set, ir.dynamic_imports
            )
            if found:
                for func_addr, api_name in found:
                    # Try to identify the callback target function
                    callback_target = CallChainAnalyzer._resolve_callback_target(
                        func_addr, ir
                    )

                    findings.append(Finding(
                        category=FindingCategory.CALLBACK_RESOLVED,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM if callback_target else Confidence.LOW,
                        description=(
                            f"Callback registration: {api_name} called from func 0x{func_addr:X}"
                            + (f" → callback impl: 0x{callback_target:X}" if callback_target else "")
                        ),
                        function_address=func_addr,
                        context={
                            "api": api_name,
                            "registration_func": func_addr,
                            "callback_target": callback_target,
                            "callback_group": group_name,
                        },
                        evidence=[{
                            "type": "instruction_pattern",
                            "location": f"func 0x{func_addr:X}",
                            "snippet": api_name,
                            "rule_id": "CC001",
                        }],
                    ))

        return findings

    @staticmethod
    def _resolve_callback_target(func_addr: int, ir: DisassemblyResult) -> int | None:
        """Heuristic: find the callback implementation function from a registration point.

        Looks at callees of the registration function, excluding known imported APIs.
        The remaining callee is likely the callback implementation.
        """
        func = ir.functions.get(func_addr)
        if not func:
            return None

        # Known API names that are NOT callback implementations
        known_apis = set()
        for apis in ir.function_apis.values():
            known_apis.update(apis)

        for callee in func.calls:
            # If callee is not a known imported API, it might be the callback
            callee_apis = ir.function_apis.get(callee, [])
            if not callee_apis and callee in ir.functions:
                return callee

        return None

    # ------------------------------------------------------------------
    # Finding creation
    # ------------------------------------------------------------------

    @staticmethod
    def _make_chain_finding(
        ioctl_code: int,
        handler_addr: int,
        reachable: set[int],
        group_name: str,
        found_apis: list[tuple[int, str]],
        ir: DisassemblyResult,
    ) -> Finding:
        """Create a finding for dangerous APIs reachable from an IOCTL handler."""
        api_names = list(set(api for _, api in found_apis))
        api_funcs = list(set(addr for addr, _ in found_apis))

        # Count validation APIs on the same path
        validation_apis = CallChainAnalyzer._find_apis_in_set(
            reachable, ir.function_apis, VALIDATION_APIS, ir.dynamic_imports
        )

        # Determine severity based on capability and validation
        if group_name in ("memory_primitive", "process_control", "token_manipulation"):
            base_severity = Severity.CRITICAL
        elif group_name in ("kernel_callback", "code_execution"):
            base_severity = Severity.HIGH
        else:
            base_severity = Severity.MEDIUM

        # Reduce severity if validation APIs are present
        if validation_apis:
            if base_severity == Severity.CRITICAL:
                base_severity = Severity.HIGH
            elif base_severity == Severity.HIGH:
                base_severity = Severity.MEDIUM

        chain_path = CallChainAnalyzer._shortest_path(
            handler_addr, api_funcs[0] if api_funcs else handler_addr, ir.functions
        )

        return Finding(
            category=FindingCategory.CALL_CHAIN_ANALYZED,
            severity=base_severity,
            confidence=Confidence.MEDIUM,
            description=(
                f"IOCTL 0x{ioctl_code:X} (handler 0x{handler_addr:X}) → "
                f"{', '.join(api_names)} reachable via call chain "
                f"({len(reachable)} functions, {len(chain_path)} hops)"
                + (f", validated by {len(validation_apis)} checks" if validation_apis else ", no validation")
            ),
            function_address=handler_addr,
            context={
                "ioctl_code": ioctl_code,
                "handler_address": handler_addr,
                "capability_group": group_name,
                "dangerous_apis": api_names,
                "reachable_function_count": len(reachable),
                "chain_length": len(chain_path),
                "validation_api_count": len(validation_apis),
            },
            evidence=[{
                "type": "instruction_pattern",
                "location": f"IOCTL 0x{ioctl_code:X}",
                "snippet": f"{' → '.join(f'0x{a:X}' for a in chain_path[:5])}",
                "rule_id": "CC002",
            }],
        )

    @staticmethod
    def _shortest_path(start: int, end: int, functions: dict) -> list[int]:
        """BFS to find shortest call path from start to end."""
        if start == end:
            return [start]

        visited = {start}
        queue = deque([(start, [start])])

        while queue:
            addr, path = queue.popleft()
            func = functions.get(addr)
            if not func:
                continue

            for callee in func.calls:
                if callee == end:
                    return path + [callee]
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))

        return [start, end]  # Fallback: no path found, just endpoints
