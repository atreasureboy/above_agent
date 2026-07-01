"""
DriverScope — File System Filter Driver Analyzer.

Deep analysis of file system filter drivers (MiniFilter and legacy FS filter):
- Detects FS filter registration APIs (IoRegisterFsRegistrationChange, FltRegisterFilter)
- Analyzes MiniFilter callback functions (Create/Read/Write/DeviceControl pre/post ops)
- Traces whitelist check patterns in filter callbacks
- Identifies fast-path放行 vs deep inspection vs pass-through behavior
"""

from __future__ import annotations

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

# FS filter registration APIs
FS_REGISTER_APIS: dict[str, set[str]] = {
    "legacy_filter": {
        "IoRegisterFsRegistrationChange",
        "IoRegisterFsRegistrationChangeEx",
    },
    "minifilter": {
        "FltRegisterFilter",
        "FltStartFiltering",
        "FltSetCallback",
    },
    "fs_callback": {
        "IoRegisterFsRegistrationChange",
        "IoRegisterFsRegistrationChangeEx",
    },
}

# MiniFilter callback operation types
MINIFILTER_OPERATIONS: dict[str, str] = {
    "IRP_MJ_CREATE": "Create",
    "IRP_MJ_READ": "Read",
    "IRP_MJ_WRITE": "Write",
    "IRP_MJ_DEVICE_CONTROL": "DeviceControl",
    "IRP_MJ_SET_INFORMATION": "SetInfo",
    "IRP_MJ_QUERY_INFORMATION": "QueryInfo",
    "IRP_MJ_DIRECTORY_CONTROL": "DirectoryControl",
    "IRP_MJ_CLEANUP": "Cleanup",
    "IRP_MJ_CLOSE": "Close",
    "IRP_MJ_SHUTDOWN": "Shutdown",
}


class FilterDriverAnalyzer(Analyzer):
    """Deep analysis of file system filter drivers and their callback behavior."""

    name = "FilterDriverAnalyzer"
    description = "File system filter driver callback analysis"

    @property
    def is_correlator(self) -> bool:
        return True

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Detect legacy FS filter registration
        findings.extend(self._detect_legacy_filter(ir))

        # 2. Deep MiniFilter callback analysis (from minifilter_handlers)
        if ir.is_minifilter or ir.minifilter_handlers:
            findings.extend(self._analyze_minifilter_callbacks(ir))

        # 3. Analyze operation rules directly (from MiniFilterRuleExtractor)
        if getattr(ir, "operation_rules", None):
            findings.extend(self._analyze_operation_rules(ir))

        # 4. Detect FS callback registrations from entry-point-reachable functions
        findings.extend(self._detect_fs_callbacks_from_entries(ir))

        return findings

    # ------------------------------------------------------------------
    # Legacy FS filter detection
    # ------------------------------------------------------------------

    def _detect_legacy_filter(self, ir: DisassemblyResult) -> list[Finding]:
        """Detect legacy FS filter registration via IoRegisterFsRegistrationChange."""
        findings = []

        for func_addr, apis in ir.function_apis.items():
            for api_name in apis:
                if api_name in FS_REGISTER_APIS["legacy_filter"]:
                    # Try to resolve callback functions from parameters
                    callbacks = self._resolve_fs_callback_targets(func_addr, ir)

                    findings.append(Finding(
                        category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        description=(
                            f"Legacy FS filter: {api_name} called from func 0x{func_addr:X}"
                            + (f", {len(callbacks)} callback(s) resolved" if callbacks else ", callback targets unresolved")
                        ),
                        function_address=func_addr,
                        context={
                            "api": api_name,
                            "registration_func": func_addr,
                            "callback_targets": callbacks,
                            "filter_type": "legacy",
                        },
                        evidence=[{
                            "type": "instruction_pattern",
                            "location": f"func 0x{func_addr:X}",
                            "snippet": api_name,
                            "rule_id": "FD001",
                        }],
                    ))

                    # Record in IR
                    ir.filter_callbacks.append({
                        "type": "legacy",
                        "registration_func": func_addr,
                        "api": api_name,
                        "callbacks": callbacks,
                    })

        return findings

    # ------------------------------------------------------------------
    # MiniFilter deep callback analysis
    # ------------------------------------------------------------------

    def _analyze_minifilter_callbacks(self, ir: DisassemblyResult) -> list[Finding]:
        """Deep analysis of MiniFilter callback handlers."""
        findings = []

        for callback_offset, handler_addrs in ir.minifilter_handlers.items():
            if not isinstance(handler_addrs, list):
                handler_addrs = [handler_addrs]

            for handler_addr in handler_addrs:
                func = ir.functions.get(handler_addr)
                if not func:
                    continue

                # Determine operation type from offset
                op_name = MINIFILTER_OPERATIONS.get(str(callback_offset), f"Unknown_{callback_offset}")

                # Analyze callback behavior
                behavior = self._analyze_callback_behavior(handler_addr, ir)

                # Determine severity based on behavior
                if behavior.get("has_whitelist_check"):
                    severity = Severity.INFO
                    desc_suffix = " (whitelist check detected)"
                elif behavior.get("has_fast_path"):
                    severity = Severity.LOW
                    desc_suffix = " (fast-path pass-through)"
                elif behavior.get("blocks_operation"):
                    severity = Severity.HIGH
                    desc_suffix = " (blocks operation)"
                else:
                    severity = Severity.MEDIUM
                    desc_suffix = " (passes to next filter)"

                findings.append(Finding(
                    category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"MiniFilter {op_name} callback: func 0x{handler_addr:X}{desc_suffix}"
                        + (f", {len(behavior.get('data_tables', []))} data table ref(s)" if behavior.get("data_tables") else "")
                        + (f", calls {len(behavior.get('apis_called', []))} API(s)" if behavior.get("apis_called") else "")
                    ),
                    function_address=handler_addr,
                    context={
                        "callback_type": "minifilter",
                        "operation": op_name,
                        "callback_offset": callback_offset,
                        "behavior": behavior,
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"func 0x{handler_addr:X}",
                        "snippet": f"MiniFilter {op_name}",
                        "rule_id": "FD002",
                    }],
                ))

                # Record in IR
                ir.filter_callbacks.append({
                    "type": "minifilter",
                    "callback_addr": handler_addr,
                    "operation": op_name,
                    "callback_offset": callback_offset,
                    "behavior": behavior,
                })

        return findings

    # ------------------------------------------------------------------
    # FS callback detection from entry points
    # ------------------------------------------------------------------

    def _detect_fs_callbacks_from_entries(self, ir: DisassemblyResult) -> list[Finding]:
        """Detect FS callback registrations reachable from any entry point."""
        findings = []

        # Collect all reachable functions from entry points
        entry_reachable = self._bfs_all_entry_points(ir)

        for func_addr in entry_reachable:
            apis = ir.function_apis.get(func_addr, [])
            for api_name in apis:
                if api_name in FS_REGISTER_APIS["fs_callback"]:
                    callbacks = self._resolve_fs_callback_targets(func_addr, ir)

                    findings.append(Finding(
                        category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM if callbacks else Confidence.LOW,
                        description=(
                            f"FS callback: {api_name} reachable from entry point, "
                            f"registered in func 0x{func_addr:X}"
                            + (f", {len(callbacks)} callback(s)" if callbacks else "")
                        ),
                        function_address=func_addr,
                        context={
                            "api": api_name,
                            "registration_func": func_addr,
                            "callbacks": callbacks,
                            "reachable_from_entry": True,
                        },
                        evidence=[{
                            "type": "instruction_pattern",
                            "location": f"func 0x{func_addr:X}",
                            "snippet": api_name,
                            "rule_id": "FD003",
                        }],
                    ))

        return findings

    # ------------------------------------------------------------------
    # Operation rules analysis (from MiniFilterRuleExtractor)
    # ------------------------------------------------------------------

    def _analyze_operation_rules(self, ir: DisassemblyResult) -> list[Finding]:
        """Analyze operation rules populated by MiniFilterRuleExtractor."""
        findings = []

        for rule in ir.operation_rules:
            mj_name = MINIFILTER_OPERATIONS.get(
                rule["major_function"],
                f"IRP_MJ_{rule['major_function']:02X}",
            )
            semantic = mj_name  # Use the name as semantic fallback

            has_pre = rule.get("pre_operation") is not None
            has_post = rule.get("post_operation") is not None

            severity = Severity.LOW
            if rule["major_function"] in (0x0E, 0x0F, 0x0D):
                severity = Severity.HIGH  # DeviceControl-like operations
            elif has_pre:
                severity = Severity.MEDIUM  # Pre-operation = potential intercept

            findings.append(Finding(
                category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                severity=severity,
                confidence=Confidence.MEDIUM,
                description=(
                    f"Filter rule: {mj_name} "
                    f"{'pre+post' if has_pre and has_post else 'pre' if has_pre else 'post'} "
                    f"callbacks — RVA 0x{rule['rva']:X}"
                ),
                instruction_address=rule["rva"],
                context={
                    "major_function": rule["major_function"],
                    "mj_name": mj_name,
                    "pre_operation": rule.get("pre_operation"),
                    "post_operation": rule.get("post_operation"),
                    "flags": rule.get("flags", 0),
                    "rule_type": "operation_registration",
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": f"RVA 0x{rule['rva']:X}",
                    "snippet": mj_name,
                    "rule_id": "FD004",
                }],
            ))

            # Record in IR
            ir.filter_callbacks.append({
                "type": "minifilter",
                "operation": mj_name,
                "callback_offset": rule["major_function"],
                "pre_operation": rule.get("pre_operation"),
                "post_operation": rule.get("post_operation"),
                "rva": rule["rva"],
            })

        return findings

    # ------------------------------------------------------------------
    # Callback target resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_fs_callback_targets(func_addr: int, ir: DisassemblyResult) -> list[int]:
        """Resolve FS filter callback target functions from registration point."""
        func = ir.functions.get(func_addr)
        if not func:
            return []

        known_apis = set()
        for apis in ir.function_apis.values():
            known_apis.update(apis)

        targets = []
        for callee in func.calls:
            callee_apis = ir.function_apis.get(callee, [])
            # Non-API functions called from registration point are likely callbacks
            if not callee_apis and callee in ir.functions:
                targets.append(callee)

        return targets

    # ------------------------------------------------------------------
    # Callback behavior analysis
    # ------------------------------------------------------------------

    @staticmethod
    def _analyze_callback_behavior(func_addr: int, ir: DisassemblyResult) -> dict[str, Any]:
        """Analyze what a filter callback does."""
        behavior: dict[str, Any] = {
            "has_whitelist_check": False,
            "has_fast_path": False,
            "blocks_operation": False,
            "apis_called": [],
            "data_tables": [],
        }

        func = ir.functions.get(func_addr)
        if not func:
            return behavior

        # Collect all APIs called by this callback
        all_apis = set()
        queue = [func_addr]
        visited: set[int] = set()

        while queue:
            addr = queue.pop(0)
            if addr in visited:
                continue
            visited.add(addr)

            apis = ir.function_apis.get(addr, [])
            all_apis.update(apis)

            f = ir.functions.get(addr)
            if f:
                for callee in f.calls:
                    if callee not in visited:
                        queue.append(callee)

        # Check for blocking behavior
        blocking_apis = {
            "STATUS_ACCESS_DENIED", "STATUS_INVALID_PARAMETER",
            "FltCancelFileOpen", "FltReleaseFileNameInformation",
        }
        if all_apis & blocking_apis:
            behavior["blocks_operation"] = True

        # Check for fast-path (quick return without deep inspection)
        # Fast-path: few callees, early return pattern
        if len(func.calls) <= 2 and func.size < 0x50:
            behavior["has_fast_path"] = True

        # Check for whitelist/privilege check APIs
        validation_apis = {
            "PsGetCurrentProcessId", "PsGetProcessId",
            "PsGetCurrentProcess", "ExGetPreviousMode",
            "SeSinglePrivilegeCheck", "PsReferencePrimaryToken",
        }
        found_validation = all_apis & validation_apis
        if found_validation:
            behavior["has_whitelist_check"] = True
            behavior["validation_apis"] = list(found_validation)

        # Collect non-trivial API calls
        trivial_apis = {
            "memset", "memcpy", "RtlCopyMemory", "RtlZeroMemory",
            "DbgPrint", "KdPrint",
        }
        behavior["apis_called"] = list(all_apis - trivial_apis)

        # Check data table references from comparison_traces
        for trace in ir.comparison_traces:
            if trace.get("func_addr") == func_addr:
                if trace.get("is_whitelist_check") or trace.get("is_blacklist_check"):
                    behavior["has_whitelist_check"] = True
                if trace.get("data_rva"):
                    behavior["data_tables"].append({
                        "rva": trace["data_rva"],
                        "type": "whitelist" if trace.get("is_whitelist_check") else "blacklist",
                    })

        return behavior

    # ------------------------------------------------------------------
    # Whitelist pattern checking in CFG
    # ------------------------------------------------------------------

    @staticmethod
    def _check_whitelist_pattern(func_addr: int, ir: DisassemblyResult) -> bool:
        """Check if a function has whitelist comparison patterns in its CFG."""
        # Check comparison traces
        for trace in ir.comparison_traces:
            if trace.get("func_addr") == func_addr:
                if trace.get("is_whitelist_check"):
                    return True

        # Check string references for known whitelist keywords
        whitelist_keywords = {"whitelist", "allowed", "trusted", "360Safe"}
        func_strings = []

        # Check data references belonging to this function
        for ref in ir.data_references:
            if ref.get("func_addr") == func_addr:
                rva = ref.get("rva")
                if rva and rva in ir.string_rvas:
                    val = ir.string_rvas[rva].lower()
                    if any(kw in val for kw in whitelist_keywords):
                        func_strings.append(val)

        return len(func_strings) > 0

    # ------------------------------------------------------------------
    # BFS from all entry points (reused pattern)
    # ------------------------------------------------------------------

    @staticmethod
    def _bfs_all_entry_points(ir: DisassemblyResult) -> set[int]:
        """BFS from all entry points through call graph."""
        from collections import deque

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
            visited: set[int] = set()
            queue = deque([ep])
            while queue:
                addr = queue.popleft()
                if addr in visited:
                    continue
                visited.add(addr)
                func = ir.functions.get(addr)
                if func:
                    for callee in func.calls:
                        if callee not in visited:
                            queue.append(callee)
            all_reachable.update(visited)

        return all_reachable
