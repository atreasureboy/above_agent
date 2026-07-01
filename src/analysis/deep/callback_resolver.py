"""
DriverScope — Callback Resolver.

Deep analysis of callback registration points:
- ObRegisterCallbacks: identifies PreOperation/PostOperation callback functions,
  object types (PsProcessType/PsThreadType), and what the callbacks do
- PsSetCreateProcessNotifyRoutine: identifies the notification callback
- CmRegisterCallback: identifies registry callback functions
- IoRegisterFsRegistrationChange: identifies file system filter callbacks

For each registration point, traces into the callback implementation to identify:
- Handle downgrading (ObDereferenceObject, access mask modification)
- Whitelist checks (PID comparison, process name lookup)
- Security decisions (allow/deny/block)
- Return value modification (STATUS_ACCESS_DENIED, etc.)
- DesiredAccess mask manipulation (handle downgrading)
- Callback security classification (protective/monitoring/manipulating)
"""

from __future__ import annotations

import re
from enum import Enum
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


class CallbackSecurityClass(Enum):
    """Security classification for callback implementations."""
    PROTECTIVE = "protective"       # whitelist check + deny return → blocks unauthorized access
    MONITORING = "monitoring"       # whitelist check + no deny → observes but allows
    MANIPULATING = "manipulating"   # no whitelist + handle modification → actively modifies handles
    PASSIVE = "passive"             # no whitelist + no modification → pure monitoring


class AccessMaskModifier(Enum):
    """Access mask values relevant to Ob callbacks."""
    PROCESS_TERMINATE = 0x0001
    PROCESS_CREATE_THREAD = 0x0002
    PROCESS_VM_OPERATION = 0x0008
    PROCESS_VM_READ = 0x0010
    PROCESS_VM_WRITE = 0x0020
    PROCESS_DUP_HANDLE = 0x0040
    PROCESS_CREATE_PROCESS = 0x0080
    PROCESS_SET_QUOTA = 0x0100
    PROCESS_SET_INFORMATION = 0x0200
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_SUSPEND_RESUME = 0x0800
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SYNCHRONIZE = 0x00100000
    ACCESS_ALL = 0x001FFFFF

# NTSTATUS return values
NTSTATUS = {
    "STATUS_SUCCESS": 0x00000000,
    "STATUS_ACCESS_DENIED": 0xC0000022,
    "STATUS_UNSUCCESSFUL": 0xC0000001,
    "STATUS_INVALID_PARAMETER": 0xC000000D,
    "STATUS_INVALID_HANDLE": 0xC0000008,
    "STATUS_OBJECT_NAME_NOT_FOUND": 0xC0000034,
    "STATUS_NOT_SUPPORTED": 0xC00000BB,
    "STATUS_CALLBACK_BYPASS": 0xC0000509,
}

# Callback API groups
CALLBACK_APIS: dict[str, set[str]] = {
    "object_callback": {
        "ObRegisterCallbacks", "ObUnRegisterCallbacks",
    },
    "process_notify": {
        "PsSetCreateProcessNotifyRoutine",
        "PsSetCreateProcessNotifyRoutineEx",
        "PsRemoveCreateProcessNotifyRoutine",
    },
    "thread_notify": {
        "PsSetCreateThreadNotifyRoutine",
        "PsRemoveCreateThreadNotifyRoutine",
    },
    "image_notify": {
        "PsSetLoadImageNotifyRoutine",
        "PsRemoveLoadImageNotifyRoutine",
    },
    "registry_callback": {
        "CmRegisterCallback", "CmRegisterCallbackEx",
        "CmUnRegisterCallback",
    },
    "fs_callback": {
        "IoRegisterFsRegistrationChange",
        "IoRegisterFsRegistrationChangeEx",
        "IoUnregisterFsRegistrationChange",
    },
    "minifilter": {
        "FltRegisterFilter", "FltStartFiltering", "FltUnregisterFilter",
    },
    "shutdown_notify": {
        "IoRegisterShutdownNotification",
        "IoUnregisterShutdownNotification",
    },
}

# APIs that indicate handle downgrading in Ob callbacks
DOWNGRADE_APIS: set[str] = {
    "ObDereferenceObject", "ObCloseHandle",
    "ExGetPreviousMode", "PsGetProcessId",
    "PsGetProcessImageFileName", "PsGetCurrentProcess",
    "PsGetCurrentProcessId", "PsLookupProcessByProcessId",
    "SeAccessCheck",
}

# OB_OPERATION_REGISTRATION structure offsets (x64)
# struct OB_OPERATION_REGISTRATION {
#   PVOID ObjectType;           // offset 0x00
#   OB_OPERATION Operations;     // offset 0x08
#   POB_PRE_OPERATION_CALLBACK PreOperation;  // offset 0x10
#   POB_POST_OPERATION_CALLBACK PostOperation; // offset 0x18
# };
OB_CALLBACK_STRUCT_OFFSETS = {0x00, 0x08, 0x10, 0x18}


class CallbackResolver(Analyzer):
    """Deep analysis of callback registration points and their implementations."""

    name = "CallbackResolver"
    description = "Callback registration point resolution (ObRegisterCallbacks, process notify, etc.)"

    @property
    def is_correlator(self) -> bool:
        """Needs ir.function_apis and ir.data_structures populated."""
        return True

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. ObRegisterCallbacks deep analysis
        ob_findings = self._resolve_ob_register_callbacks(ir)
        findings.extend(ob_findings)

        # 2. Process/thread/image notify analysis
        notify_findings = self._resolve_notify_callbacks(ir, "process_notify",
            ["PsSetCreateProcessNotifyRoutine", "PsSetCreateProcessNotifyRoutineEx"])
        findings.extend(notify_findings)

        notify_findings = self._resolve_notify_callbacks(ir, "thread_notify",
            ["PsSetCreateThreadNotifyRoutine"])
        findings.extend(notify_findings)

        notify_findings = self._resolve_notify_callbacks(ir, "image_notify",
            ["PsSetLoadImageNotifyRoutine"])
        findings.extend(notify_findings)

        # 3. Registry callback analysis
        reg_findings = self._resolve_registry_callbacks(ir)
        findings.extend(reg_findings)

        # 4. File system callback analysis
        fs_findings = self._resolve_fs_callbacks(ir)
        findings.extend(fs_findings)

        # 5. MiniFilter deep analysis (if already detected)
        if getattr(ir, "is_minifilter", False) or ir.minifilter_handlers:
            mf_findings = self._analyze_minifilter_callbacks(ir)
            findings.extend(mf_findings)

        # 6. Shutdown notification callbacks
        shutdown_findings = self._resolve_notify_callbacks(ir, "shutdown_notify",
            ["IoRegisterShutdownNotification"])
        findings.extend(shutdown_findings)

        return findings

    # ------------------------------------------------------------------
    # Helper: find functions by API name (includes dynamic_imports)
    # ------------------------------------------------------------------

    @staticmethod
    def _find_funcs_with_apis(ir: DisassemblyResult, api_names: set[str]) -> set[int]:
        """Find all function addresses that reference any of the given API names.

        Checks both ir.function_apis (static IAT) and ir.dynamic_imports (resolved at runtime).
        """
        addrs: set[int] = set()
        for func_addr, apis in ir.function_apis.items():
            if set(apis) & api_names:
                addrs.add(func_addr)
        for call_addr, info in ir.dynamic_imports.items():
            if isinstance(info, dict):
                api_name = info.get("api_name", info.get("resolved", ""))
                if api_name in api_names:
                    func_addr = info.get("func_addr") or call_addr
                    addrs.add(func_addr)
            elif isinstance(info, list):
                for item in info:
                    if isinstance(item, str) and item in api_names:
                        addrs.add(call_addr)
                    elif isinstance(item, dict):
                        api_name = item.get("api_name", item.get("resolved", ""))
                        if api_name in api_names:
                            func_addr = item.get("func_addr") or call_addr
                            addrs.add(func_addr)
        return addrs

    # ------------------------------------------------------------------
    # ObRegisterCallbacks deep analysis
    # ------------------------------------------------------------------

    def _resolve_ob_register_callbacks(self, ir: DisassemblyResult) -> list[Finding]:
        """Deep analysis of ObRegisterCallbacks registration points."""
        findings = []

        # Check both function_apis and dynamic_imports
        ob_funcs = self._find_funcs_with_apis(ir, {"ObRegisterCallbacks"})

        for func_addr in ob_funcs:
            # Resolve callback targets
            pre_op, post_op, object_type = self._resolve_ob_callback_targets(
                func_addr, ir
            )

            # Analyze callback implementations
            callback_behavior = {}
            if pre_op:
                callback_behavior["pre_operation"] = self._analyze_callback_behavior(
                    pre_op, ir
                )
            if post_op:
                callback_behavior["post_operation"] = self._analyze_callback_behavior(
                    post_op, ir
                )

            # Determine what this callback protects
            protection_type = "unknown"
            if object_type:
                if "PsProcessType" in object_type:
                    protection_type = "process protection"
                elif "PsThreadType" in object_type:
                    protection_type = "thread protection"
                elif "FileObjectType" in object_type:
                    protection_type = "file object protection"

            findings.append(Finding(
                category=FindingCategory.CALLBACK_RESOLVED,
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description=(
                    f"ObRegisterCallbacks in func 0x{func_addr:X}: "
                    f"{protection_type}"
                    + (f", PreOp=0x{pre_op:X}" if pre_op else "")
                    + (f", PostOp=0x{post_op:X}" if post_op else "")
                    + (f" ({object_type})" if object_type else "")
                ),
                function_address=func_addr,
                context={
                    "api": "ObRegisterCallbacks",
                    "registration_func": func_addr,
                    "pre_operation": pre_op,
                    "post_operation": post_op,
                    "object_type": object_type,
                    "protection_type": protection_type,
                    "callback_behavior": callback_behavior,
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": f"func 0x{func_addr:X}",
                    "snippet": f"ObRegisterCallbacks({protection_type})",
                    "rule_id": "CB001",
                }],
            ))

            # Register for IR tracking
            ir.callback_registrations.append({
                "api": "ObRegisterCallbacks",
                "func_addr": func_addr,
                "callback_funcs": [x for x in [pre_op, post_op] if x],
                "object_type": object_type,
            })

        return findings

    def _resolve_ob_callback_targets(
        self, func_addr: int, ir: DisassemblyResult
    ) -> tuple[int | None, int | None, str | None]:
        """Resolve PreOperation, PostOperation, and ObjectType from ObRegisterCallbacks caller."""
        pre_op = None
        post_op = None
        object_type = None

        func = ir.functions.get(func_addr)
        if not func:
            return None, None, None

        # Method 1: Look at direct callees — the callback implementations are
        # the non-API callees of the registration function
        known_api_names = set()
        for apis_list in ir.function_apis.values():
            known_api_names.update(apis_list)

        candidate_funcs = []
        for callee in func.calls:
            callee_apis = ir.function_apis.get(callee, [])
            if not callee_apis and callee in ir.functions:
                candidate_funcs.append(callee)

        if len(candidate_funcs) >= 1:
            pre_op = candidate_funcs[0]
        if len(candidate_funcs) >= 2:
            post_op = candidate_funcs[1]

        # Method 2: Check for OB_OPERATION_REGISTRATION struct pattern
        # Look for lea instructions with struct offsets
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg:
            for block in cfg.blocks.values():
                for insn in block.instructions:
                    text = f"{insn.mnemonic} {insn.operands}"
                    # Look for lea reg, [rip+offset] patterns near the registration
                    if insn.mnemonic == "lea":
                        # These could be loading addresses of callback functions
                        pass

        # Method 3: Check object type strings
        for s in getattr(ir, "strings", []):
            if "PsProcessType" in s:
                object_type = "PsProcessType"
                break
            elif "PsThreadType" in s:
                object_type = "PsThreadType"
                break
            elif "FileObjectType" in s:
                object_type = "FileObjectType"
                break

        return pre_op, post_op, object_type

    # ------------------------------------------------------------------
    # Process/thread notify callbacks
    # ------------------------------------------------------------------

    def _resolve_notify_callbacks(
        self, ir: DisassemblyResult, group: str, api_names: list[str]
    ) -> list[Finding]:
        """Resolve process/thread/image notify callback functions."""
        findings = []
        api_set = set(api_names)

        for func_addr in self._find_funcs_with_apis(ir, api_set):
            # Determine which API matched
            apis_in_func = ir.function_apis.get(func_addr, [])
            matched = [a for a in api_names if a in apis_in_func]
            if not matched:
                # Check dynamic_imports
                for call_addr, info in ir.dynamic_imports.items():
                    if isinstance(info, dict) and info.get("api_name") in api_set:
                        if info.get("func_addr") == func_addr:
                            matched = [info["api_name"]]
                            break
            if not matched:
                continue

            api_name = matched[0]
            callback_target = self._resolve_callback_target(func_addr, ir)

            behavior = {}
            if callback_target:
                behavior = self._analyze_callback_behavior(callback_target, ir)

            findings.append(Finding(
                category=FindingCategory.CALLBACK_RESOLVED,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM if callback_target else Confidence.LOW,
                description=(
                    f"{api_name} in func 0x{func_addr:X}"
                    + (f" → callback 0x{callback_target:X}" if callback_target else "")
                ),
                function_address=func_addr,
                context={
                    "api": api_name,
                    "registration_func": func_addr,
                    "callback_target": callback_target,
                    "callback_group": group,
                    "behavior": behavior,
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": f"func 0x{func_addr:X}",
                    "snippet": api_name,
                    "rule_id": "CB002",
                }],
            ))

            ir.callback_registrations.append({
                "api": api_name,
                "func_addr": func_addr,
                "callback_funcs": [callback_target] if callback_target else [],
                "object_type": group,
            })

        return findings

    # ------------------------------------------------------------------
    # Registry callbacks
    # ------------------------------------------------------------------

    def _resolve_registry_callbacks(self, ir: DisassemblyResult) -> list[Finding]:
        """Resolve registry callback functions."""
        findings = []
        api_names = ["CmRegisterCallback", "CmRegisterCallbackEx"]

        for func_addr in self._find_funcs_with_apis(ir, set(api_names)):
            matched = [a for a in api_names if a in ir.function_apis.get(func_addr, [])]
            if not matched:
                # Try dynamic_imports
                for call_addr, info in ir.dynamic_imports.items():
                    if isinstance(info, dict) and info.get("api_name") in api_names:
                        if info.get("func_addr") == func_addr:
                            matched = [info["api_name"]]
                            break
            if not matched:
                continue

            callback_target = self._resolve_callback_target(func_addr, ir)
            behavior = {}
            if callback_target:
                behavior = self._analyze_callback_behavior(callback_target, ir)

            findings.append(Finding(
                category=FindingCategory.CALLBACK_RESOLVED,
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM if callback_target else Confidence.LOW,
                description=(
                    f"CmRegisterCallback in func 0x{func_addr:X}"
                    + (f" → callback 0x{callback_target:X}" if callback_target else "")
                ),
                function_address=func_addr,
                context={
                    "api": matched[0],
                    "registration_func": func_addr,
                    "callback_target": callback_target,
                    "behavior": behavior,
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": f"func 0x{func_addr:X}",
                    "snippet": matched[0],
                    "rule_id": "CB003",
                }],
            ))

        return findings

    # ------------------------------------------------------------------
    # File system callbacks
    # ------------------------------------------------------------------

    def _resolve_fs_callbacks(self, ir: DisassemblyResult) -> list[Finding]:
        """Resolve file system filter callbacks."""
        findings = []
        api_names = ["IoRegisterFsRegistrationChange", "IoRegisterFsRegistrationChangeEx"]

        for func_addr in self._find_funcs_with_apis(ir, set(api_names)):
            matched = [a for a in api_names if a in ir.function_apis.get(func_addr, [])]
            if not matched:
                # Try dynamic_imports
                for call_addr, info in ir.dynamic_imports.items():
                    if isinstance(info, dict) and info.get("api_name") in api_names:
                        if info.get("func_addr") == func_addr:
                            matched = [info["api_name"]]
                            break
            if not matched:
                continue

            callback_target = self._resolve_callback_target(func_addr, ir)
            behavior = {}
            if callback_target:
                behavior = self._analyze_callback_behavior(callback_target, ir)

            findings.append(Finding(
                category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM if callback_target else Confidence.LOW,
                description=(
                    f"FS filter registration in func 0x{func_addr:X}: {matched[0]}"
                    + (f" → callback 0x{callback_target:X}" if callback_target else "")
                ),
                function_address=func_addr,
                context={
                    "api": matched[0],
                    "registration_func": func_addr,
                    "callback_target": callback_target,
                    "behavior": behavior,
                    "filter_type": "file_system",
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": f"func 0x{func_addr:X}",
                    "snippet": matched[0],
                    "rule_id": "CB004",
                }],
            ))

        return findings

    # ------------------------------------------------------------------
    # MiniFilter deep analysis
    # ------------------------------------------------------------------

    def _analyze_minifilter_callbacks(self, ir: DisassemblyResult) -> list[Finding]:
        """Analyze MiniFilter callback handlers."""
        findings = []

        for op, callback_addrs in ir.minifilter_handlers.items():
            if not isinstance(callback_addrs, list):
                callback_addrs = [callback_addrs]

            for callback_addr in callback_addrs:
                behavior = self._analyze_callback_behavior(callback_addr, ir)

                findings.append(Finding(
                    category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    description=f"MiniFilter {op} callback at 0x{callback_addr:X}"
                    + (f" (whitelist check: {behavior.get('has_whitelist_check')})" if behavior.get('has_whitelist_check') else ""),
                    function_address=callback_addr,
                    context={
                        "operation": op,
                        "callback_address": callback_addr,
                        "behavior": behavior,
                        "filter_type": "minifilter",
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"MiniFilter {op}",
                        "snippet": op,
                        "rule_id": "CB005",
                    }],
                ))

        return findings

    # ------------------------------------------------------------------
    # Callback behavior analysis
    # ------------------------------------------------------------------

    def _analyze_callback_behavior(
        self, callback_addr: int, ir: DisassemblyResult
    ) -> dict[str, Any]:
        """Analyze what a callback function does."""
        behavior: dict[str, Any] = {}

        func = ir.functions.get(callback_addr)
        if not func:
            return behavior

        # Check for downgrade APIs
        callback_apis = ir.function_apis.get(callback_addr, [])
        downgrade_found = [a for a in callback_apis if a in DOWNGRADE_APIS]
        if downgrade_found:
            behavior["downgrade_apis"] = downgrade_found

        # Check for whitelist checks (string comparisons, PID checks)
        cfg = ir.cfgs.get(callback_addr) or ir.simple_cfgs.get(callback_addr)
        if cfg:
            whitelist_check = self._check_whitelist_pattern(cfg, ir)
            if whitelist_check:
                behavior["has_whitelist_check"] = True
                behavior["whitelist_details"] = whitelist_check

        # Check for data table references
        if ir.data_references:
            data_refs = [
                r for r in ir.data_references
                if r.get("func_addr") == callback_addr
            ]
            if data_refs:
                behavior["data_references"] = [
                    {"rva": r.get("rva"), "type": r.get("access_type")}
                    for r in data_refs[:5]
                ]

        # Task B: Enhanced semantic analysis
        if cfg:
            semantics = self._analyze_semantics(callback_addr, ir)
            if semantics.get("has_deny_return"):
                behavior["has_deny_return"] = True
                behavior["deny_statuses"] = semantics.get("deny_statuses", [])
            if semantics.get("has_handle_modification"):
                behavior["has_handle_modification"] = True
                behavior["access_mask_modifications"] = semantics.get("access_mask_modifications", [])
            behavior["security_class"] = semantics.get("security_class", CallbackSecurityClass.PASSIVE).value
            behavior["decision_type"] = semantics.get("decision_type", "unknown")

        return behavior

    @staticmethod
    def _check_whitelist_pattern(cfg, ir: DisassemblyResult) -> dict | None:
        """Check if a function has whitelist checking patterns."""
        # Check for cmp against known data tables
        if ir.comparison_traces:
            for trace in ir.comparison_traces:
                # Approximate: check if trace is in this function's address range
                if trace.get("is_whitelist_check") or trace.get("is_blacklist_check"):
                    return {
                        "type": "data_comparison",
                        "data_rva": trace.get("data_rva"),
                        "is_whitelist": trace.get("is_whitelist_check"),
                        "is_blacklist": trace.get("is_blacklist_check"),
                    }

        # Check for string comparisons against process names
        for block in cfg.blocks.values():
            for insn in block.instructions:
                text = f"{insn.mnemonic} {insn.operands}"
                if "cmp" in text.lower() or "test" in text.lower():
                    # Check for common whitelist indicators
                    for kw in ("ProcessId", "ImageFileName", "PreviousMode",
                               "allowed", "whitelist", "trusted"):
                        if kw.lower() in text.lower():
                            return {
                                "type": "keyword_match",
                                "keyword": kw,
                                "instruction": text,
                            }

        return None

    # ------------------------------------------------------------------
    # Callback semantic analysis (Task B enhancements)
    # ------------------------------------------------------------------

    def _analyze_semantics(self, callback_addr: int, ir: DisassemblyResult) -> dict[str, Any]:
        """Full semantic analysis of a callback implementation.

        Returns a dict with:
        - has_whitelist_check: bool
        - has_deny_return: bool
        - has_handle_modification: bool
        - access_mask_modifications: list of modified access bits
        - decision_type: str (allow/deny/monitor/manipulate)
        - security_class: CallbackSecurityClass
        - compared_data: list of data sources compared
        """
        result: dict[str, Any] = {
            "has_whitelist_check": False,
            "has_deny_return": False,
            "has_handle_modification": False,
            "access_mask_modifications": [],
            "decision_type": "passive_monitor",
            "security_class": CallbackSecurityClass.PASSIVE,
            "compared_data": [],
        }

        cfg = ir.cfgs.get(callback_addr) or ir.simple_cfgs.get(callback_addr)
        if not cfg:
            return result

        # 1. Check for return value modification
        deny_returns = self._find_return_modification(cfg)
        if deny_returns:
            result["has_deny_return"] = True
            result["deny_statuses"] = deny_returns

        # 2. Check for access mask / DesiredAccess modification
        access_mods = self._find_access_mask_modifications(cfg, ir)
        if access_mods:
            result["has_handle_modification"] = True
            result["access_mask_modifications"] = access_mods

        # 3. Check for whitelist/blacklist checks
        whitelist_check = self._check_whitelist_pattern(cfg, ir)
        if whitelist_check:
            result["has_whitelist_check"] = True
            result["whitelist_details"] = whitelist_check
            if "type" in whitelist_check:
                result["compared_data"].append(whitelist_check["type"])

        # 4. Classify callback security
        result["security_class"] = self._classify_callback_security(result)
        result["decision_type"] = self._infer_decision_type(result)

        return result

    def _find_return_modification(self, cfg) -> list[str]:
        """Find instructions that modify return value to deny status codes.

        Looks for patterns like:
        - `mov eax, 0xC0000022`  (STATUS_ACCESS_DENIED)
        - `mov eax, 0xC0000001`  (STATUS_UNSUCCESSFUL)
        - `xor eax, eax`         (STATUS_SUCCESS = 0)
        """
        deny_statuses_found = []

        for block in cfg.blocks.values():
            for insn in block.instructions:
                mnemonic = insn.mnemonic.lower()
                full_text = f"{mnemonic} {insn.operands.lower()}"

                # mov eax/rax, imm
                if mnemonic == "mov":
                    m = re.search(
                        r"[er]ax\s*,\s*(?:0x)?([0-9a-f]+)",
                        full_text,
                        re.IGNORECASE,
                    )
                    if m:
                        val = int(m.group(1), 16)
                        for name, code in NTSTATUS.items():
                            if val == code:
                                deny_statuses_found.append(name)

                # xor eax, eax → STATUS_SUCCESS
                if mnemonic == "xor" and re.search(r"[er]ax\s*,\s*[er]ax", full_text):
                    deny_statuses_found.append("STATUS_SUCCESS")

        return deny_statuses_found

    def _find_access_mask_modifications(
        self, cfg, ir: DisassemblyResult
    ) -> list[dict[str, Any]]:
        """Find instructions that modify access masks (DesiredAccess manipulation).

        Looks for:
        - `and eax, 0xFFFFFFFE`  (clearing specific bits)
        - `and [reg+offset], imm`  (modifying access mask in structure)
        - References to OB_PRE_CREATE_HANDLE_INFORMATION structure
        """
        modifications = []

        for block in cfg.blocks.values():
            for insn in block.instructions:
                mnemonic = insn.mnemonic.lower()
                full_text = f"{mnemonic} {insn.operands.lower()}"

                # AND with mask: clearing bits from access mask
                if mnemonic == "and":
                    m = re.search(r"(?:0x)?([0-9a-f]+)", full_text, re.IGNORECASE)
                    if m:
                        mask_val = int(m.group(1), 16)
                        if mask_val != 0:
                            cleared_bits = self._identify_cleared_bits(mask_val)
                            modifications.append({
                                "instruction": full_text,
                                "address": insn.address,
                                "operation": "clear_bits",
                                "mask": hex(mask_val),
                                "cleared_bits": cleared_bits,
                            })

                # OR with mask: adding bits
                if mnemonic == "or":
                    m = re.search(r"(?:0x)?([0-9a-f]+)", full_text, re.IGNORECASE)
                    if m:
                        mask_val = int(m.group(1), 16)
                        if mask_val != 0:
                            modifications.append({
                                "instruction": full_text,
                                "address": insn.address,
                                "operation": "set_bits",
                                "mask": hex(mask_val),
                            })

        return modifications

    @staticmethod
    def _identify_cleared_bits(mask: int) -> list[str]:
        """Identify which access mask bits are being cleared."""
        cleared = []
        inverted = ~mask & 0xFFFFFFFF
        for name, value in AccessMaskModifier.__members__.items():
            if inverted & value.value:
                cleared.append(name)
        return cleared

    def _classify_callback_security(self, analysis: dict) -> CallbackSecurityClass:
        """Classify callback security based on behavior analysis.

        - has_whitelist_check + has_deny_return → PROTECTIVE
        - has_whitelist_check + no_deny_return → MONITORING
        - no_whitelist_check + has_handle_modification → MANIPULATING
        - no_whitelist_check + no_handle_modification → PASSIVE
        """
        has_whitelist = analysis.get("has_whitelist_check", False)
        has_deny = analysis.get("has_deny_return", False)
        has_modification = analysis.get("has_handle_modification", False)

        if has_whitelist and has_deny:
            return CallbackSecurityClass.PROTECTIVE
        if has_whitelist and not has_deny:
            return CallbackSecurityClass.MONITORING
        if not has_whitelist and has_modification:
            return CallbackSecurityClass.MANIPULATING
        return CallbackSecurityClass.PASSIVE

    def _infer_decision_type(self, analysis: dict) -> str:
        """Infer the callback's decision type from its behavior."""
        sec_class = analysis.get("security_class")
        if sec_class == CallbackSecurityClass.PROTECTIVE:
            return "deny_unless_whitelisted"
        if sec_class == CallbackSecurityClass.MONITORING:
            return "allow_with_logging"
        if sec_class == CallbackSecurityClass.MANIPULATING:
            return "modify_handles"
        return "passive_monitor"

    @staticmethod
    def _resolve_callback_target(func_addr: int, ir: DisassemblyResult) -> int | None:
        """Find the callback implementation from a registration function."""
        func = ir.functions.get(func_addr)
        if not func:
            return None

        known_api_names = set()
        for apis_list in ir.function_apis.values():
            known_api_names.update(apis_list)

        for callee in func.calls:
            callee_apis = ir.function_apis.get(callee, [])
            if not callee_apis and callee in ir.functions:
                return callee

        return None
