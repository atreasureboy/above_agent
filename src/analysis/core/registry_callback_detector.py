"""
DriverScope — 注册表回调保护检测器。

检测注册表回调注册和注册表操作拦截，用于：
1. CmRegisterCallback / CmRegisterCallbackEx — 注册表回调注册
2. 回调函数内的注册表操作：ZwCreateKey, ZwSetValueKey, ZwDeleteKey
3. 注册表路径字符串分析（360 自我保护注册表键）
4. 注册表回调上下文结构（CM_NOTIFY_ENTRY）初始化

360 安全卫士通过注册表回调拦截对 360 相关注册表键的修改、删除和枚举，
阻止第三方安全软件或恶意程序篡改其配置。
"""

from __future__ import annotations

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


# ---------------------------------------------------------------------------
# 1. 注册表回调 API 检测
# ---------------------------------------------------------------------------

REGISTRY_CALLBACK_APIS = {
    "CmRegisterCallback": "Register registry callback (legacy)",
    "CmRegisterCallbackEx": "Register registry callback (extended)",
    "CmUnRegisterCallback": "Unregister registry callback",
}

# Registry operations commonly used within callbacks
REGISTRY_OPERATIONS = {
    "ZwCreateKey": "Create/open registry key",
    "NtCreateKey": "Native create key",
    "ZwOpenKey": "Open registry key",
    "NtOpenKey": "Native open key",
    "ZwSetValueKey": "Set registry value",
    "NtSetValueKey": "Native set value",
    "ZwDeleteKey": "Delete registry key",
    "NtDeleteKey": "Native delete key",
    "ZwDeleteValueKey": "Delete registry value",
    "ZwEnumerateKey": "Enumerate registry keys",
    "ZwEnumerateValueKey": "Enumerate registry values",
    "ZwQueryKey": "Query key information",
    "ZwQueryValueKey": "Query value information",
    "ZwQueryMultipleValueKey": "Query multiple values",
    "ZwRenameKey": "Rename registry key",
    "ZwFlushKey": "Flush key to disk",
    "ZwLoadKey": "Load registry hive",
    "ZwUnloadKey": "Unload registry hive",
}


def detect_registry_callback_apis(ir: DisassemblyResult) -> list[Finding]:
    """Detect registry callback registration and operations."""
    findings: list[Finding] = []

    callback_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in REGISTRY_CALLBACK_APIS]
        if matched:
            callback_funcs.append((func_addr, matched))

    reg_op_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in REGISTRY_OPERATIONS]
        if matched:
            reg_op_funcs.append((func_addr, matched))

    if not callback_funcs and not reg_op_funcs:
        return findings

    all_callback_apis = []
    for _, apis in callback_funcs:
        all_callback_apis.extend(apis)

    all_reg_apis = []
    for _, apis in reg_op_funcs:
        all_reg_apis.extend(apis)

    has_ex = any("Ex" in api for _, apis in callback_funcs for api in apis)
    has_write_ops = any(
        "SetValue" in api or "Delete" in api or "Create" in api
        for _, apis in reg_op_funcs for api in apis
    )

    if has_ex and has_write_ops:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif callback_funcs and reg_op_funcs:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    elif callback_funcs:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    elif reg_op_funcs:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW
    else:
        severity = Severity.LOW
        confidence = Confidence.LOW

    findings.append(
        Finding(
            category=FindingCategory.REGISTRY_CALLBACK,
            severity=severity,
            confidence=confidence,
            description=(
                f"Registry callback indicators: {len(callback_funcs)} callback "
                f"registration(s), {len(reg_op_funcs)} functions with registry "
                f"operations. Callback APIs: {', '.join(sorted(set(all_callback_apis)))}. "
                f"Registry ops: {', '.join(sorted(set(all_reg_apis)))}. "
                f"Driver may intercept registry operations."
            ),
            function_address=callback_funcs[0][0] if callback_funcs else (reg_op_funcs[0][0] if reg_op_funcs else 0),
            context={
                "callback_functions": [
                    {"address": hex(addr), "apis": apis}
                    for addr, apis in callback_funcs[:10]
                ],
                "registry_operation_functions": [
                    {"address": hex(addr), "apis": apis}
                    for addr, apis in reg_op_funcs[:10]
                ],
                "has_extended_callback": has_ex,
                "has_write_operations": has_write_ops,
            },
            evidence=[
                Evidence(
                    type="api_match",
                    location=f"sub_{(callback_funcs[0][0] if callback_funcs else reg_op_funcs[0][0]):X}",
                    snippet=sorted(set(all_callback_apis + all_reg_apis))[0] if (all_callback_apis or all_reg_apis) else "registry callback",
                    rule_id="REGISTRY_CALLBACK_API",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 2. 注册表路径字符串检测
# ---------------------------------------------------------------------------

REGISTRY_PATH_PATTERNS = {
    "360Safe": "360 Safe registry key",
    "360AntiHack": "360 AntiHack registry key",
    "360tray": "360 Tray registry key",
    "Qihoo": "Qihoo 360 registry key",
    "QHSafe": "Qihoo Safe registry key",
    "QPCore": "QP Core registry key",
    "LeakRepair": "Leak Repair registry key",
    "SafeKrnl": "Safe Kernel registry key",
    "CurrentControlSet": "HKLM\\SYSTEM\\CurrentControlSet access",
    "Services\\": "Driver service registry path",
    "Class\\": "Device class registry path",
}


def detect_registry_paths(ir: DisassemblyResult) -> list[Finding]:
    """Detect registry path strings in the binary."""
    findings: list[Finding] = []

    reg_strings = []
    for s in ir.strings:
        for pattern, desc in REGISTRY_PATH_PATTERNS.items():
            if pattern in s:
                reg_strings.append((s, desc))
                break

    if not reg_strings:
        return findings

    seen = set()
    unique_strings = []
    for s, desc in reg_strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append((s, desc))

    has_360_paths = any(
        p in s for s, _ in unique_strings
        for p in ("360", "Qihoo", "QHSafe", "QPCore", "SafeKrnl", "LeakRepair")
    )

    if has_360_paths:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    str_names = [s for s, _ in unique_strings[:5]]

    findings.append(
        Finding(
            category=FindingCategory.REGISTRY_CALLBACK,
            severity=severity,
            confidence=confidence,
            description=(
                f"Registry paths detected: {', '.join(str_names)}. "
                f"Driver may access or protect specific registry keys."
            ),
            context={
                "registry_strings": str_names,
                "has_security_product_paths": has_360_paths,
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=str_names[0],
                    rule_id="REGISTRY_PATH",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# RegistryCallbackDetector — Main plugin
# ---------------------------------------------------------------------------

class RegistryCallbackDetector(Analyzer):
    """Detects registry callback registration and registry operation interception."""

    @property
    def name(self) -> str:
        return "RegistryCallbackDetector"

    @property
    def description(self) -> str:
        return (
            "Detects registry callback mechanisms: CmRegisterCallback/Ex registration, "
            "registry operation interception (ZwCreateKey, ZwSetValueKey, ZwDeleteKey), "
            "and 360-specific registry path protection."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Registry callback API detection
        findings.extend(detect_registry_callback_apis(ir))

        # 2. Registry path string detection
        findings.extend(detect_registry_paths(ir))

        return findings
