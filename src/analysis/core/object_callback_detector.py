"""
DriverScope — 对象回调保护详情检测器。

检测 ObRegisterCallbacks 对象保护细节，用于：
1. ObRegisterCallbacks / ObUnRegisterCallbacks — 对象回调注册
2. OB_OPERATION_REGISTRATION 结构初始化（指令级模式）
3. 受保护对象类型识别（PsProcessType, PsThreadType）
4. 被阻止的操作类型（PROCESS_TERMINATE, PROCESS_VM_READ 等）

360 安全卫士使用 ObRegisterCallbacks 注册对象回调，阻止其他进程
终止 360 进程、注入 360 进程内存或挂起 360 线程。
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
# 1. 对象回调 API 检测
# ---------------------------------------------------------------------------

OBJECT_CALLBACK_APIS = {
    "ObRegisterCallbacks": "Register object access callback",
    "ObUnRegisterCallbacks": "Unregister object callback",
}

# Object types that can be protected
OBJECT_TYPES = {
    "PsProcessType": "Process object type (prevent termination, VM read)",
    "PsThreadType": "Thread object type (prevent suspend/resume, context read)",
    "ExDesktopObjectType": "Desktop object type",
    "ExWindowStationType": "Window station type",
    "IoDeviceObjectType": "Device object type",
    "LpcPortObjectType": "LPC port object type",
    "FileObjectType": "File object type",
}

# Access rights that callbacks can block
ACCESS_RIGHTS = {
    0x0001: "PROCESS_TERMINATE",
    0x0002: "PROCESS_CREATE_THREAD",
    0x0004: "PROCESS_VM_OPERATION",
    0x0008: "PROCESS_VM_READ",
    0x0010: "PROCESS_VM_WRITE",
    0x0020: "PROCESS_DUP_HANDLE",
    0x0040: "PROCESS_CREATE_PROCESS",
    0x0080: "PROCESS_SET_QUOTA",
    0x0100: "PROCESS_SET_INFORMATION",
    0x0200: "PROCESS_QUERY_INFORMATION",
    0x0400: "PROCESS_SUSPEND_RESUME",
    0x0800: "PROCESS_QUERY_LIMITED_INFORMATION",
    0x1000: "THREAD_TERMINATE",
    0x2000: "THREAD_SUSPEND_RESUME",
    0x4000: "THREAD_GET_CONTEXT",
    0x8000: "THREAD_SET_CONTEXT",
    0x10000: "THREAD_QUERY_INFORMATION",
}


def detect_object_callback_apis(ir: DisassemblyResult) -> list[Finding]:
    """Detect ObRegisterCallbacks API usage."""
    findings: list[Finding] = []

    callback_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in OBJECT_CALLBACK_APIS]
        if matched:
            callback_funcs.append((func_addr, matched))

    if not callback_funcs:
        return findings

    all_apis = []
    for _, apis in callback_funcs:
        all_apis.extend(apis)

    # Check for process + thread protection
    findings.append(
        Finding(
            category=FindingCategory.OBJECT_CALLBACK,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description=(
                f"Object callback registration: {len(callback_funcs)} functions, "
                f"APIs: {', '.join(sorted(set(all_apis)))}. "
                f"Driver registers callbacks to intercept object access."
            ),
            function_address=callback_funcs[0][0],
            context={
                "callback_functions": [
                    {"address": hex(addr), "apis": apis}
                    for addr, apis in callback_funcs[:10]
                ],
            },
            evidence=[
                Evidence(
                    type="api_match",
                    location=f"sub_{callback_funcs[0][0]:X}",
                    snippet=sorted(set(all_apis))[0],
                    rule_id="OBJECT_CALLBACK_API",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 2. 对象类型字符串检测
# ---------------------------------------------------------------------------

def detect_object_types(ir: DisassemblyResult) -> list[Finding]:
    """Detect object type references (what is being protected)."""
    findings: list[Finding] = []

    type_refs = []
    for s in ir.strings:
        for obj_type, desc in OBJECT_TYPES.items():
            if obj_type in s:
                type_refs.append((s, desc))
                break

    if not type_refs:
        return findings

    seen = set()
    unique_refs = []
    for s, desc in type_refs:
        if s not in seen:
            seen.add(s)
            unique_refs.append((s, desc))

    has_process = any("PsProcessType" in s for s, _ in unique_refs)
    has_thread = any("PsThreadType" in s for s, _ in unique_refs)

    if has_process and has_thread:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_process or has_thread:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    str_names = [s for s, _ in unique_refs[:5]]

    findings.append(
        Finding(
            category=FindingCategory.OBJECT_CALLBACK,
            severity=severity,
            confidence=confidence,
            description=(
                f"Object type references: {', '.join(str_names)}. "
                f"Driver protects specific kernel object types from access."
            ),
            context={
                "object_type_strings": str_names,
                "protects_process": has_process,
                "protects_thread": has_thread,
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=str_names[0],
                    rule_id="OBJECT_TYPE_REF",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 3. OB_OPERATION_REGISTRATION 结构初始化检测
# ---------------------------------------------------------------------------

# OB_OPERATION_REGISTRATION structure (x64):
#   +0x00: ObjectType (POBJECT_TYPE)
#   +0x08: Operations (OB_OPERATION flags) 0x01=PRE, 0x02=POST
#   +0x10: PreOperation (POB_PRE_OPERATION_CALLBACK)
#   +0x18: PostOperation (POB_POST_OPERATION_CALLBACK)
OB_CALLBACK_OFFSETS = {
    0x00: "ObjectType pointer",
    0x08: "Operations flags (PRE=0x01, POST=0x02)",
    0x10: "PreOperation callback pointer",
    0x18: "PostOperation callback pointer",
}


def detect_ob_callback_structure(ir: DisassemblyResult) -> list[Finding]:
    """Detect OB_OPERATION_REGISTRATION structure initialization."""
    findings: list[Finding] = []

    struct_funcs = []
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        offset_hits = set()
        for block in cfg.blocks.values():
            for insn in block.instructions:
                ops = insn.operands.lower()
                if "[" not in ops or "]" not in ops:
                    continue
                for offset in OB_CALLBACK_OFFSETS:
                    if f"0x{offset:x}" in ops:
                        offset_hits.add(offset)

        # Need at least 2 offsets (e.g., ObjectType + PreOperation)
        if len(offset_hits) >= 2:
            struct_funcs.append((func_addr, sorted(offset_hits)))

    if not struct_funcs:
        return findings

    has_pre_op = any(0x10 in offsets for _, offsets in struct_funcs)
    has_object_type = any(0x00 in offsets for _, offsets in struct_funcs)

    if has_pre_op and has_object_type:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_pre_op or has_object_type:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    findings.append(
        Finding(
            category=FindingCategory.OBJECT_CALLBACK,
            severity=severity,
            confidence=confidence,
            description=(
                f"OB_OPERATION_REGISTRATION structure: {len(struct_funcs)} functions. "
                f"Offsets: {', '.join(hex(o) for o in struct_funcs[0][1])}. "
                f"Driver sets up object access callback registration structure."
            ),
            function_address=struct_funcs[0][0],
            context={
                "callback_structure_functions": [
                    {"address": hex(addr), "offsets": [hex(o) for o in offsets]}
                    for addr, offsets in struct_funcs[:10]
                ],
                "has_pre_operation_callback": has_pre_op,
                "has_object_type_field": has_object_type,
            },
            evidence=[
                Evidence(
                    type="instruction_pattern",
                    location=f"sub_{struct_funcs[0][0]:X}",
                    snippet=f"OB_CALLBACK offsets: {', '.join(hex(o) for o in struct_funcs[0][1])}",
                    rule_id="OB_CALLBACK_STRUCT",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# ObjectCallbackDetector — Main plugin
# ---------------------------------------------------------------------------

class ObjectCallbackDetector(Analyzer):
    """Detects object callback registration and object protection details."""

    @property
    def name(self) -> str:
        return "ObjectCallbackDetector"

    @property
    def description(self) -> str:
        return (
            "Detects ObRegisterCallbacks object protection: callback registration, "
            "OB_OPERATION_REGISTRATION structure setup, protected object types "
            "(PsProcessType, PsThreadType), and access right filtering."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Object callback API detection
        findings.extend(detect_object_callback_apis(ir))

        # 2. Object type string references
        findings.extend(detect_object_types(ir))

        # 3. OB_OPERATION_REGISTRATION structure initialization
        findings.extend(detect_ob_callback_structure(ir))

        return findings
