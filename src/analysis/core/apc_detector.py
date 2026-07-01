"""
DriverScope — Kernel APC / 线程注入检测器。

检测内核 APC 注入和线程劫持技术，用于：
1. KeInitializeApc / KeInsertQueueApc — 内核 APC 注入
2. ZwSuspendThread / ZwGetContextThread / ZwSetContextThread — 线程劫持
3. KAPC 结构初始化模式检测
4. 回调函数指针提取

360 安全卫士使用内核 APC 向受保护进程注入监控代码，
使用线程上下文操作进行线程级劫持。
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
# 1. APC API 检测
# ---------------------------------------------------------------------------

APC_APIS = {
    "KeInitializeApc": "Initialize kernel APC (KAPC structure)",
    "KeInsertQueueApc": "Queue APC for execution",
    "KeForceInsertQueueApc": "Force-insert APC (bypass checks)",
    "KeFlushQueuedApcs": "Flush queued APCs",
    "KeAllocateApcObject": "Allocate APC object (newer Windows)",
}

THREAD_HIJACK_APIS = {
    "ZwSuspendThread": "Suspend target thread",
    "ZwResumeThread": "Resume target thread",
    "ZwGetContextThread": "Read thread context (registers)",
    "ZwSetContextThread": "Write thread context (registers)",
    "NtGetContextThread": "Native get thread context",
    "NtSetContextThread": "Native set thread context",
    "NtSuspendThread": "Native suspend thread",
    "NtResumeThread": "Native resume thread",
}

# KAPC structure offsets (x64)
KAPC_OFFSETS = {
    0x00: "Type",
    0x02: "Size",
    0x04: "Spare0",
    0x08: "Thread",           # PKTHREAD
    0x10: "ApcListEntry",     # LIST_ENTRY
    0x20: "KernelRoutine",    # PKKERNEL_ROUTINE function pointer
    0x28: "RundownRoutine",   # PKRUNDOWN_ROUTINE function pointer
    0x30: "NormalRoutine",    # PKNORMAL_ROUTINE function pointer
    0x38: "NormalContext",    # PVOID
    0x40: "SystemArgument1",  # PVOID
    0x48: "SystemArgument2",  # PVOID
}


def detect_apc_apis(ir: DisassemblyResult) -> list[Finding]:
    """Detect kernel APC API usage."""
    findings: list[Finding] = []

    apc_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in APC_APIS]
        if matched:
            apc_funcs.append((func_addr, matched))

    if not apc_funcs:
        return findings

    all_apis = []
    for _, apis in apc_funcs:
        all_apis.extend(apis)

    has_force = any(
        "Force" in api for _, apis in apc_funcs for api in apis
    )
    has_full_chain = any(
        "KeInitializeApc" in apis and "KeInsertQueueApc" in apis
        for _, apis in apc_funcs
    )

    if has_force or has_full_chain:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif len(apc_funcs) >= 2:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    findings.append(
        Finding(
            category=FindingCategory.APC_INJECTION,
            severity=severity,
            confidence=confidence,
            description=(
                f"Kernel APC indicators: {len(apc_funcs)} functions, "
                f"APIs: {', '.join(sorted(set(all_apis)))}. "
                f"Driver may use kernel APC for code injection."
            ),
            function_address=apc_funcs[0][0],
            context={
                "apc_functions": [
                    {"address": hex(addr), "apis": apis}
                    for addr, apis in apc_funcs[:10]
                ],
                "has_force_insert": has_force,
                "has_full_chain": has_full_chain,
            },
            evidence=[
                Evidence(
                    type="api_match",
                    location=f"sub_{apc_funcs[0][0]:X}",
                    snippet=sorted(set(all_apis))[0],
                    rule_id="APC_INJECTION_API",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 2. 线程劫持 API 检测
# ---------------------------------------------------------------------------

def detect_thread_hijack(ir: DisassemblyResult) -> list[Finding]:
    """Detect thread hijacking via context manipulation."""
    findings: list[Finding] = []

    hijack_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in THREAD_HIJACK_APIS]
        if matched:
            hijack_funcs.append((func_addr, matched))

    if not hijack_funcs:
        return findings

    all_apis = []
    for _, apis in hijack_funcs:
        all_apis.extend(apis)

    api_set = set(all_apis)
    has_suspend_resume = any(
        "Suspend" in a for a in api_set
    ) and any(
        "Resume" in a for a in api_set
    )
    has_context_rw = any(
        "Context" in a for a in api_set
    )
    has_full_hijack = has_suspend_resume and has_context_rw

    if has_full_hijack:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_context_rw:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    elif has_suspend_resume:
        severity = Severity.MEDIUM
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.LOW
        confidence = Confidence.LOW

    findings.append(
        Finding(
            category=FindingCategory.APC_INJECTION,
            severity=severity,
            confidence=confidence,
            description=(
                f"Thread hijack indicators: {len(hijack_funcs)} functions, "
                f"APIs: {', '.join(sorted(set(all_apis)))}. "
                f"Driver may suspend/modify/resume threads for code injection."
            ),
            function_address=hijack_funcs[0][0],
            context={
                "hijack_functions": [
                    {"address": hex(addr), "apis": apis}
                    for addr, apis in hijack_funcs[:10]
                ],
                "has_suspend_resume": has_suspend_resume,
                "has_context_manipulation": has_context_rw,
                "has_full_hijack_chain": has_full_hijack,
            },
            evidence=[
                Evidence(
                    type="api_match",
                    location=f"sub_{hijack_funcs[0][0]:X}",
                    snippet=sorted(set(all_apis))[0],
                    rule_id="THREAD_HIJACK_API",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 3. KAPC 结构初始化模式检测（指令级）
# ---------------------------------------------------------------------------

def detect_kapc_structure(ir: DisassemblyResult) -> list[Finding]:
    """Detect KAPC structure initialization patterns.

    KAPC initialization writes specific function pointers at known offsets:
      mov [rcx+KAPC.KernelRoutine], rdx   ; 0x20
      mov [rcx+KAPC.RundownRoutine], r8   ; 0x28
      mov [rcx+KAPC.NormalRoutine], r9    ; 0x30
    """
    findings: list[Finding] = []

    kapc_funcs = []
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
                for offset in KAPC_OFFSETS:
                    if f"0x{offset:x}" in ops:
                        offset_hits.add(offset)

        # Need at least 3 KAPC offsets written (KernelRoutine + RundownRoutine + NormalRoutine)
        if len(offset_hits) >= 3:
            kapc_funcs.append((func_addr, sorted(offset_hits)))

    if not kapc_funcs:
        return findings

    findings.append(
        Finding(
            category=FindingCategory.APC_INJECTION,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description=(
                f"KAPC structure initialization: {len(kapc_funcs)} functions. "
                f"Offsets accessed: {', '.join(hex(o) for o in kapc_funcs[0][1])}. "
                f"Driver may construct APC objects for injection."
            ),
            function_address=kapc_funcs[0][0],
            context={
                "kapc_functions": [
                    {"address": hex(addr), "offsets": [hex(o) for o in offsets]}
                    for addr, offsets in kapc_funcs[:10]
                ],
            },
            evidence=[
                Evidence(
                    type="instruction_pattern",
                    location=f"sub_{kapc_funcs[0][0]:X}",
                    snippet=f"KAPC offsets: {', '.join(hex(o) for o in kapc_funcs[0][1])}",
                    rule_id="APC_KAPC_STRUCT",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# ApcInjectionDetector — Main plugin
# ---------------------------------------------------------------------------

class ApcInjectionDetector(Analyzer):
    """Detects kernel APC injection and thread hijacking techniques."""

    @property
    def name(self) -> str:
        return "ApcInjectionDetector"

    @property
    def description(self) -> str:
        return (
            "Detects kernel APC injection (KeInitializeApc, KeInsertQueueApc), "
            "thread hijacking (ZwSuspendThread + ZwSetContextThread), "
            "and KAPC structure initialization patterns."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. APC API detection
        findings.extend(detect_apc_apis(ir))

        # 2. Thread hijack API detection
        findings.extend(detect_thread_hijack(ir))

        # 3. KAPC structure initialization
        findings.extend(detect_kapc_structure(ir))

        return findings
