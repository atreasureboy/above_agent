"""
DriverScope — DKOM (Direct Kernel Object Manipulation) 检测器。

检测内核对象篡改技术，用于隐藏进程/线程、提升权限、擦除调试器痕迹。

360 安全卫士等安全产品使用 DKOM 技术保护自身进程不被终止或注入。
恶意软件也使用相同技术隐藏自身。

检测维度：
1. **进程链表 Unlink**: ActiveProcessLinks / PsActiveProcessHead 操作
2. **线程链表 Unlink**: ThreadListEntry 操作
3. **PspCidTable 擦除**: 从 CID 表移除进程/线程句柄
4. **Token 篡改**: 访问/修改 _EPROCESS.Token 提升权限
"""

from __future__ import annotations

import re

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
# 1. 进程链表 Unlink 检测
# ---------------------------------------------------------------------------

# EPROCESS.ActiveProcessLinks 偏移（随 Windows 版本变化）
# 常见偏移：0x2e8, 0x2f0, 0x448, 0x2e0, 0x3e8
APL_OFFSETS = {0x2E8, 0x2F0, 0x448, 0x2E0, 0x3E8, 0x2F8, 0x348, 0x358, 0x350}

# PsActiveProcessHead — 全局进程链表头
PROCESS_LIST_STRINGS = {
    "PsActiveProcessHead": "Active process list head reference",
    "ActiveProcessLinks": "EPROCESS.APL field reference",
    "ProcessListEntry": "Process list entry reference",
    "ProcessLinks": "Process links reference",
    "_EPROCESS": "EPROCESS structure reference",
    "UniqueProcessId": "EPROCESS.UniqueProcessId reference",
    "Peb": "PEB pointer reference (EPROCESS field)",
}


def detect_process_unlink(ir: DisassemblyResult) -> list[Finding]:
    """Detect EPROCESS.ActiveProcessLinks unlink operations.

    Pattern for unlinking a process from the active process list:
      mov rax, [rbx+APL_OFFSET]     ; load Flink
      mov rcx, [rbx+APL_OFFSET+8]   ; load Blink
      mov [rax+8], rcx              ; Flink->Blink = Blink
      mov [rcx], rax                ; Blink->Flink = Flink

    Detection strategies:
    1. String references to PsActiveProcessHead/ActiveProcessLinks
    2. mov [reg+offset], reg patterns with APL offsets
    3. Cross-reference: Flink/Blink manipulation pattern
    """
    findings: list[Finding] = []

    # 1. String-level
    process_strings = []
    for s in ir.strings:
        for pattern, desc in PROCESS_LIST_STRINGS.items():
            if pattern in s:
                process_strings.append((s, desc))
                break

    # 2. Instruction-level: APL offset manipulation
    apl_funcs = []  # [(func_addr, [offset_values])]

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        offset_hits = []
        for block in cfg.blocks.values():
            for insn in block.instructions:
                ops = insn.operands.lower()
                # Check for APL offsets in memory operands
                for offset in APL_OFFSETS:
                    hex_offset = f"0x{offset:x}"
                    if hex_offset in ops and "[" in ops and "]" in ops:
                        offset_hits.append((offset, hex(insn.address)))

        if offset_hits:
            apl_funcs.append((func_addr, offset_hits))

    if not process_strings and not apl_funcs:
        return findings

    # Deduplicate strings
    seen = set()
    unique_strings = []
    for s, desc in process_strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append((s, desc))

    # Severity
    has_apl_func = len(apl_funcs) > 0
    has_string = len(unique_strings) > 0

    if has_apl_func and has_string:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_apl_func:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    str_names = [s for s, _ in unique_strings[:5]]

    findings.append(
        Finding(
            category=FindingCategory.DKOM_PROCESS_UNLINK,
            severity=severity,
            confidence=confidence,
            description=(
                f"DKOM process unlink indicators: {len(unique_strings)} strings, "
                f"{len(apl_funcs)} functions with APL offset access. "
                f"Strings: {', '.join(str_names[:5])}. "
                f"Driver may hide processes from the active process list."
            ),
            function_address=apl_funcs[0][0] if apl_funcs else 0,
            context={
                "process_strings": str_names,
                "apl_functions": [
                    {"address": hex(a), "offsets": list({hex(o) for o, _ in offsets})}
                    for a, offsets in apl_funcs[:10]
                ],
            },
            evidence=[
                Evidence(
                    type="instruction_pattern" if apl_funcs else "string",
                    location=f"sub_{apl_funcs[0][0]:X}" if apl_funcs else "binary strings",
                    snippet=str_names[0] if str_names else "APL offset access",
                    rule_id="DKOM_PROC_UNLINK",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 2. 线程链表 Unlink 检测
# ---------------------------------------------------------------------------

THREAD_LIST_STRINGS = {
    "ThreadListEntry": "ETHREAD.ThreadListEntry reference",
    "ThreadListHead": "Thread list head reference",
    "CidHandleCount": "ETHREAD.CidHandleCount reference",
    "_ETHREAD": "ETHREAD structure reference",
    "StartAddress": "ETHREAD.StartAddress reference",
    "Teb": "TEB pointer reference (ETHREAD field)",
}


def detect_thread_unlink(ir: DisassemblyResult) -> list[Finding]:
    """Detect ETHREAD.ThreadListEntry unlink operations.

    Similar to process unlink but operates on thread list.
    """
    findings: list[Finding] = []

    thread_strings = []
    for s in ir.strings:
        for pattern, desc in THREAD_LIST_STRINGS.items():
            if pattern in s:
                thread_strings.append((s, desc))
                break

    if not thread_strings:
        return findings

    seen = set()
    unique_strings = []
    for s, desc in thread_strings:
        if s not in seen:
            seen.add(desc)
            unique_strings.append((s, desc))

    str_names = [s for s, _ in unique_strings[:5]]

    findings.append(
        Finding(
            category=FindingCategory.DKOM_THREAD_UNLINK,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description=(
                f"DKOM thread unlink indicators: {', '.join(str_names[:5])}. "
                f"Driver may hide threads from enumeration."
            ),
            context={
                "thread_strings": str_names,
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=str_names[0] if str_names else "thread unlink pattern",
                    rule_id="DKOM_THREAD_UNLINK",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 3. PspCidTable 擦除检测
# ---------------------------------------------------------------------------

CID_TABLE_STRINGS = {
    "PspCidTable": "CID table reference (process/thread handle table)",
    "CidTable": "CID table reference",
    "HandleTable": "Handle table reference",
    "ExCreateHandle": "Handle creation reference",
    "ExDestroyHandle": "Handle destruction reference",
    "TableCode": "Handle table TableCode field",
}


def detect_cid_table(ir: DisassemblyResult) -> list[Finding]:
    """Detect PspCidTable manipulation — erasing process/thread entries.

    PspCidTable is the kernel's handle table for processes and threads.
    Removing an entry makes the process/thread invisible to OpenProcess.
    """
    findings: list[Finding] = []

    cid_strings = []
    for s in ir.strings:
        for pattern, desc in CID_TABLE_STRINGS.items():
            if pattern in s:
                cid_strings.append((s, desc))
                break

    if not cid_strings:
        return findings

    seen = set()
    unique_strings = []
    for s, desc in cid_strings:
        if s not in seen:
            seen.add(desc)
            unique_strings.append((s, desc))

    str_names = [s for s, _ in unique_strings[:5]]

    has_psp = any("PspCidTable" in s for s, _ in unique_strings)

    if has_psp:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    else:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM

    findings.append(
        Finding(
            category=FindingCategory.DKOM_CID_TABLE,
            severity=severity,
            confidence=confidence,
            description=(
                f"PspCidTable manipulation: {', '.join(str_names[:5])}. "
                f"Driver may erase process/thread entries from the CID table."
            ),
            context={
                "cid_strings": str_names,
                "has_psp_cid_table": has_psp,
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=str_names[0] if str_names else "CID table pattern",
                    rule_id="DKOM_CID_TABLE",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 4. Token 篡改检测
# ---------------------------------------------------------------------------

TOKEN_STRINGS = {
    "ImpersonationToken": "Impersonation token reference",
    "PrimaryToken": "Primary token reference",
    "SeToken": "Security token reference",
    "SEP_": "Security token structure prefix",
    "Privileges": "Token privileges reference",
    "_TOKEN": "Token structure reference",
    "SepAcquireToken": "Token acquisition reference",
    "SeSetAccessStateToken": "Token state manipulation",
    "Token": "Token reference (process security token)",
}

TOKEN_APIS = {
    "PsReferencePrimaryToken": "Reference primary token",
    "PsReferenceImpersonationToken": "Reference impersonation token",
    "PsRevertToSelf": "Revert to self (remove impersonation)",
    "SeImpersonateClientEx": "Impersonate client",
    "SeAssignSecurity": "Assign security descriptor",
    "SeTokenIsAdmin": "Check admin privilege",
    "SePrivilegeCheck": "Privilege check",
}


def detect_token_manipulation(ir: DisassemblyResult) -> list[Finding]:
    """Detect token manipulation for privilege escalation.

    Patterns:
    1. Access to _EPROCESS.Token or _TOKEN structure
    2. Token reference/impersonation APIs
    3. Privilege manipulation
    """
    findings: list[Finding] = []

    token_strings = []
    for s in ir.strings:
        for pattern, desc in TOKEN_STRINGS.items():
            if pattern.lower() in s.lower():
                token_strings.append((s, desc))
                break

    # API-level detection
    token_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in TOKEN_APIS]
        if matched:
            token_funcs.append((func_addr, matched))

    if not token_strings and not token_funcs:
        return findings

    seen = set()
    unique_strings = []
    for s, desc in token_strings:
        if desc not in seen:
            seen.add(desc)
            unique_strings.append((s, desc))

    str_names = [s for s, _ in unique_strings[:5]]

    has_priv_escalation = any(
        "Impersonat" in s or "PrimaryToken" in s or "SeToken" in s
        for s, _ in unique_strings
    )

    if token_funcs or has_priv_escalation:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    else:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM

    api_names_list = []
    for _, apis in token_funcs:
        api_names_list.extend(apis)

    findings.append(
        Finding(
            category=FindingCategory.DKOM_TOKEN,
            severity=severity,
            confidence=confidence,
            description=(
                f"Token manipulation indicators: {len(unique_strings)} strings, "
                f"{len(token_funcs)} functions with token APIs. "
                f"Strings: {', '.join(str_names[:5])}. "
                f"APIs: {', '.join(set(api_names_list))}. "
                f"Driver may escalate privileges or impersonate tokens."
            ),
            function_address=token_funcs[0][0] if token_funcs else 0,
            context={
                "token_strings": str_names,
                "token_functions": [
                    {"address": hex(a), "apis": apis} for a, apis in token_funcs
                ],
                "has_privilege_escalation": has_priv_escalation,
            },
            evidence=[
                Evidence(
                    type="api_match" if token_funcs else "string",
                    location="multiple functions" if token_funcs else "binary strings",
                    snippet=str_names[0] if str_names else ", ".join(set(api_names_list)),
                    rule_id="DKOM_TOKEN",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# DkomDetector — Main plugin
# ---------------------------------------------------------------------------

class DkomDetector(Analyzer):
    """Detects DKOM (Direct Kernel Object Manipulation) techniques."""

    @property
    def name(self) -> str:
        return "DkomDetector"

    @property
    def description(self) -> str:
        return (
            "Detects DKOM techniques: process/thread list unlinking, "
            "PspCidTable erasure, and token manipulation."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Process unlink detection
        findings.extend(detect_process_unlink(ir))

        # 2. Thread unlink detection
        findings.extend(detect_thread_unlink(ir))

        # 3. CID table manipulation
        findings.extend(detect_cid_table(ir))

        # 4. Token manipulation
        findings.extend(detect_token_manipulation(ir))

        return findings
