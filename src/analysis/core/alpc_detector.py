"""
DriverScope — ALPC/LPC 跨驱动通信检测器。

检测高级本地过程调用 (ALPC) 和 LPC 端口操作，用于：
1. 内核态到用户态通信（驱动 → 360 用户态服务）
2. 跨驱动通信（多个 .sys 组件间协调）
3. 端口命名和权限配置（安全描述符）
4. 消息传递和回调机制

360 安全卫士使用 ALPC 在其 AntiHacker、SafeKrnl、LeakRepair 等模块间
建立受保护的通信通道。恶意软件也可能滥用 ALPC 进行进程间注入。
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
# 1. ALPC/LPC API 检测
# ---------------------------------------------------------------------------

ALPC_APIS = {
    "AlpcSendWaitReceiveMessage": "Send/receive ALPC message (bidirectional)",
    "AlpcConnectPort": "Connect to ALPC port (client)",
    "AlpcCreatePort": "Create ALPC server port",
    "AlpcCreateResourceReserve": "Create message resource reserve",
    "AlpcDisconnectPort": "Disconnect from ALPC port",
    "AlpcClosePort": "Close ALPC port handle",
    "AlpcQueryInformation": "Query ALPC port/message info",
    "AlpcSetInformation": "Set ALPC port/message info",
    "AlpcCreatePortSection": "Create shared memory section",
    "AlpcCreateSectionView": "Map section view",
    "AlpcCreateResourceReserveEx": "Extended resource reserve",
    "NtAlpcConnectPort": "Native connect (undocumented params)",
    "NtAlpcSendWaitReceiveMessage": "Native send/receive",
    "NtAlpcCreatePort": "Native create port",
    "NtAlpcDisconnectPort": "Native disconnect",
    "NtAlpcQueryInformation": "Native query info",
    "NtAlpcAcceptConnectPort": "Accept incoming connection",
    "NtAlpcCreateSectionView": "Native section view",
    "NtAlpcCreatePortSection": "Native port section",
    "NtAlpcCreateResourceReserve": "Native resource reserve",
    "NtAlpcCancelMessage": "Cancel pending message",
    "NtAlpcQueryInformationMessage": "Query message info",
}

# LPC (legacy, pre-Vista but still present in some drivers)
LPC_APIS = {
    "NtConnectPort": "Legacy LPC connect",
    "NtCreatePort": "Legacy LPC create port",
    "NtListenPort": "Legacy LPC listen for connections",
    "NtAcceptPort": "Legacy LPC accept connection",
    "NtRequestPort": "Legacy LPC send request",
    "NtRequestWaitReplyPort": "Legacy LPC request/reply",
    "NtReplyPort": "Legacy LPC reply",
    "NtReplyWaitReceivePort": "Legacy LPC reply/wait/receive",
    "NtReplyWaitReplyPort": "Legacy LPC reply/wait",
    "NtSecureConnectPort": "LPC with security context",
    "NtImpersonateClientOfPort": "Impersonate LPC client",
    "NtReadRequestData": "Read LPC request data",
    "NtWriteRequestData": "Write LPC reply data",
}

# ALPC port name patterns commonly used by security products
ALPC_PORT_PATTERNS = {
    "\\RPC Control\\": "RPC Control namespace (ALPC server)",
    "\\BaseNamedObjects\\": "Named objects namespace",
    "360": "360-specific port naming",
    "AntiHack": "Anti-hack communication port",
    "SafeKrn": "Safe kernel module port",
    "LeakRepair": "Leak repair module port",
    "QHSafe": "Qihoo 360 safe port",
    "QPCore": "QP Core service port",
}


def detect_alpc_apis(ir: DisassemblyResult) -> list[Finding]:
    """Detect ALPC API usage in the driver."""
    findings: list[Finding] = []

    alpc_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in ALPC_APIS]
        if matched:
            alpc_funcs.append((func_addr, matched))

    if not alpc_funcs:
        return findings

    # Severity based on API criticality
    has_connect = any(
        "Connect" in api for _, apis in alpc_funcs for api in apis
    )
    has_send_receive = any(
        "Send" in api or "Receive" in api or "Message" in api
        for _, apis in alpc_funcs for api in apis
    )
    has_section = any(
        "Section" in api or "View" in api
        for _, apis in alpc_funcs for api in apis
    )

    if has_connect and has_send_receive:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_connect or has_send_receive:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    all_apis = []
    for _, apis in alpc_funcs:
        all_apis.extend(apis)

    findings.append(
        Finding(
            category=FindingCategory.ALPC_COMMUNICATION,
            severity=severity,
            confidence=confidence,
            description=(
                f"ALPC communication indicators: {len(alpc_funcs)} functions, "
                f"{len(set(all_apis))} unique APIs. "
                f"APIs: {', '.join(sorted(set(all_apis)))}. "
                f"Driver may use ALPC for kernel-user communication."
            ),
            function_address=alpc_funcs[0][0],
            context={
                "alpc_functions": [
                    {"address": hex(addr), "apis": apis}
                    for addr, apis in alpc_funcs[:10]
                ],
                "has_connect": has_connect,
                "has_send_receive": has_send_receive,
                "has_shared_memory": has_section,
            },
            evidence=[
                Evidence(
                    type="api_match",
                    location=f"sub_{alpc_funcs[0][0]:X}",
                    snippet=sorted(set(all_apis))[0],
                    rule_id="ALPC_API",
                )
            ],
        )
    )

    return findings


def detect_lpc_apis(ir: DisassemblyResult) -> list[Finding]:
    """Detect legacy LPC API usage."""
    findings: list[Finding] = []

    lpc_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in LPC_APIS]
        if matched:
            lpc_funcs.append((func_addr, matched))

    if not lpc_funcs:
        return findings

    all_apis = []
    for _, apis in lpc_funcs:
        all_apis.extend(apis)

    has_impersonate = any(
        "Impersonate" in api for _, apis in lpc_funcs for api in apis
    )

    if has_impersonate:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    else:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM

    findings.append(
        Finding(
            category=FindingCategory.ALPC_COMMUNICATION,
            severity=severity,
            confidence=confidence,
            description=(
                f"Legacy LPC communication: {len(lpc_funcs)} functions, "
                f"APIs: {', '.join(sorted(set(all_apis)))}. "
                f"Driver uses pre-Vista LPC for inter-process communication."
            ),
            function_address=lpc_funcs[0][0],
            context={
                "lpc_functions": [
                    {"address": hex(addr), "apis": apis}
                    for addr, apis in lpc_funcs[:10]
                ],
                "has_impersonation": has_impersonate,
            },
            evidence=[
                Evidence(
                    type="api_match",
                    location=f"sub_{lpc_funcs[0][0]:X}",
                    snippet=sorted(set(all_apis))[0],
                    rule_id="LPC_API",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 2. ALPC 端口名称检测（字符串分析）
# ---------------------------------------------------------------------------

def detect_alpc_port_names(ir: DisassemblyResult) -> list[Finding]:
    """Detect ALPC port name strings in the binary."""
    findings: list[Finding] = []

    port_strings = []
    for s in ir.strings:
        for pattern, desc in ALPC_PORT_PATTERNS.items():
            if pattern in s:
                port_strings.append((s, desc))
                break

    if not port_strings:
        return findings

    seen = set()
    unique_strings = []
    for s, desc in port_strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append((s, desc))

    has_rpc_control = any(
        "\\RPC Control\\" in s for s, _ in unique_strings
    )
    has_security_product = any(
        p in s for s, _ in unique_strings
        for p in ("360", "AntiHack", "SafeKrn", "QHSafe", "QPCore", "LeakRepair")
    )

    if has_security_product:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_rpc_control:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    str_names = [s for s, _ in unique_strings[:5]]

    findings.append(
        Finding(
            category=FindingCategory.ALPC_PORT_NAME,
            severity=severity,
            confidence=confidence,
            description=(
                f"ALPC port names detected: {', '.join(str_names)}. "
                f"Driver exposes named communication endpoints."
            ),
            context={
                "port_strings": str_names,
                "has_rpc_control": has_rpc_control,
                "has_security_product_naming": has_security_product,
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=str_names[0],
                    rule_id="ALPC_PORT",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 3. 共享内存 / Section 检测
# ---------------------------------------------------------------------------

SECTION_APIS = {
    "AlpcCreatePortSection": "Create shared memory for ALPC",
    "AlpcCreateSectionView": "Map shared memory view",
    "NtAlpcCreatePortSection": "Native port section creation",
    "NtAlpcCreateSectionView": "Native section view mapping",
    "ZwCreateSection": "Create shared memory section",
    "ZwMapViewOfSection": "Map section into address space",
    "NtCreateSection": "Native section creation",
    "NtMapViewOfSection": "Native section mapping",
}


def detect_shared_memory(ir: DisassemblyResult) -> list[Finding]:
    """Detect shared memory usage potentially related to ALPC communication."""
    findings: list[Finding] = []

    section_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in SECTION_APIS]
        if matched:
            section_funcs.append((func_addr, matched))

    if not section_funcs:
        return findings

    all_apis = []
    for _, apis in section_funcs:
        all_apis.extend(apis)

    has_alpc_section = any(
        "Alpc" in api for _, apis in section_funcs for api in apis
    )

    if has_alpc_section:
        severity = Severity.HIGH
        confidence = Confidence.HIGH
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.MEDIUM

    findings.append(
        Finding(
            category=FindingCategory.ALPC_SHARED_MEMORY,
            severity=severity,
            confidence=confidence,
            description=(
                f"Shared memory for IPC: {len(section_funcs)} functions, "
                f"APIs: {', '.join(sorted(set(all_apis)))}. "
                f"Driver may share memory with user-mode processes."
            ),
            function_address=section_funcs[0][0],
            context={
                "section_functions": [
                    {"address": hex(addr), "apis": apis}
                    for addr, apis in section_funcs[:10]
                ],
                "has_alpc_section": has_alpc_section,
            },
            evidence=[
                Evidence(
                    type="api_match",
                    location=f"sub_{section_funcs[0][0]:X}",
                    snippet=sorted(set(all_apis))[0],
                    rule_id="ALPC_SECTION",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 4. ALPC 消息结构检测（指令级模式）
# ---------------------------------------------------------------------------

def detect_alpc_message_patterns(ir: DisassemblyResult) -> list[Finding]:
    """Detect ALPC PORT_MESSAGE structure access patterns.

    ALPC messages use a PORT_MESSAGE header:
    - u1.Length (USHORT)
    - u1.DataLength (USHORT)
    - u2.ZeroInit / Type (ULONG)
    - ClientId (CLIENT_ID: UniqueProcess + UniqueThread)

    Detect patterns that suggest PORT_MESSAGE construction or parsing:
    - Writing specific sizes to message buffers (0x18, 0x28, 0x30)
    - CLIENT_ID structure access (PID + TID pair)
    """
    findings: list[Finding] = []

    message_funcs = []
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        score = 0
        details = []

        for block in cfg.blocks.values():
            for insn in block.instructions:
                ops = insn.operands.lower()
                mnem = insn.mnemonic.lower()

                # PORT_MESSAGE size constants
                if "0x18" in ops or "0x28" in ops or "0x30" in ops:
                    if "mov" in mnem and "[" in ops:
                        score += 1
                        details.append(f"{mnem} {ops}")

                # CLIENT_ID: two consecutive qword writes (PID + TID)
                if "client" in ops or "cid" in ops:
                    score += 1
                    details.append(f"{mnem} {ops}")

                # ALPC message type fields
                if "message" in ops and "type" in ops:
                    score += 2
                    details.append(f"{mnem} {ops}")

        if score >= 3:
            message_funcs.append((func_addr, score, details[:5]))

    if not message_funcs:
        return findings

    findings.append(
        Finding(
            category=FindingCategory.ALPC_MESSAGE,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description=(
                f"ALPC message structure patterns: {len(message_funcs)} functions. "
                f"PORT_MESSAGE construction or parsing detected."
            ),
            function_address=message_funcs[0][0],
            context={
                "message_functions": [
                    {"address": hex(addr), "score": sc, "patterns": dets}
                    for addr, sc, dets in message_funcs[:10]
                ],
            },
            evidence=[
                Evidence(
                    type="instruction_pattern",
                    location=f"sub_{message_funcs[0][0]:X}",
                    snippet="PORT_MESSAGE structure access",
                    rule_id="ALPC_MSG_PATTERN",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# AlpcDetector — Main plugin
# ---------------------------------------------------------------------------

class AlpcDetector(Analyzer):
    """Detects ALPC/LPC communication channels and shared memory."""

    @property
    def name(self) -> str:
        return "AlpcDetector"

    @property
    def description(self) -> str:
        return (
            "Detects ALPC/LPC inter-process communication: port creation, "
            "message passing, shared memory sections, and client impersonation."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. ALPC API detection
        findings.extend(detect_alpc_apis(ir))

        # 2. Legacy LPC API detection
        findings.extend(detect_lpc_apis(ir))

        # 3. ALPC port name strings
        findings.extend(detect_alpc_port_names(ir))

        # 4. Shared memory / section detection
        findings.extend(detect_shared_memory(ir))

        # 5. ALPC message structure patterns
        findings.extend(detect_alpc_message_patterns(ir))

        return findings
