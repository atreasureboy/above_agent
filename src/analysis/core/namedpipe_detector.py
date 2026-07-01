"""
DriverScope — Named Pipe 跨驱动/用户态通信检测器。

检测命名管道（Named Pipe）通信模式，用于：
1. 内核态到用户态通信（驱动 → 360 用户态服务进程）
2. 命名管道服务端/客户端角色检测
3. 管道安全描述符和 ACL 分析
4. FSCTL 管道操作码检测

360 安全卫士在其内核驱动（360AntiHacker64.sys、360SafeKrnl64.sys）
和用户态服务（360tray.exe、360Safe.exe）之间使用命名管道进行命令分发、
状态报告和模块间协调。
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
# 1. 命名管道 API 检测
# ---------------------------------------------------------------------------

NAMED_PIPE_APIS = {
    "NtCreateNamedPipeFile": "Create named pipe (kernel mode)",
    "ZwCreateNamedPipeFile": "Create named pipe (kernel mode)",
    "NtCreateFile": "Create/open file (can target NamedPipe device)",
    "ZwCreateFile": "Create/open file (kernel mode)",
    "NtOpenFile": "Open file/pipe (kernel mode)",
    "ZwOpenFile": "Open file/pipe (kernel mode)",
    "NtFsControlFile": "File system control (pipe FSCTL operations)",
    "ZwFsControlFile": "File system control (kernel mode)",
    "NtReadFile": "Read from pipe/file",
    "ZwReadFile": "Read from pipe (kernel mode)",
    "NtWriteFile": "Write to pipe/file",
    "ZwWriteFile": "Write to pipe (kernel mode)",
    "IoCreateFileSpecifyDeviceObjectHint": "Create file with device hint",
    "IoCreateFile": "IoManager create file",
}

# FSCTL codes for named pipe operations
PIPE_FSCTL_CODES = {
    0x110018: "FSCTL_PIPE_ASSIGN_EVENT",
    0x110020: "FSCTL_PIPE_DISCONNECT",
    0x11001C: "FSCTL_PIPE_LISTEN",
    0x110024: "FSCTL_PIPE_PEEK",
    0x110040: "FSCTL_PIPE_QUERY_EVENT",
    0x110044: "FSCTL_PIPE_TRANSCEIVE",
    0x110050: "FSCTL_PIPE_WAIT",
    0x110058: "FSCTL_PIPE_IMPERSONATE",
    0x110060: "FSCTL_PIPE_SET_CLIENT_PROCESS",
    0x110064: "FSCTL_PIPE_QUERY_CLIENT_PROCESS",
}


def detect_named_pipe_apis(ir: DisassemblyResult) -> list[Finding]:
    """Detect named pipe API usage."""
    findings: list[Finding] = []

    pipe_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in NAMED_PIPE_APIS]
        if matched:
            pipe_funcs.append((func_addr, matched))

    if not pipe_funcs:
        return findings

    # Check for complete pipe operations (create + read/write = full pipe usage)
    all_apis = []
    for _, apis in pipe_funcs:
        all_apis.extend(apis)

    has_create = any(
        "Create" in api and ("NamedPipe" in api or "File" in api)
        for _, apis in pipe_funcs for api in apis
    )
    has_rw = any(
        "Read" in api or "Write" in api
        for _, apis in pipe_funcs for api in apis
    )
    has_fsctl = any(
        "FsControl" in api
        for _, apis in pipe_funcs for api in apis
    )
    has_create_named_pipe = any(
        "NamedPipe" in api
        for _, apis in pipe_funcs for api in apis
    )

    if has_create_named_pipe and has_rw:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_create and has_rw:
        severity = Severity.HIGH
        confidence = Confidence.HIGH
    elif has_fsctl:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    elif has_create:
        severity = Severity.MEDIUM
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.LOW
        confidence = Confidence.LOW

    findings.append(
        Finding(
            category=FindingCategory.NAMED_PIPE,
            severity=severity,
            confidence=confidence,
            description=(
                f"Named pipe communication: {len(pipe_funcs)} functions, "
                f"{len(set(all_apis))} unique APIs. "
                f"APIs: {', '.join(sorted(set(all_apis)))}. "
                f"Driver may use named pipes for kernel-user communication."
            ),
            function_address=pipe_funcs[0][0],
            context={
                "pipe_functions": [
                    {"address": hex(addr), "apis": apis}
                    for addr, apis in pipe_funcs[:10]
                ],
                "has_create": has_create,
                "has_read_write": has_rw,
                "has_fsctl": has_fsctl,
                "has_explicit_named_pipe": has_create_named_pipe,
            },
            evidence=[
                Evidence(
                    type="api_match",
                    location=f"sub_{pipe_funcs[0][0]:X}",
                    snippet=sorted(set(all_apis))[0],
                    rule_id="NAMED_PIPE_API",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 2. 命名管道字符串检测
# ---------------------------------------------------------------------------

PIPE_STRING_PATTERNS = {
    "\\Device\\NamedPipe": "Kernel named pipe device path",
    "\\??\\pipe": "User-mode named pipe namespace",
    "pipe\\360": "360-specific pipe name",
    "pipe\\QHP": "Qihoo 360 pipe prefix",
    "360Pipe": "360 pipe naming convention",
    "360Tray": "360 tray service pipe",
    "QHSafe": "Qihoo safe service pipe",
    "QPCore": "QP core service pipe",
    "QScan": "QScan service pipe",
    "360AntiHack": "360 AntiHack module pipe",
    "SafeKrnl": "Safe kernel module pipe",
    "LeakRepair": "Leak repair module pipe",
}


def detect_named_pipe_strings(ir: DisassemblyResult) -> list[Finding]:
    """Detect named pipe path strings in the binary."""
    findings: list[Finding] = []

    pipe_strings = []
    for s in ir.strings:
        for pattern, desc in PIPE_STRING_PATTERNS.items():
            if pattern in s:
                pipe_strings.append((s, desc))
                break

    if not pipe_strings:
        return findings

    seen = set()
    unique_strings = []
    for s, desc in pipe_strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append((s, desc))

    has_device_pipe = any(
        "\\Device\\NamedPipe" in s for s, _ in unique_strings
    )
    has_360_pipe = any(
        p in s for s, _ in unique_strings
        for p in ("360", "QHP", "QHSafe", "QPCore", "QScan", "AntiHack", "SafeKrnl", "LeakRepair")
    )

    if has_360_pipe:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_device_pipe:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    str_names = [s for s, _ in unique_strings[:5]]

    findings.append(
        Finding(
            category=FindingCategory.NAMED_PIPE,
            severity=severity,
            confidence=confidence,
            description=(
                f"Named pipe paths detected: {', '.join(str_names)}. "
                f"Driver communicates via named pipe channels."
            ),
            context={
                "pipe_strings": str_names,
                "has_device_named_pipe": has_device_pipe,
                "has_security_product_pipe": has_360_pipe,
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=str_names[0],
                    rule_id="NAMED_PIPE_STRING",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 3. FSCTL 管道操作码检测
# ---------------------------------------------------------------------------

def detect_pipe_fsctl_codes(ir: DisassemblyResult) -> list[Finding]:
    """Detect FSCTL pipe operation codes in instruction patterns."""
    findings: list[Finding] = []

    fsctl_funcs = []
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        hits = []
        for block in cfg.blocks.values():
            for insn in block.instructions:
                ops = insn.operands.lower()
                for code, name in PIPE_FSCTL_CODES.items():
                    hex_code = f"0x{code:x}"
                    if hex_code in ops:
                        hits.append((code, name, hex(insn.address)))

        if hits:
            fsctl_funcs.append((func_addr, hits))

    if not fsctl_funcs:
        return findings

    findings.append(
        Finding(
            category=FindingCategory.NAMED_PIPE,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description=(
                f"Named pipe FSCTL codes: {len(fsctl_funcs)} functions with "
                f"pipe operation codes. "
                f"Operations: {', '.join(sorted({n for _, n, _ in fsctl_funcs[0][1][:5]}))}. "
                f"Driver performs pipe control operations."
            ),
            function_address=fsctl_funcs[0][0],
            context={
                "fsctl_functions": [
                    {
                        "address": hex(addr),
                        "operations": [
                            {"code": hex(c), "name": n, "insn": ins}
                            for c, n, ins in hits[:5]
                        ],
                    }
                    for addr, hits in fsctl_funcs[:10]
                ],
            },
            evidence=[
                Evidence(
                    type="instruction_pattern",
                    location=f"sub_{fsctl_funcs[0][0]:X}",
                    snippet=", ".join(n for _, n, _ in fsctl_funcs[0][1][:3]),
                    rule_id="NAMED_PIPE_FSCTL",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# NamedPipeDetector — Main plugin
# ---------------------------------------------------------------------------

class NamedPipeDetector(Analyzer):
    """Detects named pipe communication channels between kernel and user-mode."""

    @property
    def name(self) -> str:
        return "NamedPipeDetector"

    @property
    def description(self) -> str:
        return (
            "Detects named pipe communication: NtCreateNamedPipeFile, ZwCreateFile "
            "targeting \\Device\\NamedPipe, FSCTL pipe operations, and 360-specific pipe names."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Named pipe API detection
        findings.extend(detect_named_pipe_apis(ir))

        # 2. Named pipe string patterns
        findings.extend(detect_named_pipe_strings(ir))

        # 3. FSCTL pipe operation codes
        findings.extend(detect_pipe_fsctl_codes(ir))

        return findings
