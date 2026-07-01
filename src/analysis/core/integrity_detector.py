"""
DriverScope — 完整性自检检测器（Phase 6）。

检测驱动程序的自我完整性验证机制：
1. CRC32/CRC64 计算循环（代码自校验）
2. Checksum 验证（PE header checksum 比对）
3. 代码段遍历（遍历 .text 段计算哈希）
4. RtlComputeCrc32 / 自定义 CRC 实现
5. 自我调试检测（检测自身是否被 patch）

360 安全卫士定期扫描自身代码段，计算 CRC 并与嵌入的基准值比对，
检测是否有第三方 patch 或 hook。
"""

from __future__ import annotations

from src.models import (
    BasicBlock,
    CFG,
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
# 1. CRC/Checksum API 检测
# ---------------------------------------------------------------------------

CRC_APIS = {
    "RtlComputeCrc32": "Windows RTL CRC32 function",
    "RtlComputeCrc64": "Windows RTL CRC64 function",
    "Crc32": "Generic CRC32 reference",
    "Crc64": "Generic CRC64 reference",
    "CheckSumMappedFile": "PE checksum verification",
    "RtlGetSetBootStatusData": "Boot status data (integrity)",
}

# Custom CRC implementations detected by string references
CRC_STRINGS = {
    "CRC32": "CRC32 algorithm reference",
    "crc32": "CRC32 algorithm reference (lowercase)",
    "CRC-32": "CRC-32 standard reference",
    "CRC64": "CRC64 algorithm reference",
    "checksum": "Checksum routine reference",
    "integrity check": "Integrity verification reference",
    "self_check": "Self-check routine reference",
    "verify checksum": "Checksum verification reference",
    "code integrity": "Code integrity reference",
    "hash mismatch": "Hash mismatch detection",
    "corrupt": "Corruption detection reference",
    "tamper": "Tamper detection reference",
    "modified": "Modification detection reference",
}


def detect_crc_apis(ir: DisassemblyResult) -> list[Finding]:
    """Detect CRC/checksum API usage."""
    findings: list[Finding] = []

    crc_funcs = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in CRC_APIS]
        if matched:
            crc_funcs.append((func_addr, matched))

    if not crc_funcs:
        return findings

    has_checksum_mapped = any(
        "CheckSum" in api for _, apis in crc_funcs for api in apis
    )

    if has_checksum_mapped:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    else:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM

    all_apis = []
    for _, apis in crc_funcs:
        all_apis.extend(apis)

    findings.append(
        Finding(
            category=FindingCategory.CODE_SELF_CHECK,
            severity=severity,
            confidence=confidence,
            description=(
                f"CRC/checksum APIs: {len(crc_funcs)} functions, "
                f"APIs: {', '.join(sorted(set(all_apis)))}. "
                f"Driver may perform integrity verification."
            ),
            function_address=crc_funcs[0][0],
            context={
                "crc_functions": [
                    {"address": hex(addr), "apis": apis}
                    for addr, apis in crc_funcs[:10]
                ],
                "has_pe_checksum": has_checksum_mapped,
            },
            evidence=[
                Evidence(
                    type="api_match",
                    location=f"sub_{crc_funcs[0][0]:X}",
                    snippet=sorted(set(all_apis))[0],
                    rule_id="INTEGRITY_CRC_API",
                )
            ],
        )
    )

    return findings


def detect_crc_strings(ir: DisassemblyResult) -> list[Finding]:
    """Detect CRC/integrity related strings."""
    findings: list[Finding] = []

    crc_strings = []
    for s in ir.strings:
        s_lower = s.lower()
        for pattern, desc in CRC_STRINGS.items():
            if pattern.lower() in s_lower:
                crc_strings.append((s, desc))
                break

    if not crc_strings:
        return findings

    seen = set()
    unique_strings = []
    for s, desc in crc_strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append((s, desc))

    has_tamper = any(
        p in s.lower()
        for s, _ in unique_strings
        for p in ("tamper", "corrupt", "mismatch", "modified")
    )
    has_integrity = any(
        p in s.lower()
        for s, _ in unique_strings
        for p in ("integrity", "self_check", "verify")
    )

    if has_tamper and has_integrity:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_tamper or has_integrity:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    str_names = [s for s, _ in unique_strings[:5]]

    findings.append(
        Finding(
            category=FindingCategory.CODE_SELF_CHECK,
            severity=severity,
            confidence=confidence,
            description=(
                f"Integrity check strings: {', '.join(str_names)}. "
                f"Driver may verify its own code integrity."
            ),
            context={
                "crc_strings": str_names,
                "has_tamper_detection": has_tamper,
                "has_integrity_check": has_integrity,
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=str_names[0],
                    rule_id="INTEGRITY_STRING",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 2. 代码段遍历模式检测（指令级）
# ---------------------------------------------------------------------------

def detect_code_scanning(ir: DisassemblyResult) -> list[Finding]:
    """Detect code section scanning patterns.

    Patterns that suggest iterating over code/memory for checksum:
    1. Loop with byte-by-byte reads from executable regions
    2. XOR accumulator loops (common in custom hash/CRC)
    3. Sequential memory access with rolling computation
    4. Section header traversal (IMAGE_SECTION_HEADER iteration)
    """
    findings: list[Finding] = []

    scanning_funcs = []
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        score = 0
        details = []

        # Count blocks (many blocks suggests complex loop structure)
        block_count = len(cfg.blocks)
        if block_count >= 8:
            score += 1
            details.append(f"{block_count} blocks")

        # Look for loop-like patterns
        has_loop = False
        has_sequential_read = False
        has_xor_accumulator = False
        has_section_access = False

        for block in cfg.blocks.values():
            for insn in block.instructions:
                ops = insn.operands.lower()
                mnem = insn.mnemonic.lower()

                # Backward jump = loop
                if mnem == "jmp" or mnem.startswith("j"):
                    has_loop = True

                # Sequential byte reads: movzx/movsx with [reg+offset]
                if ("movzx" in mnem or "movsx" in mnem) and "[" in ops:
                    has_sequential_read = True

                # XOR accumulator: xor reg, [mem] or xor reg, byte
                if "xor" in mnem and ("[" in ops or "byte" in ops):
                    has_xor_accumulator = True

                # Section header access
                if "section" in ops or "image_" in ops:
                    has_section_access = True

                # Rolling computation patterns
                if ("rol" in mnem or "ror" in mnem or "shl" in mnem or "shr" in mnem):
                    if "[" in ops:
                        score += 1

        if has_loop:
            score += 1
        if has_sequential_read:
            score += 2
            details.append("sequential byte reads")
        if has_xor_accumulator:
            score += 2
            details.append("XOR accumulator")
        if has_section_access:
            score += 2
            details.append("section header access")

        if score >= 4:
            scanning_funcs.append((func_addr, score, details[:5]))

    if not scanning_funcs:
        return findings

    # Severity based on signal strength
    max_score = max(s for _, s, _ in scanning_funcs)
    if max_score >= 6:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif max_score >= 5:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    findings.append(
        Finding(
            category=FindingCategory.CODE_SELF_CHECK,
            severity=severity,
            confidence=confidence,
            description=(
                f"Code scanning patterns: {len(scanning_funcs)} functions. "
                f"Driver may iterate over code sections for integrity verification."
            ),
            function_address=scanning_funcs[0][0],
            context={
                "scanning_functions": [
                    {"address": hex(addr), "score": sc, "patterns": dets}
                    for addr, sc, dets in scanning_funcs[:10]
                ],
            },
            evidence=[
                Evidence(
                    type="instruction_pattern",
                    location=f"sub_{scanning_funcs[0][0]:X}",
                    snippet=", ".join(scanning_funcs[0][2]) if scanning_funcs[0][2] else "code scanning loop",
                    rule_id="INTEGRITY_CODE_SCAN",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 3. PE Header 访问检测
# ---------------------------------------------------------------------------

PE_HEADER_STRINGS = {
    "MZ": "DOS header magic",
    "PE\0\0": "PE signature",
    "ImageDosHeader": "DOS header structure",
    "ImageNtHeaders": "NT headers structure",
    "ImageOptionalHeader": "Optional header structure",
    "ImageSectionHeader": "Section header structure",
    "ImageDebugDirectory": "Debug directory structure",
    "CheckSum": "PE checksum field",
    "SizeOfImage": "PE image size field",
    "BaseOfCode": "PE code base field",
}


def detect_pe_header_access(ir: DisassemblyResult) -> list[Finding]:
    """Detect PE header field access patterns."""
    findings: list[Finding] = []

    pe_strings = []
    for s in ir.strings:
        for pattern, desc in PE_HEADER_STRINGS.items():
            if pattern in s:
                pe_strings.append((s, desc))
                break

    if not pe_strings:
        return findings

    seen = set()
    unique_strings = []
    for s, desc in pe_strings:
        if s not in seen:
            seen.add(s)
            unique_strings.append((s, desc))

    has_checksum = any("CheckSum" in s for s, _ in unique_strings)
    has_pe_sig = any("MZ" in s or "PE" in s for s, _ in unique_strings)

    if has_checksum:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    elif has_pe_sig:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW
    else:
        severity = Severity.LOW
        confidence = Confidence.LOW

    str_names = [s for s, _ in unique_strings[:5]]

    findings.append(
        Finding(
            category=FindingCategory.CODE_SELF_CHECK,
            severity=severity,
            confidence=confidence,
            description=(
                f"PE header access: {', '.join(str_names)}. "
                f"Driver may read its own PE headers."
            ),
            context={
                "pe_strings": str_names,
                "has_checksum_access": has_checksum,
                "has_pe_signature": has_pe_sig,
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=str_names[0],
                    rule_id="INTEGRITY_PE_HEADER",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# IntegrityDetector — Main plugin
# ---------------------------------------------------------------------------

class IntegrityDetector(Analyzer):
    """Detects self-integrity verification mechanisms."""

    @property
    def name(self) -> str:
        return "IntegrityDetector"

    @property
    def description(self) -> str:
        return (
            "Detects code integrity self-check mechanisms: CRC32/CRC64 computation, "
            "PE checksum verification, code section scanning, and tamper detection."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. CRC/checksum API detection
        findings.extend(detect_crc_apis(ir))

        # 2. CRC/integrity strings
        findings.extend(detect_crc_strings(ir))

        # 3. Code scanning patterns (instruction-level)
        findings.extend(detect_code_scanning(ir))

        # 4. PE header access
        findings.extend(detect_pe_header_access(ir))

        return findings
