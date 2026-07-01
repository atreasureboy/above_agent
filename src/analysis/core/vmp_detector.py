"""
DriverScope — VMProtect / Themida 虚拟化保护深度检测。

在基础反混淆（CFG 展平、死代码、API 哈希）之上，专门检测
商业 VM 保护工具的签名级模式。

360 安全卫士使用 VMProtect 保护其核心驱动的关键逻辑。

检测维度：
1. **VM Entry 签名**: pushfd/pushad + 大量寄存器保存 + ret 跳转
2. **VM Handler 调度循环**: 状态机循环 + 间接跳转 dispatcher
3. **代码膨胀**: VM 化后指令数膨胀 5-20 倍
4. **固定寄存器用作 VM 状态指针**: 高频使用单一寄存器做内存访问
"""

from __future__ import annotations

import re

from src.models import (
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Evidence,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Sample,
    Severity,
)
from src.analysis.analyzer import Analyzer


# ---------------------------------------------------------------------------
# 1. VM Entry 签名检测
# ---------------------------------------------------------------------------

# VMProtect x86 经典 VM Entry:
#   pushfd                    ; 保存标志位
#   pushad                    ; 保存所有通用寄存器
#   mov eax, <encrypted_key>
#   push eax
#   ret                       ; 跳转到 VM handler 调度器
#
# VMProtect x64 VM Entry:
#   pushfq
#   push rax; rbx; rcx; rdx; rsi; rdi; rbp; r8-r15
#   mov rsi, <vm_state_ptr>   ; VM 状态指针
#   jmp <vm_dispatcher>
#
# Themida VM Entry:
#   pushfd
#   push 0x0
#   mov dword ptr fs:[0], esp  ; SEH 安装（反调试）
#   push <vm_entry_point>
#   ret

VM_ENTRY_SIGNATURES = [
    # pushfd/pushfq — VM 保护开始标志
    (r"pushf[dq]", "push_flags", "PUSHFD/PUSHFQ — VM entry flag save"),
    # pushad — x86 全寄存器保存
    (r"pushad", "pushad", "PUSHAD — save all GPRs (x86 VM entry)"),
    # x64: individual register pushes (VMProtect saves all registers)
    (r"^push\s+(rax|rbx|rcx|rdx|rsi|rdi|rbp|r8|r9|r10|r11|r12|r13|r14|r15)$",
     "push_reg", "PUSH GPR — register save in VM prologue"),
    # FS/GS:[0] 写 — SEH 安装（Themida 特征）
    (r"mov\s+dword\s+ptr\s+(?:dword\s+ptr\s+)?[fg]s:\[0\]", "seh_setup",
     "FS/GS:[0] write — SEH handler setup (Themida VM entry)"),
    # ret without preceding call — VM dispatcher transfer
    (r"^ret$", "ret_transfer", "RET without call — VM dispatcher transfer"),
]

# VM 相关字符串
VM_STRINGS = {
    "VMProtect": "VMProtect reference",
    "VMprotect": "VMProtect variant reference",
    "vmprotect": "VMProtect lowercase reference",
    "Themida": "Themida reference",
    "WinLicense": "WinLicense reference",
    "oreans": "Oreans Technologies (VMProtect vendor)",
    ".vmp0": "VMProtect section 0",
    ".vmp1": "VMProtect section 1",
    ".vmp2": "VMProtect section 2",
    "vmp_": "VMProtect function prefix",
    "_vmp": "VMProtect function suffix",
    "VM_START": "VM start marker",
    "VM_END": "VM end marker",
}


def detect_vm_entries(ir: DisassemblyResult) -> list[Finding]:
    """Detect VM entry point signatures in the binary."""
    findings: list[Finding] = []

    # 1. String-level
    vm_strings_found = []
    for s in ir.strings:
        for pattern, desc in VM_STRINGS.items():
            if pattern.lower() in s.lower():
                vm_strings_found.append((s, desc))
                break

    # Deduplicate
    seen = set()
    unique_vm_strings = []
    for s, desc in vm_strings_found:
        if desc not in seen:
            seen.add(desc)
            unique_vm_strings.append((s, desc))

    # 2. Instruction-level: functions with VM entry prologue
    vm_entry_funcs = []  # [(func_addr, push_count, reasons)]

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        # Check entry block
        entry_block = cfg.blocks.get(func_addr)
        if entry_block is None:
            continue

        push_count = 0
        reasons = []

        for insn in entry_block.instructions[:25]:
            full = f"{insn.mnemonic} {insn.operands}"
            for pattern, ptype, desc in VM_ENTRY_SIGNATURES:
                if re.match(pattern, full, re.IGNORECASE):
                    push_count += 1
                    reasons.append(desc)
                    break

        # VM entry: need at least 5 pushes (flags + 4+ registers)
        # or SEH setup + ret transfer
        has_seh = any("SEH" in r for r in reasons)
        has_ret = any("RET" in r for r in reasons)

        if push_count >= 5 or (has_seh and has_ret):
            vm_entry_funcs.append((func_addr, push_count, reasons))

    if not vm_entry_funcs and not unique_vm_strings:
        return findings

    # Generate finding
    if vm_entry_funcs and unique_vm_strings:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif len(vm_entry_funcs) >= 2:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif vm_entry_funcs:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM

    string_names = [s for s, _ in unique_vm_strings[:5]]

    findings.append(
        Finding(
            category=FindingCategory.VM_ENTRY,
            severity=severity,
            confidence=confidence,
            description=(
                f"VM entry points detected: {len(vm_entry_funcs)} functions. "
                f"Strings: {', '.join(string_names[:5])}. "
                f"Code virtualization is actively used."
            ),
            function_address=vm_entry_funcs[0][0] if vm_entry_funcs else 0,
            context={
                "vm_entry_count": len(vm_entry_funcs),
                "vm_entry_functions": [
                    {"address": hex(a), "push_count": c, "reasons": r}
                    for a, c, r in vm_entry_funcs[:10]
                ],
                "vm_strings": [s for s, _ in unique_vm_strings[:10]],
            },
            evidence=[
                Evidence(
                    type="instruction_pattern" if vm_entry_funcs else "string",
                    location=f"sub_{vm_entry_funcs[0][0]:X}" if vm_entry_funcs else "binary strings",
                    snippet=f"VM entry: {vm_entry_funcs[0][2][0] if vm_entry_funcs else unique_vm_strings[0][0]}",
                    rule_id="VM_ENTRY",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 2. VM Handler 调度循环检测
# ---------------------------------------------------------------------------

# VM handler 的特征：
# 1. 固定寄存器作为 VM 状态指针（rsi/rdi/r12-r15）
# 2. 大量间接跳转（computed goto dispatch）
# 3. 循环结构：读取 opcode → 查表 → 跳转
# 4. 代码膨胀：单条 VM 指令膨胀为 10-30 条 x86 指令

VM_STATE_REGISTERS = {"rsi", "rdi", "r12", "r13", "r14", "r15"}


def detect_vm_handlers(ir: DisassemblyResult) -> list[Finding]:
    """Detect VM handler dispatch loops."""
    findings: list[Finding] = []

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None or len(cfg.blocks) < 15:
            continue

        total_insns = sum(len(b.instructions) for b in cfg.blocks.values())
        if total_insns < 50:
            continue

        # Count indirect branches (computed gotos)
        indirect_branches = 0
        state_reg_access = {}  # register -> access count

        for block in cfg.blocks.values():
            if not block.instructions:
                continue

            # Check last instruction for indirect branch
            last = block.instructions[-1]
            if last.mnemonic.lower() == "jmp" and "[" in last.operands.lower():
                indirect_branches += 1

            # Track state register memory accesses
            for insn in block.instructions:
                ops = insn.operands.lower()
                if "[" in ops and "]" in ops:
                    for reg in VM_STATE_REGISTERS:
                        if reg in ops:
                            state_reg_access[reg] = state_reg_access.get(reg, 0) + 1

        # VM handler signatures
        avg_insns_per_block = total_insns / max(len(cfg.blocks), 1)

        # Dominant state register
        dominant_reg = None
        dominant_count = 0
        if state_reg_access:
            dominant_reg = max(state_reg_access, key=state_reg_access.get)
            dominant_count = state_reg_access[dominant_reg]

        # Score
        score = 0
        reasons = []

        # Many indirect branches = dispatch loop
        if indirect_branches >= 5:
            score += 3
            reasons.append(f"{indirect_branches} indirect JMPs (VM dispatch)")

        # Dominant state register
        if dominant_count >= 15:
            score += 3
            reasons.append(
                f"State register {dominant_reg} accessed {dominant_count}x "
                f"(VM state pointer)"
            )

        # High block count with low avg insns = bytecode interpretation
        if len(cfg.blocks) >= 30 and avg_insns_per_block < 4:
            score += 2
            reasons.append(
                f"{len(cfg.blocks)} blocks, avg {avg_insns_per_block:.1f} insns/block "
                f"(bytecode interpretation)"
            )

        # Code膨胀: if total_insns is very high for a single function
        if total_insns > 200:
            score += 1
            reasons.append(f"{total_insns} instructions (code bloat)")

        if score >= 5:
            confidence = Confidence.HIGH if score >= 7 else Confidence.MEDIUM

            findings.append(
                Finding(
                    category=FindingCategory.VM_HANDLER,
                    severity=Severity.HIGH,
                    confidence=confidence,
                    description=(
                        f"Function sub_{func_addr:X}: VM handler dispatch loop. "
                        f"Score={score}. {'; '.join(reasons[:3])}."
                    ),
                    function_address=func_addr,
                    context={
                        "vm_handler_score": score,
                        "total_instructions": total_insns,
                        "block_count": len(cfg.blocks),
                        "avg_insns_per_block": round(avg_insns_per_block, 1),
                        "indirect_branches": indirect_branches,
                        "state_register": dominant_reg,
                        "state_register_accesses": dominant_count,
                        "reasons": reasons,
                    },
                    evidence=[
                        Evidence(
                            type="cfg_analysis",
                            location=f"sub_{func_addr:X}",
                            snippet=reasons[0] if reasons else "VM handler pattern",
                            rule_id="VM_HANDLER",
                        )
                    ],
                )
            )

    return findings


# ---------------------------------------------------------------------------
# 3. VMProtect 整体识别（关联）
# ---------------------------------------------------------------------------


def detect_vm_protect_overall(ir: DisassemblyResult) -> list[Finding]:
    """Correlate all VM protection signals into a single finding."""
    findings: list[Finding] = []

    vm_entry_findings = detect_vm_entries(ir)
    vm_handler_findings = detect_vm_handlers(ir)

    total_signals = len(vm_entry_findings) + len(vm_handler_findings)

    if total_signals < 2:
        return findings

    if total_signals >= 3 or (vm_entry_findings and vm_handler_findings):
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    else:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM

    findings.append(
        Finding(
            category=FindingCategory.VM_PROTECT,
            severity=severity,
            confidence=confidence,
            description=(
                f"VMProtect/Themida virtualization confirmed: {total_signals} correlated signals. "
                f"VM entries: {len(vm_entry_findings)}, "
                f"VM handlers: {len(vm_handler_findings)}. "
                f"Critical driver logic is protected by code virtualization."
            ),
            context={
                "chain_type": "vm_protect_correlated",
                "signal_count": total_signals,
                "vm_entry_count": len(vm_entry_findings),
                "vm_handler_count": len(vm_handler_findings),
            },
            evidence=[
                Evidence(
                    type="correlation",
                    location="multiple sources",
                    snippet=f"{total_signals} VM protection signals correlated",
                    rule_id="VM_PROTECT_CHAIN",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# VmProtectDetector — Main plugin
# ---------------------------------------------------------------------------

class VmProtectDetector(Analyzer):
    """Detects VMProtect / Themida code virtualization in kernel drivers."""

    @property
    def name(self) -> str:
        return "VmProtectDetector"

    @property
    def description(self) -> str:
        return (
            "Detects VMProtect/Themida virtualization: VM entry signatures, "
            "VM handler dispatch loops, and correlated VM protection patterns."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. VM entry detection
        findings.extend(detect_vm_entries(ir))

        # 2. VM handler detection
        findings.extend(detect_vm_handlers(ir))

        # 3. Overall correlation
        findings.extend(detect_vm_protect_overall(ir))

        return findings
