"""
DriverScope — Kernel Hook Detector.

Detects active kernel hooking techniques in Windows drivers at four levels:

1. **Inline Hook**: jmp rel32, call rel32, push addr; ret, mov reg imm; push reg; ret
   at function prologue or within function bodies.

2. **SSDT/Shadow SSDT Hook**: References to KeServiceDescriptorTable or
   KeServiceDescriptorTableShadow + index calculation to patch syscall pointers.

3. **IDT Hook**: lidt/sidt instructions, custom IDT table construction,
   KeRegisterInterruptHandler abuse.

4. **Code Self-Check**: CRC32/checksum computation over .text section,
   RtlComputeCrc32/RtlComputeChecksum calls, code segment self-reference patterns.

These techniques are used by rootkits, commercial security drivers (360, Tencent),
and malware to intercept system calls, monitor system activity, and detect tampering.
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
# 1. Inline Hook Detection
# ---------------------------------------------------------------------------

# Inline hook signatures at function entry (first 16 bytes typically).
# x64 uses RIP-relative addresses, so hooks often look like:
#   jmp rel32          (E9 xx xx xx xx)
#   call rel32         (E8 xx xx xx xx)
#   push imm64; ret    (68/FF xx xx xx xx; C3)
#   mov rax, imm64; jmp rax  (48 B8 xx...; FF E0)

# Patterns that are ONLY meaningful at function entry (first block).
# These match the classic 5-14 byte hook trampolines.
ENTRY_HOOK_PATTERNS = [
    # Unconditional jump (jmp rel32 / jmp reg) — classic trampoline
    (r"^jmp\s+(?:0x[0-9a-f]+|\[rip\+0x[0-9a-f]+\])$", "unconditional_jump",
     "Hook trampoline: JMP redirect at function entry"),
    # Call to unknown (call rel32 — common for inline hooking)
    (r"^call\s+(?:0x[0-9a-f]+|\[rip\+0x[0-9a-f]+\])$", "unconditional_call",
     "Hook trampoline: CALL redirect at function entry"),
    # Push immediate + ret (push imm32/64; ret)
    (r"^push\s+0x[0-9a-f]+$", "push_imm_ret",
     "Hook trampoline: PUSH-RET redirect at function entry"),
    # mov reg, imm64 (full 64-bit address load)
    (r"^mov\s+rax,\s*0x[0-9a-f]+$", "mov_abs_rax",
     "Absolute address load (rax) — possible hook target"),
    # mov reg, imm64 for other general purpose registers
    (r"^mov\s+rcx,\s*0x[0-9a-f]+$", "mov_abs_rcx",
     "Absolute address load (rcx) — possible hook target"),
    # jmp register (after mov rax, imm64; jmp rax)
    (r"^jmp\s+(rax|rcx|rdx|r8|r9|r10|r11)$", "jmp_reg",
     "Indirect JMP via register — possible hook"),
]

# Instructions that suggest a function is NOT hooked (legitimate prologue).
# If we see these before any hook pattern, the function is likely clean.
LEGITIMATE_PROLOGUE_PATTERNS = [
    r"^push\s+rbp$",
    r"^mov\s+rbp,\s*rsp$",
    r"^sub\s+rsp,\s*0x[0-9a-f]+$",
    r"^push\s+(rbx|rsi|rdi|r12|r13|r14|r15)$",
    r"^xor\s+eax,\s*eax$",
    r"^mov\s+\[rsp\+",  # Spill to stack
    r"^lea\s+r[abcd]x,\s*\[",  # Address calculation
    # x64 fastcall register saves — common in real drivers
    r"^mov\s+\[rsp\+0x[0-9a-f]+\],\s*(rcx|rdx|r8|r9)$",
    r"^test\s+(rcx|rdx|r8|r9),\s*(rcx|rdx|r8|r9)$",  # Null check params
    r"^cmp\s+byte\s+ptr\s+\[rcx\],\s*0",  # Structure probe
]

# Instructions that are strong hook indicators when found inside function body.
# These detect HOOK INSTALLATION (writing hook code to another function),
# not the hooked function itself.
STRONG_HOOK_INDICATORS = [
    # Write to executable memory: mov byte ptr [rip+offset], 0xE9
    (r"^mov\s+byte\s+ptr\s+\[rip\+0x[0-9a-f]+\],\s*0xe9$", "write_jmp_opcode",
     "Writing JMP opcode (0xE9) to RIP-relative address — inline hook installation"),
    # Write 5-byte JMP: E9 xx xx xx xx
    (r"^mov\s+dword\s+ptr\s+\[rip\+0x[0-9a-f]+\],", "write_jmp_offset",
     "Writing JMP offset to RIP-relative address — hook target address setup"),
]


def _is_function_prologue_block(insns: list) -> bool:
    """Check if a basic block looks like a legitimate function prologue.

    A typical prologue: push rbp; mov rbp, rsp; sub rsp, N; push rbx/rdi/etc.
    """
    if not insns:
        return False
    for insn in insns[:4]:
        full = f"{insn.mnemonic} {insn.operands}".strip()
        if any(re.match(p, full, re.IGNORECASE) for p in LEGITIMATE_PROLOGUE_PATTERNS):
            return True
    return False


def detect_inline_hooks(ir: DisassemblyResult) -> list[Finding]:
    """Detect inline hook installation patterns in the binary.

    Strategy: only flag functions where the FIRST instruction in the entry block
    is a hook trampoline (jmp/call/push+ret/etc) AND the function does NOT have
    a legitimate prologue. Inline hooks replace the first 5-14 bytes of a
    function with a redirect — they don't coexist with push rbp; mov rbp,rsp.

    We also scan for hook INSTALLATION patterns (writing 0xE9 or JMP offsets
    to RIP-relative addresses) anywhere in the binary, which indicates the
    driver is actively patching other functions.
    """
    findings: list[Finding] = []
    hooked_functions: list[dict] = []

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        hook_signals: list[tuple[int, str, str]] = []
        is_legit_prologue = False

        for block in sorted(cfg.blocks.values(), key=lambda b: b.address):
            if not block.instructions:
                continue

            # Only check the entry block for hook trampolines
            is_entry = block.address == func_addr
            if is_entry:
                is_legit_prologue = _is_function_prologue_block(block.instructions)

            for i, insn in enumerate(block.instructions):
                full = f"{insn.mnemonic} {insn.operands}".strip()

                # Entry hook patterns: only flag the FIRST instruction
                # of the entry block. A real inline hook replaces bytes at
                # the function start, not in the middle.
                if is_entry and i == 0:
                    for pattern, ptype, desc in ENTRY_HOOK_PATTERNS:
                        if re.match(pattern, full, re.IGNORECASE):
                            hook_signals.append((insn.address, ptype, desc))
                            break

                # Strong hook installation indicators (writing hook code)
                for pattern, ptype, desc in STRONG_HOOK_INDICATORS:
                    if re.match(pattern, full, re.IGNORECASE):
                        hook_signals.append((insn.address, ptype, desc))
                        break

        if not hook_signals:
            continue

        # Skip if function has a legitimate prologue
        if is_legit_prologue:
            continue

        # Deduplicate by pattern type
        seen_types = set()
        unique_signals = []
        for addr, ptype, desc in hook_signals:
            if ptype not in seen_types:
                seen_types.add(ptype)
                unique_signals.append((addr, ptype, desc))

        # Score the hook likelihood
        score = 0
        descriptions = []
        for addr, ptype, desc in unique_signals:
            if ptype in ("unconditional_jump", "unconditional_call",
                         "write_jmp_opcode", "write_jmp_offset"):
                score += 3
            elif ptype in ("push_imm_ret", "jmp_reg",
                           "mov_abs_rax", "mov_abs_rcx"):
                score += 3
            else:
                score += 1
            descriptions.append(desc)

        # Need at least one strong signal (score >= 3)
        if score < 3:
            continue

        confidence = Confidence.HIGH if score >= 5 else Confidence.MEDIUM
        severity = Severity.CRITICAL if score >= 6 else Severity.HIGH

        hooked_functions.append({
            "func_addr": func_addr,
            "score": score,
            "signals": [{"address": hex(a), "type": p, "desc": d} for a, p, d in unique_signals],
        })

        findings.append(
            Finding(
                category=FindingCategory.INLINE_HOOK,
                severity=severity,
                confidence=confidence,
                description=(
                    f"Function sub_{func_addr:X}: Potential inline hook detected. "
                    f"Score={score}. Signals: {'; '.join(descriptions[:3])}."
                ),
                function_address=func_addr,
                context={
                    "hook_score": score,
                    "hook_signals": [
                        {"address": hex(a), "type": p, "desc": d} for a, p, d in unique_signals
                    ],
                    "legitimate_prologue": is_legit_prologue,
                },
                evidence=[
                    Evidence(
                        type="instruction_pattern",
                        location=f"sub_{func_addr:X}",
                        snippet=descriptions[0] if descriptions else "inline hook pattern",
                        rule_id="INLINE_HOOK",
                    )
                ],
            )
        )

    return findings, hooked_functions


# ---------------------------------------------------------------------------
# 2. SSDT / Shadow SSDT Hook Detection
# ---------------------------------------------------------------------------

# SSDT-related strings and API patterns
SSDT_STRINGS = {
    r"KeServiceDescriptorTable": "SSDT reference (ntoskrnl export)",
    r"KeServiceDescriptorTableShadow": "Shadow SSDT reference (win32k.sys)",
    r"ServiceTableBase": "SSDT service table base pointer",
    r"ntoskrnl": "ntoskrnl.exe reference (SSDT source)",
    r"win32k": "win32k.sys reference (Shadow SSDT source)",
}

# Pattern: mov reg, [rip+offset] → add reg, index*8 → write to [reg]
# This is the classic SSDT hook: load table base, compute index, overwrite pointer.
SSDT_HOOK_PATTERNS = [
    # Load SSDT base pointer
    (r"mov\s+(r[a-z0-9]+),\s*(?:qword\s+ptr\s+)?\[rip\+0x[0-9a-f]+\]",
     "load_ssdt_base", "Load SSDT/Shadow base pointer via RIP-relative"),
    # Index into SSDT (index * 8 since each entry is 8 bytes on x64)
    (r"(shl|sal)\s+(\w+),\s*3",
     "ssdt_index_shift", "SSDT index shift (<< 3) for 8-byte entry size"),
    # Alternative: multiply by 8
    (r"imul\s+(\w+),\s*(\w+),\s*8",
     "ssdt_index_multiply", "SSDT index multiplication by 8"),
    # Write to computed SSDT entry
    (r"mov\s+qword\s+ptr\s+\[(r[a-z0-9]+|\[)?.*\],\s*(r[a-z0-9]+|0x[0-9a-f]+)",
     "ssdt_entry_write", "Write to SSDT service table entry"),
]


def detect_ssdt_hooks(ir: DisassemblyResult) -> list[Finding]:
    """Detect SSDT/Shadow SSDT hook patterns."""
    findings: list[Finding] = []

    # 1. String-level detection
    ssdt_strings = []
    for s in ir.strings:
        for pattern, desc in SSDT_STRINGS.items():
            if re.search(pattern, s, re.IGNORECASE):
                ssdt_strings.append((s, desc))

    if not ssdt_strings:
        return findings

    # 2. Instruction-level: functions that reference SSDT
    ssdt_funcs: list[tuple[int, list[tuple[str, str]]]] = []

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        func_signals = []
        for block in cfg.blocks.values():
            for insn in block.instructions:
                full = f"{insn.mnemonic} {insn.operands}".strip()
                for pattern, stype, desc in SSDT_HOOK_PATTERNS:
                    if re.match(pattern, full, re.IGNORECASE):
                        func_signals.append((stype, desc))
                        break

        if func_signals:
            ssdt_funcs.append((func_addr, func_signals))

    # Generate findings
    matched_strings = list({s for s, _ in ssdt_strings})
    techniques = list({desc for _, desc in ssdt_strings})

    severity = Severity.CRITICAL if ssdt_funcs else Severity.HIGH
    confidence = Confidence.HIGH if ssdt_funcs else Confidence.MEDIUM

    findings.append(
        Finding(
            category=FindingCategory.SSDT_HOOK,
            severity=severity,
            confidence=confidence,
            description=(
                f"SSDT/Shadow SSDT hook indicators: {len(matched_strings)} strings, "
                f"{len(ssdt_funcs)} functions with SSDT access patterns. "
                f"Strings: {', '.join(matched_strings[:5])}. "
                f"This driver may modify the system service dispatch table."
            ),
            context={
                "ssdt_strings": matched_strings,
                "techniques": techniques,
                "ssdt_access_functions": [
                    {"address": hex(a), "signals": s} for a, s in ssdt_funcs
                ],
                "has_shadow_ssdt": any("Shadow" in t for t in techniques),
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=matched_strings[0] if matched_strings else "SSDT reference",
                    rule_id="SSDT_HOOK",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 3. IDT Hook Detection
# ---------------------------------------------------------------------------

IDT_STRINGS = {
    r"IDT": "IDT (Interrupt Descriptor Table) reference",
    r"Interrupt.*Descriptor": "Interrupt descriptor table reference",
    r"_IDT": "IDT variable name",
    r"IdtEntry": "IDT entry structure",
}

# lidt instruction patterns
IDT_HOOK_PATTERNS = [
    # lidt [mem] — load IDT register
    (r"lidt\s+\[", "lidt", "LIDT instruction — loading custom IDT"),
    # sidt [reg] — store IDT register (often used to read current IDT before hooking)
    (r"sidt\s+\[", "sidt", "SIDT instruction — reading current IDT base"),
    # sidt to stack
    (r"sidt\s+\[rsp", "sidt_stack", "SIDT to stack — reading IDT base for analysis"),
    # Write to IDT entry (after sidt + base calculation)
    (r"mov\s+(?:qword|dword)\s+ptr\s+\[(?:r[a-z0-9]+|rax|rbx|rcx|rdx)",
     "idt_entry_write", "Write to interrupt descriptor entry"),
    # Interrupt gate setup
    (r"lea\s+r[a-z0-9]+,\s*\[rip\+0x[0-9a-f]+\]",
     "idt_handler_setup", "Load handler address for IDT entry"),
]


def detect_idt_hooks(ir: DisassemblyResult) -> list[Finding]:
    """Detect IDT hook patterns."""
    findings: list[Finding] = []

    # 1. String-level
    idt_strings = []
    for s in ir.strings:
        for pattern, desc in IDT_STRINGS.items():
            if re.search(pattern, s, re.IGNORECASE):
                idt_strings.append((s, desc))

    # 2. Instruction-level
    idt_funcs: list[tuple[int, list[tuple[str, str]]]] = []

    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        func_signals = []
        for block in cfg.blocks.values():
            for insn in block.instructions:
                full = f"{insn.mnemonic} {insn.operands}".strip()
                for pattern, ptype, desc in IDT_HOOK_PATTERNS:
                    if re.match(pattern, full, re.IGNORECASE):
                        func_signals.append((ptype, desc))
                        break

        if func_signals:
            idt_funcs.append((func_addr, func_signals))

    if not idt_strings and not idt_funcs:
        return findings

    matched_strings = list({s for s, _ in idt_strings})
    severity = Severity.CRITICAL if idt_funcs else Severity.HIGH
    confidence = Confidence.HIGH if idt_funcs else Confidence.MEDIUM

    findings.append(
        Finding(
            category=FindingCategory.IDT_HOOK,
            severity=severity,
            confidence=confidence,
            description=(
                f"IDT hook indicators: {len(matched_strings)} strings, "
                f"{len(idt_funcs)} functions with IDT access patterns. "
                f"This driver may intercept hardware interrupts."
            ),
            context={
                "idt_strings": matched_strings,
                "idt_access_functions": [
                    {"address": hex(a), "signals": s} for a, s in idt_funcs
                ],
            },
            evidence=[
                Evidence(
                    type="instruction_pattern",
                    location="binary strings + instructions",
                    snippet="IDT modification pattern",
                    rule_id="IDT_HOOK",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 4. Code Self-Check / Integrity Verification Detection
# ---------------------------------------------------------------------------

SELF_CHECK_APIS = {
    "RtlComputeCrc32": "CRC32 checksum computation",
    "RtlComputeChecksum": "Generic checksum computation",
    "ZwQueryInformationProcess": "Process information query (self-inspection)",
    "ZwGetContextThread": "Thread context read (self-inspection)",
    "KeGetCurrentIrql": "IRQL check (execution context validation)",
}

# Pattern: read from .text section (code self-reference)
# mov reg, [rip+offset] where offset points to .text section
SELF_READ_PATTERNS = [
    (r"mov\s+(r[a-z0-9]+),\s*(?:byte|word|dword|qword)\s+ptr\s+\[rip\+0x[0-9a-f]+\]",
     "text_self_read", "Read from RIP-relative address (possible .text section self-reference)"),
    # Loop with increment + compare (checksum loop body)
    (r"(add|inc)\s+(\w+),",
     "loop_increment", "Loop counter increment (possible checksum loop)"),
    (r"(cmp|test)\s+(\w+),\s*(\w+)",
     "loop_compare", "Loop comparison (possible checksum verification)"),
]


def detect_code_self_check(ir: DisassemblyResult) -> list[Finding]:
    """Detect code integrity self-check patterns."""
    findings: list[Finding] = []

    # 1. API-level: self-check APIs
    self_check_funcs: list[tuple[int, list[str]]] = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in SELF_CHECK_APIS]
        if matched:
            self_check_funcs.append((func_addr, matched))

    # 2. Instruction-level: self-read patterns
    self_read_funcs: list[tuple[int, int]] = []  # (func_addr, read_count)
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        read_count = 0
        for block in cfg.blocks.values():
            for insn in block.instructions:
                full = f"{insn.mnemonic} {insn.operands}".strip()
                for pattern, ptype, desc in SELF_READ_PATTERNS:
                    if re.match(pattern, full, re.IGNORECASE):
                        read_count += 1
                        break

        if read_count >= 3:  # Threshold: significant self-reading
            self_read_funcs.append((func_addr, read_count))

    if not self_check_funcs and not self_read_funcs:
        return findings

    severity = Severity.HIGH if self_check_funcs else Severity.MEDIUM
    confidence = Confidence.MEDIUM

    api_names = []
    for _, apis in self_check_funcs:
        api_names.extend(apis)

    findings.append(
        Finding(
            category=FindingCategory.CODE_SELF_CHECK,
            severity=severity,
            confidence=confidence,
            description=(
                f"Code integrity self-check: {len(self_check_funcs)} functions call "
                f"checksum APIs ({', '.join(set(api_names))}), "
                f"{len(self_read_funcs)} functions with significant self-reading. "
                f"This driver verifies its own code integrity at runtime."
            ),
            context={
                "self_check_functions": [
                    {"address": hex(a), "apis": apis} for a, apis in self_check_funcs
                ],
                "self_read_functions": [
                    {"address": hex(a), "read_count": c} for a, c in self_read_funcs
                ],
            },
            evidence=[
                Evidence(
                    type="api_match",
                    location="multiple functions",
                    snippet=", ".join(set(api_names)) if api_names else "self-read pattern",
                    rule_id="CODE_SELF_CHECK",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# 5. IAT (Import Address Table) Hooking Detection
# ---------------------------------------------------------------------------

# IAT hooking: modify another module's IAT to redirect API calls.
# Common technique: find target module's IAT via PE parsing, overwrite entries.

IAT_STRINGS = {
    "ImageDirectoryEntryToData": "PE directory entry access (IAT lookup)",
    "IMAGE_DIRECTORY_ENTRY_IMPORT": "Import directory access",
    "Import Address Table": "IAT full string reference",
    "IMAGE_IMPORT_DESCRIPTOR": "Import descriptor structure",
    "OriginalFirstThunk": "IAT OFT field reference",
    "FirstThunk": "IAT FT field reference",
    "IMPORT_NAME_TABLE": "INT reference (IAT parsing)",
    "ThunkData": "IAT thunk data structure",
    "IMAGE_THUNK_DATA": "Thunk data structure reference",
    "RtlImageDirectoryEntryToData": "PE image directory access",
    "LdrGetProcedureAddress": "Dynamic API resolution (IAT hook target)",
    "LdrLoadDll": "DLL load for IAT hooking",
    "GetModuleHandle": "Module handle for IAT access",
    "GetProcAddress": "API address for IAT patching",
}

# APIs used in IAT hooking
IAT_APIS = {
    "ImageDirectoryEntryToData": "PE IAT directory access",
    "RtlImageDirectoryEntryToData": "PE image directory access",
    "LdrGetProcedureAddress": "API address resolution (IAT patch target)",
    "LdrLoadDll": "DLL loading (IAT hook setup)",
    "ZwMapViewOfSection": "Section mapping (IAT write access)",
    "MmGetSystemRoutineAddress": "Kernel API resolution",
}

# Instruction patterns indicating IAT manipulation
IAT_HOOK_PATTERNS = [
    # Write to RIP-relative address (IAT entry write: mov [rip+offset], rax)
    (r"mov\s+qword\s+ptr\s+\[rip\+0x[0-9a-f]+\],\s*r[a-z0-9]+",
     "iat_entry_write", "Write to RIP-relative address (possible IAT entry patch)"),
    # Read from RIP-relative (IAT entry read before patch)
    (r"mov\s+r[a-z0-9]+,\s*qword\s+ptr\s+\[rip\+0x[0-9a-f]+\]",
     "iat_entry_read", "Read from RIP-relative address (possible IAT entry access)"),
    # Loop with increment (IAT entry enumeration)
    (r"(add|inc)\s+(r[a-z0-9]+),\s*(?:0x[0-9a-f]+|\d+)",
     "iat_enumerate", "Pointer increment (IAT entry enumeration)"),
    # Compare with zero/thunk value (IAT end check)
    (r"(cmp|test)\s+(r[a-z0-9]+|eax),\s*(?:0x0|eax|r[a-z0-9]+)",
     "iat_end_check", "Comparison (possible IAT end-of-table check)"),
]


def detect_iat_hooks(ir: DisassemblyResult) -> list[Finding]:
    """Detect IAT (Import Address Table) hooking patterns."""
    findings: list[Finding] = []

    # 1. String-level
    iat_strings_found: list[tuple[str, str]] = []
    for s in ir.strings:
        for pattern, desc in IAT_STRINGS.items():
            if pattern.lower() in s.lower():
                iat_strings_found.append((s, desc))

    # 2. API-level
    iat_api_funcs: list[tuple[int, list[str]]] = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in IAT_APIS]
        if matched:
            iat_api_funcs.append((func_addr, matched))

    # 3. Instruction-level
    iat_inst_funcs: list[tuple[int, list[tuple[str, str]]]] = []
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        func_signals = []
        for block in cfg.blocks.values():
            for insn in block.instructions:
                full = f"{insn.mnemonic} {insn.operands}".strip()
                for pattern, ptype, desc in IAT_HOOK_PATTERNS:
                    if re.match(pattern, full, re.IGNORECASE):
                        func_signals.append((ptype, desc))
                        break

        if func_signals:
            iat_inst_funcs.append((func_addr, func_signals))

    if not iat_strings_found and not iat_api_funcs and not iat_inst_funcs:
        return findings

    # Severity: CRITICAL if strings + IAT write instructions, HIGH otherwise
    has_write = any(ptype == "iat_entry_write"
                   for _, signals in iat_inst_funcs
                   for ptype, _ in signals)
    has_strings = len(iat_strings_found) > 0

    if has_write and has_strings:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_write or has_strings:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    string_names = list({s for s, _ in iat_strings_found})

    findings.append(Finding(
        category=FindingCategory.IAT_HOOK,
        severity=severity,
        confidence=confidence,
        description=(
            f"IAT hook indicators: {len(string_names)} strings, "
            f"{len(iat_api_funcs)} functions with IAT APIs, "
            f"{len(iat_inst_funcs)} functions with IAT access patterns. "
            f"This driver may patch Import Address Table entries. "
            f"Key references: {', '.join(string_names[:5])}."
        ),
        context={
            "iat_strings": string_names,
            "iat_api_functions": [
                {"address": hex(a), "apis": apis} for a, apis in iat_api_funcs
            ],
            "iat_instruction_functions": [
                {"address": hex(a), "signals": s} for a, s in iat_inst_funcs
            ],
            "has_iat_write": has_write,
        },
        evidence=[
            Evidence(
                type="string" if has_strings else "instruction_pattern",
                location="binary strings" if has_strings else "instruction stream",
                snippet=string_names[0] if string_names else "IAT hook pattern",
                rule_id="IAT_HOOK",
            )
        ],
    ))

    return findings


# ---------------------------------------------------------------------------
# 6. EAT (Export Address Table) Hooking Detection
# ---------------------------------------------------------------------------

# EAT hooking: modify a module's export table to redirect API calls.
# Less common than IAT hooking, used by advanced rootkits.

EAT_STRINGS = {
    "IMAGE_DIRECTORY_ENTRY_EXPORT": "Export directory access",
    "IMAGE_EXPORT_DIRECTORY": "Export directory structure",
    "Export Address Table": "EAT full string reference",
    "AddressOfFunctions": "EAT function address array",
    "AddressOfNames": "EAT function name array",
    "AddressOfNameOrdinals": "EAT name ordinal array",
    "NumberOfFunctions": "EAT function count",
    "NumberOfNames": "EAT named function count",
    "Export Directory": "Export directory reference",
    "RtlImageNtHeader": "PE NT header access (EAT parsing prerequisite)",
    "IMAGE_NT_HEADERS": "NT header structure reference",
    "IMAGE_OPTIONAL_HEADER": "Optional header (DataDirectory for EAT)",
}

EAT_APIS = {
    "RtlImageNtHeader": "PE NT header access (EAT parsing)",
    "ImageDirectoryEntryToData": "PE directory access (EAT lookup)",
    "RtlImageDirectoryEntryToData": "PE image directory access (EAT)",
    "MmGetSystemRoutineAddress": "Kernel API resolution (EAT target)",
}

# Instruction patterns indicating EAT manipulation
EAT_HOOK_PATTERNS = [
    # Write to export function pointer
    (r"mov\s+qword\s+ptr\s+\[(?:r[a-z0-9]+|rax|rbx|rcx|rdx)\],\s*(?:r[a-z0-9]+|0x[0-9a-f]+)",
     "eat_entry_write", "Write to register-based address (possible EAT entry patch)"),
    # Read export directory field
    (r"mov\s+(?:r|e)[a-z0-9]+,\s*(?:dword|qword)\s+ptr\s+\[(?:r[a-z0-9]+|\[)?(?:r[a-z0-9]+|\[)?.*\+0x[0-9a-f]+\]",
     "eat_field_read", "Read from structure+offset (possible EAT field access)"),
    # Loop over export entries
    (r"(add|inc)\s+(r[a-z0-9]+),\s*(?:0x[0-9a-f]+|\d+)",
     "eat_enumerate", "Pointer increment (EAT entry enumeration)"),
    # Compare ordinal or index
    (r"(cmp|test)\s+(r[a-z0-9]+|eax|ecx|edx),\s*(?:0x[0-9a-f]+|\d+)",
     "eat_ordinal_cmp", "Ordinal/index comparison (EAT lookup)"),
]


def detect_eat_hooks(ir: DisassemblyResult) -> list[Finding]:
    """Detect EAT (Export Address Table) hooking patterns."""
    findings: list[Finding] = []

    # 1. String-level
    eat_strings_found: list[tuple[str, str]] = []
    for s in ir.strings:
        for pattern, desc in EAT_STRINGS.items():
            if pattern.lower() in s.lower():
                eat_strings_found.append((s, desc))

    # 2. API-level
    eat_api_funcs: list[tuple[int, list[str]]] = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in EAT_APIS]
        if matched:
            eat_api_funcs.append((func_addr, matched))

    # 3. Instruction-level
    eat_inst_funcs: list[tuple[int, list[tuple[str, str]]]] = []
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        func_signals = []
        for block in cfg.blocks.values():
            for insn in block.instructions:
                full = f"{insn.mnemonic} {insn.operands}".strip()
                for pattern, ptype, desc in EAT_HOOK_PATTERNS:
                    if re.match(pattern, full, re.IGNORECASE):
                        func_signals.append((ptype, desc))
                        break

        if func_signals:
            eat_inst_funcs.append((func_addr, func_signals))

    if not eat_strings_found and not eat_api_funcs and not eat_inst_funcs:
        return findings

    # Severity: CRITICAL if strings + EAT write, HIGH otherwise
    has_write = any(ptype == "eat_entry_write"
                   for _, signals in eat_inst_funcs
                   for ptype, _ in signals)
    has_strings = len(eat_strings_found) > 0

    if has_write and has_strings:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_write or has_strings:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    string_names = list({s for s, _ in eat_strings_found})

    findings.append(Finding(
        category=FindingCategory.EAT_HOOK,
        severity=severity,
        confidence=confidence,
        description=(
            f"EAT hook indicators: {len(string_names)} strings, "
            f"{len(eat_api_funcs)} functions with EAT APIs, "
            f"{len(eat_inst_funcs)} functions with EAT access patterns. "
            f"This driver may modify Export Address Table entries. "
            f"Key references: {', '.join(string_names[:5])}."
        ),
        context={
            "eat_strings": string_names,
            "eat_api_functions": [
                {"address": hex(a), "apis": apis} for a, apis in eat_api_funcs
            ],
            "eat_instruction_functions": [
                {"address": hex(a), "signals": s} for a, s in eat_inst_funcs
            ],
            "has_eat_write": has_write,
        },
        evidence=[
            Evidence(
                type="string" if has_strings else "instruction_pattern",
                location="binary strings" if has_strings else "instruction stream",
                snippet=string_names[0] if string_names else "EAT hook pattern",
                rule_id="EAT_HOOK",
            )
        ],
    ))

    return findings


# ---------------------------------------------------------------------------
# HookAnalyzer — Main plugin
# ---------------------------------------------------------------------------

class HookAnalyzer(Analyzer):
    """Detects kernel hooking and code integrity techniques in drivers."""

    @property
    def name(self) -> str:
        return "HookAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Detects inline hooks, SSDT/Shadow SSDT hooks, IDT hooks, "
            "code integrity self-check, IAT hooking, and EAT hooking patterns."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Inline hook detection
        inline_findings, _ = detect_inline_hooks(ir)
        findings.extend(inline_findings)

        # 2. SSDT hook detection
        ssdt_findings = detect_ssdt_hooks(ir)
        findings.extend(ssdt_findings)

        # 3. IDT hook detection
        idt_findings = detect_idt_hooks(ir)
        findings.extend(idt_findings)

        # 4. Code self-check detection
        self_check_findings = detect_code_self_check(ir)
        findings.extend(self_check_findings)

        # 5. IAT hook detection
        iat_findings = detect_iat_hooks(ir)
        findings.extend(iat_findings)

        # 6. EAT hook detection
        eat_findings = detect_eat_hooks(ir)
        findings.extend(eat_findings)

        return findings
