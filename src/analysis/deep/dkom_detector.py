"""
DriverScope — DKOM (Direct Kernel Object Manipulation) Detector.

Detects patterns where a driver directly manipulates kernel object structures
to hide processes, steal tokens, or bypass security mechanisms.

DKOM techniques used by 360 and other advanced drivers:
1. ActiveProcessLinks unlinking (PsActiveProcessHead traversal → remove entry)
2. ActiveThreadListEntry unlinking (hide threads)
3. Token swapping (EPROCESS→Token field write)
4. CID table manipulation (PsCidTable direct access)
5. EPROCESS/ETHREAD field offset access (known struct offsets)

Detection strategy:
- Known EPROCESS/ETHREAD field offsets in memory access instructions
- References to PsActiveProcessHead, PsInitialSystemProcess
- LIST_ENTRY manipulation patterns (Blink/Flink writes)
- Token field writes (offset 0x4B8 on Win10 x64, varies by version)
- CID table access (PspCidTable, PsLookupProcessByProcessId patterns)
"""

from __future__ import annotations

import re

from src.models import (
    Confidence, DisassemblyResult, Evidence, Finding, FindingCategory,
    Sample, Severity,
)
from src.analysis.analyzer import Analyzer


# Known EPROCESS field offsets (Win10/Win11 x64, approximate)
# These vary by Windows version but are stable within major releases.
EPROCESS_OFFSETS = {
    0x000: "_EPHEADER",          # nt!_EPROCESS header
    0x2E8: "ActiveProcessLinks", # LIST_ENTRY (process hiding)
    0x2F0: "ActiveProcessLinks", # Win10 21H1 variant
    0x440: "ActiveProcessLinks", # Win11 variant
    0x4B8: "Token",              # _EX_FAST_REF (token swap)
    0x4C0: "Token",              # Win10 variant
    0x5A0: "Token",              # Win11 variant
    0x480: "UniqueProcessId",    # PID field
    0x488: "InheritedFromUniqueProcessId",  # PPID
    0x5F8: "ObjectTable",        # Handle table
    0x3E8: "Protection",         # PsProtectedSignature (protection bypass)
    0x87A: "MitigationFlags",    # Process mitigation flags
}

# Known ETHREAD field offsets (Win10/Win11 x64)
ETHREAD_OFFSETS = {
    0x2F0: "ActiveThreadListEntry",  # LIST_ENTRY (thread hiding)
    0x300: "ActiveThreadListEntry",  # Win11 variant
    0x428: "Cid.UniqueProcess",      # Thread CID
    0x430: "Cid.UniqueThread",       # Thread CID
    0x4C8: "ThreadsProcess",         # Back-pointer to EPROCESS
    0x2E0: "StartAddress",           # Thread start address
}

# Known kernel symbol names that indicate DKOM
DKOM_SYMBOLS = {
    "PsActiveProcessHead",
    "PsInitialSystemProcess",
    "PspCidTable",
    "PspCreateProcessNotifyRoutine",
    "PspCreateThreadNotifyRoutine",
    "PsLoadedModuleList",
    "MmUnloadedDrivers",
    "PiDDBCacheTable",
}

# DKOM-related APIs — used for context only, NOT as standalone findings.
# These are normal kernel APIs (PsLookupProcessByProcessId, PsGetProcessId, etc.)
# used by virtually every driver. They contribute confidence when combined
# with actual DKOM evidence (offset writes, symbol references) but should
# never trigger a finding on their own.
DKOM_APIS = {
    "PsLookupProcessByProcessId",
    "PsLookupThreadByThreadId",
    "PsGetProcessId",
    "PsGetThreadId",
    "PsGetProcessImageFileName",
    "PsGetProcessPeb",
    "PsGetThreadTeb",
    "PsSuspendProcess",
    "PsResumeProcess",
    "PsIsProtectedProcess",
    "PsSetLoadImageNotifyRoutine",
    "PsSetCreateProcessNotifyRoutine",
    "PsSetCreateThreadNotifyRoutine",
    "ExEnumHandleTable",
}

# LIST_ENTRY manipulation patterns (Blink/Flink field writes)
LIST_ENTRY_PATTERNS = {
    "Blink", "Flink",
    "[rax+0x0]", "[rax+0x8]",  # LIST_ENTRY: [0]=Flink, [8]=Blink
    "[rcx+0x0]", "[rcx+0x8]",
    "[rdx+0x0]", "[rdx+0x8]",
    "list_entry", "_LIST_ENTRY",
}


class DKOMDetector(Analyzer):
    """Detect DKOM (Direct Kernel Object Manipulation) patterns."""

    @property
    def name(self) -> str:
        return "DKOMDetector"

    @property
    def description(self) -> str:
        return (
            "Detects Direct Kernel Object Manipulation patterns: "
            "process/thread unlinking, token swapping, CID table access, "
            "and EPROCESS/ETHREAD field manipulation."
        )

    @staticmethod
    def _is_memory_destination(insn) -> bool:
        """Check if the instruction writes TO a memory operand.

        x86 AT&T-style or Intel: destination operand is on the left of comma.
        mov [mem], reg  → write (True)
        mov reg, [mem]  → read  (False)
        """
        ops = insn.operands
        if "," not in ops:
            return False
        dest, _src = ops.split(",", 1)
        dest = dest.strip().lower()
        return "[" in dest or "ptr" in dest

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Check for DKOM symbol references in strings
        dkom_strings = []
        for s in ir.strings:
            for sym in DKOM_SYMBOLS:
                if sym in s:
                    dkom_strings.append((s, sym))

        if dkom_strings:
            findings.append(Finding(
                category=FindingCategory.DKOM_PROCESS_UNLINK,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                description=(
                    f"DKOM: References to kernel symbols: "
                    f"{', '.join(sorted(set(s for _, s in dkom_strings)))}"
                ),
                context={
                    "symbols": sorted(set(s for _, s in dkom_strings)),
                    "strings": [s for s, _ in dkom_strings[:5]],
                },
                evidence=[
                    Evidence(
                        type="string",
                        location=".rdata",
                        snippet=dkom_strings[0][0],
                        rule_id="DKOM_SYMBOL",
                    )
                ],
            ))

        # 2. Track DKOM API usage — used as context boost, not standalone finding.
        # These APIs are normal kernel operations; flagging them alone causes
        # false positives on clean drivers that use PsLookupProcessByProcessId,
        # PsGetProcessId, etc. for legitimate process enumeration.
        dkom_apis_used = set()
        for func_addr, api_names in ir.function_apis.items():
            for api in api_names:
                if api in DKOM_APIS:
                    dkom_apis_used.add(api)

        # 3. Check for EPROCESS/ETHREAD offset access in instructions
        eprocess_access = []
        ethread_access = []
        list_entry_access = []

        for func_addr, cfg in (list(ir.cfgs.items()) + list(ir.simple_cfgs.items())):
            for block in cfg.blocks.values():
                for insn in block.instructions:
                    ops = insn.operands.lower()

                    # Only flag write operations to EPROCESS/ETHREAD offsets.
                    # A write is when the destination operand is memory:
                    #   mov [mem], reg  — write (flag)
                    #   mov reg, [mem]  — read  (skip)
                    is_memory_write = self._is_memory_destination(insn)
                    if not is_memory_write:
                        continue
                    for offset, field_name in EPROCESS_OFFSETS.items():
                        if offset == 0:
                            continue  # offset 0x0 matches everything
                        offset_hex = f"0x{offset:x}"
                        if offset_hex in ops or f"+{offset}" in ops:
                            eprocess_access.append({
                                "func": func_addr,
                                "insn": insn.address,
                                "offset": offset,
                                "field": field_name,
                                "instruction": f"{insn.mnemonic} {insn.operands}",
                            })

                    # Check ETHREAD offsets — same write-only policy
                    for offset, field_name in ETHREAD_OFFSETS.items():
                        if offset == 0:
                            continue
                        offset_hex = f"0x{offset:x}"
                        if offset_hex in ops or f"+{offset}" in ops:
                            ethread_access.append({
                                "func": func_addr,
                                "insn": insn.address,
                                "offset": offset,
                                "field": field_name,
                                "instruction": f"{insn.mnemonic} {insn.operands}",
                            })

                    # Check LIST_ENTRY patterns — only flag stores to [reg+0x0]/[reg+0x8]
                    # which represent Flink/Blink writes (actual unlinking).
                    # Reads of [reg+0x0] are normal linked list traversal.
                    if insn.mnemonic.lower() == "mov" and "]" in ops and "," in ops:
                        for pattern in LIST_ENTRY_PATTERNS:
                            if pattern.lower() in ops:
                                list_entry_access.append({
                                    "func": func_addr,
                                    "insn": insn.address,
                                    "pattern": pattern,
                                    "instruction": f"{insn.mnemonic} {insn.operands}",
                                })

        # Report EPROCESS access (process manipulation)
        if eprocess_access:
            # Classify by type of access
            token_writes = [a for a in eprocess_access
                          if a["field"] == "Token" and "mov" in a["instruction"]]
            apl_access = [a for a in eprocess_access
                        if "ActiveProcessLinks" in a["field"]]
            protection_access = [a for a in eprocess_access
                               if "Protection" in a["field"]]

            if apl_access:
                findings.append(Finding(
                    category=FindingCategory.DKOM_PROCESS_UNLINK,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"DKOM: ActiveProcessLinks access detected "
                        f"({len(apl_access)} instructions). "
                        f"Likely process unlinking/hiding."
                    ),
                    function_address=apl_access[0]["func"],
                    instruction_address=apl_access[0]["insn"],
                    context={
                        "access_count": len(apl_access),
                        "functions": list(set(a["func"] for a in apl_access)),
                        "sample_instructions": [a["instruction"] for a in apl_access[:3]],
                    },
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"sub_{apl_access[0]['func']:X}",
                            snippet=apl_access[0]["instruction"],
                            rule_id="DKOM_APL",
                        )
                    ],
                ))

            if token_writes:
                findings.append(Finding(
                    category=FindingCategory.DKOM_TOKEN,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"DKOM: EPROCESS Token field access detected "
                        f"({len(token_writes)} instructions). "
                        f"Likely token swapping/privilege escalation."
                    ),
                    function_address=token_writes[0]["func"],
                    instruction_address=token_writes[0]["insn"],
                    context={
                        "access_count": len(token_writes),
                        "functions": list(set(a["func"] for a in token_writes)),
                        "sample_instructions": [a["instruction"] for a in token_writes[:3]],
                    },
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"sub_{token_writes[0]['func']:X}",
                            snippet=token_writes[0]["instruction"],
                            rule_id="DKOM_TOKEN",
                        )
                    ],
                ))

            if protection_access:
                findings.append(Finding(
                    category=FindingCategory.DKOM_PROCESS_UNLINK,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"DKOM: EPROCESS Protection field access "
                        f"({len(protection_access)} instructions). "
                        f"Likely protected process bypass."
                    ),
                    function_address=protection_access[0]["func"],
                    instruction_address=protection_access[0]["insn"],
                    context={
                        "access_count": len(protection_access),
                        "sample_instructions": [a["instruction"] for a in protection_access[:3]],
                    },
                ))

        # Report ETHREAD access (thread manipulation)
        if ethread_access:
            thread_hide = [a for a in ethread_access
                         if "ActiveThreadListEntry" in a["field"]]
            if thread_hide:
                findings.append(Finding(
                    category=FindingCategory.DKOM_THREAD_UNLINK,
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"DKOM: ETHREAD ActiveThreadListEntry access "
                        f"({len(thread_hide)} instructions). "
                        f"Likely thread hiding."
                    ),
                    function_address=thread_hide[0]["func"],
                    instruction_address=thread_hide[0]["insn"],
                    context={
                        "access_count": len(thread_hide),
                        "sample_instructions": [a["instruction"] for a in thread_hide[:3]],
                    },
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"sub_{thread_hide[0]['func']:X}",
                            snippet=thread_hide[0]["instruction"],
                            rule_id="DKOM_THREAD",
                        )
                    ],
                ))

        # Report LIST_ENTRY manipulation (generic)
        if list_entry_access:
            # Filter out already-captured APL/thread entries
            unique_funcs = set(a["func"] for a in list_entry_access)
            if len(list_entry_access) >= 3:  # Multiple LIST_ENTRY ops suggest DKOM
                findings.append(Finding(
                    category=FindingCategory.DKOM_PROCESS_UNLINK,
                    severity=Severity.HIGH,
                    confidence=Confidence.LOW,
                    description=(
                        f"DKOM: LIST_ENTRY manipulation pattern "
                        f"({len(list_entry_access)} instructions across "
                        f"{len(unique_funcs)} functions). "
                        f"Possible linked list unlinking."
                    ),
                    function_address=min(unique_funcs),
                    context={
                        "instruction_count": len(list_entry_access),
                        "function_count": len(unique_funcs),
                        "patterns": list(set(a["pattern"] for a in list_entry_access[:5])),
                    },
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"sub_{min(unique_funcs):X}",
                            snippet=list_entry_access[0]["instruction"],
                            rule_id="DKOM_LIST_ENTRY",
                        )
                    ],
                ))

        return findings
