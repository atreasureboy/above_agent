"""
DriverScope — DSE Bypass & PatchGuard Trigger Detector.

Detects driver-level techniques that bypass Driver Signature Enforcement (DSE)
or trigger/modify PatchGuard (Kernel Patch Protection, KPP):

1. **DSE Bypass**: Modification of g_CiOptions variable, CiInitialize calls,
   test signing enforcement, SepInitializeCodeIntegrity manipulation,
   CI.dll function abuse, HVCI bypass patterns.

2. **PatchGuard Trigger**: KiSystemCall64 hook preparation, KiDebugRoutine
   modification, KeBugCheckEx/KeBugCheckWithTfCallback calls, PatchGuard
   context structure references, KdPitchDebugger modification.

3. **ETW Bypass**: Etwp* API manipulation, EtwThreatIntProvRegHandle access,
   ETW provider unregistration, ETW buffer manipulation.

4. **KPP Callback Disable**: Disabling kernel protection callbacks,
   CmRegisterCallbackEx bypass, PsSetCreateProcessNotifyRoutine removal.

Detection strategy:
- String-level: Known variable names, function names, structure references
- API-level: Calls to CI.dll, ntoskrnl DSE/PG functions
- Instruction-level: RIP-relative writes to known DSE variables
- Pattern-level: BugCheck sequences, ETW disable sequences
"""

from __future__ import annotations

import re

from src.models import (
    Confidence, DisassemblyResult, Evidence, Finding, FindingCategory,
    Sample, Severity,
)
from src.analysis.analyzer import Analyzer


# ---------------------------------------------------------------------------
# 1. DSE Bypass Detection
# ---------------------------------------------------------------------------

# g_CiOptions is the primary DSE control variable (CI.dll, Win10+).
# Values: 0x0 = enforce, 0x6 = disable (test signing off)
DSE_STRINGS = {
    # Primary DSE variables
    "g_CiOptions": "Primary DSE enforcement variable (CI.dll)",
    "CiOptions": "DSE enforcement variable (alternate name)",
    "CiInitialize": "CI.dll initialization function",
    "CiIsEnabled": "Code integrity status check",
    "CiValidateImageHeader": "Image validation function (bypass target)",
    "CiGetPEInformation": "PE info extraction from CI.dll",
    # SEP (Security Enhancement Provider) functions
    "SepInitializeCodeIntegrity": "Kernel code integrity init",
    "SepValidateCodeIntegrity": "Code integrity validation",
    "SepSetCodeIntegrityPolicy": "CI policy modification",
    "SepFreeCodeIntegrityPolicy": "CI policy removal",
    # DSE-related imports
    "MmVerifyDriverObject": "Driver verification (DSE context)",
    "MmIsDriverVerifierEnabled": "Verifier status check",
    # HVCI / VBS bypass indicators
    "HviIsAnyHypervisorPresent": "Hypervisor presence check (VBS/HVCI)",
    "HvlGetVpRegisters": "Virtual processor registers (VBS bypass)",
    # Test signing
    "TESTSIGNING": "Test signing mode reference",
    "codesigning": "Code signing reference",
    "Driver Signature Enforcement": "DSE full string reference",
}

# APIs commonly used in DSE bypass drivers
DSE_APIS = {
    "ZwSetSystemInformation": "System information set (can disable DSE)",
    "NtSetSystemInformation": "System information set (user-mode bridge)",
    "ZwQuerySystemInformation": "System information query (recon)",
    "ZwLoadDriver": "Driver load (bypass loading unsigned driver)",
    "ZwUnloadDriver": "Driver unload (cleanup after bypass)",
}

# Instruction patterns that indicate DSE bypass
# Writing to g_CiOptions: mov [rip+offset], <value>
DSE_INSTRUCTION_PATTERNS = [
    # Write to RIP-relative variable (likely g_CiOptions)
    (r"mov\s+(?:dword|qword)\s+ptr\s+\[rip\+0x[0-9a-f]+\],\s*(?:0x[0-9a-f]+|\d+)",
     "write_ripglobal", "Write immediate to RIP-relative global variable"),
    # Load address of global variable
    (r"lea\s+r[a-z0-9]+,\s*\[rip\+0x[0-9a-f]+\]",
     "load_ripglobal", "Load RIP-relative global variable address"),
    # XOR to clear (often used to set CiOptions = 0)
    (r"xor\s+(?:eax|edx),\s*(?:eax|edx)$",
     "xor_clear", "Register zeroing (common before writing to DSE variable)"),
]


def detect_dse_bypass(ir: DisassemblyResult) -> list[Finding]:
    """Detect DSE (Driver Signature Enforcement) bypass patterns."""
    findings: list[Finding] = []

    # 1. String-level detection
    dse_strings_found: list[tuple[str, str]] = []
    for s in ir.strings:
        for pattern, desc in DSE_STRINGS.items():
            if pattern.lower() in s.lower():
                dse_strings_found.append((s, desc))

    # 2. API-level detection
    dse_api_funcs: list[tuple[int, list[str]]] = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in DSE_APIS]
        if matched:
            dse_api_funcs.append((func_addr, matched))

    # 3. Instruction-level: functions with DSE-like patterns
    dse_inst_funcs: list[tuple[int, list[tuple[str, str]]]] = []
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        func_signals = []
        for block in cfg.blocks.values():
            for insn in block.instructions:
                full = f"{insn.mnemonic} {insn.operands}".strip()
                for pattern, ptype, desc in DSE_INSTRUCTION_PATTERNS:
                    if re.match(pattern, full, re.IGNORECASE):
                        func_signals.append((ptype, desc))
                        break

        if func_signals:
            dse_inst_funcs.append((func_addr, func_signals))

    if not dse_strings_found and not dse_api_funcs and not dse_inst_funcs:
        return findings

    # Severity: CRITICAL if strings + instructions (active bypass), HIGH otherwise
    has_strings = len(dse_strings_found) > 0
    has_instructions = len(dse_inst_funcs) > 0
    has_apis = len(dse_api_funcs) > 0

    if has_strings and has_instructions:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_strings or has_apis:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    string_names = list({s for s, _ in dse_strings_found})
    techniques = list({desc for _, desc in dse_strings_found})

    findings.append(Finding(
        category=FindingCategory.DSE_BYPASS,
        severity=severity,
        confidence=confidence,
        description=(
            f"DSE bypass indicators: {len(string_names)} strings, "
            f"{len(dse_api_funcs)} functions with DSE APIs, "
            f"{len(dse_inst_funcs)} functions with suspicious instruction patterns. "
            f"This driver may bypass Driver Signature Enforcement. "
            f"Key strings: {', '.join(string_names[:5])}."
        ),
        context={
            "dse_strings": string_names,
            "techniques": techniques,
            "dse_api_functions": [
                {"address": hex(a), "apis": apis} for a, apis in dse_api_funcs
            ],
            "dse_instruction_functions": [
                {"address": hex(a), "signals": s} for a, s in dse_inst_funcs
            ],
            "has_g_cioptions": any("g_CiOptions" in s for s, _ in dse_strings_found),
            "has_testsigning": any("TESTSIGNING" in s.upper() for s, _ in dse_strings_found),
        },
        evidence=[
            Evidence(
                type="string" if has_strings else "instruction_pattern",
                location="binary strings" if has_strings else "instruction stream",
                snippet=string_names[0] if string_names else "DSE bypass pattern",
                rule_id="DSE_BYPASS",
            )
        ],
    ))

    return findings


# ---------------------------------------------------------------------------
# 2. PatchGuard Trigger Detection
# ---------------------------------------------------------------------------

PATCHGUARD_STRINGS = {
    # PatchGuard context structures
    "KeBugCheckEx": "BugCheck API (PatchGuard trigger)",
    "KeBugCheckWithTfCallback": "BugCheck with thread frame callback",
    "KiSystemCall64": "System call entry point (PatchGuard protected)",
    "KiDebugRoutine": "Kernel debug routine (PatchGuard target)",
    "KdPitchDebugger": "Debugger pitch flag (anti-debug + PG trigger)",
    "KdDebuggerEnabled": "Debugger enabled flag",
    "KiServiceTable": "SSDT internal reference (PatchGuard protected)",
    "PspCidTable": "CID table (PatchGuard protected structure)",
    "ExpInitialThreadStart": "Initial thread start (PG context)",
    "KiScbQueueEnable": "System call batch queue (PG protected)",
    "PatchGuard": "Explicit PatchGuard reference",
    "KPP": "Kernel Patch Protection abbreviation",
    "Kernel Patch Protection": "Full PatchGuard name",
    "PgContext": "PatchGuard context structure",
    "KiProcessInpcetionPatch": "PG inspection patch reference",
}

# PatchGuard-related APIs
PATCHGUARD_APIS = {
    "KeBugCheckEx": "System bug check (PatchGuard trigger)",
    "KeBugCheckWithTfCallback": "BugCheck with callback",
    "KeRegisterBugCheckCallback": "Register bug check callback",
    "KeDeregisterBugCheckCallback": "Deregister bug check callback",
    "KeBugCheck": "System bug check",
    "RtlCaptureContext": "Context capture (PG crash dump)",
    "RtlRestoreContext": "Context restore (PG manipulation)",
    "KeSetKernelStackSwapEnable": "Kernel stack swap (PG sensitive)",
    "KiUnexpectedRange2Start": "PatchGuard internal symbol",
    "KiVerifyScopesExecute": "PatchGuard verification function",
}

# Instruction patterns indicating PatchGuard interaction
PATCHGUARD_INSTRUCTION_PATTERNS = [
    # BugCheck: push bugcode, call KeBugCheckEx
    (r"call\s+(?:KeBugCheckEx|KeBugCheckWithTfCallback|KeBugCheck)",
     "bugcheck_call", "Direct call to BugCheck API"),
    # Write to global debug variable (KdPitchDebugger, KdDebuggerEnabled)
    (r"mov\s+(?:byte|dword)\s+ptr\s+\[rip\+0x[0-9a-f]+\],\s*(?:0x[0-9a-f]+|\d+)",
     "write_global_flag", "Write to RIP-relative global flag (possible Kd* variable)"),
    # Context capture (PG crash context)
    (r"(push|pop)\s+(r[a-z0-9]+)",
     "context_save", "Register save/restore (context capture for PG)"),
]

# Bug check codes related to PatchGuard / security violations
PATCHGUARD_BUGCHECK_CODES = {
    0x00000032: "MODULE_INITIALIZATION_FAILED",
    0x000000C9: "DRIVER_VERIFIER_DETECTED_VIOLATION",
    0x000000D1: "DRIVER_IRQL_NOT_LESS_OR_EQUAL",
    0x00000109: "CRITICAL_STRUCTURE_CORRUPTION",  # PatchGuard classic
    0x0000010B: "ATTEMPTED_SWITCH_FROM_DPC",
    0x00000122: "WHEA_UNCORRECTABLE_ERROR",
    0x00000132: "SECURE_KERNEL_ERROR",
    0x00000190: "KERNEL_SECURITY_CHECK_FAILURE",
}


def detect_patchguard_trigger(ir: DisassemblyResult) -> list[Finding]:
    """Detect PatchGuard (KPP) trigger patterns."""
    findings: list[Finding] = []

    # 1. String-level
    pg_strings_found: list[tuple[str, str]] = []
    for s in ir.strings:
        for pattern, desc in PATCHGUARD_STRINGS.items():
            if pattern.lower() in s.lower():
                pg_strings_found.append((s, desc))

    # 2. API-level
    pg_api_funcs: list[tuple[int, list[str]]] = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in PATCHGUARD_APIS]
        if matched:
            pg_api_funcs.append((func_addr, matched))

    # 3. Bug check code references (immediate values)
    bugcheck_codes_found: list[int] = []
    for func_addr, cfg in (list(ir.cfgs.items()) + list(ir.simple_cfgs.items())):
        for block in cfg.blocks.values():
            for insn in block.instructions:
                ops = insn.operands.lower()
                # Look for push <bugcheck_code> before KeBugCheckEx call
                if insn.mnemonic.lower() == "push":
                    try:
                        code = int(ops.replace("0x", ""), 16)
                        if code in PATCHGUARD_BUGCHECK_CODES:
                            bugcheck_codes_found.append(code)
                    except (ValueError, AttributeError):
                        pass

    if not pg_strings_found and not pg_api_funcs and not bugcheck_codes_found:
        return findings

    # Severity scoring
    has_explicit_pg = any("PatchGuard" in s or "KPP" in s or "Kernel Patch" in s
                         for s, _ in pg_strings_found)
    has_bugcheck = len(pg_api_funcs) > 0
    has_structural_corruption = any(
        code == 0x00000109 for code in bugcheck_codes_found
    )

    if has_explicit_pg or has_structural_corruption:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_bugcheck and pg_strings_found:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    string_names = list({s for s, _ in pg_strings_found})

    findings.append(Finding(
        category=FindingCategory.PATCHGUARD_TRIGGER,
        severity=severity,
        confidence=confidence,
        description=(
            f"PatchGuard trigger indicators: {len(string_names)} strings, "
            f"{len(pg_api_funcs)} functions with PG-related APIs, "
            f"{len(bugcheck_codes_found)} bug check code references. "
            f"This driver may trigger or interact with Kernel Patch Protection. "
            f"Key references: {', '.join(string_names[:5])}."
        ),
        context={
            "patchguard_strings": string_names,
            "patchguard_api_functions": [
                {"address": hex(a), "apis": apis} for a, apis in pg_api_funcs
            ],
            "bugcheck_codes": [
                {"code": hex(c), "name": PATCHGUARD_BUGCHECK_CODES.get(c, "UNKNOWN")}
                for c in bugcheck_codes_found
            ],
            "has_explicit_patchguard_ref": has_explicit_pg,
            "has_critical_structure_corruption": has_structural_corruption,
        },
        evidence=[
            Evidence(
                type="string",
                location="binary strings",
                snippet=string_names[0] if string_names else "PatchGuard pattern",
                rule_id="PATCHGUARD_TRIGGER",
            )
        ],
    ))

    return findings


# ---------------------------------------------------------------------------
# 3. ETW Bypass Detection
# ---------------------------------------------------------------------------

ETW_STRINGS = {
    # ETW provider/handle names
    "EtwThreatIntProvRegHandle": "ETW threat intel provider handle",
    "EtwProvHandle": "ETW provider handle",
    "EtwKernelLoggerContext": "ETW kernel logger context",
    "Etwp": "ETW internal prefix (Etwp = ETW Provider)",
    "EtwRegistration": "ETW registration structure",
    "EtwBufferCallback": "ETW buffer callback",
    "EtwDisable": "ETW disable reference",
    "EtwUnregister": "ETW unregistration",
    "ThreatIntel": "Threat intelligence ETW provider",
    "SecurityAudit": "Security audit ETW provider",
}

ETW_APIS = {
    "EtwUnregister": "ETW provider unregistration",
    "EtwSetInformation": "ETW information set (can disable logging)",
    "EtwWriteTransfer": "ETW write with transfer (log manipulation)",
    "EtwTraceKernelEvent": "Kernel event trace (can suppress)",
    "EtwWriteUMSecurityEvent": "User-mode security event (can suppress)",
    "EtwpRegisterProvider": "ETW provider registration (internal)",
    "EtwpUnregisterProvider": "ETW provider unregistration (internal)",
    "EtwpStartTrace": "ETW trace start",
    "EtwpStopTrace": "ETW trace stop (disable logging)",
    "EtwNotificationUnregister": "ETW notification unregistration",
    "NtTraceEvent": "NT trace event (ETW user-mode bridge)",
    "NtTraceControl": "NT trace control (ETW configuration)",
    "ZwTraceEvent": "Zw trace event",
    "ZwTraceControl": "Zw trace control",
}

# ETW disable patterns: disabling providers, stopping traces
ETW_DISABLE_PATTERNS = [
    # Call to unregistration API
    (r"call\s+(?:EtwUnregister|EtwpUnregisterProvider|EtwNotificationUnregister)",
     "etw_unregister", "ETW provider unregistration"),
    # Write to ETW handle (possibly NULL to disable)
    (r"mov\s+qword\s+ptr\s+\[rip\+0x[0-9a-f]+\],\s*(?:0x0|rdx|rax)",
     "nullify_etw_handle", "Nullifying ETW handle via RIP-relative write"),
    # Stop trace: call EtwpStopTrace
    (r"call\s+EtwpStopTrace",
     "etw_stop_trace", "ETW trace stop call"),
]


def detect_etw_bypass(ir: DisassemblyResult) -> list[Finding]:
    """Detect ETW (Event Tracing for Windows) bypass patterns."""
    findings: list[Finding] = []

    # 1. String-level
    etw_strings_found: list[tuple[str, str]] = []
    for s in ir.strings:
        for pattern, desc in ETW_STRINGS.items():
            if pattern.lower() in s.lower():
                etw_strings_found.append((s, desc))

    # 2. API-level
    etw_api_funcs: list[tuple[int, list[str]]] = []
    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in ETW_APIS]
        if matched:
            etw_api_funcs.append((func_addr, matched))

    # 3. Instruction-level: ETW disable patterns
    etw_inst_funcs: list[tuple[int, list[tuple[str, str]]]] = []
    for func_addr, func in ir.functions.items():
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if cfg is None:
            continue

        func_signals = []
        for block in cfg.blocks.values():
            for insn in block.instructions:
                full = f"{insn.mnemonic} {insn.operands}".strip()
                for pattern, ptype, desc in ETW_DISABLE_PATTERNS:
                    if re.match(pattern, full, re.IGNORECASE):
                        func_signals.append((ptype, desc))
                        break

        if func_signals:
            etw_inst_funcs.append((func_addr, func_signals))

    if not etw_strings_found and not etw_api_funcs and not etw_inst_funcs:
        return findings

    # Severity: CRITICAL if explicit disable patterns, HIGH if strings/APIs only
    has_disable = len(etw_inst_funcs) > 0
    has_threat_intel = any("ThreatIntel" in s or "EtwThreatInt" in s
                          for s, _ in etw_strings_found)

    if has_disable and has_threat_intel:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif has_disable or has_threat_intel:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    string_names = list({s for s, _ in etw_strings_found})

    findings.append(Finding(
        category=FindingCategory.ETW_BYPASS,
        severity=severity,
        confidence=confidence,
        description=(
            f"ETW bypass indicators: {len(string_names)} strings, "
            f"{len(etw_api_funcs)} functions with ETW APIs, "
            f"{len(etw_inst_funcs)} functions with ETW disable patterns. "
            f"This driver may disable Event Tracing for Windows. "
            f"Key references: {', '.join(string_names[:5])}."
        ),
        context={
            "etw_strings": string_names,
            "etw_api_functions": [
                {"address": hex(a), "apis": apis} for a, apis in etw_api_funcs
            ],
            "etw_disable_functions": [
                {"address": hex(a), "signals": s} for a, s in etw_inst_funcs
            ],
            "has_threat_intel_bypass": has_threat_intel,
            "has_explicit_disable": has_disable,
        },
        evidence=[
            Evidence(
                type="string" if etw_strings_found else "instruction_pattern",
                location="binary strings" if etw_strings_found else "instruction stream",
                snippet=string_names[0] if string_names else "ETW bypass pattern",
                rule_id="ETW_BYPASS",
            )
        ],
    ))

    return findings


# ---------------------------------------------------------------------------
# 4. KPP Callback Disable Detection
# ---------------------------------------------------------------------------

KPP_CALLBACK_STRINGS = {
    # Callback registration/deregistration
    "PsSetCreateProcessNotifyRoutine": "Process creation callback (disable = hide processes)",
    "PsSetCreateThreadNotifyRoutine": "Thread creation callback",
    "PsSetLoadImageNotifyRoutine": "Image load notification callback",
    "PsRemoveCreateThreadNotifyRoutine": "Thread notify removal",
    "PsRemoveLoadImageNotifyRoutine": "Image load notify removal",
    "CmRegisterCallbackEx": "Registry callback (KPP protected)",
    "CmUnRegisterCallback": "Registry callback removal",
    "ObRegisterCallbacks": "Object callback registration",
    "ObUnRegisterCallbacks": "Object callback removal",
    "PsSetCreateProcessNotifyRoutineEx": "Extended process notify",
}

KPP_CALLBACK_APIS = {
    "PsSetCreateProcessNotifyRoutine": "Process creation notification",
    "PsSetCreateProcessNotifyRoutineEx": "Process creation notification (extended)",
    "PsSetCreateThreadNotifyRoutine": "Thread creation notification",
    "PsSetLoadImageNotifyRoutine": "Image load notification",
    "PsRemoveCreateThreadNotifyRoutine": "Remove thread notification",
    "PsRemoveLoadImageNotifyRoutine": "Remove image load notification",
    "CmRegisterCallbackEx": "Registry callback registration",
    "CmUnRegisterCallback": "Registry callback removal",
    "ObRegisterCallbacks": "Object callback registration",
    "ObUnRegisterCallbacks": "Object callback removal",
    "PsSetImageNotifyVersion": "Image notify version set",
    "PsSetCreateProcessNotifyRoutineEx2": "Process notify v2",
}


def detect_kpp_callback_disable(ir: DisassemblyResult) -> list[Finding]:
    """Detect KPP-protected callback disable patterns."""
    findings: list[Finding] = []

    # 1. String-level
    kpp_strings_found: list[tuple[str, str]] = []
    for s in ir.strings:
        for pattern, desc in KPP_CALLBACK_STRINGS.items():
            if pattern.lower() in s.lower():
                kpp_strings_found.append((s, desc))

    # 2. API-level: focus on *Remove* APIs (deregistration = disable)
    kpp_api_funcs: list[tuple[int, list[str]]] = []
    remove_apis = {"PsRemoveCreateThreadNotifyRoutine", "PsRemoveLoadImageNotifyRoutine",
                   "CmUnRegisterCallback", "ObUnRegisterCallbacks"}

    for func_addr, api_names in ir.function_apis.items():
        matched = [api for api in api_names if api in KPP_CALLBACK_APIS]
        if matched:
            kpp_api_funcs.append((func_addr, matched))

    # Functions specifically using remove/unregister APIs
    remove_funcs = [
        (addr, apis) for addr, apis in kpp_api_funcs
        if any(api in remove_apis for api in apis)
    ]

    if not kpp_strings_found and not kpp_api_funcs:
        return findings

    # Severity: CRITICAL if explicit remove/unregister APIs, HIGH if general callbacks
    has_remove = len(remove_funcs) > 0

    if has_remove:
        severity = Severity.CRITICAL
        confidence = Confidence.HIGH
    elif kpp_api_funcs:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
    else:
        severity = Severity.MEDIUM
        confidence = Confidence.LOW

    string_names = list({s for s, _ in kpp_strings_found})
    remove_api_names = list({api for _, apis in remove_funcs for api in apis if api in remove_apis})

    findings.append(Finding(
        category=FindingCategory.KPP_CALLBACK_DISABLE,
        severity=severity,
        confidence=confidence,
        description=(
            f"KPP callback disable indicators: {len(string_names)} strings, "
            f"{len(kpp_api_funcs)} functions with callback APIs, "
            f"{len(remove_funcs)} functions with explicit callback removal. "
            f"This driver may disable kernel protection callbacks. "
            f"Removal APIs: {', '.join(remove_api_names[:5]) if remove_api_names else 'none detected'}."
        ),
        context={
            "callback_strings": string_names,
            "callback_api_functions": [
                {"address": hex(a), "apis": apis} for a, apis in kpp_api_funcs
            ],
            "callback_remove_functions": [
                {"address": hex(a), "apis": apis} for a, apis in remove_funcs
            ],
            "removes_process_notify": any(
                "PsSetCreateProcessNotifyRoutine" in api or "PsRemoveCreateThreadNotifyRoutine" in api
                for _, apis in remove_funcs for api in apis
            ),
            "removes_registry_callback": any(
                "CmUnRegisterCallback" in api for _, apis in remove_funcs for api in apis
            ),
        },
        evidence=[
            Evidence(
                type="api_match",
                location="function imports",
                snippet=remove_api_names[0] if remove_api_names else "callback disable pattern",
                rule_id="KPP_CALLBACK_DISABLE",
            )
        ],
    ))

    return findings


# ---------------------------------------------------------------------------
# DSEPgAnalyzer — Main plugin
# ---------------------------------------------------------------------------

class DSEPgAnalyzer(Analyzer):
    """Detects DSE bypass, PatchGuard trigger, ETW bypass,
    and KPP callback disable patterns in drivers."""

    @property
    def name(self) -> str:
        return "DSEPgAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Detects DSE bypass (g_CiOptions, CI.dll), PatchGuard trigger "
            "(KiSystemCall64, KeBugCheckEx), ETW bypass (Etwp* APIs), "
            "and KPP callback disable (PsRemove*, CmUnRegisterCallback) patterns."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. DSE bypass detection
        findings.extend(detect_dse_bypass(ir))

        # 2. PatchGuard trigger detection
        findings.extend(detect_patchguard_trigger(ir))

        # 3. ETW bypass detection
        findings.extend(detect_etw_bypass(ir))

        # 4. KPP callback disable detection
        findings.extend(detect_kpp_callback_disable(ir))

        return findings
