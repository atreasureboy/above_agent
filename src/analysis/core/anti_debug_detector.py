"""
DriverScope — Anti-Debug Detector.

Detects active anti-debug / anti-reversing techniques in kernel drivers
at three levels:

1. **API-level**: Calls to NtSetInformationThread(ThreadHideFromDebugger),
   NtClose (invalid handle trap), KdDebuggerEnabled flag checks,
   ObRegisterCallbacks (block debugger attachment), etc.

2. **String-level**: Strings that reveal anti-debug intent:
   "NtGlobalFlag", "KdDebuggerEnabled", "NtSetInformationThread", etc.

3. **Correlation**: When multiple anti-debug signals combine, produce
   a single ANTI_DEBUG_CHAIN finding that represents a coordinated
   anti-debug defense strategy.
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


# ---------------------------------------------------------------------------
# API-based anti-debug detection
# ---------------------------------------------------------------------------

# APIs that directly hide a thread from debuggers
ANTI_DEBUG_HIDE_APIS = {
    "NtSetInformationThread": "ThreadHideFromDebugger (0x11)",
    "ZwSetInformationThread": "ThreadHideFromDebugger (0x11)",
    "NtCreateThreadEx": "CreateHiddenThreadFlag (0x01000000)",
}

# APIs that check for debugger presence
ANTI_DEBUG_DETECT_APIS = {
    "NtQueryInformationProcess": "ProcessDebugPort(0x7)/DebugFlags(0x1F)/DebugObjectHandle(0x1E)",
    "ZwQueryInformationProcess": "ProcessDebugPort/DebugFlags query",
    "NtQueryObject": "Debug object enumeration",
    "ZwQuerySystemInformation": "Process/thread enumeration",
    "ZwQueryInformationThread": "ThreadHideFromDebugger check",
}

# APIs that manipulate debugger objects/state
ANTI_DEBUG_MANIPULATE_APIS = {
    "NtCreateDebugObject": "Create exclusive debug object",
    "NtRemoveProcessDebug": "Detach debugger from process",
    "ZwSystemDebugControl": "Direct debug control",
    "NtSystemDebugControl": "Direct debug control",
    "KdDisableDebugger": "Disable kernel debugger",
    "KdRefreshDebuggerHidden": "Manipulate debugger visibility",
    "KdPowerDispatch": "Power-state debugger manipulation",
}

# APIs that block debugger attachment
ANTI_DEBUG_BLOCK_APIS = {
    "ObRegisterCallbacks": "Block debugger object access",
    "ObUnRegisterCallbacks": "Remove debugger blocking",
    "PsSetCreateProcessNotifyRoutine": "Monitor debugger process creation",
    "PsSetCreateThreadNotifyRoutineEx": "Monitor debugger thread creation",
    "KeRegisterNmiCallback": "NMI callback (debugger interference)",
}

# APIs used as anti-debug traps
ANTI_DEBUG_TRAP_APIS = {
    "NtClose": "Invalid handle trap (STATUS_INVALID_HANDLE)",
    "ZwClose": "Invalid handle trap",
    "NtContinue": "Context manipulation trap",
}


def _check_api_category(
    ir: DisassemblyResult,
    api_dict: dict[str, str],
) -> list[dict]:
    """Scan ir.function_apis for APIs in the given dict.

    Returns list of {func_addr, api_name, technique, instruction_addr} dicts.
    """
    hits = []
    for func_addr, apis in ir.function_apis.items():
        for api in apis:
            base = api.split(".")[-1] if "." in api else api
            if base in api_dict:
                hits.append({
                    "func_addr": func_addr,
                    "api_name": base,
                    "technique": api_dict[base],
                    "instruction_addr": None,  # May be populated from api_details
                })

    # Also check ir.function_api_details for more precise instruction addresses
    for func_addr, details in ir.function_api_details.items():
        for detail in details:
            api_name = getattr(detail, "name", "")
            base = api_name.split(".")[-1] if "." in api_name else api_name
            if base in api_dict:
                for h in hits:
                    if h["func_addr"] == func_addr and h["api_name"] == base:
                        h["instruction_addr"] = getattr(detail, "call_address", None)
                        break

    return hits


def detect_anti_debug_apis(ir: DisassemblyResult) -> list[Finding]:
    """Detect API-based anti-debug techniques."""
    findings: list[Finding] = []

    all_apis = {
        **ANTI_DEBUG_HIDE_APIS,
        **ANTI_DEBUG_DETECT_APIS,
        **ANTI_DEBUG_MANIPULATE_APIS,
        **ANTI_DEBUG_BLOCK_APIS,
        **ANTI_DEBUG_TRAP_APIS,
    }

    hits = _check_api_category(ir, all_apis)

    # Group by technique category
    grouped: dict[str, list[dict]] = {}
    for hit in hits:
        # Determine category
        if hit["api_name"] in ANTI_DEBUG_HIDE_APIS:
            cat = "Hide from debugger"
        elif hit["api_name"] in ANTI_DEBUG_DETECT_APIS:
            cat = "Detect debugger"
        elif hit["api_name"] in ANTI_DEBUG_MANIPULATE_APIS:
            cat = "Manipulate debugger"
        elif hit["api_name"] in ANTI_DEBUG_BLOCK_APIS:
            cat = "Block debugger"
        elif hit["api_name"] in ANTI_DEBUG_TRAP_APIS:
            cat = "Anti-debug trap"
        else:
            cat = "Unknown"

        grouped.setdefault(cat, []).append(hit)

    for category, cat_hits in grouped.items():
        api_names = [h["api_name"] for h in cat_hits]
        techniques = [h["technique"] for h in cat_hits]
        func_addrs = list({h["func_addr"] for h in cat_hits})

        severity = Severity.CRITICAL if "Hide" in category else Severity.HIGH
        confidence = Confidence.HIGH if len(cat_hits) >= 2 else Confidence.MEDIUM

        desc = (
            f"Anti-debug API calls detected ({category}): "
            f"{', '.join(api_names)}. "
            f"Techniques: {', '.join(techniques)}."
        )

        findings.append(
            Finding(
                category=FindingCategory.ANTI_DEBUG_SYSTEM_FLAG,
                severity=severity,
                confidence=confidence,
                description=desc,
                function_address=func_addrs[0] if func_addrs else 0,
                context={
                    "anti_debug_category": category,
                    "api_names": api_names,
                    "techniques": techniques,
                    "function_addresses": [hex(a) for a in func_addrs],
                    "count": len(cat_hits),
                },
                evidence=[
                    Evidence(
                        type="api_match",
                        location=f"sub_{func_addrs[0]:X}" if func_addrs else "unknown",
                        snippet=", ".join(api_names),
                        rule_id="ANTI_DEBUG_API",
                    )
                ],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# String-level anti-debug detection
# ---------------------------------------------------------------------------

ANTI_DEBUG_STRINGS = {
    # Kernel debugger flags
    r"\bKdDebuggerEnabled\b": "Kernel debugger enabled flag check",
    r"\bKdPitchDebugger\b": "Debugger disabled at boot",
    r"\bKdDebuggerNotPresent\b": "Debugger not present flag",
    # NtGlobalFlag
    r"\bNtGlobalFlag\b": "NtGlobalFlag anti-debug check",
    r"\bg_dwNtGlobalFlag\b": "NtGlobalFlag global variable",
    # Heap flags
    r"\bHeapFlags\b": "Heap anti-debug flag check",
    r"\bForceFlags\b": "Heap ForceFlags anti-debug",
    # Debugger device
    r"\\\.\\ntice": "SoftICE debugger device",
    r"\\\.\\SiwVID": "SiWVID debugger device",
    r"\\\.\\SICE": "SICE debugger device",
    r"\\\.\\TRW": "TRW debugger device",
    r"\\\.\\OllyICE": "OllyICE debugger device",
    r"\\\.\\XPtrace": "XPtrace debugger device",
    # Debug object
    r"\b\\DebugObject\\": "Debug object path",
    r"\bNtDebugActiveProcess\b": "Active debugger check",
    # Hypervisor / VM
    r"\bVBoxMouse\b": "VirtualBox detection",
    r"\bVMware\b": "VMware detection",
    r"\bVirtualBox\b": "VirtualBox detection",
    r"\bVPC\b": "VirtualPC detection",
    # Anti-debug registry keys
    r"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Debug Print Filter": "Debug print filter registry",
    r"MachineDebugManager": "JIT debugger check",
}


def detect_anti_debug_strings(ir: DisassemblyResult) -> list[Finding]:
    """Detect anti-debug related strings in the binary."""
    findings: list[Finding] = []
    hits: list[tuple[str, str]] = []  # (pattern, matched_string)

    for s in getattr(ir, "strings", []):
        for pattern, description in ANTI_DEBUG_STRINGS.items():
            if re.search(pattern, s, re.IGNORECASE):
                hits.append((s, description))

    if not hits:
        return findings

    # Deduplicate by description
    seen = set()
    unique_hits = []
    for s, desc in hits:
        if desc not in seen:
            seen.add(desc)
            unique_hits.append((s, desc))

    matched_strings = [h[0] for h in unique_hits]
    descriptions = [h[1] for h in unique_hits]

    findings.append(
        Finding(
            category=FindingCategory.DANGEROUS_STRING,
            severity=Severity.HIGH if len(unique_hits) >= 3 else Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description=(
                f"Anti-debug strings detected: {', '.join(descriptions)}. "
                f"Matched: {', '.join(matched_strings[:10])}."
            ),
            context={
                "anti_debug_strings": matched_strings,
                "techniques": descriptions,
                "count": len(unique_hits),
            },
            evidence=[
                Evidence(
                    type="string",
                    location="binary strings",
                    snippet=", ".join(matched_strings[:5]),
                    rule_id="ANTI_DEBUG_STR",
                )
            ],
        )
    )

    return findings


# ---------------------------------------------------------------------------
# Anti-debug correlation
# ---------------------------------------------------------------------------

def correlate_anti_debug(
    api_findings: list[Finding],
    string_findings: list[Finding],
    instruction_findings: list[Finding],
) -> list[Finding]:
    """Correlate multiple anti-debug signals into a chain finding.

    A single anti-debug instruction (e.g., RDTSC) is a weak signal.
    But RDTSC + ThreadHideFromDebugger + NtGlobalFlag + ObRegisterCallbacks
    = coordinated anti-debug defense strategy.

    Correlation levels:
    - 1 signal: no chain
    - 2 signals: LOW confidence chain
    - 3+ signals: MEDIUM confidence chain
    - 5+ signals or hide+block+detect: HIGH confidence chain
    """
    total_signals = len(api_findings) + len(string_findings) + len(instruction_findings)

    if total_signals < 2:
        return []

    # Collect all techniques
    all_techniques: list[str] = []
    for f in api_findings:
        all_techniques.extend(f.context.get("techniques", []))
    for f in string_findings:
        all_techniques.extend(f.context.get("techniques", []))
    for f in instruction_findings:
        all_techniques.append(f.context.get("rule_id", f.description[:50]))

    # Determine confidence
    has_hide = any("Hide" in t for t in all_techniques)
    has_detect = any("Detect" in t for t in all_techniques)
    has_block = any("Block" in t for t in all_techniques)
    has_manipulate = any("Manipulate" in t for t in all_techniques)

    if total_signals >= 5 or (has_hide and has_block and has_detect):
        confidence = Confidence.HIGH
        severity = Severity.CRITICAL
    elif total_signals >= 3:
        confidence = Confidence.MEDIUM
        severity = Severity.HIGH
    else:
        confidence = Confidence.LOW
        severity = Severity.MEDIUM

    return [
        Finding(
            category=FindingCategory.ANTI_DEBUG_TIMING,
            severity=severity,
            confidence=confidence,
            description=(
                f"Coordinated anti-debug defense: {total_signals} signals detected. "
                f"Techniques: {', '.join(set(all_techniques[:10]))}. "
                f"This driver actively attempts to prevent debugging and analysis."
            ),
            context={
                "chain_type": "anti_debug_correlated",
                "signal_count": total_signals,
                "api_signals": len(api_findings),
                "string_signals": len(string_findings),
                "instruction_signals": len(instruction_findings),
                "has_hide_from_debugger": has_hide,
                "has_detect_debugger": has_detect,
                "has_block_debugger": has_block,
                "has_manipulate_debugger": has_manipulate,
                "techniques": all_techniques,
            },
            evidence=[
                Evidence(
                    type="correlation",
                    location="multiple sources",
                    snippet=f"{total_signals} anti-debug signals correlated",
                    rule_id="ANTI_DEBUG_CHAIN",
                )
            ],
        )
    ]


def run_anti_debug_analysis(
    sample: Sample,
    ir: DisassemblyResult,
    instruction_findings: list[Finding] | None = None,
) -> list[Finding]:
    """Run the complete anti-debug analysis pipeline.

    1. Detect API-based anti-debug
    2. Detect string-based anti-debug
    3. Correlate with instruction-level findings (from SemanticAnalyzer)

    Returns combined findings list.
    """
    findings: list[Finding] = []

    api_findings = detect_anti_debug_apis(ir)
    string_findings = detect_anti_debug_strings(ir)

    findings.extend(api_findings)
    findings.extend(string_findings)

    # Correlate if we have instruction findings
    if instruction_findings is not None:
        ad_instruction = [
            f for f in instruction_findings
            if f.category.value.startswith("anti_debug")
        ]
        chain_findings = correlate_anti_debug(api_findings, string_findings, ad_instruction)
        findings.extend(chain_findings)

    return findings
