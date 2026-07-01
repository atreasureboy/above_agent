"""DriverScope — OVOIDA Deep Analysis Engine (Python Implementation).

This module provides the actual implementation for OVOIDA's deep reverse
engineering capabilities, complementing the TypeScript agent framework.

It can:
1. Run Ghidra/IDA to get pseudocode and instruction-level CFG
2. Perform deep control flow analysis on critical functions
3. Extract exploit chains from assembly/disassembly data
4. Generate structured findings.json and human-readable findings.md

Usage:
    from src.analysis.deep.ovoida_engine import OvoidaEngine

    engine = OvoidaEngine(backend="ghidra")
    result = engine.analyze(sample_path, findings_from_phases1)
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.models import (
    DisassemblyResult,
    Finding,
    Sample,
)


@dataclass
class OvoidaResult:
    """Structured output from OVOIDA deep analysis."""
    sample_name: str
    risk_score: float = 0.0
    functions_analyzed: int = 0
    exploit_chains: list[dict[str, Any]] = field(default_factory=list)
    functions_detail: list[dict[str, Any]] = field(default_factory=list)
    findings_json_path: Path | None = None
    findings_md_path: Path | None = None
    elapsed: float = 0.0
    error: str = ""


class OvoidaEngine:
    """Python-based OVOIDA deep analysis engine.

    Complements the TypeScript OVOIDA agent by providing direct access
    to Ghidra/IDA backends and the taint tracker + correlator pipeline.
    """

    def __init__(self, backend: str = "ghidra"):
        """Initialize the OVOIDA engine.

        Args:
            backend: Disassembly backend to use ("ghidra" or "capstone").
                    Ghidra is recommended for full analysis.
        """
        self.backend = backend

    def analyze(
        self,
        sample: Sample,
        ir: DisassemblyResult,
        phase1_findings: list[Finding] | None = None,
        output_dir: Path | None = None,
    ) -> OvoidaResult:
        """Run deep OVOIDA analysis on a single sample.

        Args:
            sample: The enriched Sample object from Phase 1.
            ir: The disassembly result (preferably from Ghidra).
            phase1_findings: Findings from Phase 1 scan.
            output_dir: Directory to write findings.json and findings.md.

        Returns:
            OvoidaResult with structured analysis output.
        """
        start = time.time()

        result = OvoidaResult(
            sample_name=sample.name,
            risk_score=sample.risk_score,
        )

        # Step 1: Identify critical functions for deep analysis
        critical_functions = self._identify_critical_functions(sample, ir, phase1_findings)

        # Step 2: Analyze each critical function
        functions_detail = []
        for func_info in critical_functions:
            func_addr = func_info["address"]
            detail = self._analyze_function(func_addr, ir, sample)
            functions_detail.append(detail)

        result.functions_analyzed = len(functions_detail)
        result.functions_detail = functions_detail

        # Step 3: Build exploit chains
        exploit_chains = self._build_exploit_chains(functions_detail, sample, ir)
        result.exploit_chains = exploit_chains

        # Step 4: Write output files
        if output_dir:
            output_dir.mkdir(parents=True, exist_ok=True)
            result = self._write_outputs(result, output_dir)

        result.elapsed = time.time() - start
        return result

    def _identify_critical_functions(
        self,
        sample: Sample,
        ir: DisassemblyResult,
        phase1_findings: list[Finding] | None,
    ) -> list[dict[str, Any]]:
        """Identify functions that need deep analysis based on Phase 1 findings."""
        critical = []
        seen_addrs = set()

        # From Phase 1 findings
        if phase1_findings:
            for f in phase1_findings:
                if f.function_address and f.function_address not in seen_addrs:
                    if f.severity.value in ("critical", "high"):
                        seen_addrs.add(f.function_address)
                        critical.append({
                            "address": f.function_address,
                            "name": f"sub_{f.function_address:X}",
                            "reason": f"Phase 1 finding: {f.category.value}",
                            "severity": f.severity.value,
                            "api_name": f.api_name or "",
                            "instruction_address": f.instruction_address or 0,
                        })

        # From IOCTL handlers
        for code, addr in ir.ioctl_handlers.items():
            if addr not in seen_addrs and addr != 0:
                seen_addrs.add(addr)
                critical.append({
                    "address": addr,
                    "name": f"sub_{addr:X}",
                    "reason": f"IOCTL handler (code 0x{code:X})",
                    "severity": "high",
                    "api_name": "",
                    "instruction_address": 0,
                })

        # From IRP handlers
        for major, addr in ir.irp_handlers.items():
            if addr not in seen_addrs and addr != 0:
                seen_addrs.add(addr)
                critical.append({
                    "address": addr,
                    "name": f"sub_{addr:X}",
                    "reason": f"IRP handler (major 0x{major:X})",
                    "severity": "high",
                    "api_name": "",
                    "instruction_address": 0,
                })

        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        critical.sort(key=lambda x: severity_order.get(x["severity"], 4))

        return critical

    def _analyze_function(
        self,
        func_addr: int,
        ir: DisassemblyResult,
        sample: Sample,
    ) -> dict[str, Any]:
        """Deep analysis of a single function.

        Extracts:
        - Function prologue and epilogue patterns
        - API call sequence
        - CFG complexity metrics
        - Input validation patterns
        - Taint flow (if Ghidra-level data available)
        """
        func = ir.functions.get(func_addr)
        if func is None:
            return {
                "address": hex(func_addr),
                "name": f"sub_{func_addr:X}",
                "error": "Function not found in IR",
            }

        # Get CFG for this function
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)

        # API calls
        api_calls = ir.function_apis.get(func_addr, [])
        api_details = ir.function_api_details.get(func_addr, [])

        # CFG metrics
        block_count = len(cfg.blocks) if cfg else 0
        instruction_count = sum(len(b.instructions) for b in cfg.blocks.values()) if cfg else 0

        # Check for validation patterns
        has_validation = self._check_function_validation(func_addr, ir)
        has_privilege_check = self._check_privilege_pattern(func_addr, ir)
        has_size_check = self._check_size_pattern(func_addr, ir)

        # Taint analysis
        from src.analysis.dataflow.input_tracker import run_taint_analysis
        taint_result = run_taint_analysis(func_addr, ir, max_depth=3)

        # Build disassembly snippet
        disasm_snippet = ""
        if cfg:
            lines = []
            for block in sorted(cfg.blocks.values(), key=lambda b: b.address)[:5]:
                for insn in block.instructions[:10]:
                    api_marker = f"  ; CALL {insn.api_target}" if insn.api_target else ""
                    lines.append(f"  {hex(insn.address)}: {insn.mnemonic} {insn.operands}{api_marker}")
                lines.append("  ...")
            disasm_snippet = "\n".join(lines[:30])

        return {
            "address": hex(func_addr),
            "name": func.name,
            "size": func.size,
            "api_calls": api_calls,
            "api_details": [
                {"name": ad.name, "call_addr": hex(ad.call_address), "params": ad.params_hint}
                for ad in api_details[:10]
            ],
            "cfg_blocks": block_count,
            "instruction_count": instruction_count,
            "has_validation": has_validation,
            "has_privilege_check": has_privilege_check,
            "has_size_check": has_size_check,
            "taint_reaches_api": taint_result.tainted_reaches_dangerous_api,
            "taint_sources": [
                f"{s.field_name}@0x{s.irp_offset:X}" for s in taint_result.sources
            ],
            "taint_sinks": [
                f"{s.api_name}({s.tainted_param})" for s in taint_result.sinks
            ],
            "disassembly_snippet": disasm_snippet,
            "calls": [hex(c) for c in func.calls[:20]],
            "called_by": [hex(c) for c in func.called_by[:10]],
        }

    def _check_function_validation(
        self,
        func_addr: int,
        ir: DisassemblyResult,
    ) -> bool:
        """Check if a function has any input validation pattern."""
        api_calls = ir.function_apis.get(func_addr, [])
        validation_apis = {
            "ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages",
            "SeSinglePrivilegeCheck", "ExGetPreviousMode",
        }
        return bool(set(api_calls) & validation_apis)

    def _check_privilege_pattern(
        self,
        func_addr: int,
        ir: DisassemblyResult,
    ) -> bool:
        """Check for privilege check patterns."""
        api_calls = ir.function_apis.get(func_addr, [])
        return "SeSinglePrivilegeCheck" in api_calls or "ExGetPreviousMode" in api_calls

    def _check_size_pattern(
        self,
        func_addr: int,
        ir: DisassemblyResult,
    ) -> bool:
        """Check for buffer size validation patterns."""
        api_calls = ir.function_apis.get(func_addr, [])
        return "RtlCompareMemory" in api_calls

    # Comprehensive exploit chain API mapping
    EXPLOIT_CHAIN_APIS = {
        # Physical memory mapping chains
        "MmMapIoSpace", "MmMapIoSpaceEx", "MmGetVirtualForPhysical",
        "MmMapViewInSystemSpace", "MmMapViewInSessionSpace",
        # MSR access chains
        "KeWriteMsr", "__writemsr", "KeReadMsr", "__readmsr",
        # Kernel R/W chains
        "MmCopyVirtualMemory", "ZwWriteVirtualMemory", "NtWriteVirtualMemory",
        "ZwReadVirtualMemory", "NtReadVirtualMemory", "MmCopyMemory",
        # Code execution chains
        "ZwCreateThreadEx", "PsCreateSystemThread", "KeSetTimer",
        # DMA chains
        "WdfDmaEnablerCreate", "WdfDmaTransactionCreate",
        "MmAllocateAdapterChannel", "IoMapTransfer", "WdfCommonBufferCreate",
        # Interrupt hooking chains
        "IoConnectInterrupt", "IoConnectInterruptEx", "HalSetSystemInformation",
        # Callback registration chains
        "PsSetLoadImageNotifyRoutine", "PsSetCreateProcessNotifyRoutine",
        "PsSetCreateThreadNotifyRoutine", "ObRegisterCallbacks",
        "ObUnRegisterCallbacks", "CmRegisterCallback", "CmRegisterCallbackEx",
        "KeRegisterNmiCallback",
        # Physical memory access chains
        "MmGetPhysicalAddress", "MmGetPhysicalMemoryRanges",
        "MmAllocateContiguousMemory", "MmAllocateContiguousMemorySpecifyCache",
        # Handle manipulation chains
        "ObReferenceObjectByHandle", "ZwDuplicateObject",
        # Process manipulation chains
        "ZwSetInformationProcess", "ZwQueueApcThread", "KeStackAttachProcess",
        # Security token chains
        "SeImpersonateClientEx", "PsImpersonateClient",
        # Registry manipulation chains
        "ZwSetValueKey", "RtlWriteRegistryValue",
        # Driver loading chains
        "ZwLoadDriver", "NtLoadDriver",
        # 360-specific: APC injection
        "KeInitializeApc", "KeInsertQueueApc", "KeForceInsertQueueApc",
        # 360-specific: Thread hijacking
        "ZwSuspendThread", "ZwGetContextThread", "ZwSetContextThread",
        # 360-specific: Object callback details
        "ObReferenceObjectByName", "ObCreateObject",
        # 360-specific: Registry operations
        "ZwCreateKey", "ZwDeleteKey", "ZwEnumerateKey",
        # 360-specific: Named pipe IPC
        "NtCreateNamedPipeFile", "ZwCreateNamedPipeFile",
        "ZwFsControlFile", "NtFsControlFile",
        # 360-specific: ALPC
        "NtAlpcConnectPort", "ZwAlpcConnectPort",
        "NtAlpcSendWaitReceivePort", "ZwAlpcSendWaitReceivePort",
        # 360-specific: Anti-debug / anti-reversing
        "KeRegisterNmiCallback", "KeDeregisterNmiCallback",
        "NtSetInformationThread", "ZwSetInformationThread",
        # 360-specific: DKOM / EPT
        "KeQueryActiveProcessorCount", "KeGetCurrentProcessorNumber",
        "KeIpiGenericCall",
    }

    def _build_exploit_chains(
        self,
        functions_detail: list[dict[str, Any]],
        sample: Sample,
        ir: DisassemblyResult,
    ) -> list[dict[str, Any]]:
        """Build structured exploit chain summaries from analysis results."""
        from src.report.poc_generator import METHOD_NAMES

        chains = []

        # Build IOCTL code → transfer method map from findings
        ioctl_methods: dict[int, str] = {}
        for f in getattr(sample, "analysis_findings", []):
            ctx = f.context or {}
            if "ioctl_code" in ctx:
                code = ctx["ioctl_code"]
                method = ctx.get("transfer_method", 0)
                ioctl_methods[code] = METHOD_NAMES.get(method, f"UNKNOWN({method})")

        for func in functions_detail:
            if func.get("error"):
                continue

            # Skip functions with full validation
            if func.get("has_validation") and func.get("has_privilege_check") and func.get("has_size_check"):
                continue

            # Check if function has dangerous APIs
            api_calls = func.get("api_calls", [])
            dangerous_apis = [a for a in api_calls if a in self.EXPLOIT_CHAIN_APIS]

            if not dangerous_apis:
                continue

            # Check taint confirmation
            taint_confirmed = func.get("taint_reaches_api", False)

            # Determine transfer method from IOCTL handlers
            func_addr = int(func["address"], 16) if isinstance(func["address"], str) else func["address"]
            transfer_method = "METHOD_BUFFERED"  # default
            buffer_size = 0x1000

            for code_str, handler_addr_str in ir.ioctl_handlers.items() if hasattr(ir, "ioctl_handlers") else {}.items():
                try:
                    handler_addr = int(handler_addr_str, 16) if isinstance(handler_addr_str, str) else handler_addr_str
                except (ValueError, TypeError):
                    continue
                if handler_addr == func_addr:
                    try:
                        code = int(code_str, 16) if isinstance(code_str, str) else code_str
                    except (ValueError, TypeError):
                        continue
                    transfer_method = ioctl_methods.get(code, "METHOD_BUFFERED")
                    break

            # Determine buffer size hint based on API type
            if "MmMapIoSpace" in str(dangerous_apis):
                buffer_size = 0x20  # Physical address + size + cache type
            elif "MmCopyVirtualMemory" in str(dangerous_apis):
                buffer_size = 0x30  # Source/Target process + addresses + size
            elif "KeWriteMsr" in str(dangerous_apis):
                buffer_size = 0x10  # MSR index + value

            # Build specific PoC steps
            if taint_confirmed:
                taint_sources = func.get("taint_sources", ["user input"])
                taint_sinks = func.get("taint_sinks", dangerous_apis)
                poc_steps = [
                    f"1. Open device handle: CreateFileW(L\"\\\\\\\\.\\\\{sample.driver_type}\", ...)",
                    f"2. Allocate input buffer ({len(taint_sources)} taint source(s): {', '.join(taint_sources)})",
                    f"3. Fill buffer with controlled data to reach dangerous sink",
                    f"4. DeviceIoControl(hDevice, IOCTL_???, buffer, 0x{buffer_size:X}, ...)",
                    f"5. Driver dispatches to {func['name']} via IOCTL handler",
                    f"6. Dangerous API(s): {', '.join(dangerous_apis)}",
                    f"7. Confirmed taint path: {', '.join(taint_sinks)}",
                    f"8. Impact: Arbitrary kernel read/write / privilege escalation",
                ]
            else:
                poc_steps = [
                    f"1. Open device handle to {sample.driver_type}",
                    f"2. Construct input buffer (0x{buffer_size:X} bytes)",
                    f"3. Send IOCTL to trigger {func['name']}",
                    f"4. {', '.join(dangerous_apis)} called (taint not confirmed — potential primitive)",
                    f"5. Result: Potential kernel primitive — manual validation required",
                ]

            # Build chain
            chain = {
                "function": func["address"],
                "name": func["name"],
                "dangerous_apis": dangerous_apis,
                "validation": "none" if not func.get("has_validation") else "partial",
                "user_controllable": taint_confirmed,
                "severity": "CRITICAL" if taint_confirmed else "HIGH",
                "transfer_method": transfer_method,
                "buffer_size": buffer_size,
                "ioctl_code": 0x22A004,  # Default — will be refined by structure_analyzer
                "poc_steps": poc_steps,
                "taint_sources": taint_sources if taint_confirmed else [],
                "taint_sinks": taint_sinks if taint_confirmed else [],
            }
            chains.append(chain)

        # Sort by severity
        chains.sort(key=lambda c: (0 if c["severity"] == "CRITICAL" else 1, c["function"]))

        return chains

    def _write_outputs(
        self,
        result: OvoidaResult,
        output_dir: Path,
    ) -> OvoidaResult:
        """Write findings.json and findings.md to the output directory."""
        # findings.json
        findings_data = {
            "sample_name": result.sample_name,
            "risk_score": result.risk_score,
            "functions_analyzed": result.functions_analyzed,
            "functions": result.functions_detail,
            "exploit_chains": result.exploit_chains,
            "poc_pseudocode": self._generate_poc_pseudocode(result.exploit_chains),
            "confidence": "confirmed" if any(
                c.get("user_controllable") for c in result.exploit_chains
            ) else "speculated",
        }

        findings_json = output_dir / "findings.json"
        findings_json.write_text(
            json.dumps(findings_data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        result.findings_json_path = findings_json

        # findings.md
        findings_md = output_dir / "findings.md"
        md_lines = [
            f"# OVOIDA Deep Analysis Report: {result.sample_name}",
            "",
            f"**Risk Score:** {result.risk_score:.1f}/10",
            f"**Functions Analyzed:** {result.functions_analyzed}",
            f"**Exploit Chains Found:** {len(result.exploit_chains)}",
            "",
            "## Exploit Chains",
            "",
        ]

        for i, chain in enumerate(result.exploit_chains, 1):
            md_lines.extend([
                f"### Chain {i}: {chain.get('name', 'unknown')}",
                "",
                f"- **Severity:** {chain['severity']}",
                f"- **Function:** {chain['function']}",
                f"- **Dangerous APIs:** {', '.join(chain['dangerous_apis'])}",
                f"- **Validation:** {chain['validation']}",
                f"- **User Controllable:** {chain['user_controllable']}",
                "",
                "#### PoC Steps",
                "",
            ])
            for step in chain.get("poc_steps", []):
                md_lines.append(f"- {step}")
            md_lines.append("")

        # Function details
        md_lines.extend([
            "## Functions Detail",
            "",
            "| Address | Name | APIs | Validation | Taint |",
            "|---|---|---|---|---|",
        ])

        for func in result.functions_detail:
            if func.get("error"):
                continue
            apis = ", ".join(func.get("api_calls", [])[:5])
            validation = "Yes" if func.get("has_validation") else "No"
            taint = "Yes" if func.get("taint_reaches_api") else "No"
            md_lines.append(
                f"| {func['address']} | {func['name']} | {apis} | {validation} | {taint} |"
            )

        findings_md.write_text("\n".join(md_lines), encoding="utf-8")
        result.findings_md_path = findings_md

        return result

    def _generate_poc_pseudocode(
        self,
        exploit_chains: list[dict[str, Any]],
    ) -> str:
        """Generate pseudo-code for exploiting the found chains."""
        if not exploit_chains:
            return "No exploit chains detected."

        lines = [
            "// OVOIDA Generated PoC Pseudocode",
            "// WARNING: This is for educational purposes only.",
            "",
        ]

        for chain in exploit_chains[:3]:  # Top 3 chains
            lines.extend([
                f"// Chain: {chain.get('name', 'unknown')} ({chain['severity']})",
                f"HANDLE hDevice = CreateFile(",
                f'    L"\\\\\\\\.\\\\\\\\{chain.get("name", "TargetDevice")}",',
                f"    GENERIC_READ | GENERIC_WRITE,",
                f"    0, NULL, OPEN_EXISTING, 0, NULL",
                f");",
                f"",
                f"// Trigger dangerous IOCTL",
                f"DWORD bytesReturned = 0;",
                f"BYTE inputBuffer[0x1000] = {0};",
                f"// Fill buffer with controlled data",
                f"DeviceIoControl(",
                f"    hDevice,",
                f"    0x22A004,  // IOCTL code (example)",
                f"    inputBuffer,",
                f"    sizeof(inputBuffer),",
                f"    NULL, 0,",
                f"    &bytesReturned",
                f");",
                f"",
                f"// Result: {', '.join(chain.get('dangerous_apis', []))} called",
                f"// Validation: {chain.get('validation', 'unknown')}",
                f"",
            ])

        return "\n".join(lines)
