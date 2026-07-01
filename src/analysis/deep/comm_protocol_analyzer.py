"""
DriverScope — Communication Protocol Analyzer.

Analyzes kernel-user communication protocols:
1. **IOCTL command extraction** — Decode CTL_CODE values into DeviceType,
   FunctionCode, Method, and Access components.
2. **Buffer transfer method analysis** — Classify METHOD_BUFFERED, METHOD_NEITHER,
   METHOD_IN_DIRECT, METHOD_OUT_DIRECT and flag unsafe patterns.
3. **ALPC port analysis** — Extract ALPC port names and analyze message handlers.
4. **NamedPipe analysis** — Extract pipe names and analyze read/write handlers.
5. **Command semantics inference** — Infer command functionality from handler API calls.
"""

from __future__ import annotations

from typing import Any

from src.analysis.analyzer import Analyzer
from src.models import (
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)


# CTL_CODE method values
METHOD_NAMES: dict[int, str] = {
    0: "METHOD_BUFFERED",
    1: "METHOD_IN_DIRECT",
    2: "METHOD_OUT_DIRECT",
    3: "METHOD_NEITHER",
}

# CTL_CODE access values
ACCESS_NAMES: dict[int, str] = {
    0: "FILE_ANY_ACCESS",
    1: "FILE_READ_DATA",
    2: "FILE_WRITE_DATA",
    3: "FILE_READ_DATA | FILE_WRITE_DATA",
}

# Device type name mapping (subset of common types)
DEVICE_TYPE_NAMES: dict[int, str] = {
    0x00000001: "FILE_DEVICE_BEEP",
    0x00000002: "FILE_DEVICE_CD_ROM",
    0x00000007: "FILE_DEVICE_DISK",
    0x00000009: "FILE_DEVICE_FILE_SYSTEM",
    0x0000000E: "FILE_DEVICE_MAILSLOT",
    0x00000013: "FILE_DEVICE_NAMED_PIPE",
    0x00000014: "FILE_DEVICE_NETWORK",
    0x00000022: "FILE_DEVICE_UNKNOWN",
    0x00000023: "FILE_DEVICE_TRANSPORT",
    0x00000024: "FILE_DEVICE_VIDEO",
    0x00008000: "FILE_DEVICE_360_CUSTOM",
}

# API-to-command semantic mapping
API_SEMANTICS: dict[str, str] = {
    "ZwTerminateProcess": "process termination",
    "ZwOpenProcess": "process handle acquisition",
    "ZwReadVirtualMemory": "memory read primitive",
    "ZwWriteVirtualMemory": "memory write primitive",
    "MmMapIoSpaceEx": "physical memory mapping",
    "MmMapLockedPagesSpecifyCache": "locked page mapping",
    "ZwCreateSection": "section/object creation",
    "ZwMapViewOfSection": "section view mapping",
    "ZwDeviceIoControlFile": "forwarded IOCTL",
    "ZwCreateFile": "file creation",
    "ZwOpenFile": "file open",
    "ZwReadFile": "file read",
    "ZwWriteFile": "file write",
    "ZwQuerySystemInformation": "system information disclosure",
    "ZwQueryInformationProcess": "process information disclosure",
    "ZwSetInformationProcess": "process manipulation",
    "PsLookupProcessByProcessId": "process lookup",
    "ObOpenObjectByPointer": "object handle opening",
    "SeImpersonateClient": "token impersonation",
    "ZwDuplicateToken": "token duplication",
}

# Unsafe APIs for METHOD_NEITHER
NEITHER_UNSAFE_APIS = {
    "ProbeForRead", "ProbeForWrite", "_try", "__except",
}


class CommProtocolAnalyzer(Analyzer):
    """Analyze kernel-user communication protocols."""

    name = "CommProtocolAnalyzer"
    description = (
        "IOCTL command extraction, buffer method analysis, ALPC/NamedPipe "
        "protocol analysis, and command semantics inference"
    )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # 1. Decode IOCTL codes
        findings.extend(self._decode_ioctl_codes(ir))

        # 2. Analyze buffer transfer methods
        findings.extend(self._analyze_buffer_methods(ir))

        # 3. Analyze ALPC ports
        findings.extend(self._analyze_alpc_ports(ir))

        # 4. Analyze NamedPipe
        findings.extend(self._analyze_named_pipes(ir))

        # 5. Infer command semantics
        findings.extend(self._infer_command_semantics(ir))

        # 6. Detect cross-driver communication via device names
        findings.extend(self._detect_cross_driver_devices(ir))

        # 7. Detect HTTP/HTTPS network communication
        findings.extend(self._detect_http_communication(ir))

        # 8. Detect WFP Callout communication patterns
        findings.extend(self._detect_wfp_callouts(ir))

        return findings

    # ------------------------------------------------------------------
    # IOCTL code decoding
    # ------------------------------------------------------------------

    def _decode_ioctl_codes(self, ir: DisassemblyResult) -> list[Finding]:
        """Decode CTL_CODE values into their components."""
        findings = []
        decoded_ioctls: list[dict[str, Any]] = []

        for ioctl_code in (ir.ioctl_codes or []):
            if isinstance(ioctl_code, int):
                device_type = (ioctl_code >> 16) & 0xFFFF
                function_code = (ioctl_code >> 2) & 0xFFF
                method = ioctl_code & 0x3
                access = (ioctl_code >> 2) & 0x3

                decoded = {
                    "ioctl_code": ioctl_code,
                    "device_type": device_type,
                    "device_type_name": DEVICE_TYPE_NAMES.get(
                        device_type, f"UNKNOWN_0x{device_type:04X}"
                    ),
                    "function_code": function_code,
                    "method": method,
                    "method_name": METHOD_NAMES.get(method, f"UNKNOWN_{method}"),
                    "access": access,
                    "access_name": ACCESS_NAMES.get(access, f"UNKNOWN_{access}"),
                }
                decoded_ioctls.append(decoded)

                severity = Severity.INFO
                if method == 3:  # METHOD_NEITHER
                    severity = Severity.MEDIUM
                if device_type == 0x8000:  # 360 custom
                    severity = Severity.MEDIUM

                findings.append(Finding(
                    category=FindingCategory.IOCTL_CODE_EXPOSED,
                    severity=severity,
                    confidence=Confidence.HIGH,
                    description=(
                        f"IOCTL 0x{ioctl_code:X}: {decoded['device_type_name']} "
                        f"Func={function_code} {decoded['method_name']} "
                        f"{decoded['access_name']}"
                    ),
                    ioctl_code=ioctl_code,
                    context=decoded,
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": "ioctl_dispatch",
                        "snippet": f"0x{ioctl_code:X}",
                        "rule_id": "CP001",
                    }],
                ))

        ir.decoded_ioctls = decoded_ioctls
        return findings

    # ------------------------------------------------------------------
    # Buffer method analysis
    # ------------------------------------------------------------------

    def _analyze_buffer_methods(self, ir: DisassemblyResult) -> list[Finding]:
        """Analyze IOCTL handler buffer transfer methods for safety."""
        findings = []

        decoded_ioctls = getattr(ir, "decoded_ioctls", []) or []

        for decoded in decoded_ioctls:
            method = decoded.get("method", 0)
            ioctl_code = decoded.get("ioctl_code", 0)

            if method == 3:  # METHOD_NEITHER
                # Direct user-mode pointer — unsafe without ProbeForRead/Write
                handler_addr = (ir.ioctl_handlers or {}).get(ioctl_code, 0)
                has_probe = self._check_for_probe(handler_addr, ir)

                if not has_probe:
                    findings.append(Finding(
                        category=FindingCategory.UNVALIDATED_USER_INPUT,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            f"IOCTL 0x{ioctl_code:X} uses METHOD_NEITHER "
                            f"without ProbeForRead/ProbeForWrite — unsafe direct "
                            f"user-mode pointer access"
                        ),
                        function_address=handler_addr,
                        ioctl_code=ioctl_code,
                        context={
                            "ioctl_code": ioctl_code,
                            "method": "METHOD_NEITHER",
                            "has_probe_check": False,
                            "risk": "potential arbitrary kernel memory access",
                        },
                        evidence=[{
                            "type": "instruction_pattern",
                            "location": f"handler 0x{handler_addr:X}",
                            "snippet": f"IOCTL 0x{ioctl_code:X} METHOD_NEITHER",
                            "rule_id": "CP002",
                        }],
                    ))
                else:
                    findings.append(Finding(
                        category=FindingCategory.VALIDATED_SURFACE,
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        description=(
                            f"IOCTL 0x{ioctl_code:X} uses METHOD_NEITHER "
                            f"with ProbeForRead/ProbeForWrite — validated"
                        ),
                        function_address=handler_addr,
                        ioctl_code=ioctl_code,
                        context={
                            "ioctl_code": ioctl_code,
                            "method": "METHOD_NEITHER",
                            "has_probe_check": True,
                        },
                        evidence=[{
                            "type": "instruction_pattern",
                            "location": f"handler 0x{handler_addr:X}",
                            "snippet": "ProbeForRead/Write present",
                            "rule_id": "CP003",
                        }],
                    ))

            elif method == 0:  # METHOD_BUFFERED
                findings.append(Finding(
                    category=FindingCategory.VALIDATED_SURFACE,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=f"IOCTL 0x{ioctl_code:X} uses METHOD_BUFFERED — safe",
                    ioctl_code=ioctl_code,
                    context={
                        "ioctl_code": ioctl_code,
                        "method": "METHOD_BUFFERED",
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": "ioctl_dispatch",
                        "snippet": "METHOD_BUFFERED",
                        "rule_id": "CP004",
                    }],
                ))

        return findings

    def _check_for_probe(self, handler_addr: int, ir: DisassemblyResult) -> bool:
        """Check if a handler function uses ProbeForRead/ProbeForWrite."""
        if not handler_addr:
            return False

        # Check function_apis
        apis = ir.function_apis.get(handler_addr, [])
        for api in apis:
            if api in NEITHER_UNSAFE_APIS:
                return True

        # Check dynamic_imports
        for call_addr, info in (ir.dynamic_imports or {}).items():
            if isinstance(info, dict):
                api_name = info.get("api_name", "")
                if api_name in NEITHER_UNSAFE_APIS:
                    return True

        return False

    # ------------------------------------------------------------------
    # ALPC port analysis
    # ------------------------------------------------------------------

    def _analyze_alpc_ports(self, ir: DisassemblyResult) -> list[Finding]:
        """Analyze ALPC port names and message handlers."""
        findings = []

        # Extract ALPC port names from wide strings
        alpc_ports = []
        for ws in (ir.wide_strings or []):
            s = ws.get("string", "")
            # Clean Ghidra format
            if s.startswith('u"') and s.endswith('"'):
                s = s[2:-1].replace("\\\\", "\\")
            if "\\Alpc\\" in s or "\\RPC Control\\" in s:
                alpc_ports.append(s)

        if alpc_ports:
            findings.append(Finding(
                category=FindingCategory.ALPC_PORT_NAME,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=f"ALPC ports detected: {', '.join(alpc_ports[:5])}",
                context={
                    "ports": alpc_ports,
                    "count": len(alpc_ports),
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": "wide_strings",
                    "snippet": ", ".join(alpc_ports[:3]),
                    "rule_id": "CP005",
                }],
            ))

        return findings

    # ------------------------------------------------------------------
    # NamedPipe analysis
    # ------------------------------------------------------------------

    def _analyze_named_pipes(self, ir: DisassemblyResult) -> list[Finding]:
        """Analyze NamedPipe names and handlers."""
        findings = []

        pipe_names = []
        for ws in (ir.wide_strings or []):
            s = ws.get("string", "")
            if s.startswith('u"') and s.endswith('"'):
                s = s[2:-1].replace("\\\\", "\\")
            if s.startswith("\\\\.\\pipe\\") or s.startswith("\\pipe\\"):
                pipe_names.append(s)

        if pipe_names:
            findings.append(Finding(
                category=FindingCategory.NAMED_PIPE,
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description=f"Named pipes detected: {', '.join(pipe_names[:5])}",
                context={
                    "pipes": pipe_names,
                    "count": len(pipe_names),
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": "wide_strings",
                    "snippet": ", ".join(pipe_names[:3]),
                    "rule_id": "CP006",
                }],
            ))

        return findings

    # ------------------------------------------------------------------
    # Command semantics inference
    # ------------------------------------------------------------------

    def _infer_command_semantics(self, ir: DisassemblyResult) -> list[Finding]:
        """Infer command functionality from handler API calls."""
        findings = []
        inferred_commands: list[dict[str, Any]] = []

        for ioctl_code, handler_addr in (ir.ioctl_handlers or {}).items():
            apis = ir.function_apis.get(handler_addr, [])

            # Map APIs to semantic descriptions
            semantics = []
            for api in apis:
                if api in API_SEMANTICS:
                    semantics.append(API_SEMANTICS[api])

            if semantics:
                inferred_commands.append({
                    "ioctl_code": ioctl_code,
                    "handler_address": handler_addr,
                    "semantics": semantics,
                    "apis": apis,
                })

                # High severity for dangerous primitives
                dangerous = [
                    s for s in semantics
                    if any(kw in s for kw in ("memory", "execution", "impersonation", "token"))
                ]
                severity = Severity.MEDIUM if dangerous else Severity.INFO

                findings.append(Finding(
                    category=FindingCategory.DATA_CONTENT_ANALYZED,
                    severity=severity,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"IOCTL 0x{ioctl_code:X} handler inferred purpose: "
                        f"{', '.join(semantics)}"
                    ),
                    function_address=handler_addr,
                    ioctl_code=ioctl_code,
                    context={
                        "ioctl_code": ioctl_code,
                        "handler_address": handler_addr,
                        "semantics": semantics,
                        "apis": apis,
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"handler 0x{handler_addr:X}",
                        "snippet": ", ".join(apis[:5]),
                        "rule_id": "CP007",
                    }],
                ))

        ir.inferred_commands = inferred_commands
        return findings

    # ------------------------------------------------------------------
    # Cross-driver communication via device names
    # ------------------------------------------------------------------

    # Known 360 device name patterns for cross-driver communication
    _VENDOR_DEVICE_PATTERNS = [
        ("360", "\\Device\\360"),
        ("Qihu", "\\Device\\Qihu"),
    ]

    # Security product device names
    _SECURITY_DEVICES = {
        "\\Device\\360AntiAttack": "360 Anti-Attack driver",
        "\\Device\\360AntiHacker": "360 Anti-Hacker driver",
        "\\Device\\360AntiHijack": "360 Anti-Hijack driver",
        "\\Device\\360AntiSteal": "360 Anti-Steal driver",
        "\\Device\\360SelfProtection": "360 Self-Protection driver",
        "\\Device\\360Hvm": "360 HVM (hypervisor) driver",
        "\\Device\\360IPFilter": "360 IP Filter driver",
        "\\Device\\360NsiFilter": "360 NSI Filter driver",
        "\\Device\\360elam": "360 ELAM (early launch) driver",
        "\\Device\\360FsFlt": "360 File System Filter driver",
    }

    def _detect_cross_driver_devices(self, ir: DisassemblyResult) -> list[Finding]:
        """Detect cross-driver communication via \\Device\\<vendor> names."""
        findings = []
        devices: list[str] = []
        matched_devices: list[str] = []

        for ws in (ir.wide_strings or []):
            s = ws.get("string", "")
            # Clean Ghidra format: u"\\Device\\..." -> \\Device\\...
            if s.startswith('u"') and s.endswith('"'):
                s = s[2:-1].replace("\\\\", "\\")

            for prefix, label in self._VENDOR_DEVICE_PATTERNS:
                if s.startswith(f"\\Device\\{prefix}") and s not in devices:
                    devices.append(s)
                    if s in self._SECURITY_DEVICES:
                        matched_devices.append(f"{s} ({self._SECURITY_DEVICES[s]})")

        if devices:
            findings.append(Finding(
                category=FindingCategory.CROSS_DRIVER_SHARED_DEVICE,
                severity=Severity.MEDIUM if matched_devices else Severity.INFO,
                confidence=Confidence.HIGH,
                description=(
                    f"Cross-driver communication: {len(devices)} vendor device(s) "
                    f"detected — {', '.join(devices[:5])}"
                ),
                context={
                    "devices": devices,
                    "matched": matched_devices,
                    "count": len(devices),
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": "wide_strings",
                    "snippet": ", ".join(devices[:3]),
                    "rule_id": "CP008",
                }],
            ))

        return findings

    # ------------------------------------------------------------------
    # HTTP/HTTPS network communication
    # ------------------------------------------------------------------

    def _detect_http_communication(self, ir: DisassemblyResult) -> list[Finding]:
        """Detect HTTP/HTTPS network communication patterns."""
        findings = []

        # Check for URL strings
        url_strings = []
        for ws in (ir.wide_strings or []):
            s = ws.get("string", "")
            clean_s = s
            if s.startswith('u"') and s.endswith('"'):
                clean_s = s[2:-1].replace("\\\\", "\\")
            if clean_s.lower().startswith("http://") or clean_s.lower().startswith("https://"):
                url_strings.append(clean_s)

        # Check for HTTP-related APIs
        http_apis = {
            "HttpSendRequestA", "HttpSendRequestW", "HttpOpenRequestA",
            "HttpOpenRequestW", "InternetOpenA", "InternetOpenW",
            "InternetConnectA", "InternetConnectW", "WinHttpOpen",
            "WinHttpConnect", "WinHttpSendRequest", "WinHttpReceiveResponse",
        }
        all_imports = set(ir.import_addresses.values())
        http_imports = all_imports & http_apis

        if url_strings or http_imports:
            findings.append(Finding(
                category=FindingCategory.NAMED_PIPE,  # closest category for network comm
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description=(
                    f"HTTP/HTTPS communication: {len(url_strings)} URL(s) "
                    f"{', '.join(url_strings[:3])}"
                    + (f", {len(http_imports)} HTTP API(s)" if http_imports else "")
                ),
                context={
                    "urls": url_strings,
                    "http_apis": sorted(http_imports),
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": "wide_strings" + ("/imports" if http_imports else ""),
                    "snippet": ", ".join(url_strings[:3]) if url_strings else ", ".join(http_imports),
                    "rule_id": "CP009",
                }],
            ))

        return findings

    # ------------------------------------------------------------------
    # WFP Callout detection
    # ------------------------------------------------------------------

    _WFP_APIS = {
        "FwpsCalloutRegister", "FwpsCalloutUnregisterById",
        "FwpsInjectionHandleCreate", "FwpsInjectNetworkReceiveAsync",
        "FwpsInjectTransportReceiveAsync", "FwpsInjectNetworkSendAsync",
        "FwpsAleClassify", "FwpsCalloutAdd",
    }

    def _detect_wfp_callouts(self, ir: DisassemblyResult) -> list[Finding]:
        """Detect Windows Filtering Platform (WFP) Callout usage."""
        findings = []

        all_apis: set[str] = set()
        for api_list in ir.function_apis.values():
            all_apis.update(api_list)
        for api_details in ir.function_api_details.values():
            for api_info in api_details:
                all_apis.add(api_info.name)

        wfp_apis = all_apis & self._WFP_APIS

        if wfp_apis:
            findings.append(Finding(
                category=FindingCategory.CALLBACK_REGISTRATION,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description=f"WFP Callout detected: {', '.join(sorted(wfp_apis))}",
                context={
                    "wfp_apis": sorted(wfp_apis),
                    "type": "wfp_callout",
                },
                evidence=[{
                    "type": "import_pattern",
                    "location": "function_apis",
                    "snippet": ", ".join(sorted(wfp_apis)),
                    "rule_id": "CP010",
                }],
            ))

        return findings
