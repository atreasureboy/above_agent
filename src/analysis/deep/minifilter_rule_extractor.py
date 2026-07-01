"""
DriverScope — MiniFilter Rule Extractor.

Extracts FLT_REGISTRATION structure and OperationRegistration arrays from
MiniFilter driver PE files. Capabilities:

1. **FLT_REGISTRATION structure location** — Search .rdata for known
   SizeOfStruct + Version patterns (0x30/0x38/0x48 + 0x0100/0x0200/0x0201).
2. **OperationRegistration array parsing** — Each FLT_OPERATION_REGISTRATION
   entry is {MajorFunction, PreOperation, PostOperation, Flags}.
3. **Rule semantic interpretation** — Map IRP_MJ_* codes to file operation
   semantics (create, read, write, set info, directory control, etc.).
4. **Filter rule classification** — Pre-operation with return value check →
   intercept filter; pre-operation without return check → monitor filter;
   post-operation modification → data tampering filter.
"""

from __future__ import annotations

import struct
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


# IRP_MJ_* operation names
IRP_MJ_NAMES: dict[int, str] = {
    0x00: "IRP_MJ_CREATE",
    0x01: "IRP_MJ_CREATE_NAMED_PIPE",
    0x02: "IRP_MJ_CLOSE",
    0x03: "IRP_MJ_READ",
    0x04: "IRP_MJ_WRITE",
    0x05: "IRP_MJ_QUERY_INFORMATION",
    0x06: "IRP_MJ_SET_INFORMATION",
    0x07: "IRP_MJ_QUERY_EA",
    0x08: "IRP_MJ_SET_EA",
    0x09: "IRP_MJ_FLUSH_BUFFERS",
    0x0A: "IRP_MJ_QUERY_VOLUME_INFORMATION",
    0x0B: "IRP_MJ_SET_VOLUME_INFORMATION",
    0x0C: "IRP_MJ_DIRECTORY_CONTROL",
    0x0D: "IRP_MJ_FILE_SYSTEM_CONTROL",
    0x0E: "IRP_MJ_DEVICE_CONTROL",
    0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    0x10: "IRP_MJ_SHUTDOWN",
    0x11: "IRP_MJ_LOCK_CONTROL",
    0x12: "IRP_MJ_CLEANUP",
    0x13: "IRP_MJ_CREATE_MAILSLOT",
    0x14: "IRP_MJ_QUERY_SECURITY",
    0x15: "IRP_MJ_SET_SECURITY",
    0x16: "IRP_MJ_POWER",
    0x17: "IRP_MJ_SYSTEM_CONTROL",
    0x18: "IRP_MJ_DEVICE_CHANGE",
    0x19: "IRP_MJ_QUERY_QUOTA",
    0x1A: "IRP_MJ_SET_QUOTA",
    0x1B: "IRP_MJ_PNP",
    0x1C: "IRP_MJ_PNP_POWER",
    0x1F: "IRP_MJ_MAXIMUM_FUNCTION",
    0xFE: "IRP_MJ_OPERATION_END",  # Sentinel
}

# Semantic meaning of IRP operations
IRP_MJ_SEMANTICS: dict[int, str] = {
    0x00: "file creation monitoring/interception",
    0x01: "named pipe creation monitoring/interception",
    0x02: "handle close monitoring",
    0x03: "file read monitoring",
    0x04: "file write monitoring",
    0x05: "file metadata query monitoring",
    0x06: "file metadata modification monitoring",
    0x07: "extended attribute query",
    0x08: "extended attribute modification",
    0x09: "buffer flush monitoring",
    0x0A: "volume information query",
    0x0B: "volume information modification",
    0x0C: "directory enumeration monitoring",
    0x0D: "file system control IOCTL",
    0x0E: "device control IOCTL (custom commands)",
    0x0F: "internal device control IOCTL",
    0x10: "system shutdown notification",
    0x11: "file lock control monitoring",
    0x12: "handle cleanup monitoring",
    0x13: "mailslot creation monitoring",
    0x14: "security descriptor query",
    0x15: "security descriptor modification",
    0x1C: "PNP/Power state manipulation",
}

# FLT_REGISTRATION known sizes and versions
FLT_REGISTRATION_SIZES = {0x30, 0x38, 0x48}
FLT_REGISTRATION_VERSIONS = {0x0100, 0x0200, 0x0201}


class MinifilterRuleExtractor(Analyzer):
    """Extract FLT_REGISTRATION and OperationRegistration rules from MiniFilter drivers."""

    name = "MinifilterRuleExtractor"
    description = (
        "MiniFilter FLT_REGISTRATION structure parsing and OperationRegistration "
        "array extraction with semantic rule classification"
    )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # Initialize IR fields
        ir.operation_rules = []
        ir.operation_behaviors = []

        # 1. Extract OperationRegistration rules from PE sections
        findings.extend(self._extract_operation_rules(sample, ir))

        # 2. If PE parsing found nothing, try API-based detection fallback
        if not ir.operation_rules:
            findings.extend(self._detect_minifilter_via_apis(sample, ir))

        # 3. Analyze pre/post operation behavior
        findings.extend(self._analyze_operation_behavior(ir))

        # 4. Classify filter rules
        findings.extend(self._classify_filter_rules(ir))

        return findings

    # ------------------------------------------------------------------
    # OperationRegistration extraction from PE sections
    # ------------------------------------------------------------------

    def _extract_operation_rules(
        self, sample: Sample, ir: DisassemblyResult
    ) -> list[Finding]:
        """Scan PE .rdata section for FLT_OPERATION_REGISTRATION arrays.

        Each FLT_OPERATION_REGISTRATION (x64) is:
            MajorFunction:    BYTE   (offset 0x00)
            Flags:            ULONG  (offset 0x04)
            PreOperation:     PVOID  (offset 0x08)
            PostOperation:    PVOID  (offset 0x10)
        Total: 0x18 bytes per entry.

        Array ends with IRP_MJ_OPERATION_END (0xFE) sentinel.
        """
        findings = []
        operation_rules: list[dict[str, Any]] = []

        try:
            import pefile
            pe = pefile.PE(str(sample.path), fast_load=True)
        except Exception:
            return findings

        target_sections = {".rdata", ".data", ".rodata"}

        for section in pe.sections:
            name = section.Name.decode("ascii", errors="replace").rstrip("\x00")
            if name not in target_sections:
                continue

            try:
                raw_data = section.get_data()
            except Exception:
                continue

            base_rva = section.VirtualAddress

            # Scan for FLT_OPERATION_REGISTRATION arrays
            # Look for sentinel pattern: byte 0xFE followed by zeros
            rules = self._scan_for_operation_array(raw_data, base_rva, name, ir)
            operation_rules.extend(rules)

            for rule in rules:
                mj_name = IRP_MJ_NAMES.get(rule["major_function"], f"IRP_MJ_{rule['major_function']:02X}")
                semantic = IRP_MJ_SEMANTICS.get(rule["major_function"], "unknown operation")

                findings.append(Finding(
                    category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    description=f"MiniFilter {mj_name} rule at {name}:0x{rule['rva']:X} — {semantic}",
                    instruction_address=rule["rva"],
                    context={
                        "major_function": rule["major_function"],
                        "mj_name": mj_name,
                        "semantic": semantic,
                        "pre_operation": rule.get("pre_operation"),
                        "post_operation": rule.get("post_operation"),
                        "flags": rule.get("flags", 0),
                        "section": name,
                        "rule_type": "operation_registration",
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"{name}:0x{rule['rva']:X}",
                        "snippet": f"MajorFunction={mj_name}",
                        "rule_id": "MF001",
                    }],
                ))

        ir.operation_rules = operation_rules

        # Populate ir.minifilter_handlers for FilterDriverAnalyzer consumption
        for rule in operation_rules:
            if rule.get("pre_operation"):
                ir.minifilter_handlers[rule["major_function"]] = rule["pre_operation"]
            if rule.get("post_operation"):
                # Post-operation can share the same key; store as list if needed
                existing = ir.minifilter_handlers.get(rule["major_function"])
                if existing is not None:
                    # Already has pre-operation; store post separately
                    pass  # pre-operation takes priority in the dict
                else:
                    ir.minifilter_handlers[rule["major_function"]] = rule["post_operation"]

        pe.close()
        return findings

    def _scan_for_operation_array(
        self, data: bytes, base_rva: int, section_name: str,
        ir: DisassemblyResult,
    ) -> list[dict[str, Any]]:
        """Scan section data for FLT_OPERATION_REGISTRATION arrays.

        Strategy: search for the sentinel byte 0xFE (IRP_MJ_OPERATION_END)
        at positions that align with MajorFunction field (every 0x18 bytes).
        """
        rules = []
        entry_size = 0x18  # sizeof(FLT_OPERATION_REGISTRATION) x64

        if len(data) < entry_size:
            return rules

        # Scan for 0xFE byte (sentinel) as potential array end
        for i in range(0, len(data)):
            if data[i] != 0xFE:
                continue

            # Found sentinel — walk backwards to find start of array
            # Sentinel entry should be: 0xFE, 0x00, 0x00, 0x00, 0x00...
            entry_rva = base_rva + i
            is_sentinel = True

            # Check if this looks like a proper sentinel entry
            if i + 4 <= len(data):
                sentinel_bytes = data[i:i + 4]
                # Should be 0xFE followed by 3 zero bytes (Flags field)
                if sentinel_bytes[1:4] != b"\x00\x00\x00":
                    is_sentinel = False
            else:
                is_sentinel = False

            if not is_sentinel:
                continue

            # Walk backwards to find array start (entries must be aligned to entry_size)
            j = i - entry_size
            while j >= 0:
                mj = data[j]
                if mj == 0xFE or mj > 0x1F:
                    break  # Invalid MajorFunction, not part of array

                # Parse entry
                flags = 0
                pre_op = 0
                post_op = 0

                if j + 4 <= len(data):
                    flags = struct.unpack_from("<I", data, j + 4)[0]
                if j + 8 <= len(data):
                    pre_op = struct.unpack_from("<Q", data, j + 8)[0]
                if j + 0x10 <= len(data):
                    post_op = struct.unpack_from("<Q", data, j + 0x10)[0]

                # Only add if at least one callback is non-zero
                if pre_op != 0 or post_op != 0:
                    rules.append({
                        "rva": base_rva + j,
                        "major_function": mj,
                        "flags": flags,
                        "pre_operation": pre_op if pre_op != 0 else None,
                        "post_operation": post_op if post_op != 0 else None,
                    })

                j -= entry_size

        return rules

    # ------------------------------------------------------------------
    # Operation behavior analysis
    # ------------------------------------------------------------------

    def _analyze_operation_behavior(
        self, ir: DisassemblyResult
    ) -> list[Finding]:
        """Analyze pre/post operation callback behavior."""
        findings = []
        behavior_results: list[dict[str, Any]] = []

        operation_rules = getattr(ir, "operation_rules", []) or []

        for rule in operation_rules:
            behavior: dict[str, Any] = {
                "major_function": rule["major_function"],
                "rva": rule["rva"],
            }

            # Analyze pre-operation callback
            if rule.get("pre_operation"):
                pre_behavior = self._analyze_callback_semantics(
                    rule["pre_operation"], ir
                )
                behavior["pre_behavior"] = pre_behavior

            # Analyze post-operation callback
            if rule.get("post_operation"):
                post_behavior = self._analyze_callback_semantics(
                    rule["post_operation"], ir
                )
                behavior["post_behavior"] = post_behavior

            # Classify rule type
            behavior["rule_type"] = self._classify_rule_type(behavior)
            behavior_results.append(behavior)

            # Report significant findings
            if behavior["rule_type"] == "intercept":
                mj_name = IRP_MJ_NAMES.get(
                    rule["major_function"],
                    f"IRP_MJ_{rule['major_function']:02X}",
                )
                findings.append(Finding(
                    category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=f"MiniFilter {mj_name} is intercept-type (pre-op returns decision)",
                    context={
                        "major_function": rule["major_function"],
                        "mj_name": mj_name,
                        "rule_type": "intercept",
                        "pre_behavior": behavior.get("pre_behavior"),
                    },
                    evidence=[{
                        "type": "instruction_pattern",
                        "location": f"pre-op 0x{rule['pre_operation']:X}",
                        "snippet": "intercept filter",
                        "rule_id": "MF002",
                    }],
                ))

        ir.operation_behaviors = behavior_results
        return findings

    def _analyze_callback_semantics(
        self, callback_addr: int, ir: DisassemblyResult
    ) -> dict[str, Any]:
        """Analyze a callback function's semantics."""
        result: dict[str, Any] = {
            "address": callback_addr,
            "has_return_check": False,
            "has_whitelist_check": False,
            "has_data_modification": False,
        }

        cfg = ir.cfgs.get(callback_addr) or ir.simple_cfgs.get(callback_addr)
        if not cfg:
            return result

        for block in cfg.blocks.values():
            for insn in block.instructions:
                full_text = f"{insn.mnemonic} {insn.operands}"

                # Check for return value modification (STATUS_ codes)
                if insn.mnemonic.lower() == "mov":
                    if "eax" in full_text.lower() and "0xc0" in full_text.lower():
                        result["has_return_check"] = True
                    if "eax" in full_text.lower() and "0x0" in full_text.lower():
                        result["has_return_check"] = True

                # Check for comparison patterns (whitelist checks)
                if insn.mnemonic.lower() in ("cmp", "test"):
                    if any(kw in full_text.lower() for kw in (
                        "processid", "imagefilename", "previousmode",
                        "trusted", "allowed", "whitelist",
                    )):
                        result["has_whitelist_check"] = True

        return result

    def _classify_rule_type(self, behavior: dict) -> str:
        """Classify the filter rule type based on behavior analysis.

        - intercept: pre-operation has return check → blocks/allows
        - monitor: pre-operation without return check → observes
        - tamper: post-operation modifies data → data tampering
        - passive: no significant behavior
        """
        pre = behavior.get("pre_behavior", {})
        post = behavior.get("post_behavior", {})

        if pre.get("has_return_check"):
            return "intercept"
        if post.get("has_data_modification"):
            return "tamper"
        if pre.get("has_whitelist_check"):
            return "monitor"
        if pre or post:
            return "monitor"
        return "passive"

    # ------------------------------------------------------------------
    # Filter rule classification summary
    # ------------------------------------------------------------------

    def _classify_filter_rules(self, ir: DisassemblyResult) -> list[Finding]:
        """Generate a summary classification of all filter rules."""
        findings = []

        operation_rules = getattr(ir, "operation_rules", []) or []
        operation_behaviors = getattr(ir, "operation_behaviors", []) or []

        if not operation_rules:
            return findings

        # Count rule types
        intercept_count = sum(
            1 for b in operation_behaviors if b.get("rule_type") == "intercept"
        )
        monitor_count = sum(
            1 for b in operation_behaviors if b.get("rule_type") == "monitor"
        )
        tamper_count = sum(
            1 for b in operation_behaviors if b.get("rule_type") == "tamper"
        )

        # High-severity operations
        high_severity_ops = {0x0E, 0x0F, 0x0D}  # DeviceControl, InternalDeviceControl, FileSystemControl
        high_sev_count = sum(
            1 for r in operation_rules
            if r["major_function"] in high_severity_ops
        )

        if intercept_count > 0:
            findings.append(Finding(
                category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=f"MiniFilter has {intercept_count} intercept-type filter(s)",
                context={
                    "intercept_count": intercept_count,
                    "monitor_count": monitor_count,
                    "tamper_count": tamper_count,
                    "total_rules": len(operation_rules),
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": "operation_rules",
                    "snippet": f"{intercept_count} intercept, {monitor_count} monitor",
                    "rule_id": "MF003",
                }],
            ))

        if high_sev_count > 0:
            findings.append(Finding(
                category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description=f"MiniFilter exposes {high_sev_count} IOCTL-like surface(s)",
                context={
                    "high_severity_operations": [
                        IRP_MJ_NAMES.get(r["major_function"], f"IRP_MJ_{r['major_function']:02X}")
                        for r in operation_rules
                        if r["major_function"] in high_severity_ops
                    ],
                },
                evidence=[{
                    "type": "instruction_pattern",
                    "location": "operation_rules",
                    "snippet": "IOCTL-like surface",
                    "rule_id": "MF004",
                }],
            ))

        return findings

    # ------------------------------------------------------------------
    # API-based MiniFilter detection (fallback for obfuscated drivers)
    # ------------------------------------------------------------------

    # MiniFilter API classification
    _MF_LIFECYCLE_APIS = {"FltRegisterFilter", "FltStartFiltering", "FltUnregisterFilter"}
    _MF_COMM_APIS = {"FltCreateCommunicationPort", "FltCloseCommunicationPort",
                     "FltSendMessage", "FltCloseClientPort"}
    _MF_CONTEXT_APIS = {"FltAllocateContext", "FltSetStreamHandleContext",
                        "FltGetStreamHandleContext", "FltDeleteContext",
                        "FltReleaseContext", "FltSetStreamContext",
                        "FltGetStreamContext", "FltSetFileContext",
                        "FltGetFileContext"}
    _MF_FILE_APIS = {"FltCreateFile", "FltClose", "FltReadFile", "FltWriteFile",
                     "FltQueryInformationFile", "FltSetInformationFile",
                     "FltGetFileNameInformation", "FltReleaseFileNameInformation",
                     "FltGetDestinationFileNameInformation", "FltCancelFileOpen",
                     "FltGetTunneledName"}
    _MF_VOLUME_APIS = {"FltGetDeviceObject", "FltReleaseDeviceObject",
                       "FltEnumerateFilters", "FltEnumerateInstances"}

    def _detect_minifilter_via_apis(
        self, sample: Sample, ir: DisassemblyResult,
    ) -> list[Finding]:
        """Detect MiniFilter driver via Flt* API usage patterns.

        When the PE structure parsing fails (obfuscated drivers, non-standard
        FLT_REGISTRATION layouts), fall back to API-based detection:
        - If FltRegisterFilter + FltStartFiltering are present → confirmed MiniFilter
        - Categorize the driver's capabilities by API groups
        - Report each API group as a finding
        """
        findings = []

        # Collect all unique API names used by this driver
        all_apis: set[str] = set()
        for api_list in ir.function_apis.values():
            all_apis.update(api_list)
        for api_details in ir.function_api_details.values():
            for api_info in api_details:
                all_apis.add(api_info.name)

        # Check for lifecycle APIs (confirms MiniFilter)
        lifecycle_found = all_apis & self._MF_LIFECYCLE_APIS
        comm_found = all_apis & self._MF_COMM_APIS
        context_found = all_apis & self._MF_CONTEXT_APIS
        file_found = all_apis & self._MF_FILE_APIS
        volume_found = all_apis & self._MF_VOLUME_APIS

        if not lifecycle_found:
            return findings

        # This is a confirmed MiniFilter driver
        ir.is_minifilter = True

        total_apis = len(all_apis & (
            self._MF_LIFECYCLE_APIS | self._MF_COMM_APIS |
            self._MF_CONTEXT_APIS | self._MF_FILE_APIS | self._MF_VOLUME_APIS
        ))

        findings.append(Finding(
            category=FindingCategory.MINIFILTER_CALLBACK_FOUND,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description=(
                f"MiniFilter driver confirmed via {len(lifecycle_found)} lifecycle API(s): "
                f"{', '.join(sorted(lifecycle_found))}"
            ),
            context={
                "lifecycle_apis": sorted(lifecycle_found),
                "comm_apis": sorted(comm_found),
                "context_apis": sorted(context_found),
                "file_apis": sorted(file_found),
                "volume_apis": sorted(volume_found),
                "total_flt_apis": total_apis,
                "driver_type": "minifilter",
            },
            evidence=[{
                "type": "import_pattern",
                "location": "IAT",
                "snippet": f"MiniFilter: {', '.join(sorted(lifecycle_found))}",
                "rule_id": "MF005",
            }],
        ))

        if comm_found:
            findings.append(Finding(
                category=FindingCategory.ALPC_PORT_NAME,
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                description=f"MiniFilter communication port via {', '.join(sorted(comm_found))}",
                context={"comm_apis": sorted(comm_found)},
                evidence=[{
                    "type": "import_pattern",
                    "location": "IAT",
                    "snippet": f"Comm: {', '.join(sorted(comm_found))}",
                    "rule_id": "MF006",
                }],
            ))

        if file_found:
            findings.append(Finding(
                category=FindingCategory.FILTER_CALLBACK_ANALYZED,
                severity=Severity.INFO,
                confidence=Confidence.MEDIUM,
                description=f"MiniFilter monitors file operations ({len(file_found)} APIs)",
                context={"file_apis": sorted(file_found)},
                evidence=[{
                    "type": "import_pattern",
                    "location": "IAT",
                    "snippet": f"File ops: {len(file_found)} APIs",
                    "rule_id": "MF007",
                }],
            ))

        return findings
