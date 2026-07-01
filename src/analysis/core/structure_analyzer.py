from __future__ import annotations

import os
from pathlib import Path

from src.models import Confidence, DisassemblyResult, Evidence, Finding, FindingCategory, Sample, Severity
from src.analysis.analyzer import Analyzer
from src.analysis.dataflow.input_tracker import DANGEROUS_SINKS


# PDB path patterns that indicate specific build toolchains or environments
PDB_TOOLCHAIN_HINTS: list[tuple[str, str]] = [
    ("\\build\\", "WDK build environment"),
    ("\\sources\\", "Driver source tree (sources file build)"),
    ("\\obj\\", "WDK object directory (intermediate build)"),
    ("\\public\\", "WDK DDK-style layout"),
    ("\\private\\", "Microsoft internal tree"),
    ("\\github\\", "GitHub Actions CI build"),
    ("\\gitlab\\", "GitLab CI build"),
    ("\\jenkins\\", "Jenkins CI build"),
    ("\\visual studio\\", "Visual Studio IDE build"),
    ("\\vs\\", "Visual Studio workspace"),
    ("\\cargo\\", "Rust kernel driver (rust-bindgen/wdk-rs)"),
    ("\\cmake", "CMake-based build system"),
    ("\\msbuild\\", "MSBuild orchestration"),
]


def _find_called_handlers(
    func_addr: int,
    candidates: set[int],
    ir,
) -> set[int]:
    """Find which candidate handler functions are called by func_addr.

    Does a BFS through the call graph starting from func_addr, collecting
    any function that appears in the candidates set.
    """
    found: set[int] = set()
    queue = [func_addr]
    visited: set[int] = set()
    max_depth = 4  # WDF setup → wrapper → handler is typically 2-3 levels

    while queue:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        if current in candidates and current != func_addr:
            found.add(current)
            continue  # Don't recurse through handlers
        func = ir.functions.get(current)
        if func:
            for callee in func.calls:
                if callee not in visited and len(visited) < max_depth * 20:
                    queue.append(callee)

    return found


class StructureAnalyzer(Analyzer):
    """Analyzes driver structure: IOCTL dispatch, IRP handlers, entry points."""

    @property
    def name(self) -> str:
        return "StructureAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Identifies IOCTL dispatch functions, extracts IOCTL codes, "
            "and maps IRP handler relationships."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # Finding 1: IOCTL dispatcher detected
        if 0xE in ir.irp_handlers:
            findings.append(
                Finding(
                    category=FindingCategory.IOCTL_DISPATCHER_FOUND,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=(
                        "Driver handles IRP_MJ_DEVICE_CONTROL — "
                        "it processes user-mode IOCTL requests."
                    ),
                    function_address=ir.irp_handlers[0xE],
                    evidence=[
                        Evidence(
                            type="instruction_pattern",
                            location=f"0x{ir.irp_handlers[0xE]:X}",
                            snippet="IRP_MJ_DEVICE_CONTROL (0xE) handler registered",
                            rule_id="STRUCT_IOCTL_DISPATCHER",
                        )
                    ],
                )
            )

        # Finding 2: IOCTL code summary
        if ir.ioctl_codes:
            findings.append(
                Finding(
                    category=FindingCategory.IOCTL_DISPATCHER_FOUND,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Driver references {len(ir.ioctl_codes)} IOCTL code(s) in dispatch logic."
                    ),
                    function_address=ir.ioctl_dispatcher,
                    context={"ioctl_count": len(ir.ioctl_codes)},
                )
            )

        # Finding 3: IOCTL handler mapping (code -> function)
        if ir.ioctl_handlers:
            handler_details = []
            method_names = {0: "METHOD_BUFFERED", 1: "METHOD_IN_DIRECT", 2: "METHOD_OUT_DIRECT", 3: "METHOD_NEITHER"}
            transfer_methods = {}
            for code, func_addr in sorted(ir.ioctl_handlers.items()):
                handler_details.append(f"0x{code:X}->sub_{func_addr:X}")
                method = code & 0x3
                transfer_methods[hex(code)] = method_names.get(method, f"UNKNOWN({method})")
            findings.append(
                Finding(
                    category=FindingCategory.IOCTL_CODE_EXPOSED,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=(
                        f"IOCTL code to handler mapping: {', '.join(handler_details[:10])}"
                        + (f" and {len(handler_details) - 10} more..." if len(handler_details) > 10 else "")
                    ),
                    context={
                        "ioctl_handlers": {hex(k): f"sub_{v:X}" for k, v in ir.ioctl_handlers.items()},
                        "transfer_methods": transfer_methods,
                    },
                )
            )

        # Finding 4: Other IRP handlers
        other_irp = {k: v for k, v in ir.irp_handlers.items() if k != 0xE}
        if other_irp:
            irp_names = {
                0x00: "IRP_MJ_CREATE",
                0x02: "IRP_MJ_CLOSE",
                0x03: "IRP_MJ_READ",
                0x04: "IRP_MJ_WRITE",
                0x0F: "IRP_MJ_INTERNAL_DEVICE_CONTROL",
                0x10: "IRP_MJ_SHUTDOWN",
                0x1B: "IRP_MJ_PNP",
                0x1C: "IRP_MJ_POWER",
            }
            handler_list = []
            for irp_idx, addr in sorted(other_irp.items()):
                name = irp_names.get(irp_idx, f"IRP_MJ_0x{irp_idx:02X}")
                handler_list.append(f"{name}(sub_{addr:X})")
            findings.append(
                Finding(
                    category=FindingCategory.IOCTL_DISPATCHER_FOUND,
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    description=f"Other IRP handlers: {', '.join(handler_list)}",
                    context={"irp_handlers": handler_list},
                )
            )

        # Finding 5: Driver type info
        if ir.is_wdf_driver:
            findings.append(
                Finding(
                    category=FindingCategory.IOCTL_DISPATCHER_FOUND,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=(
                        "WDF/KMDF driver detected — all functions potentially "
                        "reachable via framework dispatch. In WDF drivers, "
                        "EvtIoDeviceControl callbacks are not visible in the "
                        "IRP dispatch table."
                    ),
                    context={"driver_type": "WDF"},
                )
            )

        # M5: Filter driver detection — IoAttachDevice pattern
        filter_apis = {
            "IoAttachDevice",
            "IoAttachDeviceToDeviceStack",
            "IoAttachDeviceToDeviceStackSafe",
            "IoGetAttachedDevice",
            "IoGetAttachedDeviceReference",
            "IoGetDeviceAttachmentBaseRef",
        }
        detected_filter = set()
        for func_addr, api_names in ir.function_apis.items():
            for api in api_names:
                if api in filter_apis:
                    detected_filter.add(api)

        if detected_filter:
            ir.is_filter_driver = True
            findings.append(
                Finding(
                    category=FindingCategory.IOCTL_DISPATCHER_FOUND,
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Filter driver detected via {', '.join(sorted(detected_filter))}. "
                        f"Filter drivers attach to existing device stacks and can "
                        f"intercept IOCTLs without explicit IRP_MJ_DEVICE_CONTROL "
                        f"registration. All functions should be considered IOCTL-reachable."
                    ),
                    context={
                        "driver_type": "FILTER",
                        "filter_apis": sorted(detected_filter),
                    },
                )
            )

        # M5: Deferred execution detection — IoQueueWorkItem/KeInitializeDpc callbacks
        deferred_apis = {
            "IoQueueWorkItem": "work item callback",
            "IoQueueWorkItemEx": "extended work item callback",
            "KeInitializeDpc": "DPC callback",
            "KeSetTimer": "timer DPC callback",
            "KeSetTimerEx": "extended timer DPC callback",
        }
        for func_addr, api_names in ir.function_apis.items():
            for api in api_names:
                if api in deferred_apis:
                    # Try to extract callback function pointer from context
                    callback_addr = self._extract_callback_target(func_addr, ir)
                    if callback_addr:
                        # Add implicit call graph edge: handler → callback
                        handler_func = ir.functions.get(func_addr)
                        if handler_func and callback_addr not in handler_func.calls:
                            handler_func.calls.append(callback_addr)
                        callback_func = ir.functions.get(callback_addr)
                        if callback_func and func_addr not in callback_func.called_by:
                            callback_func.called_by.append(func_addr)
                        # Mark callback as IOCTL-reachable
                        ir.deferred_callbacks.setdefault(callback_addr, []).append({
                            "queue_api": api,
                            "caller_func": func_addr,
                            "callback_type": deferred_apis[api],
                        })

        # Finding 6: PDB path analysis — infer build toolchain and context
        pdb_path = sample.debug_path
        if pdb_path:
            toolchain = self._infer_toolchain(pdb_path)
            original_name = os.path.splitext(os.path.basename(pdb_path))[0]
            driver_hint = self._infer_driver_from_pdb(pdb_path)

            desc_parts = [f"PDB path reveals original build artefact: {original_name}"]
            if toolchain:
                desc_parts.append(f"build system: {toolchain}")
            if driver_hint:
                desc_parts.append(f"driver hint: {driver_hint}")

            # PDB paths on production drivers from unknown vendors are a signal
            # that the driver was built without stripping debug info
            desc = ". ".join(desc_parts) + "."

            findings.append(
                Finding(
                    category=FindingCategory.DEBUG_SYMBOLS_PRESENT,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=desc,
                    context={
                        "pdb_path": pdb_path,
                        "original_name": original_name,
                        "toolchain": toolchain,
                        "driver_hint": driver_hint,
                    },
                    evidence=[
                        Evidence(
                            type="string",
                            location="debug_directory",
                            snippet=pdb_path,
                            rule_id="STRUCT_PDB_INFO",
                        )
                    ],
                )
            )

        # Finding 7: WDF IOCTL dispatch — EvtIoDeviceControl callbacks
        if ir.is_wdf_driver:
            ir.wdf_dispatch_functions = self._extract_wdf_dispatch_functions(ir)
            # Extract real IOCTL codes from WdfRequestGetIoControlCode patterns
            self._extract_wdf_real_ioctl_codes(ir, ir.wdf_dispatch_functions)
            # Also extract WDF context objects and IO queue configs
            ir.wdf_context_objects = self._extract_wdf_context_objects(ir)
            ir.wdf_io_queue_configs = self._extract_wdf_queue_configs(ir)

        if ir.is_wdf_driver and ir.wdf_dispatch_functions:
            handler_list = []
            for code, addrs in sorted(ir.wdf_dispatch_functions.items()):
                for addr in addrs:
                    if code == 0:
                        handler_list.append(f"unknown_code->sub_{addr:X}")
                    else:
                        handler_list.append(f"0x{code:X}->sub_{addr:X}")
                        # Only inject real IOCTL codes into downstream analysis
                        ir.ioctl_handlers.setdefault(code, addr)
            if handler_list:
                # Only include real IOCTL codes (non-zero) in ioctl_codes
                real_codes = [k for k in ir.wdf_dispatch_functions.keys() if k != 0]
                if real_codes:
                    ir.ioctl_codes = sorted(set(ir.ioctl_codes) | set(real_codes))
                findings.append(
                    Finding(
                        category=FindingCategory.IOCTL_DISPATCHER_FOUND,
                        severity=Severity.INFO,
                        confidence=Confidence.HIGH,
                        description=(
                            f"WDF EvtIoDeviceControl callbacks detected: "
                            f"{', '.join(handler_list[:10])}"
                            + (f" and {len(handler_list) - 10} more..." if len(handler_list) > 10 else "")
                        ),
                        context={
                            "wdf_dispatch": {
                                hex(k): [f"sub_{a:X}" for a in v]
                                for k, v in ir.wdf_dispatch_functions.items()
                            },
                            "driver_type": "WDF",
                        },
                        evidence=[
                            Evidence(
                                type="instruction_pattern",
                                location="WdfIoQueueCreate call site",
                                snippet="WDF framework dispatch via EvtIoDeviceControl",
                                rule_id="STRUCT_WDF_DISPATCH",
                            )
                        ],
                    )
                )

        # Phase 1: PnP/Power/WMI security analysis
        SECURITY_IRP_TYPES = {
            0x1B: ("IRP_MJ_PNP", "PnP handler may expose device enumeration and arbitrary device access"),
            0x1C: ("IRP_MJ_POWER", "Power handler may expose power state manipulation"),
            0x1E: ("IRP_MJ_SYSTEM_CONTROL", "System Control (WMI) handler may expose arbitrary WMI execution"),
        }

        for irp_type, (name, desc) in SECURITY_IRP_TYPES.items():
            if irp_type in ir.irp_handlers:
                handler_addr = ir.irp_handlers[irp_type]
                func_apis = ir.function_apis.get(handler_addr, [])
                dangerous_found = [
                    api for api in func_apis
                    if api in DANGEROUS_SINKS
                ]
                if dangerous_found:
                    findings.append(
                        Finding(
                            category=FindingCategory.ARBITRARY_MEMORY_MAP,
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            description=(
                                f"{name} handler sub_{handler_addr:X} calls "
                                f"{', '.join(sorted(dangerous_found)[:5])} — {desc}"
                            ),
                            function_address=handler_addr,
                            context={"irp_type": irp_type, "irp_name": name, "dangerous_apis": dangerous_found},
                            evidence=[
                                Evidence(
                                    type="instruction_pattern",
                                    location=f"{name} handler@0x{handler_addr:X}",
                                    snippet=f"{name} with dangerous APIs: {', '.join(sorted(dangerous_found)[:5])}",
                                    rule_id=f"STRUCT_{name.replace('IRP_MJ_', '')}",
                                )
                            ],
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            category=FindingCategory.IOCTL_DISPATCHER_FOUND,
                            severity=Severity.INFO,
                            confidence=Confidence.MEDIUM,
                            description=f"{name} detected at sub_{handler_addr:X} — {desc}",
                            function_address=handler_addr,
                            context={"irp_type": irp_type, "irp_name": name},
                        )
                    )

        # Phase 1: FastIO dispatch findings
        if ir.fastio_handlers:
            handler_details = []
            for off, addr in sorted(ir.fastio_handlers.items()):
                handler_details.append(f"offset_0x{off:X}->sub_{addr:X}")
            findings.append(
                Finding(
                    category=FindingCategory.FASTIO_DISPATCHER_FOUND,
                    severity=Severity.INFO,
                    confidence=Confidence.MEDIUM,
                    description=f"FastIO dispatch detected: {', '.join(handler_details[:10])}",
                    context={"fastio_handlers": {f"0x{k:X}": f"sub_{v:X}" for k, v in ir.fastio_handlers.items()}},
                )
            )

        # Phase 1: MiniFilter findings
        if ir.is_minifilter:
            findings.append(
                Finding(
                    category=FindingCategory.MINIFILTER_CALLBACK_FOUND,
                    severity=Severity.INFO,
                    confidence=Confidence.HIGH,
                    description=(
                        f"MiniFilter driver detected. "
                        f"Callbacks: {len(ir.minifilter_handlers)} registered. "
                        f"DeviceControl/FileSystemControl callbacks are IOCTL-equivalent surfaces."
                    ),
                    context={
                        "minifilter_callbacks": {
                            f"0x{k:X}": f"sub_{v:X}" for k, v in ir.minifilter_handlers.items()
                        },
                    },
                )
            )

        # Phase 1: MMIO surface summary
        if ir.mmio_surfaces:
            entry_count = sum(1 for s in ir.mmio_surfaces if s.get("is_entry_point"))
            findings.append(
                Finding(
                    category=FindingCategory.MMIO_SURFACE,
                    severity=Severity.HIGH if entry_count > 0 else Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"MMIO surface: {len(ir.mmio_surfaces)} function(s) use "
                        f"MmMapIoSpace/HalTranslateBusAddress. "
                        f"{entry_count} reachable from entry points."
                    ),
                    context={"mmio_surfaces": ir.mmio_surfaces},
                )
            )

        return findings

    @staticmethod
    def _extract_callback_target(func_addr: int, ir) -> int | None:
        """Extract callback function pointer from deferred execution API calls.

        For IoQueueWorkItem(handler, ...) the callback is in the R8 register
        (3rd argument, x64 fastcall). For KeInitializeDpc(dpc, callback, ...)
        it's in RDX (2nd arg). For KeSetTimer(timer, due_time, dpc) it's
        in R8 (3rd arg).

        Scans instructions for lea rcx/rdx/r8, [rip+offset] patterns that
        load function pointers into argument registers before the call.
        """
        cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
        if not cfg:
            return None

        # Callback arg positions (x64 fastcall)
        callback_arg_regs = {
            "IoQueueWorkItem": "r8",       # 3rd arg
            "IoQueueWorkItemEx": "r8",     # 3rd arg
            "KeInitializeDpc": "rdx",      # 2nd arg
            "KeSetTimer": "r8",            # 3rd arg
            "KeSetTimerEx": "r8",          # 3rd arg
        }

        for block in cfg.blocks.values():
            for insn in block.instructions:
                # Look for: lea r8/rdx, [rip+offset] or mov r8/rdx, imm
                if insn.mnemonic in ("lea", "mov"):
                    for target_reg in callback_arg_regs.values():
                        if target_reg in insn.operands.lower():
                            # Try to parse the target address
                            # lea r8, [rip+0x1234] → look at what's at that address
                            if "rip" in insn.operands.lower():
                                try:
                                    offset_str = insn.operands.split("0x")[-1]
                                    offset = int(offset_str.rstrip("h"), 16)
                                    # The loaded address points to the callback
                                    target = insn.address + insn.size + offset
                                    # Mask to valid bits for function address
                                    target = target & 0xFFFFFFFFFFFFFFFF
                                    # Check if it's a known function
                                    if target in ir.functions:
                                        return target
                                except (ValueError, IndexError):
                                    pass
                            # mov r8, 0xADDR — immediate function pointer
                            elif "0x" in insn.operands.lower():
                                try:
                                    addr_str = insn.operands.split("0x")[-1]
                                    addr = int(addr_str.rstrip("h"), 16)
                                    if addr in ir.functions:
                                        return addr
                                except (ValueError, IndexError):
                                    pass
        return None

    @staticmethod
    def _extract_wdf_dispatch_functions(ir) -> dict[int, list[int]]:
        """Detect WDF EvtIoDeviceControl callback functions.

        WDF drivers register IOCTL handlers via WdfIoQueueCreate with a
        WDF_IO_QUEUE_CONFIG struct containing EvtIoDeviceControl function
        pointers.  Since the struct is populated at compile time, we
        identify handler candidates by looking for functions that call
        WDF request-completion APIs (unique to IOCTL handlers) and that
        are called from functions that themselves call WdfIoQueueCreate.

        Returns dict: IOCTL_code (placeholder) -> [handler func addrs].
        For WDF we use sequential placeholders since actual IOCTL codes
        are embedded in the handler logic, not visible in dispatch table.
        """
        # WDF-specific request APIs that only appear in EvtIo* callbacks
        wdf_request_apis = {
            "WdfRequestRetrieveInputBuffer",
            "WdfRequestRetrieveOutputBuffer",
            "WdfRequestRetrieveParameters",
            "WdfRequestComplete",
            "WdfRequestCompleteWithInformation",
            "WdfRequestSend",
            "WdfIoTargetSendIoctlSynchronously",
        }

        # Step 1: Find functions that call WdfIoQueueCreate (queue setup funcs)
        queue_setup_funcs = set()
        for func_addr, api_names in ir.function_apis.items():
            for api in api_names:
                if api == "WdfIoQueueCreate":
                    queue_setup_funcs.add(func_addr)

        # Step 2: Find functions with WDF request APIs (handler candidates)
        handler_candidates = set()
        for func_addr, api_names in ir.function_apis.items():
            for api in api_names:
                if api in wdf_request_apis:
                    handler_candidates.add(func_addr)
                    break

        # Step 3: For each queue setup func, find which handler candidates
        # it calls (directly or transitively). These are the dispatch callbacks.
        dispatch: dict[int, list[int]] = {}
        for setup_func in queue_setup_funcs:
            called_handlers = _find_called_handlers(setup_func, handler_candidates, ir)
            for handler_addr in called_handlers:
                # Use 0 as unknown marker — real IOCTL codes may be extracted
                # later by _extract_wdf_real_ioctl_codes from WdfRequestGetIoControlCode patterns.
                dispatch.setdefault(0, []).append(handler_addr)

        # If no queue setup found, fall back to all handler candidates
        if not dispatch and handler_candidates:
            for addr in handler_candidates:
                dispatch.setdefault(0, []).append(addr)

        return dispatch

    @staticmethod
    def _extract_wdf_real_ioctl_codes(
        ir,
        dispatch: dict[int, list[int]],
    ) -> None:
        """Extract real IOCTL codes from WDF handler functions.

        WDF drivers check IOCTL codes inside the EvtIoDeviceControl callback
        via WdfRequestGetIoControlCode(), then compare with known values.

        Pattern (x64):
            call    WdfRequestGetIoControlCode  ; returns IOCTL in rax
            mov     r12, rax                     ; save to register
            cmp     r12, 0x22A004                ; compare with IOCTL code
            jne     fail_path

        We scan handler candidates for this pattern and extract the
        immediate comparison values as real IOCTL codes.
        """
        import re as _re

        for handler_addr in list(dispatch.values()):
            if isinstance(handler_addr, list):
                addrs = handler_addr
            else:
                addrs = [handler_addr]

            for addr in addrs:
                cfg = ir.cfgs.get(addr) or ir.simple_cfgs.get(addr)
                if not cfg:
                    continue

                # Track which register holds the IOCTL code result
                # WdfRequestGetIoControlCode returns in rax (x64)
                ioctl_reg = None

                for block in sorted(cfg.blocks.values(), key=lambda b: b.address):
                    for insn in block.instructions:
                        full = f"{insn.mnemonic} {insn.operands}"

                        # Detect WdfRequestGetIoControlCode call
                        if insn.api_target == "WdfRequestGetIoControlCode":
                            ioctl_reg = "rax"  # x64 return value
                            continue

                        # Detect: mov reg, rax (copy return value)
                        if ioctl_reg and insn.mnemonic == "mov":
                            parts = [p.strip().lower() for p in insn.operands.split(",")]
                            if len(parts) == 2 and parts[1] == ioctl_reg:
                                ioctl_reg = parts[0]
                                continue

                        # Detect: cmp ioctl_reg, 0xNNNN
                        if ioctl_reg and insn.mnemonic == "cmp":
                            parts = [p.strip() for p in insn.operands.split(",")]
                            if len(parts) == 2 and ioctl_reg in parts[0].lower():
                                imm = parts[1]
                                # Extract hex value
                                val = None
                                try:
                                    if imm.startswith("0x"):
                                        val = int(imm, 16)
                                    elif imm.endswith("h"):
                                        val = int(imm[:-1], 16)
                                    else:
                                        val = int(imm)
                                except ValueError:
                                    pass

                                if val and val > 0x100:  # Sanity: real IOCTL > 0x100
                                    # Map this IOCTL code to the handler
                                    dispatch.setdefault(val, []).append(addr)
                                    # Also update the flat ioctl_handlers
                                    ir.ioctl_handlers.setdefault(val, addr)
                                    # Track the IOCTL code
                                    if val not in ir.ioctl_codes:
                                        ir.ioctl_codes.append(val)

        # Sort ioctl_codes for consistency
        ir.ioctl_codes = sorted(set(ir.ioctl_codes))

    @staticmethod
    def _extract_wdf_context_objects(ir) -> dict[int, list[str]]:
        """Extract WDF context object types used by each function.

        WDF drivers use WdfObjectCreate, WdfMemoryCreate, etc. to create
        framework objects. Tracking these helps understand the driver's
        data flow and context management.

        Returns dict: func_addr -> [context type names]
        """
        context_apis = {
            "WdfObjectCreate": "WDF_OBJECT",
            "WdfMemoryCreate": "WDF_MEMORY",
            "WdfStringCreate": "WDF_STRING",
            "WdfCollectionCreate": "WDF_COLLECTION",
            "WdfIoQueueCreate": "WDF_IO_QUEUE",
            "WdfIoTargetCreate": "WDF_IO_TARGET",
            "WdfDeviceCreate": "WDF_DEVICE",
            "WdfDriverCreate": "WDF_DRIVER",
            "WdfFileObjectCreate": "WDF_FILE_OBJECT",
        }

        context_map: dict[int, list[str]] = {}
        for func_addr, api_names in ir.function_apis.items():
            for api in api_names:
                if api in context_apis:
                    context_map.setdefault(func_addr, [])
                    ctx_type = context_apis[api]
                    if ctx_type not in context_map[func_addr]:
                        context_map[func_addr].append(ctx_type)

        return context_map

    @staticmethod
    def _extract_wdf_queue_configs(ir) -> list[dict]:
        """Extract WDF IO queue configuration details.

        WdfIoQueueCreate takes a WDF_IO_QUEUE_CONFIG struct that defines
        the queue type and dispatch callbacks. We extract this info
        to understand the driver's IOCTL handling strategy.

        Returns list of queue config dicts.
        """
        configs = []
        queue_types = {
            "WdfIoQueueDispatchSequential": "sequential",
            "WdfIoQueueDispatchParallel": "parallel",
            "WdfIoQueueDispatchManual": "manual",
            "WdfIoQueueDispatchProgressive": "progressive",
        }

        for func_addr, api_names in ir.function_apis.items():
            if "WdfIoQueueCreate" in api_names:
                # Determine queue type from preceding calls
                queue_type = "unknown"
                for api in api_names:
                    if api in queue_types:
                        queue_type = queue_types[api]
                        break

                configs.append({
                    "function": hex(func_addr),
                    "queue_type": queue_type,
                    "has_evt_io_device_control": any(
                        "EvtIoDeviceControl" in str(ir.functions.get(a))
                        for a in ir.function_apis
                    ),
                })

        return configs

    @staticmethod
    def _infer_toolchain(pdb_path: str) -> str:
        """Infer the build toolchain from a PDB path string."""
        pdb_lower = pdb_path.lower()
        for pattern, label in PDB_TOOLCHAIN_HINTS:
            if pattern in pdb_lower:
                return label
        # Check for WDK-style paths even without exact match
        if "windows kits" in pdb_lower or "ddk" in pdb_lower:
            return "WDK/DDK build"
        return ""

    @staticmethod
    def _infer_driver_from_pdb(pdb_path: str) -> str:
        """Infer the driver purpose from PDB path components.

        Looks for keywords in the PDB path that suggest the driver's
        role (e.g., filter, class, miniport, security, etc.).
        """
        pdb_lower = pdb_path.lower()
        hints = [
            ("filter", "filter driver (attach/detach pattern)"),
            ("class", "class driver (generic device class)"),
            ("miniport", "miniport driver (hardware-specific)"),
            ("security", "security/anti-malware driver"),
            ("antivir", "antivirus driver"),
            ("fw", "firewall driver"),
            ("net", "network driver"),
            ("storage", "storage driver"),
            ("usb", "USB driver"),
            ("gpu", "GPU/display driver"),
            ("audio", "audio driver"),
            ("hid", "human interface device driver"),
        ]
        for keyword, label in hints:
            if keyword in pdb_lower:
                return label
        return ""


# ---------------------------------------------------------------------------
# Device name extraction
# ---------------------------------------------------------------------------

def extract_device_names(ir: DisassemblyResult) -> list[str]:
    """Extract kernel device names from strings and API patterns.

    Detection strategies:
    1. Strings containing ``\\Device\\`` (kernel device object names)
    2. Strings containing ``\\DosDevices\\`` or ``\\??\\`` (symlink names)
    3. Inference from ``IoCreateSymbolicLink`` / ``IoCreateDevice`` API calls.

    Returns a list of user-accessible device names (\\\\.\\DeviceName format).
    """
    device_names: list[str] = []
    seen: set[str] = set()

    for s in ir.strings:
        if "\\Device\\" in s or "\\device\\" in s:
            parts = s.split("\\")
            for i, part in enumerate(parts):
                if part.lower() == "device" and i + 1 < len(parts):
                    name = parts[i + 1]
                    if name and name not in seen:
                        seen.add(name)
                        device_names.append(f"\\\\.\\\\{name}")

        if "\\DosDevices\\" in s or "\\dosdevices\\" in s:
            parts = s.split("\\")
            for i, part in enumerate(parts):
                if part.lower() == "dosdevices" and i + 1 < len(parts):
                    name = parts[i + 1]
                    if name and name not in seen:
                        seen.add(name)
                        device_names.append(f"\\\\.\\\\{name}")

        if s.startswith("\\??\\") and len(s) > 4:
            raw_name = s[4:]
            if raw_name and raw_name not in seen:
                seen.add(raw_name)
                device_names.append(f"\\\\.\\\\{raw_name}")

    # Infer from IoCreateSymbolicLink/IoCreateDevice calls via CFG blocks
    for func_addr, api_names in ir.function_apis.items():
        if any("IoCreateSymbolicLink" in a or "IoCreateDevice" in a for a in api_names):
            cfg = ir.cfgs.get(func_addr) or ir.simple_cfgs.get(func_addr)
            if not cfg:
                continue
            for block in cfg.blocks.values():
                for insn in block.instructions:
                    target = getattr(insn, "api_target", "")
                    if target and "\\" in str(target):
                        name_part = str(target).split("\\")[-1]
                        if name_part and name_part not in seen and len(name_part) > 2:
                            seen.add(name_part)
                            device_names.append(f"\\\\.\\\\{name_part}")

    # ALPC port names can serve as device-like communication surfaces
    for s in ir.strings:
        if s.startswith("\\RPC Control\\") or s.startswith("\\BaseNamedObjects\\"):
            name_part = s.split("\\")[-1]
            if name_part and name_part not in seen and len(name_part) > 2:
                seen.add(name_part)
                device_names.append(f"\\\\.\\\\{name_part}")

    # Global\\ prefix — commonly used for cross-session device names
    for s in ir.strings:
        if s.startswith("Global\\") and len(s) > 7:
            name_part = s[7:]
            if name_part and name_part not in seen and len(name_part) > 2:
                seen.add(name_part)
                device_names.append(f"\\\\.\\\\{name_part}")

    # PDB/debug paths often contain the driver's canonical name which can hint at device names
    if not device_names and hasattr(ir, "sample_path"):
        driver_base = Path(str(ir.sample_path)).stem.lower()
        # Strip common suffixes
        for suffix in ("64", "_win10", "_win11", "_64_win10", "x64", "_x64"):
            if driver_base.endswith(suffix.lower()):
                driver_base = driver_base[: -len(suffix)]
                break
        # Common 360 device name patterns: 360antihacker -> 360AntiHacker
        if driver_base and driver_base not in seen:
            seen.add(driver_base)
            device_names.append(f"\\\\.\\\\{driver_base}")

    return device_names
