"""
DriverScope — Dangerous Primitive Analyzer.

Scans disassembled driver code for calls to dangerous kernel APIs
that, if exposed to user-mode via IOCTL without proper validation,
create vulnerability primitives.

MVP focus: WDM arbitrary memory mapping, MSR access, kernel R/W.
"""

from __future__ import annotations

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
from src.analysis.core.cfg_utils import cfg_reachable_funcs
from src.config.defaults import DANGEROUS_API_SET


# ---------------------------------------------------------------------------
# Dangerous API definitions grouped by primitive category.
# Each entry maps an API name pattern to a finding template.
# ---------------------------------------------------------------------------

DANGEROUS_API_RULES: list[dict] = [
    # --- Arbitrary Memory Mapping ---
    {
        "category": FindingCategory.ARBITRARY_MEMORY_MAP,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["MmMapIoSpace", "MmMapIoSpaceEx"],
        "description": (
            "Calls {api} — maps physical memory to kernel virtual address space. "
            "If the physical address is user-controlled, this enables arbitrary "
            "physical memory access."
        ),
    },
    {
        "category": FindingCategory.ARBITRARY_MEMORY_MAP,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.MEDIUM,
        "apis": ["MmMapLockedPagesSpecifyCache", "MmMapLockedPages"],
        "description": (
            "Calls {api} — maps locked pages to user-mode accessible addresses. "
            "Commonly used in BYOVD exploits to create user-mode read/write "
            "primitives to kernel memory."
        ),
    },
    {
        "category": FindingCategory.ARBITRARY_MEMORY_MAP,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["ZwMapViewOfSection", "NtMapViewOfSection"],
        "description": (
            "Calls {api} — maps a section object into a process address space. "
            "Can be used to map arbitrary memory regions."
        ),
    },

    # --- MSR Access (IAT-based) ---
    {
        "category": FindingCategory.MSR_ACCESS,
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "apis": ["KeReadMsr", "__readmsr"],
        "description": (
            "Calls {api} — reads model-specific registers. "
            "Information disclosure risk if MSR values leak kernel addresses."
        ),
    },
    {
        "category": FindingCategory.MSR_ACCESS,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "apis": ["KeWriteMsr", "__writemsr"],
        "description": (
            "Calls {api} — writes to model-specific registers. "
            "Writing to LSTAR (0xC0000082) redirects the syscall handler "
            "for arbitrary kernel code execution."
        ),
    },

    # --- MSR Access (inline instruction level) ---
    {
        "category": FindingCategory.MSR_ACCESS,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "apis": ["__insn_writemsr"],
        "description": (
            "Inline WRMSR instruction detected — writes to model-specific registers "
            "without function call overhead. Writing LSTAR (0xC0000082) redirects "
            "the syscall handler for arbitrary kernel code execution."
        ),
    },
    {
        "category": FindingCategory.MSR_ACCESS,
        "severity": Severity.MEDIUM,
        "confidence": Confidence.HIGH,
        "apis": ["__insn_readmsr"],
        "description": (
            "Inline RDMSR instruction detected — reads model-specific registers."
        ),
    },

    # --- Physical Memory Access ---
    {
        "category": FindingCategory.PHYSICAL_MEMORY_ACCESS,
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "apis": ["MmGetPhysicalAddress"],
        "description": (
            "Calls {api} — translates virtual to physical addresses. "
            "Useful for building physical memory read/write primitives."
        ),
    },
    {
        "category": FindingCategory.PHYSICAL_MEMORY_ACCESS,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["MmGetPhysicalMemoryRanges", "MmGetPhysicalMemoryRangesEx", "MmGetPhysicalMemoryRangesEx2"],
        "description": (
            "Calls {api} — enumerates physical memory ranges. "
            "Reveals the physical memory layout for targeted attacks."
        ),
    },

    # --- Kernel Read/Write ---
    {
        "category": FindingCategory.KERNEL_RW_PRIMITIVE,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["MmCopyVirtualMemory"],
        "description": (
            "Calls {api} — copies memory between processes. "
            "If source/destination process is user-controlled, "
            "enables arbitrary kernel memory read/write."
        ),
    },
    {
        "category": FindingCategory.KERNEL_RW_PRIMITIVE,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["ZwWriteVirtualMemory", "NtWriteVirtualMemory"],
        "description": (
            "Calls {api} — writes to another process's virtual memory. "
            "Can be used to modify kernel memory if target process is kernel."
        ),
    },

    # --- Code Execution ---
    {
        "category": FindingCategory.CODE_EXECUTION_PRIMITIVE,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.HIGH,
        "apis": ["ZwCreateThreadEx"],
        "description": (
            "Calls {api} — creates a thread in another process. "
            "With user-controlled start address, enables arbitrary code execution."
        ),
    },

    # --- Process Manipulation ---
    {
        "category": FindingCategory.PROCESS_MANIPULATION,
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "apis": ["ZwOpenProcess"],
        "description": (
            "Calls {api} — opens a handle to another process. "
            "With user-controlled PID, can target arbitrary processes."
        ),
    },
    {
        "category": FindingCategory.PROCESS_MANIPULATION,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["ZwQueueApcThread"],
        "description": (
            "Calls {api} — queues an APC to a thread. "
            "Can be used for code injection into arbitrary threads."
        ),
    },
    {
        "category": FindingCategory.PROCESS_MANIPULATION,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.MEDIUM,
        "apis": ["ZwSetInformationProcess"],
        "description": (
            "Calls {api} — sets process information. "
            "Can be used to swap process tokens for privilege escalation."
        ),
    },

    # --- Security / Privilege ---
    {
        "category": FindingCategory.MISSING_PRIVILEGE_CHECK,
        "severity": Severity.LOW,
        "confidence": Confidence.LOW,
        "apis": ["SeSinglePrivilegeCheck"],
        "description": (
            "Calls {api} — checks caller privilege. "
            "Presence suggests the driver attempt privilege validation, "
            "but absence does not guarantee lack of checks."
        ),
    },

    # --- DPC / Work Queue (indirect code execution) ---
    {
        "category": FindingCategory.DPC_WORK_QUEUE,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["IoQueueWorkItem"],
        "description": (
            "Calls {api} — queues work item to system thread pool. "
            "If the work item function pointer or context is user-controlled, "
            "enables deferred arbitrary code execution in kernel context."
        ),
    },
    {
        "category": FindingCategory.DPC_WORK_QUEUE,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["KeInitializeDpc"],
        "description": (
            "Calls {api} — initializes a deferred procedure call object. "
            "If the DPC routine or deferred context is user-controlled, "
            "enables arbitrary code execution at DISPATCH_LEVEL."
        ),
    },
    {
        "category": FindingCategory.DPC_WORK_QUEUE,
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "apis": ["KeSetTimer", "KeSetTimerEx"],
        "description": (
            "Calls {api} — sets a kernel timer with DPC callback. "
            "If the timer's DPC routine is user-controlled, "
            "enables timed arbitrary code execution."
        ),
    },

    # --- DMA Primitives ---
    {
        "category": FindingCategory.DMA_PRIMITIVE,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["WdfDmaEnablerCreate", "WdfDmaTransactionCreate"],
        "description": (
            "Calls {api} — creates DMA enabler/transaction. "
            "If DMA parameters are user-controlled, enables arbitrary "
            "physical memory read/write through DMA."
        ),
    },
    {
        "category": FindingCategory.DMA_PRIMITIVE,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["MmAllocateAdapterChannel", "IoGetDmaAdapter"],
        "description": (
            "Calls {api} — allocates DMA adapter channel. "
            "Can be used to set up arbitrary DMA read/write operations."
        ),
    },

    # --- Pool Manipulation ---
    {
        "category": FindingCategory.POOL_MANIPULATION,
        "severity": Severity.MEDIUM,
        "confidence": Confidence.MEDIUM,
        "apis": ["ExAllocatePoolWithTag", "ExAllocatePool", "ExAllocatePool2", "ExAllocatePool3"],
        "description": (
            "Calls {api} — allocates kernel pool memory. "
            "If the allocation size is user-controlled, enables pool overflow "
            "attacks for arbitrary kernel memory corruption."
        ),
    },

    # --- Interrupt Hooking ---
    {
        "category": FindingCategory.INTERRUPT_HOOKING,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.MEDIUM,
        "apis": ["IoConnectInterrupt", "IoConnectInterruptEx"],
        "description": (
            "Calls {api} — connects an interrupt service routine. "
            "If the ISR address is user-controlled, enables arbitrary "
            "code execution at interrupt level."
        ),
    },
    {
        "category": FindingCategory.INTERRUPT_HOOKING,
        "severity": Severity.CRITICAL,
        "confidence": Confidence.MEDIUM,
        "apis": ["HalSetSystemInformation"],
        "description": (
            "Calls {api} — sets system information via HAL. "
            "Can be abused to modify firmware-level settings or "
            "bypass security mechanisms."
        ),
    },

    # --- Handle / Object Manipulation ---
    {
        "category": FindingCategory.HANDLE_MANIPULATION,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["ObReferenceObjectByHandle"],
        "description": (
            "Calls {api} — resolves a handle to a kernel object pointer. "
            "If the handle is user-controlled, enables access to arbitrary "
            "kernel objects."
        ),
    },
    {
        "category": FindingCategory.HANDLE_MANIPULATION,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["ZwDuplicateObject"],
        "description": (
            "Calls {api} — duplicates an object handle. "
            "Can be used to escalate privileges by duplicating "
            "protected process handles."
        ),
    },

    # --- Callback Registration ---
    {
        "category": FindingCategory.CALLBACK_REGISTRATION,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": [
            "PsSetLoadImageNotifyRoutine", "PsSetCreateProcessNotifyRoutine",
            "PsSetCreateThreadNotifyRoutine",
        ],
        "description": (
            "Calls {api} — registers a kernel notification callback. "
            "If the callback routine is user-controllable or the driver "
            "can be unloaded without removing callbacks, causes system instability."
        ),
    },
    {
        "category": FindingCategory.CALLBACK_REGISTRATION,
        "severity": Severity.HIGH,
        "confidence": Confidence.MEDIUM,
        "apis": ["ObRegisterCallbacks"],
        "description": (
            "Calls {api} — registers object manager callbacks. "
            "Commonly used to bypass security software by intercepting "
            "handle creation for protected processes."
        ),
    },
]

# Set of all APIs covered by DANGEROUS_API_RULES (for fallback detection)
_RULE_COVERED_APIS = {api.lower() for rule in DANGEROUS_API_RULES for api in rule["apis"]}


class DangerousPrimitiveAnalyzer(Analyzer):
    """Scans for dangerous kernel API calls in IOCTL-reachable code paths."""

    @property
    def name(self) -> str:
        return "DangerousPrimitiveAnalyzer"

    @property
    def description(self) -> str:
        return (
            "Identifies calls to dangerous kernel APIs that create "
            "vulnerability primitives when exposed via IOCTL."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # Build a reverse lookup: API name -> rule
        api_to_rule: dict[str, dict] = {}
        for rule in DANGEROUS_API_RULES:
            for api in rule["apis"]:
                api_to_rule[api.lower()] = rule

        # Build API -> instruction address mapping per function
        func_api_addrs: dict[int, dict[str, list[int]]] = {}
        for func_addr, api_names in ir.function_apis.items():
            for api_name in api_names:
                func_api_addrs.setdefault(func_addr, {}).setdefault(api_name, [])

        # Build API -> (call_address, params_hint, user_controllable) per function
        # from function_api_details (populated by Capstone backend).
        func_call_info: dict[int, dict[str, list[dict]]] = {}
        for func_addr, api_details in getattr(ir, 'function_api_details', {}).items():
            for detail in api_details:
                api_short = detail.name.split(".")[-1] if "." in detail.name else detail.name
                func_call_info.setdefault(func_addr, {}).setdefault(api_short, []).append({
                    "call_address": detail.call_address,
                    "params_hint": detail.params_hint,
                    "user_controllable": detail.user_controllable,
                })

        # Scan all instructions for API calls via IAT.
        # Primary path: use ir.function_apis which the backend already populated
        # with func_addr -> [api_names] mappings.
        for func_addr, api_names in ir.function_apis.items():
            for api_name in api_names:
                api_short = api_name.split(".")[-1] if "." in api_name else api_name
                rule = api_to_rule.get(api_short.lower())
                if not rule:
                    continue

                # Check if this is IOCTL-reachable
                ioctl_reachable = self._is_ioctl_reachable(func_addr, ir)

                description = rule["description"].format(api=api_short)
                if not ioctl_reachable:
                    description += (
                        " Note: This API reference was not confirmed to be "
                        "on an IOCTL-reachable path."
                    )

                # Find the IAT address for this API in this function
                iat_addr = 0
                for addr, insn_name in ir.import_addresses.items():
                    iat_short = insn_name.split(".")[-1] if "." in insn_name else insn_name
                    if iat_short.lower() == api_short.lower():
                        iat_addr = addr
                        break

                # Get call instruction addresses and param context from function_api_details
                call_details = func_call_info.get(func_addr, {}).get(api_short, [])
                call_addrs = [d["call_address"] for d in call_details if d["call_address"]]
                param_hints = [d["params_hint"] for d in call_details if d.get("params_hint")]
                user_ctrl = any(d.get("user_controllable") for d in call_details)

                # Check if called by an IOCTL handler (for context)
                caller_chain = self._get_caller_chain(func_addr, ir)

                context = {
                    "iat_address": hex(iat_addr) if iat_addr else "unknown",
                    "import": api_name,
                    "ioctl_reachable": ioctl_reachable,
                    "called_by": caller_chain,
                }
                if call_addrs:
                    context["call_addresses"] = [hex(a) for a in call_addrs]
                if param_hints:
                    context["params_hints"] = param_hints
                if user_ctrl:
                    context["user_controllable"] = True

                findings.append(
                    Finding(
                        category=rule["category"],
                        severity=rule["severity"],
                        confidence=(
                            rule["confidence"]
                            if ioctl_reachable
                            else Confidence.LOW
                        ),
                        description=description,
                        function_address=func_addr,
                        instruction_address=call_addrs[0] if call_addrs else (iat_addr or 0),
                        api_name=api_short,
                        context=context,
                        evidence=[
                            Evidence(
                                type="import",
                                location=f"IAT@{hex(iat_addr)}" if iat_addr else "unknown",
                                snippet=api_name,
                                rule_id=f"PRIM_{rule['category'].value.upper()}",
                            )
                        ],
                    )
                )

        # Fallback: scan raw import addresses for APIs not found in function_apis.
        # This catches cases where the backend couldn't map the call to a function.
        covered_apis = {api for apis in ir.function_apis.values() for api in apis}
        for addr, insn_name in ir.import_addresses.items():
            api_short = insn_name.split(".")[-1] if "." in insn_name else insn_name
            if api_short in covered_apis or api_short.lower() in {a.lower() for a in covered_apis}:
                continue

            rule = api_to_rule.get(api_short.lower())
            if not rule:
                continue

            containing_func = self._find_function_containing(addr, ir)
            ioctl_reachable = self._is_ioctl_reachable(containing_func, ir)

            description = rule["description"].format(api=api_short)
            if not ioctl_reachable:
                description += (
                    " Note: This API reference was not confirmed to be "
                    "on an IOCTL-reachable path."
                )

            caller_chain = self._get_caller_chain(containing_func, ir)

            findings.append(
                Finding(
                    category=rule["category"],
                    severity=rule["severity"],
                    confidence=(
                        rule["confidence"]
                        if ioctl_reachable
                        else Confidence.LOW
                    ),
                    description=description,
                    function_address=containing_func,
                    instruction_address=addr,
                    api_name=api_short,
                    context={
                        "iat_address": hex(addr),
                        "import": insn_name,
                        "ioctl_reachable": ioctl_reachable,
                        "called_by": caller_chain,
                    },
                    evidence=[
                        Evidence(
                            type="import",
                            location=f"IAT@{hex(addr)}",
                            snippet=insn_name,
                            rule_id=f"PRIM_{rule['category'].value.upper()}",
                        )
                    ],
                )
            )

        # Phase 1: MMIO surface detection
        MMIO_APIS = {"MmMapIoSpace", "MmMapIoSpaceEx", "HalTranslateBusAddress",
                     "MmMapVideoDisplay"}
        for func_addr, api_names in ir.function_apis.items():
            mmio_found = set(api_names) & MMIO_APIS
            if mmio_found:
                ir.mmio_surfaces.append({
                    "func_addr": func_addr,
                    "apis": sorted(mmio_found),
                    "is_entry_point": self._is_ioctl_reachable(func_addr, ir),
                })

                # If MMIO API is not entry-point reachable, still flag it
                # (could be called from other un-discovered entry points)
                if not self._is_ioctl_reachable(func_addr, ir):
                    continue

                # Already covered by API-based findings above

        # Fallback detection: APIs in DANGEROUS_API_SET but not covered by rules
        for func_addr, api_names in ir.function_apis.items():
            for api_name in api_names:
                if api_name.lower() not in _RULE_COVERED_APIS and api_name in DANGEROUS_API_SET:
                    findings.append(
                        Finding(
                            category=FindingCategory.DANGEROUS_STRING,
                            severity=Severity.INFO,
                            confidence=Confidence.LOW,
                            description=(
                                f"Function sub_{func_addr:X}: Calls {api_name} "
                                f"— recognized as dangerous API (fallback detection). Review manually."
                            ),
                            function_address=func_addr,
                            api_name=api_name,
                            context={"api": api_name, "detection": "fallback"},
                            evidence=[
                                Evidence(
                                    type="import",
                                    location=f"sub_{func_addr:X}",
                                    snippet=f"Imports {api_name}",
                                    rule_id="PRIM_FALLBACK",
                                )
                            ],
                        )
                    )

        # Deduplicate findings by API name + function
        seen: set[tuple[str, int]] = set()
        unique_findings: list[Finding] = []
        for f in findings:
            key = (f.api_name, f.function_address)
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)

        return unique_findings

    def _find_function_containing(
        self,
        addr: int,
        ir: DisassemblyResult,
    ) -> int:
        """Find the function that contains the given address."""
        for func_addr, func in ir.functions.items():
            if func_addr <= addr < func_addr + max(func.size, 0x1000):
                return func_addr
        return 0

    def _is_ioctl_reachable(
        self,
        func_addr: int,
        ir: DisassemblyResult,
    ) -> bool:
        """Check if a function is reachable from any user-triggerable entry point.

        Combines strategies for all entry point types:
        1. WDF drivers: all functions reachable (framework dispatch)
        2. IRP_MJ_DEVICE_CONTROL (IOCTL) — primary path
        3. FastIO dispatch (filesystem drivers)
        4. MiniFilter callbacks (DeviceControl/FileSystemControl)
        5. IRP_MJ_PNP, IRP_MJ_POWER, IRP_MJ_SYSTEM_CONTROL (WMI)
        6. Call graph: if handler calls this function directly
        7. CFG-based: BFS through handler's CFG + call edges
        """
        # WDF driver with IOCTL capability: all functions reachable
        if ir.is_wdf_driver and (ir.irp_handlers or ir.ioctl_codes):
            return True

        # WDM: IRP_MJ_DEVICE_CONTROL handler
        if ir.irp_handlers and func_addr in ir.irp_handlers.values():
            return True

        # Phase 1: FastIO handlers
        if ir.fastio_handlers and func_addr in ir.fastio_handlers.values():
            return True

        # Phase 1: MiniFilter callbacks
        if ir.is_minifilter and ir.minifilter_handlers and func_addr in ir.minifilter_handlers.values():
            return True

        # WMI: IRP_MJ_SYSTEM_CONTROL (0x1E) handler
        if 0x1E in ir.irp_handlers and func_addr == ir.irp_handlers[0x1E]:
            return True

        # PnP: IRP_MJ_PNP (0x1B) handler
        if 0x1B in ir.irp_handlers and func_addr == ir.irp_handlers[0x1B]:
            return True

        # Power: IRP_MJ_POWER (0x1C) handler
        if 0x1C in ir.irp_handlers and func_addr == ir.irp_handlers[0x1C]:
            return True

        # Check if called by any handler type
        all_handler_addrs: set[int] = set()
        all_handler_addrs.update(ir.irp_handlers.values())
        all_handler_addrs.update(ir.fastio_handlers.values())
        all_handler_addrs.update(ir.minifilter_handlers.values())
        for handler_addr in all_handler_addrs:
            handler = ir.functions.get(handler_addr)
            if handler and func_addr in handler.calls:
                return True

        # IOCTL handler mapping (WDF or detected codes)
        if ir.ioctl_handlers and func_addr in ir.ioctl_handlers.values():
            return True

        # CFG-based: BFS from all handler types through CFG + call edges
        if all_handler_addrs:
            reachable = cfg_reachable_funcs(all_handler_addrs, ir)
            if func_addr in reachable:
                return True

        # Conservative fallback: if there's a dispatcher, assume reachable
        if ir.ioctl_dispatcher or 0xE in ir.irp_handlers:
            if func_addr in ir.functions:
                return True

        return False

    def _get_caller_chain(
        self,
        func_addr: int,
        ir: DisassemblyResult,
    ) -> list[str]:
        """Get the chain of callers leading to this function."""
        chain = []
        current = func_addr
        visited = set()
        for _ in range(5):  # Limit depth to avoid infinite recursion
            if current in visited:
                break
            visited.add(current)

            func = ir.functions.get(current)
            if not func or not func.called_by:
                break

            # Find first caller that's not this function itself
            callers = [c for c in func.called_by if c != current]
            if not callers:
                break

            caller = callers[0]
            caller_func = ir.functions.get(caller)
            if caller_func:
                chain.append(f"sub_{caller:X}")
                current = caller
            else:
                break

        return chain
