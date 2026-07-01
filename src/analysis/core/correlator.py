"""
DriverScope — BYOVD Attack Chain Correlator.

Correlates findings from independent analyzers into cohesive attack chains.
A complete BYOVD attack chain requires:
  1. An IOCTL entry point (user-mode trigger)
  2. A dangerous kernel API (vulnerability primitive)
  3. Missing input validation (the vulnerability condition)

When all three are present in the same handler function, the correlator
produces a single high-confidence ATTACK_CHAIN finding that represents
the complete exploitation path.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.models import (
    BasicBlock,
    CFG,
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
from src.analysis.dataflow.input_tracker import run_taint_analysis
from src.config.defaults import (
    SAFE_ARITHMETIC_APIS,
    VALIDATION_APIS,
    X64_ARITHMETIC_MNEMONICS,
    ARM64_ARITHMETIC_MNEMONICS,
    X64_OVERFLOW_FLAG_CHECKS,
    ARM64_OVERFLOW_FLAG_CHECKS,
    X64_VALIDATION_BRANCHES,
    ARM64_VALIDATION_BRANCHES,
)


# APIs that constitute a BYOVD primitive, grouped by impact.
#
# Excluded from primitives (normal kernel operations that only become dangerous
# with user-controlled data, handled via taint analysis):
# - pool_manipulation: ExAllocatePool* is used by virtually every driver
# - handle_manipulation: Ob* APIs are normal object management
# - dpc_work_queue: IoQueueWorkItem/KeSetTimer are normal deferred execution;
#   only dangerous if the callback pointer/context is user-controlled
BYOVD_PRIMITIVES = {
    "arbitrary_memory_map": "arbitrary physical memory mapping",
    "msr_access": "MSR read/write capability",
    "kernel_rw_primitive": "kernel memory read/write",
    "code_execution_primitive": "remote code execution primitive",
    "process_manipulation": "process manipulation",
    "physical_memory_access": "physical memory access",
    "dma_primitive": "DMA-based physical memory access",
    "interrupt_hooking": "interrupt handler code execution",
    "callback_registration": "persistent callback code execution",
}

# Severity escalation for complete attack chains
CHAIN_SEVERITY_MAP = {
    "arbitrary_memory_map": Severity.CRITICAL,
    "msr_access": Severity.CRITICAL,
    "kernel_rw_primitive": Severity.CRITICAL,
    "code_execution_primitive": Severity.CRITICAL,
    "interrupt_hooking": Severity.CRITICAL,
    "callback_registration": Severity.CRITICAL,
    "process_manipulation": Severity.HIGH,
    "physical_memory_access": Severity.HIGH,
    "dma_primitive": Severity.HIGH,
}


@dataclass
class AttackChain:
    """A correlated attack chain linking entry point → primitive → missing validation."""
    handler_addr: int
    primitive_category: str
    primitive_apis: list[str] = field(default_factory=list)
    missing_checks: list[str] = field(default_factory=list)
    ioctl_codes: list[int] = field(default_factory=list)
    supporting_findings: list[Finding] = field(default_factory=list)
    confidence: Confidence = Confidence.LOW


class BYOVDChainCorrelator(Analyzer):
    """Correlates independent analyzer findings into BYOVD attack chains."""

    @property
    def name(self) -> str:
        return "BYOVDChainCorrelator"

    @property
    def is_correlator(self) -> bool:
        return True

    @property
    def description(self) -> str:
        return (
            "Correlates IOCTL entry points, dangerous primitives, and "
            "missing validation into complete BYOVD attack chains."
        )

    def analyze(self, sample: Sample, ir: DisassemblyResult) -> list[Finding]:
        findings: list[Finding] = []

        # Step 1: Index findings by function address
        func_findings: dict[int, list[Finding]] = {}
        for f in sample.analysis_findings:
            if f.function_address and f.function_address != 0:
                func_findings.setdefault(f.function_address, []).append(f)

        # Step 2: Identify IOCTL handler entry points
        handler_addrs = set()
        for addr in ir.ioctl_handlers.values():
            handler_addrs.add(addr)
        if 0xE in ir.irp_handlers:
            handler_addrs.add(ir.irp_handlers[0xE])
        # For WDF: all functions with dangerous sinks are reachable
        if ir.is_wdf_driver and ir.irp_handlers:
            for addr in ir.functions:
                handler_addrs.add(addr)
        # Filter driver: all functions are potentially IOCTL-reachable
        if ir.is_filter_driver and ir.irp_handlers:
            for addr in ir.functions:
                handler_addrs.add(addr)
        # Include deferred callback functions as handler extensions
        for callback_addr in ir.deferred_callbacks:
            handler_addrs.add(callback_addr)
        # Mini-filter callbacks — DeviceControl/FileSystemControl are IOCTL-equivalent
        for addr in ir.minifilter_handlers.values():
            handler_addrs.add(addr)
        # FastIO handlers — direct kernel-to-kernel IOCTL surface
        for addr in ir.fastio_handlers.values():
            handler_addrs.add(addr)
        # WMI handlers — user-accessible via \\.\root\WMI surface
        for addr in ir.wmi_handlers.values():
            handler_addrs.add(addr)
        handler_addrs.discard(0)

        # Step 2b: Detect METHOD_NEITHER IOCTLs — these pass a direct
        # user-mode pointer to the kernel, which is a vulnerability amplifier.
        # Even without dangerous primitives, METHOD_NEITHER warrants flagging.
        neither_ioctls: list[int] = []
        for code in ir.ioctl_handlers:
            if (code & 0x3) == 3:
                neither_ioctls.append(code)

        if neither_ioctls:
            ioctl_hex = ", ".join(f"0x{c:X}" for c in sorted(neither_ioctls))
            findings.append(
                Finding(
                    category=FindingCategory.MISSING_SIZE_CHECK,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Driver uses METHOD_NEITHER for IOCTL(s): {ioctl_hex}. "
                        f"This gives user-mode a direct pointer to kernel memory, "
                        f"bypassing the I/O manager's automatic copy mechanism. "
                        f"Any handler using these IOCTLs must validate pointer "
                        f"provenance, size, and accessibility."
                    ),
                    context={
                        "method_neither_ioctls": [hex(c) for c in neither_ioctls],
                    },
                    evidence=[
                        Evidence(
                            type="code",
                            location="ioctl_dispatcher",
                            snippet=f"METHOD_NEITHER IOCTLs: {ioctl_hex}",
                            rule_id="IOCTL_METHOD_NEITHER",
                        )
                    ],
                )
            )

        # Step 3: For each handler with findings, check for complete chains
        chains: list[AttackChain] = []

        for handler_addr in handler_addrs:
            findings_for_func = func_findings.get(handler_addr, [])
            if not findings_for_func:
                continue

            chain = self._build_chain(handler_addr, findings_for_func, ir)
            if chain:
                chains.append(chain)

        # Step 4: Generate correlated findings
        for chain in chains:
            primitive_desc = BYOVD_PRIMITIVES.get(chain.primitive_category, chain.primitive_category)
            missing_desc = " + ".join(chain.missing_checks) if chain.missing_checks else "none"

            # Build description
            desc_parts = [
                f"Complete BYOVD attack chain detected in sub_{chain.handler_addr:X}:",
                f"  Entry: IOCTL handler function",
                f"  Primitive: {primitive_desc} via {', '.join(chain.primitive_apis)}",
                f"  Missing validation: {missing_desc}",
            ]
            if chain.ioctl_codes:
                ioctl_hex = ", ".join(f"0x{c:X}" for c in chain.ioctl_codes[:5])
                desc_parts.append(f"  Exposed IOCTLs: {ioctl_hex}")
            if ir.is_wdf_driver:
                desc_parts.append("  Framework: WDF (all functions IOCTL-reachable)")
            if ir.is_filter_driver:
                desc_parts.append("  Driver type: Filter (intercepts IOCTLs via device stack)")
            # Taint confirmation
            taint_finding = next(
                (f for f in chain.supporting_findings
                 if f.context.get("taint_sources")),
                None,
            )
            if taint_finding:
                sources = ", ".join(taint_finding.context.get("taint_sources", []))
                sinks = ", ".join(taint_finding.context.get("taint_sinks", []))
                desc_parts.append(f"  Taint: {sources} → {sinks}")

            description = "\n".join(desc_parts)

            # Determine severity
            chain_severity = CHAIN_SEVERITY_MAP.get(chain.primitive_category, Severity.HIGH)

            findings.append(
                Finding(
                    category=FindingCategory.ATTACK_CHAIN,
                    severity=chain_severity,
                    confidence=chain.confidence,
                    description=description,
                    function_address=chain.handler_addr,
                    context={
                        "chain_type": "byovd_complete",
                        "primitive_category": chain.primitive_category,
                        "primitive_apis": chain.primitive_apis,
                        "missing_checks": chain.missing_checks,
                        "ioctl_codes": [hex(c) for c in chain.ioctl_codes],
                        "num_supporting_findings": len(chain.supporting_findings),
                    },
                    evidence=[
                        Evidence(
                            type="cfg_path",
                            location=f"sub_{chain.handler_addr:X}",
                            snippet=f"BYOVD chain: {', '.join(chain.primitive_apis)} without {missing_desc}",
                            rule_id="CHAIN_BYOVD_COMPLETE",
                        )
                    ],
                )
            )

        # Step 5: Partial chain summary
        partial_chains = self._find_partial_chains(handler_addrs, func_findings)
        if partial_chains:
            for partial in partial_chains:
                findings.append(
                    Finding(
                        category=FindingCategory.ATTACK_CHAIN,
                        severity=Severity.MEDIUM,
                        confidence=Confidence.LOW,
                        description=partial,
                        context={"chain_type": "byovd_partial"},
                        evidence=[
                            Evidence(
                                type="cfg_path",
                                location="multiple",
                                snippet="Partial attack chain — dangerous API present, validation status unclear",
                                rule_id="CHAIN_BYOVD_PARTIAL",
                            )
                        ],
                    )
                )

        return findings

    def _build_chain(
        self,
        handler_addr: int,
        findings: list[Finding],
        ir: DisassemblyResult,
    ) -> AttackChain | None:
        """Build an attack chain from findings for a single handler function.

        Uses path-level CFG analysis: for each dangerous API, checks whether
        the call site is reachable from the handler without passing through
        a validation block (size check, privilege check, etc.).
        """
        primitive_findings = []
        validation_findings = []
        ioctl_findings = []

        for f in findings:
            cat = f.category.value
            if cat in BYOVD_PRIMITIVES:
                primitive_findings.append(f)
            elif cat in (
                "unvalidated_user_input", "missing_privilege_check",
                "missing_size_check", "partial_validation",
            ):
                validation_findings.append(f)
            elif cat in ("ioctl_code_exposed", "ioctl_dispatcher"):
                ioctl_findings.append(f)

        # Need at least one dangerous primitive to form a chain
        if not primitive_findings:
            return None

        # Group primitives by category
        prim_by_cat: dict[str, list[Finding]] = {}
        for f in primitive_findings:
            prim_by_cat.setdefault(f.category.value, []).append(f)

        # Build chains — one per primitive category
        best_chain: AttackChain | None = None
        best_score = 0

        # Run taint analysis once per handler (expensive, cache result)
        taint_result = run_taint_analysis(handler_addr, ir)

        for cat, cat_findings in prim_by_cat.items():
            apis = list({f.api_name for f in cat_findings if f.api_name})
            if not apis:
                continue

            # Determine missing checks from validation findings
            missing = set()
            for vf in validation_findings:
                checks = vf.context.get("missing_checks", [])
                missing.update(checks)

            # Get IOCTL codes for this handler
            ioctl_codes = []
            for if_ in ioctl_findings:
                if if_.ioctl_code:
                    ioctl_codes.append(if_.ioctl_code)

            # Also check ir.ioctl_handlers for this function
            for code, addr in ir.ioctl_handlers.items():
                if addr == handler_addr:
                    ioctl_codes.append(code)

            # Taint analysis: check if any of this category's APIs are
            # reached by user input.  This is the strongest BYOVD signal —
            # user-controlled data flowing to a dangerous primitive without
            # validation is a complete exploit path.
            taint_confirmed = False
            taint_sinks_for_cat: list[str] = []
            if taint_result.tainted_reaches_dangerous_api:
                for sink in taint_result.sinks:
                    if sink.api_name in apis:
                        taint_confirmed = True
                        taint_sinks_for_cat.append(
                            f"{sink.api_name}({sink.tainted_param})"
                        )
                # Also check by API name match against known dangerous sinks
                # even if not in the exact apis list (covers ordinal imports)
                if not taint_confirmed:
                    for sink in taint_result.sinks:
                        sink_api = sink.api_name
                        for api in apis:
                            if api.lower() in sink_api.lower() or sink_api.lower() in api.lower():
                                taint_confirmed = True
                                taint_sinks_for_cat.append(
                                    f"{sink.api_name}({sink.tainted_param})"
                                )
                                break

            # Path-level CFG analysis: check if dangerous API call sites
            # are reachable from the handler without validation guards.
            # For each primitive finding with an instruction_address,
            # verify CFG reachability and check for validation gaps.
            path_unprotected = 0
            path_protected = 0
            has_overflow_bypass = False
            for pf in cat_findings:
                if pf.instruction_address and pf.instruction_address != 0:
                    # Check if this call site is CFG-reachable from handler
                    if not self._cfg_reachable(handler_addr, pf.instruction_address, ir):
                        continue
                    # Check if there's validation on the path
                    is_protected, is_overflow_risky = self._path_has_validation(
                        handler_addr, pf.instruction_address, ir,
                    )
                    if is_protected and not is_overflow_risky:
                        path_protected += 1
                    elif is_overflow_risky:
                        has_overflow_bypass = True
                        path_unprotected += 1
                    else:
                        path_unprotected += 1
                        # Add the specific missing validation types
                        for check_type in _infer_missing_checks(
                            handler_addr, pf.instruction_address, ir,
                        ):
                            # Skip "cfg_unavailable" — it's metadata, not a check
                            if check_type == "cfg_unavailable":
                                continue
                            missing.add(check_type)

            # If path is unprotected but no specific checks inferred,
            # the entire path lacks validation — flag it clearly.
            if path_unprotected > 0 and not missing:
                missing.add("no_validation_on_path")

            has_validation_gap = path_unprotected > 0 or bool(missing)
            has_ioctl_context = bool(ioctl_codes)

            # Integer overflow bypass detection: if we found arithmetic
            # before a cmp without overflow flag check, flag it
            if has_overflow_bypass:
                missing.add("integer_overflow")
                # Overflow bypass on a validated path is still dangerous
                has_validation_gap = True

            # CFG-based reachability
            cfg_reachable = self._cfg_reachable_funcs(handler_addr, ir)
            has_cfg_confirmation = any(
                pf.function_address in cfg_reachable or pf.function_address == handler_addr
                for pf in cat_findings if pf.function_address
            )

            # Check if any IOCTL uses METHOD_NEITHER (direct user pointer)
            has_neither_method = any(
                (code & 0x3) == 3 for code in ioctl_codes
            )

            # WDF dispatch marker
            is_wdf_dispatch = bool(ir.wdf_dispatch_functions) if ir.is_wdf_driver else False

            # Score and confidence calculation — taint confirmation is
            # the highest signal: user input proven to reach dangerous API
            if taint_confirmed and has_validation_gap:
                confidence = Confidence.HIGH
                score = 15 + path_unprotected  # Highest priority: confirmed taint + no validation
            elif taint_confirmed and path_unprotected == 0:
                confidence = Confidence.HIGH
                score = 12  # Taint confirmed but paths are protected — still risky
            elif has_validation_gap and path_unprotected > 0:
                confidence = Confidence.HIGH
                score = 10 + path_unprotected
            elif has_validation_gap and has_cfg_confirmation:
                confidence = Confidence.HIGH
                score = 10
            elif has_validation_gap:
                confidence = Confidence.HIGH
                score = 9
            elif has_neither_method and has_cfg_confirmation:
                confidence = Confidence.HIGH
                score = 8
            elif has_neither_method:
                confidence = Confidence.MEDIUM
                score = 7
            elif is_wdf_dispatch and has_cfg_confirmation:
                confidence = Confidence.MEDIUM
                score = 5
            elif has_ioctl_context and has_cfg_confirmation:
                confidence = Confidence.LOW
                score = 4
            elif has_ioctl_context:
                confidence = Confidence.LOW
                score = 3
            else:
                confidence = Confidence.LOW
                score = 3

            if score > best_score:
                chain = AttackChain(
                    handler_addr=handler_addr,
                    primitive_category=cat,
                    primitive_apis=apis,
                    missing_checks=sorted(missing),
                    ioctl_codes=list(set(ioctl_codes)),
                    supporting_findings=cat_findings + validation_findings,
                    confidence=confidence,
                )
                # Add path-level metadata
                chain.supporting_findings.extend([
                    f for f in cat_findings if f.instruction_address
                ])
                # Store taint metadata on the chain for reporting
                if taint_confirmed:
                    chain.supporting_findings.extend([
                        f for f in cat_findings
                        if f.api_name in taint_sinks_for_cat
                    ])
                best_chain = chain
                best_score = score

        # If we found a chain, attach taint context to supporting findings
        if best_chain:
            # Enrich the chain's missing_checks with taint-confirmed info
            if taint_result.tainted_reaches_dangerous_api:
                best_chain.supporting_findings.append(
                    Finding(
                        category=FindingCategory.UNVALIDATED_USER_INPUT,
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            f"Taint analysis confirms user input reaches "
                            f"dangerous API in sub_{handler_addr:X}: "
                            f"{', '.join(taint_sinks_for_cat) if taint_sinks_for_cat else 'see sinks'}"
                        ),
                        function_address=handler_addr,
                        context={
                            "taint_sources": [
                                f"{s.field_name}@0x{s.irp_offset:X}"
                                for s in taint_result.sources
                            ],
                            "taint_sinks": [
                                f"{s.api_name}({s.tainted_param})"
                                for s in taint_result.sinks
                            ],
                            "tainted_params": taint_result.tainted_params,
                        },
                        evidence=[
                            Evidence(
                                type="data_flow",
                                location=f"sub_{handler_addr:X}",
                                snippet=(
                                    f"IRP → {', '.join(taint_result.tainted_params)} → "
                                    f"{', '.join(s.api_name for s in taint_result.sinks)}"
                                ),
                                rule_id="TAINT_CONFIRMED",
                            )
                        ],
                    )
                )

        # Don't return chains below score 5 — without a validation gap,
        # taint confirmation, or METHOD_NEITHER, a dangerous API in an
        # IOCTL handler is just the driver doing its job.
        if best_chain and best_score < 5:
            return None

        return best_chain

    def _find_partial_chains(
        self,
        handler_addrs: set[int],
        func_findings: dict[int, list[Finding]],
    ) -> list[str]:
        """Find functions with dangerous APIs but no validation analysis."""
        partials = []
        for addr in handler_addrs:
            findings = func_findings.get(addr, [])
            has_primitive = any(f.category.value in BYOVD_PRIMITIVES for f in findings)
            has_validation = any(
                f.category.value in (
                    "unvalidated_user_input", "missing_privilege_check",
                    "missing_size_check", "partial_validation",
                )
                for f in findings
            )
            if has_primitive and not has_validation:
                apis = {f.api_name for f in findings if f.api_name and f.category.value in BYOVD_PRIMITIVES}
                if apis:
                    partials.append(
                        f"Function sub_{addr:X} calls {', '.join(sorted(apis))} "
                        f"but input validation was not analyzed — manual review recommended"
                    )
        return partials

    def _cfg_reachable_funcs(
        self,
        handler_addr: int,
        ir: DisassemblyResult,
    ) -> set[int]:
        """Get all function addresses reachable from a handler via call edges."""
        return cfg_reachable_funcs({handler_addr}, ir)

    def _cfg_reachable(
        self,
        handler_addr: int,
        target_addr: int,
        ir: DisassemblyResult,
    ) -> bool:
        """Check if target_addr is CFG-reachable from handler_addr.

        Uses intra-function basic block reachability if both addresses
        are in the same function, otherwise falls back to call graph.
        """
        # Same function: check basic block reachability
        cfg = ir.cfgs.get(handler_addr) or ir.simple_cfgs.get(handler_addr)
        if cfg:
            target_block = None
            entry_block = None
            for block in cfg.blocks.values():
                if block.address <= target_addr < block.end_address:
                    target_block = block
                if block.address == cfg.entry_block:
                    entry_block = block

            if target_block and entry_block:
                return self._block_reachable(entry_block, target_block, cfg)

        # Cross-function: check call graph
        return target_addr in self._cfg_reachable_funcs(handler_addr, ir)

    @staticmethod
    def _block_reachable(
        start: BasicBlock,
        target: BasicBlock,
        cfg: CFG,
    ) -> bool:
        """BFS through CFG basic blocks to check reachability."""
        queue = [start.address]
        visited: set[int] = set()
        while queue:
            addr = queue.pop(0)
            if addr in visited:
                continue
            visited.add(addr)
            if addr == target.address:
                return True
            block = cfg.blocks.get(addr)
            if block:
                queue.extend(block.successors)
        return False

    def _path_has_validation(
        self,
        handler_addr: int,
        api_call_addr: int,
        ir: DisassemblyResult,
    ) -> bool:
        """Check if all CFG paths from handler to api_call pass through validation.

        Validation patterns:
        - Size checks: compares input buffer size against expected minimum
        - Privilege checks: SeSinglePrivilegeCheck, ExGetPreviousMode
        - ProbeForRead/Write calls
        - METHOD_BUFFERED IOCTL (implicit kernel-buffered I/O)

        Uses cross-function analysis: scans callees on the path between
        handler and the API call for validation in helper functions.

        Returns True if ALL paths have at least one validation,
        False if ANY path reaches the API call without validation.
        """
        cfg = ir.cfgs.get(handler_addr) or ir.simple_cfgs.get(handler_addr)
        if not cfg:
            return False, True  # No CFG data, assume unprotected + overflow risky

        validation_blocks, overflow_risky_blocks = self._find_validation_blocks(cfg, ir)

        # Cross-function: scan callees for validation in helper functions.
        # Only count cross-function validation if the dangerous API call
        # is actually inside a validated callee (not just any callee).
        cross_func_validated = False
        cross_func_overflow_risky = False
        handler_cfg = cfg  # Remember the handler's CFG for BFS below
        if ir.functions:
            handler_func = ir.functions.get(handler_addr)
            if handler_func:
                callees = self._collect_callees(handler_addr, ir)
                for callee_addr in callees:
                    callee_cfg = ir.cfgs.get(callee_addr) or ir.simple_cfgs.get(callee_addr)
                    if callee_cfg:
                        cv, co = self._find_validation_blocks(callee_cfg, ir)
                        if cv:
                            # Check if api_call_addr is within this callee's function
                            callee_func = ir.functions.get(callee_addr)
                            if callee_func and (
                                callee_func.address <= api_call_addr
                                < callee_func.address + max(callee_func.size, 0x1000)
                            ):
                                cross_func_validated = True
                        if co:
                            callee_func = ir.functions.get(callee_addr)
                            if callee_func and (
                                callee_func.address <= api_call_addr
                                < callee_func.address + max(callee_func.size, 0x1000)
                            ):
                                cross_func_overflow_risky = True

        if not validation_blocks and not cross_func_validated:
            return False, False  # No validation anywhere

        # If handler has no validation but callee (containing api_call) does
        if not validation_blocks and cross_func_validated:
            return True, cross_func_overflow_risky

        # Check if any path from entry to call site avoids validation
        # BFS from entry, tracking whether we've seen validation
        entry_block = handler_cfg.blocks.get(handler_cfg.entry_block)
        if not entry_block:
            return False, False

        # Find the block containing the API call
        call_block = None
        for block in handler_cfg.blocks.values():
            if block.address <= api_call_addr < block.end_address:
                call_block = block
                break

        if not call_block:
            return False, False

        # BFS: (block_addr, has_seen_validation)
        # If we can reach call_block with has_seen_validation=False, unprotected
        queue = [(entry_block.address, entry_block.address in validation_blocks)]
        visited: dict[int, bool] = {entry_block.address: queue[0][1]}

        while queue:
            block_addr, has_val = queue.pop(0)
            if block_addr == call_block.address and not has_val:
                # Check if the only "validation" on any path is overflow-risky
                has_overflow_risk = any(
                    ba in overflow_risky_blocks for ba in visited
                ) or cross_func_overflow_risky
                return False, has_overflow_risk  # Unprotected, with overflow flag

            block = handler_cfg.blocks.get(block_addr)
            if block:
                for succ_addr in block.successors:
                    succ_has_val = has_val or succ_addr in validation_blocks
                    if succ_addr not in visited or not visited[succ_addr]:
                        visited[succ_addr] = succ_has_val
                        queue.append((succ_addr, succ_has_val))

        # All paths have validation — but check for overflow bypass
        has_overflow_risk = len(overflow_risky_blocks) > 0 or cross_func_overflow_risky
        return True, has_overflow_risk

    def _collect_callees(
        self,
        func_addr: int,
        ir: DisassemblyResult,
        max_depth: int = 3,
    ) -> set[int]:
        """Collect all transitive callees of func_addr up to max_depth.

        Returns function addresses of callees (not the function itself).
        """
        callees: set[int] = set()
        queue = [(func_addr, 0)]
        visited: set[int] = {func_addr}

        while queue:
            addr, depth = queue.pop(0)
            if depth >= max_depth:
                continue
            func = ir.functions.get(addr)
            if func:
                for callee in func.calls:
                    if callee not in visited:
                        visited.add(callee)
                        callees.add(callee)
                        queue.append((callee, depth + 1))

        return callees

    @staticmethod
    def _find_validation_blocks(cfg: CFG, ir: DisassemblyResult) -> tuple[set[int], set[int]]:
        """Identify basic blocks that contain validation logic.

        Returns:
            (validation_blocks, overflow_risky_blocks)
            - validation_blocks: blocks with genuine size/privilege checks
            - overflow_risky_blocks: blocks with cmp preceded by
              arithmetic (add/mul/etc) without overflow flag check

        Supports both x64 and ARM64 architectures.
        """
        is_arm64 = getattr(ir, "is_arm64", False)

        if is_arm64:
            arith_mnemonics = ARM64_ARITHMETIC_MNEMONICS
            overflow_flag_checks = ARM64_OVERFLOW_FLAG_CHECKS
            validation_branches = ARM64_VALIDATION_BRANCHES
        else:
            arith_mnemonics = X64_ARITHMETIC_MNEMONICS
            overflow_flag_checks = X64_OVERFLOW_FLAG_CHECKS
            validation_branches = X64_VALIDATION_BRANCHES
        cmp_mnemonic = "cmp"

        validation_blocks: set[int] = set()
        overflow_risky_blocks: set[int] = set()

        for block in cfg.blocks.values():
            has_validation_api = False
            has_genuine_cmp = False
            has_overflow_check = False
            has_safe_arith_api = False

            # First pass: detect overflow checks and safe APIs
            for insn in block.instructions:
                if insn.api_target in VALIDATION_APIS:
                    has_validation_api = True
                if insn.api_target in SAFE_ARITHMETIC_APIS:
                    has_safe_arith_api = True
                if insn.mnemonic.lower() in overflow_flag_checks:
                    has_overflow_check = True

            # Second pass: detect cmp with preceding arithmetic
            cmp_instructions = []
            for insn in block.instructions:
                # ARM64 cmp operands don't use # prefix; check both formats
                is_cmp = insn.mnemonic.lower() == cmp_mnemonic
                has_immediate = "#" in insn.operands or "," in insn.operands
                if is_cmp and has_immediate:
                    cmp_instructions.append(insn)

            for insn in cmp_instructions:
                try:
                    # Extract immediate value: "rax, #0x1000" (x64) or "x0, #0x1000" (ARM64)
                    # Also handle bare hex: "x0, 0x1000" (some ARM64 disassemblers)
                    if "#" in insn.operands:
                        val_str = insn.operands.split("#")[-1].rstrip("h").strip()
                    else:
                        # Bare hex: extract value after last comma
                        val_str = insn.operands.split(",")[-1].strip().rstrip("h")

                    if val_str.startswith("0x"):
                        val = int(val_str, 16)
                    else:
                        val = int(val_str)

                    if 0 < val < 0x10000:
                        # Find index of this cmp in the block
                        cmp_idx = None
                        for j, bi in enumerate(block.instructions):
                            if bi.address == insn.address:
                                cmp_idx = j
                                break

                        has_preceding_arith = False
                        if cmp_idx is not None:
                            for j in range(max(0, cmp_idx - 5), cmp_idx):
                                if block.instructions[j].mnemonic.lower() in arith_mnemonics:
                                    has_preceding_arith = True
                                    break

                        if has_preceding_arith:
                            if has_overflow_check or has_safe_arith_api:
                                has_genuine_cmp = True
                            else:
                                overflow_risky_blocks.add(block.address)
                        else:
                            has_genuine_cmp = True
                except ValueError:
                    pass

            # ARM64 validation branches
            for insn in block.instructions:
                if insn.mnemonic.lower() in validation_branches:
                    validation_blocks.add(block.address)

            if has_validation_api:
                validation_blocks.add(block.address)
            if has_genuine_cmp:
                validation_blocks.add(block.address)
            if block.address in overflow_risky_blocks:
                validation_blocks.discard(block.address)

        return validation_blocks, overflow_risky_blocks


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _infer_missing_checks(
    handler_addr: int,
    api_call_addr: int,
    ir: DisassemblyResult,
) -> list[str]:
    """Infer what validation checks are missing on the path to api_call_addr.

    Examines only the CFG blocks that are on at least one path from the
    handler entry to the block containing the API call, rather than
    scanning the entire function.

    Enhanced v2:
    - Better integer overflow detection: only flag when arithmetic feeds
      a cmp that looks like a size check (0 < val < 0x10000)
    - Better validation pattern recognition (test+jcc, bound, etc.)
    - Support for more validation modes (ExGetPreviousMode, etc.)
    """
    missing = []
    cfg = ir.cfgs.get(handler_addr) or ir.simple_cfgs.get(handler_addr)
    if not cfg:
        return ["cfg_unavailable"]

    # Find the block containing the API call
    call_block_addr = None
    for block_addr, block in cfg.blocks.items():
        if block.address <= api_call_addr < block.end_address:
            call_block_addr = block_addr
            break

    if call_block_addr is None:
        return ["cfg_unavailable"]

    # BFS from entry to call block, collecting all blocks reachable
    # without passing through validation (the "unprotected" path)
    entry_block = cfg.blocks.get(cfg.entry_block)
    if not entry_block:
        return ["cfg_unavailable"]

    is_arm64 = getattr(ir, "is_arm64", False)
    arith_mnemonics = ARM64_ARITHMETIC_MNEMONICS if is_arm64 else X64_ARITHMETIC_MNEMONICS
    overflow_flag_checks = ARM64_OVERFLOW_FLAG_CHECKS if is_arm64 else X64_OVERFLOW_FLAG_CHECKS

    # Collect blocks on paths that reach the call block
    # Forward BFS from entry, backward BFS from call block
    forward_reachable: set[int] = set()
    queue = [entry_block.address]
    while queue:
        addr = queue.pop(0)
        if addr in forward_reachable:
            continue
        forward_reachable.add(addr)
        block = cfg.blocks.get(addr)
        if block:
            for succ in block.successors:
                if succ not in forward_reachable:
                    queue.append(succ)

    if call_block_addr not in forward_reachable:
        return ["cfg_unavailable"]

    # Backward: which blocks can reach the call block?
    backward_reachable: set[int] = {call_block_addr}
    # Build predecessor map
    predecessors: dict[int, set[int]] = {}
    for block in cfg.blocks.values():
        for succ in block.successors:
            predecessors.setdefault(succ, set()).add(block.address)

    queue = [call_block_addr]
    while queue:
        addr = queue.pop(0)
        for pred in predecessors.get(addr, set()):
            if pred not in backward_reachable and pred in forward_reachable:
                backward_reachable.add(pred)
                queue.append(pred)

    # Only inspect blocks on the actual path
    path_blocks = forward_reachable & backward_reachable

    has_privilege_check = False
    has_size_check = False
    has_probe = False
    # For overflow: only flag if arithmetic feeds a cmp that looks like a
    # size check (immediate comparison in range 0 < val < 0x10000) without
    # an overflow flag check. This avoids false positives on unrelated
    # arithmetic (e.g., pointer math, index calculations).
    has_risky_arith_cmp = False
    has_overflow_check = False
    # Track which cmp values look like size checks (for overflow detection)
    size_check_cmps: list[int] = []  # list of immediate values from cmp

    for block_addr in path_blocks:
        block = cfg.blocks.get(block_addr)
        if not block:
            continue

        # Collect arithmetic instructions in this block
        arith_addrs = set()
        for insn in block.instructions:
            if insn.mnemonic.lower() in arith_mnemonics:
                arith_addrs.add(insn.address)

        # Check each instruction
        for insn in block.instructions:
            if insn.api_target in VALIDATION_APIS:
                has_privilege_check = True
            if insn.api_target in {"ProbeForRead", "ProbeForWrite", "MmProbeAndLockPages"}:
                has_probe = True

            # Size check detection: cmp with immediate value
            is_cmp = insn.mnemonic.lower() in ("cmp", "test")
            has_immediate = "#" in insn.operands or "," in insn.operands
            if is_cmp and has_immediate:
                # Extract immediate value for size check detection
                try:
                    if "#" in insn.operands:
                        val_str = insn.operands.split("#")[-1].rstrip("h").strip()
                    else:
                        # Bare hex: extract value after last comma
                        val_str = insn.operands.split(",")[-1].strip().rstrip("h")

                    if val_str.startswith("0x"):
                        val = int(val_str, 16)
                    else:
                        val = int(val_str)

                    # Only consider it a size check if value is in reasonable range
                    if 0 < val < 0x10000:
                        has_size_check = True
                        size_check_cmps.append(val)

                    # Overflow risk: arithmetic feeds any cmp used as validation
                    # (not just size-check range). Check if there's arithmetic
                    # immediately before this cmp.
                    if arith_addrs:
                        cmp_addr = insn.address
                        # Find preceding arithmetic within 5 instructions
                        for j, bi in enumerate(block.instructions):
                            if bi.address == cmp_addr:
                                for k in range(max(0, j - 5), j):
                                    if block.instructions[k].address in arith_addrs:
                                        has_risky_arith_cmp = True
                                        break
                                break

                    if val == 0:
                        # cmp reg, 0 is often a null check, not size check
                        has_size_check = True
                except ValueError:
                    has_size_check = True  # Unknown cmp pattern, count as validation

            if insn.mnemonic.lower() in overflow_flag_checks:
                has_overflow_check = True

    # Check for privilege check patterns
    # ExGetPreviousMode comparison: cmp al, 1 (user mode) or cmp al, 0 (kernel mode)
    # SeSinglePrivilegeCheck: already handled by VALIDATION_APIS

    if not has_privilege_check:
        missing.append("privilege_check")
    if not has_size_check:
        missing.append("size_check")
    if not has_probe:
        missing.append("probe_check")
    if has_risky_arith_cmp and not has_overflow_check:
        missing.append("integer_overflow")

    return missing
