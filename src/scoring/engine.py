"""
DriverScope — Scoring engine interface.

Aggregates findings from multiple analyzers into a single risk score.
Optimized for BYOVD detection: multiple vulnerable functions + dangerous
memory mapping APIs + no validation = high risk.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from src.models import Finding, Report, RiskScore, Sample
from src.config.defaults import CATEGORY_WEIGHTS


class ScoringEngine(ABC):
    """Base class for scoring engines."""

    @abstractmethod
    def score(self, sample: Sample, findings: list[Finding]) -> RiskScore:
        """Calculate risk score for a single sample."""

    @abstractmethod
    def explain(self, sample: Sample, findings: list[Finding]) -> list[str]:
        """Return human-readable explanation of why this score was assigned."""


class DefaultScoringEngine(ScoringEngine):
    """Default scoring engine tuned for BYOVD vulnerability detection.

    Key design decisions:
    - UNVALIDATED_USER_INPUT is the primary BYOVD indicator (weight 1.5)
    - Dangerous memory mapping APIs are the primary attack surface
    - Multiple vulnerable functions = exponentially higher risk (count^0.5)
    - MISSING_SIZE_CHECK is supporting evidence, not a separate finding
    - Wave 1-3: String decryption, API hash resolution, and advanced taint
      findings are factored into the score as risk amplifiers.
    """

    SEVERITY_WEIGHTS = {
        "critical": 2.5,
        "high": 1.8,
        "medium": 1.0,
        "low": 0.4,
        "info": 0.0,
    }

    CONFIDENCE_MULTIPLIERS = {
        1.0: 1.0,   # CERTAIN — full weight
        0.9: 1.0,   # HIGH confidence — full weight
        0.7: 0.7,   # MEDIUM confidence — reduced weight
        0.4: 0.4,   # LOW confidence — minimal weight
    }

    # APIs that are especially dangerous for BYOVD
    BYOVD_CRITICAL_APIS = {
        "MmMapLockedPagesSpecifyCache",
        "MmMapLockedPages",
        "MmMapIoSpace",
        "MmMapIoSpaceEx",
        "KeWriteMsr",
        "__writemsr",
        "MmCopyVirtualMemory",
        "IoConnectInterrupt",
        "IoConnectInterruptEx",
        "ZwCreateThreadEx",
    }

    # Wave 1: Dangerous decrypted string patterns that elevate risk
    DANGEROUS_DECRYPTED_STRINGS = {
        "\\Device\\",
        "\\??\\",
        "cmd.exe",
        "powershell",
        "ObRegisterCallbacks",
        "FltRegisterFilter",
    }

    # Wave 3: Dangerous sinks specific to advanced taint analysis
    ADVANCED_TAINT_SINKS = {
        "__writemsr", "KeWriteMsr",
        "MmMapIoSpace", "MmMapIoSpaceEx",
        "ObRegisterCallbacks",
        "CmRegisterCallbackEx",
        "FltRegisterFilter",
    }

    # Category weights — imported from centralized defaults
    CATEGORY_WEIGHTS = CATEGORY_WEIGHTS

    # Categories that are informational/structural only — should NOT contribute
    # to risk score. They describe code structure, not vulnerabilities.
    INFORMATIONAL_CATEGORIES = {
        "data_structure_identified",
        "array_iteration_cmp",
        "comm_protocol_analyzed",
        "call_chain_analyzed",
        "callback_resolved",
        "filter_callback_analyzed",
        "memory_map_analyzed",
        "memory_map_positioning",
        "xref_table_usage",
        "xref_hot_data",
        "struct_inferred",
        "stack_string_reconstructed",
        "wide_string_found",
        "string_rva_resolved",
        "dispatch_table_resolved",
        "runtime_alloc_table",
        "whitelist_table_detected",
        "minifilter_rules_analyzed",
        "coverage_analyzed",
        "data_content_analyzed",
        "custom_code_execution",
    }

    # High-noise categories that produce many false positives on legitimate
    # drivers. Cap the number of findings that contribute to the score.
    # Beyond the cap, additional findings of the same category are ignored.
    NOISE_CAPS: dict[str, int] = {
        "inline_hook": 5,
        "control_flow_flattening": 3,
        "dead_code_injection": 2,
        "anti_debug_timing": 2,
        "anti_debug_hypervisor": 2,
        "anti_debug_trap": 2,
        "string_encryption": 2,
        "api_hashing": 3,
        "vm_handler": 2,
        "code_self_check": 2,
        "blacklist_check_detected": 2,
        "whitelist_check_detected": 2,
        # Pool/handle operations are normal for any kernel driver
        "pool_manipulation": 2,
        "handle_manipulation": 2,
        # DKOM indicators on legitimate drivers are usually just EPROCESS
        # traversal (e.g. finding a target PID), not actual unlinking attacks
        "dkom_process_unlink": 2,
        "dkom_thread_unlink": 2,
        # ALPC port names are informational — many drivers register named ports
        "alpc_port_name": 2,
        # VmProtect/packed binary detection is noisy on WHQL-signed drivers
        "vm_protect": 1,
        "packed_binary": 1,
        "vm_entry": 1,
        "hypervisor_setup": 1,
        "eptp_construction": 2,
        "idt_hook": 2,
        "apc_injection": 1,
        "dse_bypass": 1,
    }

    def score(self, sample: Sample, findings: list[Finding]) -> RiskScore:
        raw_score = 0.0
        breakdown: dict[str, float] = {}

        # Count vulnerable functions (unique function addresses with unvalidated input)
        vulnerable_func_addrs = set()
        has_unvalidated = False
        has_dangerous_primitive = False

        # Wave 1-3 tracking
        has_decrypted_strings = False
        has_resolved_api_hashes = False
        has_advanced_taint = False
        dangerous_decrypted_count = 0

        for f in findings:
            if f.category.value == "unvalidated_user_input":
                has_unvalidated = True
                vulnerable_func_addrs.add(f.function_address)
            if f.category.value in (
                "arbitrary_memory_map", "msr_access", "kernel_rw_primitive",
                "code_execution_primitive", "physical_memory_access",
                "dpc_work_queue", "dma_primitive", "interrupt_hooking",
            ):
                has_dangerous_primitive = True

            # Wave 1: Track string decryption findings
            if f.category.value == "string_decrypted":
                has_decrypted_strings = True
                desc_lower = f.description.lower() if f.description else ""
                for pattern in self.DANGEROUS_DECRYPTED_STRINGS:
                    if pattern.lower() in desc_lower:
                        dangerous_decrypted_count += 1
                        break

            # Wave 2: Track extended API hash resolution
            if f.category.value == "api_hash_resolved_extended":
                has_resolved_api_hashes = True

            # Wave 3: Track advanced taint findings
            if f.category.value in (
                "unvalidated_data_flow",
                "validated_surface",
            ):
                has_advanced_taint = True
                # Check if taint reaches especially dangerous sinks
                if f.context:
                    for sink in self.ADVANCED_TAINT_SINKS:
                        if sink.lower() in str(f.context).lower():
                            dangerous_decrypted_count += 1
                            break

        n_funcs = len(vulnerable_func_addrs)

        # Count dangerous API calls in vulnerable functions
        dangerous_api_count = 0
        for f in findings:
            if f.category.value == "arbitrary_memory_map":
                if f.api_name in self.BYOVD_CRITICAL_APIS:
                    dangerous_api_count += 1

        # Amplifier: dangerous primitive + no validation + multiple functions
        # Base amplifier for 1 function: 1.3
        # Each additional vulnerable function adds 0.1 (up to 2.0 max)
        validation_amplifier = 1.0
        if has_dangerous_primitive and has_unvalidated:
            validation_amplifier = min(1.3 + (n_funcs - 1) * 0.1, 2.0)

        # Wave 1-3: Additional amplifier for deobfuscation + advanced taint
        deobfuscation_amplifier = 1.0
        if has_decrypted_strings or has_resolved_api_hashes or has_advanced_taint:
            deob_factors = sum([
                has_decrypted_strings * 0.15,
                has_resolved_api_hashes * 0.2,
                has_advanced_taint * 0.15,
                min(dangerous_decrypted_count * 0.05, 0.2),
            ])
            deobfuscation_amplifier = 1.0 + deob_factors

        # Count multiplier: if many functions have the same vulnerability,
        # it's worse. Apply sqrt scaling to avoid runaway scores.
        import math
        count_multiplier = math.sqrt(max(n_funcs, 1)) if has_unvalidated else 1.0

        for finding in findings:
            # Skip informational/structural categories — they describe code
            # structure, not vulnerabilities. Including them causes massive
            # score inflation on legitimate drivers (e.g. fileinfo.sys → 698
            # findings → 10.0/10).
            if finding.category.value in self.INFORMATIONAL_CATEGORIES:
                continue

            sev_w = self.SEVERITY_WEIGHTS.get(finding.severity.value, 0.0)
            conf_m = self.CONFIDENCE_MULTIPLIERS.get(finding.confidence.value, 0.5)
            cat_w = self.CATEGORY_WEIGHTS.get(finding.category.value, 1.0)

            contribution = sev_w * conf_m * cat_w * validation_amplifier * deobfuscation_amplifier

            # Apply count multiplier only to core BYOVD findings
            if finding.category.value in ("unvalidated_user_input", "arbitrary_memory_map"):
                contribution *= count_multiplier

            raw_score += contribution

            cat_key = finding.category.value
            breakdown[cat_key] = breakdown.get(cat_key, 0.0) + contribution

        # Per-category cap: when there are 3+ categories contributing, no single
        # category can contribute more than 40% of the total raw score. Prevents
        # one noisy analyzer from dominating. Only applies when there are enough
        # categories that a cap makes statistical sense.
        if len(breakdown) >= 3:
            cap = raw_score * 0.4
            for cat in list(breakdown.keys()):
                if breakdown[cat] > cap:
                    overage = breakdown[cat] - cap
                    raw_score -= overage
                    breakdown[cat] = cap

        # Apply noise caps: high-noise categories are capped at N findings.
        # Count how many findings per noise category and subtract overage.
        noise_counts: dict[str, int] = {}
        for finding in findings:
            cat = finding.category.value
            if cat in self.NOISE_CAPS:
                noise_counts[cat] = noise_counts.get(cat, 0) + 1
        for cat, count in noise_counts.items():
            cap_val = self.NOISE_CAPS[cat]
            if count > cap_val:
                # Calculate the per-finding contribution for this category
                cat_total = breakdown.get(cat, 0.0)
                if cat_total > 0 and count > 0:
                    per_finding = cat_total / count
                    excess = (count - cap_val) * per_finding
                    raw_score -= excess
                    breakdown[cat] = cap_val * per_finding

        # Normalize: divide by 5.0 instead of 3.0 to account for higher weights
        normalized = min(raw_score / 5.0, 10.0)

        # Finding density limit: drivers with very few non-info findings cannot
        # have a high risk score — BYOVD requires a meaningful attack surface.
        # Count non-info findings (already filtered in the loop above).
        n_scored = sum(1 for f in findings if f.category.value not in self.INFORMATIONAL_CATEGORIES)
        if n_scored < 10:
            normalized = min(normalized, 3.0)  # Tiny drivers max at LOW
        elif n_scored < 30:
            normalized = min(normalized, 5.0)  # Small drivers max at MEDIUM

        # Trusted signer downgrade:
        # - "Microsoft Windows" (MS own drivers): 70% reduction
        # - ELAM publisher (anti-malware certified by MS): 50% reduction
        # - "Microsoft Windows Hardware Compatibility Publisher" (WHQL 3rd party):
        #   50% reduction — certified but still complex security drivers
        # - Other signed drivers: 30% reduction
        signer = (sample.signer_name or "").lower()
        if signer == "microsoft windows":
            normalized *= 0.3
        elif "early launch anti-malware" in signer:
            normalized *= 0.5
        elif "hardware compatibility publisher" in signer:
            normalized *= 0.5
        elif sample.signature_status.value == "signed" and signer:
            normalized *= 0.7

        return RiskScore(overall=round(normalized, 1), breakdown=breakdown)

    def explain(self, sample: Sample, findings: list[Finding]) -> list[str]:
        explanations = []

        # Count vulnerable functions for context
        vuln_funcs = set()
        for f in findings:
            if f.category.value == "unvalidated_user_input":
                vuln_funcs.add(f.function_address)

        if vuln_funcs:
            apis = set()
            for f in findings:
                if f.category.value == "arbitrary_memory_map" and f.api_name:
                    apis.add(f.api_name)
            explanations.append(
                f"[CRITICAL] {len(vuln_funcs)} function(s) call dangerous APIs "
                f"({', '.join(sorted(apis))}) without input validation"
            )

        # Wave 1: Report decrypted dangerous strings
        decrypted_findings = [f for f in findings if f.category.value == "string_decrypted"]
        if decrypted_findings:
            dangerous_strings = []
            for f in decrypted_findings:
                desc = f.description or ""
                for pattern in self.DANGEROUS_DECRYPTED_STRINGS:
                    if pattern.lower() in desc.lower():
                        dangerous_strings.append(pattern)
            if dangerous_strings:
                explanations.append(
                    f"[HIGH] Decrypted strings reveal dangerous patterns: "
                    f"{', '.join(sorted(set(dangerous_strings)))}"
                )

        # Wave 2: Report resolved API hashes
        hash_findings = [f for f in findings if f.category.value == "api_hash_resolved_extended"]
        if hash_findings:
            resolved_apis = set()
            for f in hash_findings:
                if f.context and "resolved_apis" in f.context:
                    resolved_apis.update(f.context["resolved_apis"])
            if resolved_apis:
                explanations.append(
                    f"[HIGH] Extended API hash resolution revealed: "
                    f"{', '.join(sorted(resolved_apis)[:5])}"
                )

        # Wave 3: Report advanced taint findings
        taint_findings = [f for f in findings if f.category.value == "unvalidated_data_flow"]
        if taint_findings:
            explanations.append(
                f"[MEDIUM] {len(taint_findings)} advanced taint path(s) detected "
                f"(shadow space / callback / global variable propagation)"
            )

        # Top findings by contribution
        has_unvalidated = any(f.category.value == "unvalidated_user_input" for f in findings)
        has_dangerous_primitive = any(
            f.category.value in (
                "arbitrary_memory_map", "msr_access", "kernel_rw_primitive",
                "code_execution_primitive", "physical_memory_access",
                "dpc_work_queue", "dma_primitive", "interrupt_hooking",
            )
            for f in findings
        )
        n_funcs = len(vuln_funcs)
        validation_amplifier = 1.0
        if has_dangerous_primitive and has_unvalidated:
            validation_amplifier = min(1.3 + (n_funcs - 1) * 0.1, 2.0)

        # Re-compute deobfuscation amplifier for explanation
        deobfuscation_amplifier = 1.0
        has_decrypted = any(f.category.value == "string_decrypted" for f in findings)
        has_resolved = any(f.category.value == "api_hash_resolved_extended" for f in findings)
        has_adv_taint = any(f.category.value in ("unvalidated_data_flow", "validated_surface") for f in findings)
        if has_decrypted or has_resolved or has_adv_taint:
            deob_factors = sum([
                has_decrypted * 0.15,
                has_resolved * 0.2,
                has_adv_taint * 0.15,
            ])
            deobfuscation_amplifier = 1.0 + deob_factors

        import math
        count_multiplier = math.sqrt(max(n_funcs, 1)) if has_unvalidated else 1.0

        scored_findings = []
        for finding in findings:
            sev_w = self.SEVERITY_WEIGHTS.get(finding.severity.value, 0.0)
            conf_m = self.CONFIDENCE_MULTIPLIERS.get(finding.confidence.value, 0.5)
            cat_w = self.CATEGORY_WEIGHTS.get(finding.category.value, 1.0)
            contribution = sev_w * conf_m * cat_w * validation_amplifier * deobfuscation_amplifier
            if finding.category.value in ("unvalidated_user_input", "arbitrary_memory_map"):
                contribution *= count_multiplier
            scored_findings.append((contribution, finding))

        scored_findings.sort(key=lambda x: x[0], reverse=True)

        for contribution, finding in scored_findings[:5]:
            level = finding.severity.value.upper()
            explanations.append(
                f"[{level}] {finding.description[:100]} "
                f"(contribution: {contribution:.2f})"
            )

        if sample.driver_type:
            explanations.append(f"[INFO] Driver type: {sample.driver_type}")
        if sample.signature_status.value != "unsigned":
            explanations.append(
                f"[INFO] Signature status: {sample.signature_status.value}"
            )

        # Summary: actionable recommendation
        attack_chains = [f for f in findings if f.category.value == "attack_chain"
                         and f.context.get("chain_type") == "byovd_complete"]
        if attack_chains:
            all_apis = set()
            for chain in attack_chains:
                all_apis.update(chain.context.get("primitive_apis", []))
            explanations.append(
                f"\n[SUMMARY] {len(attack_chains)} complete BYOVD attack chain(s) detected. "
                f"Top priority APIs: {', '.join(sorted(all_apis))}. "
                f"Action: Validate input buffers in IOCTL handlers or restrict IOCTL access."
            )
        elif vuln_funcs:
            all_apis = set()
            for f in findings:
                if f.api_name and f.category.value in (
                    "arbitrary_memory_map", "msr_access", "kernel_rw_primitive",
                    "code_execution_primitive", "physical_memory_access",
                    "dpc_work_queue", "dma_primitive", "interrupt_hooking",
                ):
                    all_apis.add(f.api_name)
            if all_apis:
                explanations.append(
                    f"\n[SUMMARY] {len(vuln_funcs)} function(s) with dangerous APIs "
                    f"({', '.join(sorted(all_apis))}). "
                    f"Action: Validate input buffers or restrict IOCTL access."
                )

        # Wave 1-3 summary
        wave_features = []
        if any(f.category.value == "string_decrypted" for f in findings):
            wave_features.append("string decryption")
        if any(f.category.value == "api_hash_resolved_extended" for f in findings):
            wave_features.append("API hash resolution")
        if any(f.category.value == "unvalidated_data_flow" for f in findings):
            wave_features.append("advanced taint analysis")
        if wave_features:
            explanations.append(
                f"\n[ENHANCED] Analysis used: {', '.join(wave_features)}. "
                f"These findings are derived from deobfuscation and dataflow analysis."
            )

        return explanations
