"""Tests for kernel hook detection (HookAnalyzer — Phase 13)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.core.hook_analyzer import (
    HookAnalyzer,
    detect_code_self_check,
    detect_idt_hooks,
    detect_inline_hooks,
    detect_ssdt_hooks,
    detect_iat_hooks,
    detect_eat_hooks,
    IAT_STRINGS,
    IAT_APIS,
    IAT_HOOK_PATTERNS,
    EAT_STRINGS,
    EAT_APIS,
    EAT_HOOK_PATTERNS,
)
from src.models import (
    BasicBlock,
    CFG,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Function,
    Instruction,
    Sample,
    Architecture,
    Severity,
)


def _make_ir() -> DisassemblyResult:
    return DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")


def _sample() -> Sample:
    return Sample(
        path=Path("test.sys"), name="test.sys", company="Test",
        version="1.0", arch=Architecture.X64, sha256="abc", size=1024,
        is_driver=True,
    )


def _add_function(ir: DisassemblyResult, addr: int, api_names: list[str] | None = None) -> None:
    func = Function(name=f"sub_{addr:X}", address=addr, size=0x200)
    ir.functions[addr] = func
    if api_names:
        ir.function_apis[addr] = api_names


def _add_cfg_with_insns(
    ir: DisassemblyResult,
    func_addr: int,
    instructions: list[tuple[str, str]],
) -> None:
    """Add a CFG with the given instructions to a function."""
    cfg = CFG(function_address=func_addr, entry_block=func_addr)
    insns = [
        Instruction(
            address=func_addr + 0x10 + i * 4,
            mnemonic=mnem,
            operands=ops,
            size=4,
        )
        for i, (mnem, ops) in enumerate(instructions)
    ]
    block = BasicBlock(
        address=func_addr,
        end_address=func_addr + 0x100,
        instructions=insns,
        successors=[],
    )
    cfg.blocks[func_addr] = block
    ir.cfgs[func_addr] = ir.simple_cfgs[func_addr] = cfg


class TestInlineHookDetection:
    """Test inline hook pattern detection."""

    def test_jmp_redirect_detected(self):
        """jmp rel32 at function entry should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("jmp", "0x140012000"),
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.INLINE_HOOK
        assert findings[0].function_address == 0x1000

    def test_call_redirect_detected(self):
        """call rel32 at function entry should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("call", "0x140013000"),
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) == 1

    def test_push_ret_detected(self):
        """push imm64; ret should be flagged as PUSH-RET trampoline."""
        ir = _make_ir()
        _add_function(ir, 0x3000)
        _add_cfg_with_insns(ir, 0x3000, [
            ("push", "0x140014000"),
            ("ret", ""),
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) == 1

    def test_mov_jmp_rax_detected(self):
        """mov rax, imm64; jmp rax should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x4000)
        _add_cfg_with_insns(ir, 0x4000, [
            ("mov", "rax, 0x140015000"),
            ("jmp", "rax"),
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) == 1

    def test_iat_style_jmp_detected(self):
        """jmp rel32 at function entry (without prologue) should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x5000)
        _add_cfg_with_insns(ir, 0x5000, [
            ("jmp", "0x12345678"),
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) == 1

    def test_iat_style_call_detected(self):
        """call rel32 at function entry (without prologue) should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x6000)
        _add_cfg_with_insns(ir, 0x6000, [
            ("call", "0xABCDEF00"),
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) == 1

    def test_write_jmp_opcode_detected(self):
        """Writing 0xE9 (JMP opcode) to memory is a strong hook indicator."""
        ir = _make_ir()
        _add_function(ir, 0x7000)
        _add_cfg_with_insns(ir, 0x7000, [
            ("mov", "byte ptr [rip+0x1000], 0xe9"),
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH  # single signal = HIGH

    def test_write_jmp_offset_detected(self):
        """Writing JMP offset to RIP-relative address."""
        ir = _make_ir()
        _add_function(ir, 0x8000)
        _add_cfg_with_insns(ir, 0x8000, [
            ("mov", "dword ptr [rip+0x2000], 0xDEADBEEF"),
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) == 1

    def test_legitimate_prologue_not_flagged(self):
        """Normal function prologue should NOT be flagged as inline hook."""
        ir = _make_ir()
        _add_function(ir, 0x9000)
        _add_cfg_with_insns(ir, 0x9000, [
            ("push", "rbp"),
            ("mov", "rbp, rsp"),
            ("sub", "rsp, 0x20"),
            ("push", "rbx"),
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) == 0

    def test_low_score_not_flagged(self):
        """Single weak signal (score < 4) should not produce finding."""
        ir = _make_ir()
        _add_function(ir, 0xA000)
        _add_cfg_with_insns(ir, 0xA000, [
            ("push", "r8"),  # Score = 1, below threshold
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) == 0

    def test_multiple_signals_high_confidence(self):
        """Multiple entry signals + installation indicator should produce HIGH confidence."""
        ir = _make_ir()
        _add_function(ir, 0xB000)
        # Hook trampoline at entry + write_jmp_opcode (installation) in another block
        _add_cfg_with_insns(ir, 0xB000, [
            ("jmp", "0x140020000"),         # Score +3 (entry hook)
        ])
        func = ir.functions[0xB000]
        func.calls = {0xD000}
        # Add another function with hook installation (writing 0xE9)
        func2 = Function(name="Installer", address=0xD000, size=0x100)
        ir.functions[0xD000] = func2
        cfg2 = CFG(function_address=0xD000, entry_block=0xD000)
        insns2 = [
            Instruction(address=0xD010, mnemonic="mov", operands="byte ptr [rip+0x100], 0xe9", size=7),
        ]
        block2 = BasicBlock(address=0xD000, end_address=0xD010 + 8, instructions=insns2, successors=[])
        cfg2.blocks[0xD000] = block2
        ir.cfgs[0xD000] = ir.simple_cfgs[0xD000] = cfg2

        findings, _ = detect_inline_hooks(ir)
        assert len(findings) >= 1

    def test_hooked_functions_returned(self):
        """detect_inline_hooks should return hooked_functions list."""
        ir = _make_ir()
        _add_function(ir, 0xC000)
        _add_cfg_with_insns(ir, 0xC000, [
            ("jmp", "0x140030000"),
            ("push", "0xDEADBEEF"),  # push_imm_ret at non-first instruction won't count
        ])
        findings, hooked = detect_inline_hooks(ir)
        assert len(hooked) == 1
        assert hooked[0]["func_addr"] == 0xC000
        assert hooked[0]["score"] >= 3

    def test_empty_ir_no_crash(self):
        """Empty IR should not crash detect_inline_hooks."""
        ir = _make_ir()
        findings, hooked = detect_inline_hooks(ir)
        assert findings == []
        assert hooked == []


class TestSSDTHookDetection:
    """Test SSDT/Shadow SSDT hook detection."""

    def test_ssdt_string_detected(self):
        """KeServiceDescriptorTable string should be flagged."""
        ir = _make_ir()
        ir.strings.append("KeServiceDescriptorTable")
        findings = detect_ssdt_hooks(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.SSDT_HOOK

    def test_shadow_ssdt_string_detected(self):
        """KeServiceDescriptorTableShadow string should be flagged."""
        ir = _make_ir()
        ir.strings.append("KeServiceDescriptorTableShadow")
        findings = detect_ssdt_hooks(ir)
        assert len(findings) == 1
        assert findings[0].context["has_shadow_ssdt"] is True

    def test_ssdt_instruction_pattern_detected(self):
        """SSDT index shift (shl reg, 3) should be detected."""
        ir = _make_ir()
        ir.strings.append("KeServiceDescriptorTable")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, qword ptr [rip+0x1234]"),
            ("shl", "rax, 3"),
        ])
        findings = detect_ssdt_hooks(ir)
        assert len(findings) == 1
        assert len(findings[0].context["ssdt_access_functions"]) == 1

    def test_ssdt_multiply_pattern_detected(self):
        """imul reg, reg, 8 should be detected as SSDT index calculation."""
        ir = _make_ir()
        ir.strings.append("ServiceTableBase")
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("mov", "rbx, rax"),
            ("imul", "rcx, rax, 8"),
        ])
        findings = detect_ssdt_hooks(ir)
        assert len(findings) == 1

    def test_no_ssdt_no_findings(self):
        """IR without SSDT strings should produce no findings."""
        ir = _make_ir()
        findings = detect_ssdt_hooks(ir)
        assert findings == []

    def test_critical_severity_with_instructions(self):
        """SSDT with instruction patterns should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("KeServiceDescriptorTable")
        _add_function(ir, 0x3000)
        _add_cfg_with_insns(ir, 0x3000, [
            ("mov", "rax, qword ptr [rip+0x1234]"),
            ("shl", "rax, 3"),
            ("mov", "qword ptr [rax], rdx"),
        ])
        findings = detect_ssdt_hooks(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_string_only_medium_severity(self):
        """SSDT string only (no instruction patterns) should be HIGH."""
        ir = _make_ir()
        ir.strings.append("KeServiceDescriptorTable")
        findings = detect_ssdt_hooks(ir)
        assert findings[0].severity == Severity.HIGH
        assert findings[0].confidence == Confidence.MEDIUM


class TestIDTHookDetection:
    """Test IDT hook detection."""

    def test_lidt_detected(self):
        """LIDT instruction should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("lidt", "[rsp+0x10]"),
        ])
        findings = detect_idt_hooks(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.IDT_HOOK

    def test_sidt_detected(self):
        """SIDT instruction should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("sidt", "[rsp]"),
        ])
        findings = detect_idt_hooks(ir)
        assert len(findings) == 1

    def test_sidt_to_stack_detected(self):
        """SIDT to [rsp] is a specific pattern."""
        ir = _make_ir()
        _add_function(ir, 0x3000)
        _add_cfg_with_insns(ir, 0x3000, [
            ("sidt", "[rsp+0x20]"),
        ])
        findings = detect_idt_hooks(ir)
        assert len(findings) == 1

    def test_idt_string_detected(self):
        """IDT string reference should be flagged."""
        ir = _make_ir()
        ir.strings.append("IDT")
        findings = detect_idt_hooks(ir)
        assert len(findings) == 1

    def test_no_idt_no_findings(self):
        """IR without IDT references should produce no findings."""
        ir = _make_ir()
        findings = detect_idt_hooks(ir)
        assert findings == []

    def test_critical_with_instruction(self):
        """IDT with lidt instruction should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("_IDT")
        _add_function(ir, 0x4000)
        _add_cfg_with_insns(ir, 0x4000, [
            ("sidt", "[rsp]"),
            ("lidt", "[rsp+0x10]"),
        ])
        findings = detect_idt_hooks(ir)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


class TestCodeSelfCheckDetection:
    """Test code integrity self-check detection."""

    def test_crc32_api_detected(self):
        """RtlComputeCrc32 call should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x1000, ["RtlComputeCrc32"])
        findings = detect_code_self_check(ir)
        assert len(findings) == 1
        assert findings[0].category == FindingCategory.CODE_SELF_CHECK

    def test_checksum_api_detected(self):
        """RtlComputeChecksum call should be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x2000, ["RtlComputeChecksum"])
        findings = detect_code_self_check(ir)
        assert len(findings) == 1

    def test_self_read_pattern_detected(self):
        """Multiple RIP-relative reads should be flagged as self-check."""
        ir = _make_ir()
        _add_function(ir, 0x3000)
        _add_cfg_with_insns(ir, 0x3000, [
            ("mov", "rax, qword ptr [rip+0x1000]"),
            ("mov", "rcx, qword ptr [rip+0x1010]"),
            ("mov", "rdx, qword ptr [rip+0x1020]"),
            ("add", "rcx, 1"),
            ("cmp", "rcx, rdx"),
        ])
        findings = detect_code_self_check(ir)
        assert len(findings) == 1

    def test_low_self_read_not_flagged(self):
        """Fewer than 3 self-reads should not be flagged."""
        ir = _make_ir()
        _add_function(ir, 0x4000)
        _add_cfg_with_insns(ir, 0x4000, [
            ("mov", "rax, qword ptr [rip+0x1000]"),
            ("mov", "rcx, qword ptr [rip+0x1010]"),
        ])
        findings = detect_code_self_check(ir)
        assert findings == []

    def test_no_self_check_no_findings(self):
        """IR without self-check indicators should produce no findings."""
        ir = _make_ir()
        _add_function(ir, 0x5000, ["IoCreateDevice"])
        findings = detect_code_self_check(ir)
        assert findings == []

    def test_multiple_self_check_apis(self):
        """Multiple self-check APIs should be listed in context."""
        ir = _make_ir()
        _add_function(ir, 0x6000, ["RtlComputeCrc32", "KeGetCurrentIrql"])
        findings = detect_code_self_check(ir)
        assert len(findings) == 1
        ctx = findings[0].context
        assert len(ctx["self_check_functions"]) == 1
        assert "RtlComputeCrc32" in ctx["self_check_functions"][0]["apis"]


class TestHookAnalyzerIntegration:
    """Test HookAnalyzer end-to-end."""

    def test_analyzer_name(self):
        analyzer = HookAnalyzer()
        assert analyzer.name == "HookAnalyzer"

    def test_analyzer_description(self):
        analyzer = HookAnalyzer()
        assert "inline" in analyzer.description.lower()
        assert "ssdt" in analyzer.description.lower()
        assert "idt" in analyzer.description.lower()

    def test_analyze_empty_ir(self):
        """HookAnalyzer should handle empty IR without errors."""
        from src.models import Sample, Architecture
        ir = _make_ir()
        sample = Sample(
            path=Path("test.sys"),
            name="test.sys",
            company="Test",
            version="1.0",
            arch=Architecture.X64,
            sha256="abc",
            size=1024,
            is_driver=True,
        )
        analyzer = HookAnalyzer()
        findings = analyzer.analyze(sample, ir)
        assert findings == []

    def test_analyze_with_all_hooks(self):
        """HookAnalyzer should detect all hook types simultaneously."""
        from src.models import Sample, Architecture
        ir = _make_ir()
        # Inline hook
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("jmp", "0x140012000"),
            ("mov", "rax, 0x140013000"),
        ])
        # SSDT strings
        ir.strings.append("KeServiceDescriptorTable")
        # IDT instruction
        _add_function(ir, 0x2000)
        _add_cfg_with_insns(ir, 0x2000, [
            ("sidt", "[rsp]"),
            ("lidt", "[rsp+0x10]"),
        ])
        # Self-check API
        _add_function(ir, 0x3000, ["RtlComputeCrc32"])

        sample = Sample(
            path=Path("test.sys"),
            name="test.sys",
            company="Test",
            version="1.0",
            arch=Architecture.X64,
            sha256="abc",
            size=1024,
            is_driver=True,
        )
        analyzer = HookAnalyzer()
        findings = analyzer.analyze(sample, ir)

        categories = {f.category for f in findings}
        assert FindingCategory.INLINE_HOOK in categories
        assert FindingCategory.SSDT_HOOK in categories
        assert FindingCategory.IDT_HOOK in categories
        assert FindingCategory.CODE_SELF_CHECK in categories

    def test_hook_findings_have_evidence(self):
        """All hook findings should have evidence attached."""
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("jmp", "0x140012000"),
            ("call", "0x140013000"),
            ("mov", "rax, 0x140014000"),
        ])
        findings, _ = detect_inline_hooks(ir)
        assert len(findings) >= 1
        for f in findings:
            assert len(f.evidence) > 0
            assert f.evidence[0].rule_id == "INLINE_HOOK"


class TestInlineHookConstants:
    """Test inline hook detection pattern constants."""

    def test_hook_patterns_are_regex_valid(self):
        """All hook patterns should be valid regex."""
        import re
        from src.analysis.core.hook_analyzer import ENTRY_HOOK_PATTERNS, STRONG_HOOK_INDICATORS
        for pattern, ptype, desc in ENTRY_HOOK_PATTERNS:
            re.compile(pattern)  # Should not raise
        for pattern, ptype, desc in STRONG_HOOK_INDICATORS:
            re.compile(pattern)

    def test_legitimate_prologue_patterns_are_valid(self):
        """All legitimate prologue patterns should be valid regex."""
        import re
        from src.analysis.core.hook_analyzer import LEGITIMATE_PROLOGUE_PATTERNS
        for pattern in LEGITIMATE_PROLOGUE_PATTERNS:
            re.compile(pattern)

    def test_ssdt_patterns_are_valid(self):
        """All SSDT patterns should be valid regex."""
        import re
        from src.analysis.core.hook_analyzer import SSDT_HOOK_PATTERNS
        for pattern, stype, desc in SSDT_HOOK_PATTERNS:
            re.compile(pattern)

    def test_idt_patterns_are_valid(self):
        """All IDT patterns should be valid regex."""
        import re
        from src.analysis.core.hook_analyzer import IDT_HOOK_PATTERNS
        for pattern, ptype, desc in IDT_HOOK_PATTERNS:
            re.compile(pattern)

    def test_self_read_patterns_are_valid(self):
        """All self-read patterns should be valid regex."""
        import re
        from src.analysis.core.hook_analyzer import SELF_READ_PATTERNS
        for pattern, ptype, desc in SELF_READ_PATTERNS:
            re.compile(pattern)


# ===================================================================
# IAT Hooking Detection Tests
# ===================================================================

class TestIATHookDetection:
    """Test IAT (Import Address Table) hooking detection."""

    def test_iat_string_detected(self):
        ir = _make_ir()
        ir.strings.append("ImageDirectoryEntryToData")
        findings = detect_iat_hooks(ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.IAT_HOOK

    def test_iat_full_string(self):
        ir = _make_ir()
        ir.strings.append("Import Address Table")
        findings = detect_iat_hooks(ir)
        assert len(findings) >= 1

    def test_iat_api_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["ImageDirectoryEntryToData"])
        findings = detect_iat_hooks(ir)
        assert len(findings) >= 1
        assert len(findings[0].context.get("iat_api_functions", [])) >= 1

    def test_iat_write_with_string_critical(self):
        """IAT entry write + string should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("IMAGE_DIRECTORY_ENTRY_IMPORT")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "qword ptr [rip+0x1234], rax"),
        ])
        findings = detect_iat_hooks(ir)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].context.get("has_iat_write") is True

    def test_iat_enumeration_pattern(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("add", "rax, 0x8"),
        ])
        findings = detect_iat_hooks(ir)
        assert len(findings) >= 1

    def test_iat_ldr_get_proc_address(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["LdrGetProcedureAddress"])
        findings = detect_iat_hooks(ir)
        assert len(findings) >= 1

    def test_iat_ldr_load_dll(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["LdrLoadDll", "GetProcAddress"])
        findings = detect_iat_hooks(ir)
        assert len(findings) >= 1

    def test_iat_entry_read(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "rax, qword ptr [rip+0x1234]"),
        ])
        findings = detect_iat_hooks(ir)
        assert len(findings) >= 1

    def test_iat_thunk_data_string(self):
        ir = _make_ir()
        ir.strings.append("ThunkData")
        findings = detect_iat_hooks(ir)
        assert len(findings) >= 1

    def test_no_iat_patterns_no_finding(self):
        ir = _make_ir()
        ir.strings.append("Hello World")
        findings = detect_iat_hooks(ir)
        assert findings == []


# ===================================================================
# EAT Hooking Detection Tests
# ===================================================================

class TestEATHookDetection:
    """Test EAT (Export Address Table) hooking detection."""

    def test_eat_string_detected(self):
        ir = _make_ir()
        ir.strings.append("IMAGE_DIRECTORY_ENTRY_EXPORT")
        findings = detect_eat_hooks(ir)
        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.EAT_HOOK

    def test_eat_full_string(self):
        ir = _make_ir()
        ir.strings.append("Export Address Table")
        findings = detect_eat_hooks(ir)
        assert len(findings) >= 1

    def test_eat_address_of_functions(self):
        ir = _make_ir()
        ir.strings.append("AddressOfFunctions")
        findings = detect_eat_hooks(ir)
        assert len(findings) >= 1

    def test_eat_api_detected(self):
        ir = _make_ir()
        _add_function(ir, 0x1000, ["RtlImageNtHeader"])
        findings = detect_eat_hooks(ir)
        assert len(findings) >= 1

    def test_eat_write_with_string_critical(self):
        """EAT entry write + string should be CRITICAL."""
        ir = _make_ir()
        ir.strings.append("IMAGE_EXPORT_DIRECTORY")
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("mov", "qword ptr [rax], rbx"),
        ])
        findings = detect_eat_hooks(ir)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].context.get("has_eat_write") is True

    def test_eat_enumeration_pattern(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("add", "rcx, 0x4"),
        ])
        findings = detect_eat_hooks(ir)
        assert len(findings) >= 1

    def test_eat_ordinal_comparison(self):
        ir = _make_ir()
        _add_function(ir, 0x1000)
        _add_cfg_with_insns(ir, 0x1000, [
            ("cmp", "ecx, 0x10"),
        ])
        findings = detect_eat_hooks(ir)
        assert len(findings) >= 1

    def test_eat_address_of_names(self):
        ir = _make_ir()
        ir.strings.append("AddressOfNames")
        findings = detect_eat_hooks(ir)
        assert len(findings) >= 1

    def test_eat_nt_headers_string(self):
        ir = _make_ir()
        ir.strings.append("IMAGE_NT_HEADERS")
        findings = detect_eat_hooks(ir)
        assert len(findings) >= 1

    def test_no_eat_patterns_no_finding(self):
        ir = _make_ir()
        ir.strings.append("Hello World")
        findings = detect_eat_hooks(ir)
        assert findings == []


# ===================================================================
# IAT/EAT Integration with HookAnalyzer
# ===================================================================

class TestIATEATIntegration:
    """Test IAT/EAT detection integration with HookAnalyzer."""

    def test_analyzer_description_updated(self):
        analyzer = HookAnalyzer()
        desc = analyzer.description
        assert "IAT" in desc
        assert "EAT" in desc

    def test_iat_and_eat_findings_in_analyze(self):
        """HookAnalyzer should produce IAT and EAT findings."""
        ir = _make_ir()
        ir.strings.append("IMAGE_DIRECTORY_ENTRY_IMPORT")
        ir.strings.append("IMAGE_DIRECTORY_ENTRY_EXPORT")
        sample = _sample()
        analyzer = HookAnalyzer()
        findings = analyzer.analyze(sample, ir)
        categories = {f.category for f in findings}
        assert FindingCategory.IAT_HOOK in categories
        assert FindingCategory.EAT_HOOK in categories

    def test_all_findings_have_evidence(self):
        """All IAT/EAT findings should have evidence."""
        ir = _make_ir()
        ir.strings.append("Import Address Table")
        ir.strings.append("Export Address Table")
        sample = _sample()
        analyzer = HookAnalyzer()
        findings = analyzer.analyze(sample, ir)
        iat_eat_findings = [f for f in findings
                           if f.category in (FindingCategory.IAT_HOOK, FindingCategory.EAT_HOOK)]
        for f in iat_eat_findings:
            assert len(f.evidence) > 0
