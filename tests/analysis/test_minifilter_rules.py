"""Tests for the MinifilterRuleExtractor (Task C: MiniFilter rule extraction)."""

from __future__ import annotations

import struct
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from src.analysis.deep.minifilter_rule_extractor import (
    MinifilterRuleExtractor,
    IRP_MJ_NAMES,
    IRP_MJ_SEMANTICS,
)
from src.models import (
    Architecture,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)


def _make_sample(**kwargs) -> Sample:
    return Sample(
        path=Path("test.sys"),
        name="test.sys",
        company="Test",
        version="1.0",
        arch=Architecture.X64,
        sha256="abc",
        size=1000,
        **kwargs,
    )


def _make_ir(**kwargs) -> DisassemblyResult:
    return DisassemblyResult(
        sample_path=Path("test.sys"),
        backend="capstone",
        **kwargs,
    )


def _make_instruction(address, mnemonic, operands, size=4):
    from types import SimpleNamespace
    return SimpleNamespace(
        address=address,
        mnemonic=mnemonic,
        operands=operands,
        size=size,
    )


def _make_block(address, instructions, successors=None):
    from types import SimpleNamespace
    return SimpleNamespace(
        address=address,
        instructions=instructions,
        successors=successors or [],
    )


def _make_cfg(blocks, entry_block=0):
    from types import SimpleNamespace
    return SimpleNamespace(
        blocks=blocks,
        entry_block=entry_block,
    )


# ------------------------------------------------------------------
# Test structure
# ------------------------------------------------------------------

class TestMinifilterRuleExtractorStructure:
    def test_name(self):
        a = MinifilterRuleExtractor()
        assert a.name == "MinifilterRuleExtractor"

    def test_description_nonempty(self):
        a = MinifilterRuleExtractor()
        assert a.description != ""

    def test_enabled_by_default(self):
        a = MinifilterRuleExtractor()
        assert a.enabled is True

    def test_not_correlator(self):
        a = MinifilterRuleExtractor()
        assert a.is_correlator is False


# ------------------------------------------------------------------
# Test IRP_MJ constants
# ------------------------------------------------------------------

class TestIRPMJConstants:
    def test_names_populated(self):
        assert len(IRP_MJ_NAMES) > 10
        assert IRP_MJ_NAMES[0x00] == "IRP_MJ_CREATE"
        assert IRP_MJ_NAMES[0x03] == "IRP_MJ_READ"
        assert IRP_MJ_NAMES[0x04] == "IRP_MJ_WRITE"
        assert IRP_MJ_NAMES[0x0E] == "IRP_MJ_DEVICE_CONTROL"

    def test_semantics_populated(self):
        assert len(IRP_MJ_SEMANTICS) > 10
        assert "file creation" in IRP_MJ_SEMANTICS[0x00]
        assert "read" in IRP_MJ_SEMANTICS[0x03]
        assert "write" in IRP_MJ_SEMANTICS[0x04]


# ------------------------------------------------------------------
# Test operation rule extraction from PE
# ------------------------------------------------------------------

class TestOperationRuleExtraction:
    def test_empty_pe_no_findings(self):
        """PE without matching sections should return empty."""
        a = MinifilterRuleExtractor()
        sample = _make_sample()
        ir = _make_ir()
        findings = a._extract_operation_rules(sample, ir)
        assert isinstance(findings, list)

    @patch("pefile.PE")
    def test_extracts_operation_array(self, mock_pe_cls):
        """Should find FLT_OPERATION_REGISTRATION entries in .rdata."""
        mock_pe = MagicMock()
        mock_pe_cls.return_value = mock_pe

        # Build a .rdata section with properly aligned FLT_OPERATION_REGISTRATION array
        # Each entry is 0x18 (24) bytes: MajorFunction(1) + padding(3) + Flags(4) + PreOp(8) + PostOp(8)
        def make_entry(mj, pre_op=0, post_op=0):
            buf = bytearray(0x18)
            buf[0] = mj
            struct.pack_into('<Q', buf, 8, pre_op)
            struct.pack_into('<Q', buf, 0x10, post_op)
            return bytes(buf)

        def make_sentinel():
            buf = bytearray(0x18)
            buf[0] = 0xFE
            return bytes(buf)

        rdata = (
            make_entry(0x00, pre_op=0x5000) +         # IRP_MJ_CREATE
            make_entry(0x0E, pre_op=0x6000, post_op=0x7000) +  # IRP_MJ_DEVICE_CONTROL
            make_sentinel()
        )

        rdata_section = MagicMock()
        rdata_section.Name = b".rdata\x00\x00"
        rdata_section.VirtualAddress = 0x1000
        rdata_section.PointerToRawData = 0
        rdata_section.get_data.return_value = rdata

        mock_pe.sections = [rdata_section]

        a = MinifilterRuleExtractor()
        sample = _make_sample()
        ir = _make_ir()
        findings = a._extract_operation_rules(sample, ir)

        assert len(findings) >= 2

        # Check CREATE rule
        create_rules = [f for f in findings if f.context.get("major_function") == 0x00]
        assert len(create_rules) >= 1
        assert create_rules[0].context.get("pre_operation") == 0x5000

        # Check DEVICE_CONTROL rule
        device_rules = [f for f in findings if f.context.get("major_function") == 0x0E]
        assert len(device_rules) >= 1
        assert device_rules[0].context.get("pre_operation") == 0x6000
        assert device_rules[0].context.get("post_operation") == 0x7000

        mock_pe.close()

    @patch("pefile.PE")
    def test_extracts_multiple_rules(self, mock_pe_cls):
        """Should find multiple operation rules."""
        mock_pe = MagicMock()
        mock_pe_cls.return_value = mock_pe

        def make_entry(mj, pre_op=0x5000):
            buf = bytearray(0x18)
            buf[0] = mj
            struct.pack_into('<Q', buf, 8, pre_op)
            return bytes(buf)

        def make_sentinel():
            buf = bytearray(0x18)
            buf[0] = 0xFE
            return bytes(buf)

        entries = b""
        for mj in [0x00, 0x02, 0x03, 0x04, 0x06, 0x0C]:
            entries += make_entry(mj, pre_op=0x5000 + mj * 0x100)
        entries += make_sentinel()
        rdata = entries

        rdata_section = MagicMock()
        rdata_section.Name = b".rdata\x00\x00"
        rdata_section.VirtualAddress = 0x1000
        rdata_section.get_data.return_value = rdata
        mock_pe.sections = [rdata_section]

        a = MinifilterRuleExtractor()
        sample = _make_sample()
        ir = _make_ir()
        findings = a._extract_operation_rules(sample, ir)

        assert len(findings) >= 5

        mock_pe.close()


# ------------------------------------------------------------------
# Test callback semantics analysis
# ------------------------------------------------------------------

class TestCallbackSemanticsAnalysis:
    def test_callback_with_return_check(self):
        """Callback returning STATUS_ code should have has_return_check."""
        from types import SimpleNamespace

        a = MinifilterRuleExtractor()
        ir = _make_ir()
        cfg = _make_cfg({0x5000: _make_block(0x5000, [
            _make_instruction(0x5010, "mov", "eax, 0xC0000022"),
            _make_instruction(0x5020, "ret", ""),
        ])})
        ir.cfgs[0x5000] = cfg

        result = a._analyze_callback_semantics(0x5000, ir)
        assert result["has_return_check"] is True

    def test_callback_with_whitelist_check(self):
        """Callback with cmp against process name should have has_whitelist_check."""
        a = MinifilterRuleExtractor()
        ir = _make_ir()
        cfg = _make_cfg({0x5000: _make_block(0x5000, [
            _make_instruction(0x5010, "cmp", "rax, ImageFileName"),
            _make_instruction(0x5020, "ret", ""),
        ])})
        ir.cfgs[0x5000] = cfg

        result = a._analyze_callback_semantics(0x5000, ir)
        assert result["has_whitelist_check"] is True

    def test_callback_without_cfg(self):
        """Callback without CFG should return default empty semantics."""
        a = MinifilterRuleExtractor()
        ir = _make_ir()
        result = a._analyze_callback_semantics(0x5000, ir)
        assert result["has_return_check"] is False
        assert result["has_whitelist_check"] is False
        assert result["has_data_modification"] is False


# ------------------------------------------------------------------
# Test rule type classification
# ------------------------------------------------------------------

class TestRuleTypeClassification:
    def test_classify_intercept(self):
        """Pre-op with return check should be intercept."""
        a = MinifilterRuleExtractor()
        behavior = {
            "pre_behavior": {"has_return_check": True},
            "post_behavior": {},
        }
        assert a._classify_rule_type(behavior) == "intercept"

    def test_classify_tamper(self):
        """Post-op with data modification should be tamper."""
        a = MinifilterRuleExtractor()
        behavior = {
            "pre_behavior": {},
            "post_behavior": {"has_data_modification": True},
        }
        assert a._classify_rule_type(behavior) == "tamper"

    def test_classify_monitor(self):
        """Pre-op with whitelist check should be monitor."""
        a = MinifilterRuleExtractor()
        behavior = {
            "pre_behavior": {"has_whitelist_check": True},
            "post_behavior": {},
        }
        assert a._classify_rule_type(behavior) == "monitor"

    def test_classify_passive(self):
        """No significant behavior should be passive."""
        a = MinifilterRuleExtractor()
        behavior = {
            "pre_behavior": {},
            "post_behavior": {},
        }
        assert a._classify_rule_type(behavior) == "passive"

    def test_classify_monitor_with_callbacks(self):
        """Pre-behavior present without special flags should be monitor."""
        a = MinifilterRuleExtractor()
        behavior = {
            "pre_behavior": {"address": 0x5000},
            "post_behavior": {"address": 0x6000},
        }
        assert a._classify_rule_type(behavior) == "monitor"


# ------------------------------------------------------------------
# Test filter rule classification summary
# ------------------------------------------------------------------

class TestFilterRuleClassification:
    def test_intercept_summary(self):
        """Should report intercept-type filters."""
        a = MinifilterRuleExtractor()
        ir = _make_ir()
        ir.operation_rules = [
            {"major_function": 0x00, "rva": 0x1000, "pre_operation": 0x5000},
            {"major_function": 0x0E, "rva": 0x1018, "pre_operation": 0x6000},
        ]
        ir.operation_behaviors = [
            {"major_function": 0x00, "rva": 0x1000, "rule_type": "intercept",
             "pre_behavior": {"has_return_check": True}},
            {"major_function": 0x0E, "rva": 0x1018, "rule_type": "intercept",
             "pre_behavior": {"has_return_check": True}},
        ]
        findings = a._classify_filter_rules(ir)
        assert len(findings) >= 1
        assert findings[0].context["intercept_count"] == 2

    def test_ioctl_like_surface(self):
        """Should flag DEVICE_CONTROL as high-severity."""
        a = MinifilterRuleExtractor()
        ir = _make_ir()
        ir.operation_rules = [
            {"major_function": 0x0E, "rva": 0x1000, "pre_operation": 0x5000},
            {"major_function": 0x0F, "rva": 0x1018, "pre_operation": 0x6000},
        ]
        ir.operation_behaviors = [
            {"major_function": 0x0E, "rva": 0x1000, "rule_type": "monitor",
             "pre_behavior": {"address": 0x5000}},
            {"major_function": 0x0F, "rva": 0x1018, "rule_type": "monitor",
             "pre_behavior": {"address": 0x6000}},
        ]
        findings = a._classify_filter_rules(ir)
        high_sev = [f for f in findings if f.severity == Severity.HIGH]
        assert len(high_sev) >= 1
        assert "IRP_MJ_DEVICE_CONTROL" in high_sev[0].context["high_severity_operations"]

    def test_empty_rules_no_findings(self):
        """No operation rules should return empty findings."""
        a = MinifilterRuleExtractor()
        ir = _make_ir()
        findings = a._classify_filter_rules(ir)
        assert findings == []


# ------------------------------------------------------------------
# Test full analyze pipeline
# ------------------------------------------------------------------

class TestFullAnalyze:
    def test_analyze_returns_list(self):
        """analyze() should always return a list."""
        a = MinifilterRuleExtractor()
        sample = _make_sample()
        ir = _make_ir()
        findings = a.analyze(sample, ir)
        assert isinstance(findings, list)

    def test_analyze_populates_ir(self):
        """analyze() should populate IR fields."""
        a = MinifilterRuleExtractor()
        sample = _make_sample()
        ir = _make_ir()
        a.analyze(sample, ir)
        assert hasattr(ir, "operation_rules")
        assert hasattr(ir, "operation_behaviors")

    @patch("pefile.PE")
    def test_full_analyze_with_pe_data(self, mock_pe_cls):
        """Full analyze with mock PE should produce findings."""
        mock_pe = MagicMock()
        mock_pe_cls.return_value = mock_pe

        # Create .rdata with properly aligned operation registration entries
        def make_entry(mj, pre_op=0):
            buf = bytearray(0x18)
            buf[0] = mj
            struct.pack_into('<Q', buf, 8, pre_op)
            return bytes(buf)

        def make_sentinel():
            buf = bytearray(0x18)
            buf[0] = 0xFE
            return bytes(buf)

        rdata = make_entry(0x00, 0x5000) + make_entry(0x0E, 0x6000) + make_sentinel()

        rdata_section = MagicMock()
        rdata_section.Name = b".rdata\x00\x00"
        rdata_section.VirtualAddress = 0x1000
        rdata_section.get_data.return_value = rdata
        mock_pe.sections = [rdata_section]

        a = MinifilterRuleExtractor()
        sample = _make_sample()
        ir = _make_ir()
        findings = a.analyze(sample, ir)

        assert isinstance(findings, list)
        # Should have at least 2 findings (one per rule)
        rule_findings = [f for f in findings if f.category == FindingCategory.FILTER_CALLBACK_ANALYZED]
        assert len(rule_findings) >= 2

        mock_pe.close()


# ------------------------------------------------------------------
# Test scan for operation array (edge cases)
# ------------------------------------------------------------------

class TestScanOperationArray:
    def test_empty_data(self):
        """Empty data should return no rules."""
        a = MinifilterRuleExtractor()
        rules = a._scan_for_operation_array(b"", 0, ".rdata", _make_ir())
        assert rules == []

    def test_data_too_small(self):
        """Data smaller than entry size should return no rules."""
        a = MinifilterRuleExtractor()
        rules = a._scan_for_operation_array(b"\x00" * 10, 0, ".rdata", _make_ir())
        assert rules == []

    def test_no_sentinel(self):
        """Data without 0xFE sentinel should return no rules."""
        a = MinifilterRuleExtractor()
        data = struct.pack("B", 0x00) + struct.pack("<I", 0) + struct.pack("<Q", 0x5000) + struct.pack("<Q", 0)
        rules = a._scan_for_operation_array(data, 0, ".rdata", _make_ir())
        assert rules == []

    def test_single_entry_with_sentinel(self):
        """Single entry + sentinel should be found."""
        a = MinifilterRuleExtractor()
        entry = bytearray(0x18)
        entry[0] = 0x00
        struct.pack_into('<Q', entry, 8, 0x5000)
        sentinel = bytearray(0x18)
        sentinel[0] = 0xFE
        data = bytes(entry) + bytes(sentinel)
        rules = a._scan_for_operation_array(data, 0, ".rdata", _make_ir())
        assert len(rules) >= 1
        assert rules[0]["major_function"] == 0x00
        assert rules[0]["pre_operation"] == 0x5000

    def test_entry_with_post_operation(self):
        """Should detect entries with PostOperation set."""
        a = MinifilterRuleExtractor()
        entry = bytearray(0x18)
        entry[0] = 0x0E
        struct.pack_into('<Q', entry, 0x10, 0x6000)
        sentinel = bytearray(0x18)
        sentinel[0] = 0xFE
        data = bytes(entry) + bytes(sentinel)
        rules = a._scan_for_operation_array(data, 0, ".rdata", _make_ir())
        assert len(rules) >= 1
        assert rules[0]["post_operation"] == 0x6000
        assert rules[0]["pre_operation"] is None
