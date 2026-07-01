"""Tests for analyzer base class and plugin interface."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.analysis.analyzer import Analyzer
from src.models import (
    Architecture,
    Confidence,
    DisassemblyResult,
    Finding,
    FindingCategory,
    Sample,
    Severity,
)


# ------------------------------------------------------------------
# Test concrete analyzer implementations
# ------------------------------------------------------------------

class TestAnalyzerImplementations:
    """Verify all registered analyzers properly implement the interface."""

    def _make_sample(self) -> Sample:
        return Sample(
            path=Path("test.sys"),
            name="test.sys",
            company="Test",
            version="1.0",
            arch=Architecture.X64,
            sha256="abc",
            size=1000,
        )

    def _make_ir(self) -> DisassemblyResult:
        return DisassemblyResult(
            sample_path=Path("test.sys"),
            backend="capstone",
        )

    def test_structure_analyzer(self):
        from src.analysis.core.structure_analyzer import StructureAnalyzer
        a = StructureAnalyzer()
        assert a.name == "StructureAnalyzer"
        assert a.description != ""
        assert a.enabled is True
        assert a.is_correlator is False
        findings = a.analyze(self._make_sample(), self._make_ir())
        assert isinstance(findings, list)

    def test_dangerous_primitive_analyzer(self):
        from src.analysis.core.primitive_analyzer import DangerousPrimitiveAnalyzer
        a = DangerousPrimitiveAnalyzer()
        assert a.name == "DangerousPrimitiveAnalyzer"
        assert a.enabled is True
        findings = a.analyze(self._make_sample(), self._make_ir())
        assert isinstance(findings, list)

    def test_semantic_analyzer(self):
        from src.analysis.core.semantic_analyzer import SemanticAnalyzer
        a = SemanticAnalyzer()
        assert a.name == "SemanticAnalyzer"
        assert a.is_correlator is False

    def test_constraint_solver(self):
        from src.analysis.core.constraint_solver import ConstraintAnalyzer
        # ConstraintAnalyzer is not an Analyzer (not registered),
        # it's a utility class. Just verify import and construction.
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        a = ConstraintAnalyzer(ir)
        assert a.ir is ir

    def test_dataflow_analyzer(self):
        from src.analysis.dataflow.input_tracker import InputValidationAnalyzer
        a = InputValidationAnalyzer()
        assert a.name == "InputValidationAnalyzer"

    def test_deep_protection_analyzers(self):
        from src.analysis.deep.callback_resolver import CallbackResolver
        from src.analysis.deep.call_chain_analyzer import CallChainAnalyzer
        a = CallbackResolver()
        assert a.is_correlator is True
        b = CallChainAnalyzer()
        assert b.is_correlator is True

    def test_ovoida_engine(self):
        from src.analysis.deep.ovoida_engine import OvoidaEngine
        a = OvoidaEngine()
        # OvoidaEngine has an analyze method and stores backend
        assert hasattr(a, "analyze")
        assert a.backend == "ghidra"


# ------------------------------------------------------------------
# Test analyzer registry
# ------------------------------------------------------------------

class TestAnalyzerRegistry:
    def test_list_analyzers(self):
        from src.analysis.core.registry import list_analyzers
        analyzers = list_analyzers()
        assert len(analyzers) >= 2
        for a in analyzers:
            assert "name" in a
            assert "description" in a
            assert "enabled" in a

    def test_get_registered_analyzers(self):
        from src.analysis.core.registry import get_registered_analyzers
        analyzers = get_registered_analyzers()
        assert len(analyzers) >= 2

    def test_run_all_analyzers(self):
        from src.analysis.core.registry import run_all_analyzers
        sample = Sample(
            path=Path("test.sys"),
            name="test.sys",
            company="Test",
            version="1.0",
            arch=Architecture.X64,
            sha256="abc",
            size=1000,
        )
        ir = DisassemblyResult(sample_path=Path("test.sys"), backend="capstone")
        findings = run_all_analyzers(sample, ir)
        assert isinstance(findings, list)

    def test_register_custom_analyzer(self):
        from src.analysis.core.registry import (
            register_analyzers, list_analyzers, get_registered_analyzers,
            discover_analyzers, _registry,
        )

        class CustomAnalyzer(Analyzer):
            name = "CustomTestAnalyzer"
            description = "Custom test analyzer"

            def analyze(self, sample, ir):
                return []

        # Save original registry state
        original_registry = list(_registry)  # Copy the list

        # Discover and register all analyzers including our custom one
        discovered = discover_analyzers()
        discovered.append(CustomAnalyzer)
        instances = register_analyzers(discovered)

        # Verify our custom analyzer is present
        names = [a["name"] for a in list_analyzers()]
        assert "CustomTestAnalyzer" in names

        # Restore original registry
        from src.analysis.core import registry
        registry._registry[:] = original_registry  # Restore in-place


# ------------------------------------------------------------------
# Test Analyzer base class behavior
# ------------------------------------------------------------------

class TestAnalyzerBaseClass:
    def test_default_enabled(self):
        class TestAnalyzer(Analyzer):
            name = "TestEnabled"
            description = "Test"

            def analyze(self, sample, ir):
                return []

        a = TestAnalyzer()
        assert a.enabled is True

    def test_default_not_correlator(self):
        class TestAnalyzer(Analyzer):
            name = "TestCorrelator"
            description = "Test"

            def analyze(self, sample, ir):
                return []

        a = TestAnalyzer()
        assert a.is_correlator is False

    def test_get_metadata(self):
        class TestAnalyzer(Analyzer):
            name = "TestMeta"
            description = "Metadata test"

            def analyze(self, sample, ir):
                return []

        a = TestAnalyzer()
        meta = a.get_metadata()
        assert meta["name"] == "TestMeta"
        assert meta["description"] == "Metadata test"
        assert meta["enabled"] is True


# ------------------------------------------------------------------
# Test DisassemblyBackend base class
# ------------------------------------------------------------------

class TestDisassemblyBackendBase:
    def test_backend_is_abstract(self):
        """Cannot instantiate DisassemblyBackend directly."""
        from src.disassembly.backend import DisassemblyBackend
        with pytest.raises(TypeError):
            DisassemblyBackend()

    def test_capstone_backend_implementation(self):
        from src.disassembly.capstone_backend import CapstoneBackend
        b = CapstoneBackend()
        assert b.name == "capstone"
        assert b.is_available() is True
        assert "capstone" in b.get_version().lower() or b.get_version() != "unknown"

    def test_ghidra_backend_implementation(self):
        from src.disassembly.ghidra_backend import GhidraBackend
        b = GhidraBackend()
        assert b.name == "ghidra"
        # Ghidra may or may not be available, but the backend should exist
        assert isinstance(b.is_available(), bool)
        assert isinstance(b.get_version(), str)
