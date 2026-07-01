"""
DriverScope — Analyzer Registry.

Automatically discovers and registers all Analyzer subclasses from
the core and dataflow modules. Provides a unified interface for
running all analyzers against a sample.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Type

from src.analysis.analyzer import Analyzer
from src.models import DisassemblyResult, Finding, Sample

# Module paths to scan for Analyzer subclasses
_ANALYZER_MODULES = [
    "src.analysis.core",
    "src.analysis.dataflow",
    "src.analysis.dynamic",
    "src.analysis.deep",
]

_registry: list[Analyzer] = []


def discover_analyzers() -> list[Type[Analyzer]]:
    """Discover all Analyzer subclasses in registered modules."""
    analyzers: list[Type[Analyzer]] = []

    for module_path in _ANALYZER_MODULES:
        try:
            pkg = importlib.import_module(module_path)
            for importer, modname, is_pkg in pkgutil.walk_packages(
                pkg.__path__, prefix=module_path + "."
            ):
                try:
                    mod = importlib.import_module(modname)
                    for attr_name in dir(mod):
                        attr = getattr(mod, attr_name)
                        if (
                            isinstance(attr, type)
                            and issubclass(attr, Analyzer)
                            and attr is not Analyzer
                        ):
                            analyzers.append(attr)
                except ImportError:
                    continue
        except ImportError:
            continue

    return analyzers


def register_analyzers(analyzer_classes: list[Type[Analyzer]]) -> list[Analyzer]:
    """Instantiate and register analyzer classes."""
    global _registry
    _registry = []
    for cls in analyzer_classes:
        try:
            _registry.append(cls())
        except Exception as e:
            print(f"[registry] Failed to instantiate {cls.__name__}: {e}")
    return _registry


def get_registered_analyzers() -> list[Analyzer]:
    """Return the list of registered analyzer instances."""
    if not _registry:
        discovered = discover_analyzers()
        register_analyzers(discovered)
    return _registry


def run_all_analyzers(
    sample: Sample,
    ir: DisassemblyResult,
    enabled_only: bool = True,
) -> list[Finding]:
    """Run all registered analyzers against a sample.

    Runs in three phases:
    0. Deobfuscation — resolve hashed APIs / encrypted strings (mutates IR)
    1. Independent analyzers (all except correlators)
    2. Correlators (which need all other findings populated)
    """
    all_findings: list[Finding] = []

    # Phase 0: Deobfuscation — resolve API hashes before other analyzers
    try:
        from src.analysis.core.deobfuscation import (
            create_resolution_findings,
            resolve_api_hashes,
        )
        resolved = resolve_api_hashes(ir)
        if resolved:
            deob_findings = create_resolution_findings(ir, resolved)
            all_findings.extend(deob_findings)
            print(f"[deobfuscation] Resolved {sum(len(v) for v in resolved.values())} hashed APIs in {len(resolved)} functions")
    except Exception as e:
        print(f"[deobfuscation] Resolution failed: {e}")

    # Phase 0b: Extended API hash resolution (CRC32, DJB2, FNV-1a, ELF, Jenkins)
    try:
        from src.analysis.core.api_hash_bruteforce import (
            create_extended_findings,
            resolve_extended_api_hashes,
        )
        extended = resolve_extended_api_hashes(ir)
        if extended:
            ext_findings = create_extended_findings(ir, extended)
            all_findings.extend(ext_findings)
            total_resolved = sum(len(v) for v in extended.values())
            print(f"[deobfuscation] Extended hash resolution: {total_resolved} APIs in {len(extended)} functions")
    except Exception as e:
        print(f"[deobfuscation] Extended resolution failed: {e}")

    # Phase 0c: String decryption (multi-byte XOR, rolling XOR, ADD/SUB, NOT+XOR)
    try:
        from src.analysis.core.string_decryptor import (
            create_decryption_findings,
            decrypt_all_strings,
        )
        decrypted = decrypt_all_strings(ir)
        if decrypted:
            str_findings = create_decryption_findings(ir, decrypted)
            all_findings.extend(str_findings)
            print(f"[deobfuscation] Decrypted {len(decrypted)} strings")
    except Exception as e:
        print(f"[deobfuscation] String decryption failed: {e}")

    # Phase 1: Run independent analyzers
    for analyzer in get_registered_analyzers():
        if enabled_only and not analyzer.enabled:
            continue
        # Skip correlators in phase 1
        if analyzer.is_correlator:
            continue

        print(f"[analysis] Running {analyzer.name}...")
        try:
            findings = analyzer.analyze(sample, ir)
            all_findings.extend(findings)
            print(f"  {analyzer.name}: {len(findings)} findings")
        except Exception as e:
            print(f"  {analyzer.name}: ERROR — {e}")

    # Populate sample with phase 1 findings so correlators can use them
    sample.analysis_findings = list(all_findings)

    # Phase 2: Run correlators (need all other findings available)
    for analyzer in get_registered_analyzers():
        if enabled_only and not analyzer.enabled:
            continue
        if not analyzer.is_correlator:
            continue

        print(f"[analysis] Running {analyzer.name}...")
        try:
            findings = analyzer.analyze(sample, ir)
            all_findings.extend(findings)
            print(f"  {analyzer.name}: {len(findings)} findings")
        except Exception as e:
            print(f"  {analyzer.name}: ERROR — {e}")

    return all_findings


def list_analyzers() -> list[dict]:
    """Return metadata for all registered analyzers."""
    return [a.get_metadata() for a in get_registered_analyzers()]
