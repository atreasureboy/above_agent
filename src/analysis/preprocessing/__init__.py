"""
DriverScope — Phase 0: Preprocessing Layer.

Handles unpacking, deobfuscation, and sample preparation before
the main static analysis pipeline.

Architecture:
    Input sample → packer_classifier → static_unpacker / dynamic_unpacker
                                     → deobfuscator
                                     → pe_repair
                                     → clean PE → Phase 1 (DriverScope)

Modules:
    pipeline.py            — Preprocessing pipeline orchestrator
    static_unpacker.py     — UPX / MPRESS / Generic static unpackers
    dynamic_unpacker.py    — Frida + Sandbox dynamic unpacking
    deobfuscator.py        — CFF deflattening + dead code removal
    iat_reconstructor.py   — IAT auto-reconstruction with lief
    pe_repair.py           — PE header repair after memory dump
    unpack_strategies.py   — Known packer → optimal strategy mapping
    cape_bridge.py         — CAPE Sandbox integration

Usage:
    from src.analysis.preprocessing import run_preprocessing

    result = run_preprocessing(target_path)
    if result.unpacked_path:
        config.target = str(result.unpacked_path)
"""

from src.analysis.preprocessing.pipeline import (
    PreprocessingResult,
    PreprocessingConfig,
    PackerInfo,
    run_preprocessing,
)
from src.analysis.preprocessing.unpack_strategies import (
    get_strategy,
    get_strategy_for_sample,
    PACKER_DATABASE,
)

__all__ = [
    "PreprocessingResult",
    "PreprocessingConfig",
    "PackerInfo",
    "run_preprocessing",
    "get_strategy",
    "get_strategy_for_sample",
    "PACKER_DATABASE",
]
