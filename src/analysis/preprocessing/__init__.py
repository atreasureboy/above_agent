"""
DriverScope — Phase 0: Preprocessing Layer.

Handles unpacking, deobfuscation, and sample preparation before
the main static analysis pipeline.

Architecture:
    Input sample → packer_classifier → static_unpacker / dynamic_unpacker
                                     → deobfuscator
                                     → clean PE → Phase 1 (DriverScope)

This layer can:
1. Detect known packers (UPX, MPRESS, VMProtect, Themida, etc.)
2. Statically unpack simple packers (UPX)
3. Dynamically unpack complex packers via sandbox + Frida
4. Deobfuscate control flow flattening, string encryption, API hashing
5. Route samples to the optimal analysis path

Usage:
    from src.analysis.preprocessing import run_preprocessing

    result = run_preprocessing(target_path)
    if result.unpacked_path:
        # Analyze the unpacked binary instead
        config.target = str(result.unpacked_path)
"""

from src.analysis.preprocessing.pipeline import (
    PreprocessingResult,
    PreprocessingConfig,
    run_preprocessing,
)

__all__ = [
    "PreprocessingResult",
    "PreprocessingConfig",
    "run_preprocessing",
]
