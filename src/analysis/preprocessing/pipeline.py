"""
DriverScope — Preprocessing Pipeline Orchestrator.

Routes samples through the appropriate unpacking/deobfuscation path
based on detected packer type and obfuscation level.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

class UnpackStrategy(Enum):
    """Strategy for unpacking a sample."""
    NONE = "none"                     # No unpacking needed
    STATIC_UPX = "static_upx"         # UPX static unpack
    STATIC_MPRESS = "static_mpress"   # MPRESS static unpack
    STATIC_GENERIC = "static_generic" # Generic PE rebuild
    DYNAMIC_FRIDA = "dynamic_frida"   # Frida-based dynamic unpack
    DYNAMIC_DEBUGGER = "dynamic_debugger"  # WinDbg-based unpack
    CAPE_SANDBOX = "cape_sandbox"     # CAPE automatic unpack


@dataclass
class PreprocessingConfig:
    """Configuration for the preprocessing pipeline."""
    # Enable/disable preprocessing
    enabled: bool = True

    # Static unpacking
    upx_binary: str = ""              # Path to upx binary (auto-detect if empty)
    allow_static_unpack: bool = True

    # Dynamic unpacking
    allow_dynamic_unpack: bool = True
    dynamic_unpack_timeout: int = 120

    # Sandbox config (for dynamic unpacking)
    qemu_path: str = ""
    vm_image: str = ""
    sandbox_snapshot: str = "clean"

    # Frida config
    frida_server_port: int = 27042

    # CAPE config
    cape_api_url: str = "http://localhost:8090"
    use_cape: bool = False

    # Deobfuscation
    allow_deobfuscation: bool = True
    cff_deflatten: bool = True
    string_decrypt: bool = True
    api_hash_resolve: bool = True

    # Output
    output_dir: str = ""              # Where to store unpacked binaries


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class PackerInfo:
    """Detected packer/protector information."""
    name: str = ""                    # "UPX", "VMProtect", "Themida", etc.
    version: str = ""
    confidence: float = 0.0           # 0.0 - 1.0
    reasons: list[str] = field(default_factory=list)
    entropy: float = 0.0
    section_entropies: dict[str, float] = field(default_factory=dict)
    has_empty_iat: bool = False
    entry_point_anomaly: bool = False
    is_packed: bool = False


@dataclass
class UnpackResult:
    """Result of an unpacking operation."""
    success: bool = False
    strategy: UnpackStrategy = UnpackStrategy.NONE
    unpacked_path: Path | None = None
    original_path: Path | None = None
    elapsed: float = 0.0
    error: str = ""
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class PreprocessingResult:
    """Complete preprocessing result."""
    target: str = ""
    packer_info: PackerInfo | None = None
    unpack_result: UnpackResult | None = None
    deobfuscation_applied: list[str] = field(default_factory=list)
    elapsed: float = 0.0
    # The final path to use for analysis (unpacked if successful, original otherwise)
    cleaned_target: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def was_unpacked(self) -> bool:
        return self.unpack_result is not None and self.unpack_result.success


# ---------------------------------------------------------------------------
# Router — decide how to handle a sample
# ---------------------------------------------------------------------------

class PreprocessingRouter:
    """Decides the optimal analysis path based on sample characteristics."""

    def route(
        self,
        sample_path: Path,
        packer_info: PackerInfo,
        config: PreprocessingConfig,
    ) -> list[tuple[str, str]]:
        """Return a list of (step_name, handler_name) tuples.

        The pipeline executes these steps in order.
        """
        steps: list[tuple[str, str]] = []

        if not packer_info.is_packed:
            # No packing detected — maybe just obfuscated
            if config.allow_deobfuscation:
                steps.append(("deobfuscate", "deobfuscator"))
            return steps

        packer = packer_info.name.upper()

        # Route based on known packer type
        if packer == "UPX":
            if config.allow_static_unpack:
                steps.append(("unpack", "UPXUnpacker"))
            else:
                steps.append(("unpack", "UPXUnpacker"))  # Still try

        elif packer == "MPRESS":
            if config.allow_static_unpack:
                steps.append(("unpack", "MPRESSUnpacker"))

        elif packer in ("VMPROTECT", "THEMIDA", "ASPACK", "PECOMPACT"):
            # Commercial packers — need dynamic unpacking
            if config.use_cape and config.cape_api_url:
                steps.append(("unpack", "CAPEBridge"))
            elif config.allow_dynamic_unpack:
                steps.append(("unpack", "DynamicUnpacker"))
            else:
                steps.append(("warn", "cannot_unpack"))

        else:
            # Unknown packer — try generic static, fallback to dynamic
            if config.allow_static_unpack:
                steps.append(("unpack", "GenericPEUnpacker"))
            if config.allow_dynamic_unpack:
                steps.append(("unpack_fallback", "DynamicUnpacker"))

        # Always deobfuscate after unpacking
        if config.allow_deobfuscation:
            steps.append(("deobfuscate", "deobfuscator"))

        return steps


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run_preprocessing(
    target: str,
    config: PreprocessingConfig | None = None,
) -> PreprocessingResult:
    """Run the preprocessing pipeline on a target file or directory.

    Args:
        target: Path to .sys/.exe/.dll file or directory.
        config: Preprocessing configuration.

    Returns:
        PreprocessingResult with packer info, unpack results, and
        the path to use for subsequent analysis.
    """
    start = time.time()
    cfg = config or PreprocessingConfig()
    result = PreprocessingResult(target=target)

    if not cfg.enabled:
        result.cleaned_target = target
        return result

    target_path = Path(target)
    if not target_path.exists():
        result.warnings.append(f"Target does not exist: {target}")
        result.cleaned_target = target
        return result

    logger.info("[preprocessing] Starting preprocessing for: %s", target)

    # Step 1: Classify packer/protector
    packer_info = _classify_packer(target_path)
    result.packer_info = packer_info

    if packer_info.is_packed:
        logger.info(
            "[preprocessing] Detected packer: %s (confidence: %.2f)",
            packer_info.name,
            packer_info.confidence,
        )
    else:
        logger.info("[preprocessing] No packer detected")

    # Step 2: Route and execute
    router = PreprocessingRouter()
    steps = router.route(target_path, packer_info, cfg)

    current_target = target_path
    for step_name, handler_name in steps:
        logger.info("[preprocessing] Executing step: %s → %s", step_name, handler_name)

        if step_name == "unpack":
            unpack_result = _execute_unpack(current_target, handler_name, cfg)
            result.unpack_result = unpack_result

            if unpack_result.success and unpack_result.unpacked_path:
                current_target = unpack_result.unpacked_path
                logger.info(
                    "[preprocessing] Unpacked to: %s",
                    unpack_result.unpacked_path,
                )
            else:
                logger.warning(
                    "[preprocessing] Unpack failed: %s",
                    unpack_result.error,
                )
                result.warnings.append(f"Unpack failed: {unpack_result.error}")

        elif step_name == "deobfuscate":
            deobf_results = _execute_deobfuscation(current_target, cfg)
            result.deobfuscation_applied = deobf_results

        elif step_name == "warn":
            result.warnings.append(f"Cannot unpack {packer_info.name} — no suitable handler")

    # Step 3: Set final target
    result.cleaned_target = str(current_target)
    result.elapsed = time.time() - start

    logger.info(
        "[preprocessing] Complete in %.2fs — final target: %s",
        result.elapsed,
        result.cleaned_target,
    )

    return result


def _classify_packer(sample_path: Path) -> PackerInfo:
    """Classify packer/protector of a sample.

    Uses the existing anti_obfuscation analyzer and extends it.
    """
    from src.analysis.core.anti_obfuscation import detect_packer

    info = PackerInfo()

    try:
        raw = detect_packer(sample_path)

        info.name = raw.get("packer_name") or ""
        info.confidence = 1.0 if info.name else 0.0
        info.reasons = raw.get("reasons", [])
        info.section_entropies = raw.get("section_entropy", {})
        # Compute overall entropy as max of section entropies
        if info.section_entropies:
            info.entropy = max(info.section_entropies.values()) if info.section_entropies else 0.0
        info.has_empty_iat = raw.get("has_empty_iat", False)
        info.entry_point_anomaly = raw.get("entry_point_anomaly", False)
        info.is_packed = raw.get("overall_suspicious", False)

        # Additional heuristics for packer identification
        if not info.name and info.is_packed:
            info.name = "unknown_packer"
            info.confidence = 0.5

    except Exception as e:
        logger.warning("[preprocessing] Packer detection failed: %s", e)
        info.reasons.append(f"Detection error: {e}")

    return info


def _execute_unpack(
    sample_path: Path,
    handler_name: str,
    config: PreprocessingConfig,
) -> UnpackResult:
    """Execute an unpacking handler on the sample."""
    start = time.time()
    result = UnpackResult(original_path=sample_path)

    try:
        if handler_name == "UPXUnpacker":
            from src.analysis.preprocessing.static_unpacker import UPXUnpacker
            unpacker = UPXUnpacker(upx_binary=config.upx_binary)
            if unpacker.can_handle(sample_path):
                unpacked = unpacker.unpack(sample_path, config.output_dir)
                if unpacked:
                    result.success = True
                    result.strategy = UnpackStrategy.STATIC_UPX
                    result.unpacked_path = unpacked
                else:
                    result.error = "UPX unpack returned no output"
            else:
                result.error = "UPXUnpacker: sample is not UPX-packed"

        elif handler_name == "MPRESSUnpacker":
            from src.analysis.preprocessing.static_unpacker import MPRESSUnpacker
            unpacker = MPRESSUnpacker()
            if unpacker.can_handle(sample_path):
                unpacked = unpacker.unpack(sample_path, config.output_dir)
                if unpacked:
                    result.success = True
                    result.strategy = UnpackStrategy.STATIC_MPRESS
                    result.unpacked_path = unpacked
                else:
                    result.error = "MPRESS unpack returned no output"
            else:
                result.error = "MPRESSUnpacker: sample is not MPRESS-packed"

        elif handler_name == "GenericPEUnpacker":
            from src.analysis.preprocessing.static_unpacker import GenericPEUnpacker
            unpacker = GenericPEUnpacker()
            unpacked = unpacker.try_rebuild(sample_path, config.output_dir)
            if unpacked:
                result.success = True
                result.strategy = UnpackStrategy.STATIC_GENERIC
                result.unpacked_path = unpacked
            else:
                result.error = "Generic rebuild failed"

        elif handler_name == "DynamicUnpacker":
            from src.analysis.preprocessing.dynamic_unpacker import DynamicUnpacker
            unpacker = DynamicUnpacker(
                qemu_path=config.qemu_path,
                vm_image=config.vm_image,
                snapshot=config.sandbox_snapshot,
                frida_port=config.frida_server_port,
                timeout=config.dynamic_unpack_timeout,
            )
            unpacked = unpacker.unpack(sample_path, config.output_dir)
            if unpacked:
                result.success = True
                result.strategy = UnpackStrategy.DYNAMIC_FRIDA
                result.unpacked_path = unpacked
            else:
                result.error = unpacker.last_error or "Dynamic unpack failed"

        elif handler_name == "CAPEBridge":
            from src.analysis.preprocessing.cape_bridge import CAPEBridge
            bridge = CAPEBridge(cape_url=config.cape_api_url)
            unpacked = bridge.submit_and_unpack(sample_path, config.output_dir)
            if unpacked:
                result.success = True
                result.strategy = UnpackStrategy.CAPE_SANDBOX
                result.unpacked_path = unpacked
            else:
                result.error = "CAPE unpack failed"

        else:
            result.error = f"Unknown unpack handler: {handler_name}"

    except ImportError as e:
        result.error = f"Missing dependency: {e}"
    except Exception as e:
        result.error = f"Unpack error: {e}"

    result.elapsed = time.time() - start
    return result


def _execute_deobfuscation(
    sample_path: Path,
    config: PreprocessingConfig,
) -> list[str]:
    """Execute deobfuscation passes on the sample.

    Returns list of applied deobfuscation techniques.
    """
    applied: list[str] = []

    try:
        # These deobfuscation passes enrich the analysis context
        # but don't modify the binary — they prepare metadata
        # for the static analysis phase

        if config.string_decrypt:
            try:
                from src.analysis.deep.string_decryptor import detect_encrypted_strings
                encrypted = detect_encrypted_strings(sample_path)
                if encrypted:
                    applied.append(f"string_encryption({len(encrypted)} streams)")
            except Exception:
                pass

        if config.api_hash_resolve:
            try:
                from src.analysis.deep.api_hash_bruteforce import detect_api_hashing
                hashes = detect_api_hashing(sample_path)
                if hashes:
                    applied.append(f"api_hashing({len(hashes)} hashes)")
            except Exception:
                pass

        if config.cff_deflatten:
            # CFF detection is done by the static analyzer —
            # just note it as available
            applied.append("cff_deflatten(available)")

    except Exception as e:
        logger.warning("[preprocessing] Deobfuscation error: %s", e)

    return applied
