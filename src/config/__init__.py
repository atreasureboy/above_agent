"""DEVOPS_driver — Unified configuration.

Combines PipelineConfig (top-level pipeline), DriverScope defaults,
and OVOIDA API settings (model URL, API key, etc.).

Precedence (highest to lowest):
  1. CLI arguments
  2. ~/.devops_driver/config.json
  3. defaults.py constants
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class PipelineConfig:
    """Top-level configuration for the DEVOPS_driver pipeline."""

    # Target directory containing .sys files to analyze
    target: Path

    # Output workspace for all generated artifacts
    workspace: Path = Path("workspace")

    # --- Phase 0: Preprocessing (unpacking / deobfuscation) ---
    enable_preprocessing: bool = True
    allow_static_unpack: bool = True
    allow_dynamic_unpack: bool = False        # Requires QEMU + Frida
    upx_binary: str = ""                      # Auto-detect if empty
    dynamic_unpack_timeout: int = 120
    qemu_path: str = ""                       # Path to qemu-system-x86_64
    vm_image: str = ""                        # Path to QEMU disk image
    sandbox_snapshot: str = "clean"
    frida_server_port: int = 27042
    cape_api_url: str = "http://localhost:8090"
    use_cape: bool = False
    evasion_level: int = 0                    # 0=off, 1=basic, 2=medium, 3=aggressive

    # --- Phase 1: DriverScope ---
    risk_threshold: float = 5.0       # Min risk score to qualify for Phase 2
    max_deep_targets: int = 5         # Max drivers for OVOIDA (0 = unlimited)
    ds_backend: str = "capstone"
    ds_timeout: int = 30
    ds_workers: int = 0               # 0 = auto
    ds_use_funnel: bool = True
    ds_use_cache: bool = True
    ds_include_usermode: bool = False  # Also analyze .exe/.dll files
    ds_score_engine: str = "default"   # default | exploitability

    # --- Phase 1.5: Ghidra Deep Analysis (between Phase 1 and Phase 2) ---
    ghidra_deep: bool = False            # Run Ghidra full analysis on high-risk candidates
    ghidra_deep_threshold: float = 5.0   # Min risk score for Ghidra deep analysis
    ghidra_deep_timeout: int = 300       # Timeout per driver for Ghidra (5 min)
    ghidra_deep_max: int = 5             # Max drivers for Ghidra deep analysis

    # --- Phase 2: OVOIDA ---
    ovoida_root: Path | None = None      # Override default components/ovoida path
    ov_output_mode: str = "pseudocode"   # full_reconstruction | live_logic | pseudocode
    ov_max_iter: int = 30
    ov_timeout: int = 0                  # 0 = unlimited

    # OVOIDA LLM API settings
    ov_api_url: str = ""                 # e.g. https://api.openai.com/v1
    ov_api_key: str = ""
    ov_model: str = ""                   # e.g. gpt-4o, claude-sonnet-4-6

    # --- Reporting ---
    report_formats: list[str] = field(default_factory=lambda: ["json", "markdown"])
    unified_report: bool = True

    def resolve_paths(self) -> None:
        """Ensure all Path values are absolute."""
        self.target = self.target.resolve()
        self.workspace = self.workspace.resolve()

    def ov_session_dir(self, sample_name: str) -> Path:
        """Return the OVOIDA session directory for a given sample."""
        safe_name = sample_name.replace(".", "_").replace(" ", "_")
        return self.workspace / "sessions" / safe_name

    def has_ovoida_api(self) -> bool:
        """Check if OVOIDA API credentials are configured."""
        return bool(self.ov_api_url and self.ov_api_key)
