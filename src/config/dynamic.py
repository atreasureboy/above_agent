"""
DriverScope — Dynamic analysis configuration.

Safety-gated: all dynamic operations require explicit opt-in via
DRIVERSCOPE_DYNAMIC=1 environment variable AND administrator privileges.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DynamicConfig:
    """Dynamic analysis configuration."""
    safety_gate: bool = True           # Must be True (only env var can override)
    sandbox_enabled: bool = True       # Require sandbox for all dynamic ops
    debugger_attached: bool = False    # WinDbg/KD attached for runtime analysis
    max_crash_retries: int = 0         # Never retry after a crash
    timeout_per_test: int = 30         # Seconds per individual test case
    qemu_path: str = ""                # Path to qemu-system-x86_64.exe
    vm_image: str = ""                 # Path to VM disk image
    snapshot_name: str = "clean"       # VM snapshot name for revert
    windbg_path: str = ""              # Path to WinDbg (windbgx.exe)
    symbol_path: str = (
        "srv*https://msdl.microsoft.com/download/symbols"
    )

    @classmethod
    def from_dict(cls, data: dict) -> "DynamicConfig":
        """Create from dictionary (CLI args / config file)."""
        known = {
            "safety_gate", "sandbox_enabled", "debugger_attached",
            "max_crash_retries", "timeout_per_test", "qemu_path",
            "vm_image", "snapshot_name", "windbg_path", "symbol_path",
        }
        return cls(**{k: v for k, v in data.items() if k in known})


def check_admin() -> bool:
    """Check if running with administrator privileges."""
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def safety_check(config: DynamicConfig) -> bool:
    """
    Verify all safety gates before allowing dynamic analysis.

    Raises RuntimeError if any gate fails.
    """
    env_override = os.environ.get("DRIVERSCOPE_DYNAMIC", "0")
    if env_override != "1":
        raise RuntimeError(
            "动态分析被安全门控阻止。设置环境变量 DRIVERSCOPE_DYNAMIC=1 以启用。\n"
            "PowerShell: $env:DRIVERSCOPE_DYNAMIC='1'\n"
            "CMD: set DRIVERSCOPE_DYNAMIC=1"
        )

    if not check_admin():
        raise RuntimeError("动态分析需要管理员权限。请以管理员身份运行。")

    if config.sandbox_enabled and not config.qemu_path:
        raise RuntimeError(
            "沙箱模式需要 QEMU。请配置 qemu_path 或禁用沙箱。"
        )

    return True
