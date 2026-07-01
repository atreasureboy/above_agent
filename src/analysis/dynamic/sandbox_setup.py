"""
DriverScope -- Dynamic Analysis Environment Checker.

Validates that the host system has the required tools and configuration
for optional dynamic analysis (Phase 2 dynamic validation):

  1. QEMU VM engine (qemu-system-x86_64)
  2. VM disk image (Windows guest)
  3. WinDbg Preview / Debugging Tools for Windows
  4. KDNET (kernel debugging over network) configuration status

Usage:
    python -m src check-env
    # or programmatically:
    from src.analysis.dynamic.sandbox_setup import check_environment
    result = check_environment()
    print(result.summary())

All checks are read-only -- no VMs are started, no drivers are loaded.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ComponentStatus:
    """Status of a single environment component."""
    name: str
    available: bool = False
    path: str = ""
    version: str = ""
    details: str = ""
    hint: str = ""


@dataclass
class EnvCheckResult:
    """Aggregated result of the full environment check."""
    components: list[ComponentStatus] = field(default_factory=list)
    overall_ready: bool = False
    summary_lines: list[str] = field(default_factory=list)

    def summary(self) -> str:
        """Return a human-readable summary."""
        lines = ["=" * 60, "DriverScope Dynamic Analysis Environment", "=" * 60]
        for comp in self.components:
            status = "OK" if comp.available else "MISSING"
            line = f"  [{status}] {comp.name}"
            if comp.version:
                line += f"  ({comp.version})"
            if comp.path:
                line += f" -- {comp.path}"
            lines.append(line)
            if comp.details:
                lines.append(f"        {comp.details}")
            if comp.hint and not comp.available:
                lines.append(f"        Hint: {comp.hint}")
        lines.append("")
        lines.append(f"  Overall ready: {'YES' if self.overall_ready else 'NO'}")
        lines.append("=" * 60)
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# Individual checkers
# ---------------------------------------------------------------------------


def _find_in_path(*names: str) -> str:
    """Return the full path of the first executable found in PATH."""
    for name in names:
        full = shutil.which(name)
        if full:
            return full
    return ""


def _run(cmd: list[str], timeout: int = 10) -> str:
    """Run a command and return stdout, or empty string on failure."""
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return (result.stdout or result.stderr or "").strip()
    except Exception:
        return ""


def _check_qemu() -> ComponentStatus:
    """Check if QEMU system emulator is available."""
    candidates = [
        "qemu-system-x86_64.exe",
        "qemu-system-x86_64",
        "qemu-system-i386.exe",
        "qemu-system-i386",
    ]
    qemu_path = _find_in_path(*candidates)

    # Also check common install locations on Windows
    if not qemu_path:
        for base in [
            r"C:\Program Files\qemu",
            r"C:\Program Files (x86)\qemu",
        ]:
            for exe in candidates:
                p = Path(base) / exe
                if p.exists():
                    qemu_path = str(p)
                    break
            if qemu_path:
                break

    # Also check environment variable override
    env_override = os.environ.get("DRIVERSCOPE_QEMU_PATH", "")
    if env_override and Path(env_override).exists():
        qemu_path = env_override

    status = ComponentStatus(name="QEMU", available=bool(qemu_path), path=qemu_path)

    if qemu_path:
        version_out = _run([qemu_path, "--version"])
        if version_out:
            status.version = version_out.splitlines()[0] if version_out else "unknown"
        status.details = "QEMU system emulator found"
    else:
        status.hint = (
            "Install QEMU from https://www.qemu.org/download/ and add it to PATH, "
            "or set DRIVERSCOPE_QEMU_PATH to qemu-system-x86_64.exe"
        )

    return status


def _check_vm_image() -> ComponentStatus:
    """Check if a VM disk image is configured and exists."""
    image_path = os.environ.get("DRIVERSCOPE_VM_IMAGE", "")
    status = ComponentStatus(name="VM Image")

    if not image_path:
        status.available = False
        status.hint = (
            "Set DRIVERSCOPE_VM_IMAGE to a Windows VM disk image (.qcow2 or .raw). "
            "Recommended: Windows 10/11 VM from https://developer.microsoft.com/windows/downloads/virtual-machines/"
        )
        status.details = "No VM image configured (env var DRIVERSCOPE_VM_IMAGE)"
        return status

    if Path(image_path).exists():
        size_mb = Path(image_path).stat().st_size / (1024 * 1024)
        status.available = True
        status.path = image_path
        status.details = f"Image exists ({size_mb:.0f} MB)"
    else:
        status.available = False
        status.path = image_path
        status.hint = f"File not found: {image_path}"

    return status


def _check_windbg() -> ComponentStatus:
    """Check if WinDbg (kernel debugger) is available."""
    # WinDbg Preview (Microsoft Store)
    candidates = [
        "windbgx.exe",  # WinDbg Preview (new)
        "windbg.exe",    # Debugging Tools for Windows (classic)
        "kd.exe",        # Kernel debugger (classic)
    ]
    windbg_path = _find_in_path(*candidates)

    # Common install locations
    if not windbg_path:
        common_dirs = [
            # WinDbg Preview (Store app)
            r"C:\Program Files\WindowsApps\Microsoft.WinDbg_*\windbgx.exe",
            # WDK
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe",
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kd.exe",
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\windbg.exe",
        ]
        for pattern in common_dirs:
            # Handle wildcard for Store app
            if "*" in pattern:
                parent = Path(pattern).parent
                search_name = Path(pattern).name
                if parent.exists():
                    matches = list(parent.glob(search_name))
                    if matches:
                        windbg_path = str(matches[0])
                        break
            else:
                if Path(pattern).exists():
                    windbg_path = pattern
                    break

    # Environment override
    env_override = os.environ.get("DRIVERSCOPE_WINDBG_PATH", "")
    if env_override and Path(env_override).exists():
        windbg_path = env_override

    status = ComponentStatus(name="WinDbg", available=bool(windbg_path), path=windbg_path)

    if windbg_path:
        # WinDbg Preview doesn't support --version the same way
        if "windbgx" in windbg_path.lower():
            status.version = "WinDbg Preview (Store)"
            status.details = "Modern WinDbg (supports KDNET, time travel)"
        elif "kd.exe" in windbg_path.lower():
            status.details = "Kernel debugger (classic)"
        else:
            status.details = "WinDbg classic"
    else:
        status.hint = (
            "Install WinDbg Preview from the Microsoft Store, or install the "
            "Windows Driver Kit (WDK) from https://learn.microsoft.com/windows-hardware/drivers/download-the-wdk"
        )

    return status


def _check_kdnet() -> ComponentStatus:
    """Check KDNET (kernel debugging over network) configuration hints."""
    status = ComponentStatus(name="KDNET")

    # KDNET requires:
    # 1. Target VM with debugging enabled
    # 2. Host IP and port known
    # 3. WinDbg can connect via KDNET

    kdnet_host = os.environ.get("DRIVERSCOPE_KDNET_HOST", "")
    kdnet_port = os.environ.get("DRIVERSCOPE_KDNET_PORT", "50000")

    if kdnet_host:
        status.available = True
        status.details = f"KDNET target: {kdnet_host}:{kdnet_port}"
    else:
        status.available = False
        status.hint = (
            "Set DRIVERSCOPE_KDNET_HOST to the target VM's IP address. "
            "On the VM, enable kernel debugging: 'bcdedit /debug on' and "
            "'bcdedit /dbgsettings net hostip:<VM_IP> port:50000'. "
            "See https://learn.microsoft.com/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection"
        )
        status.details = "Not configured (env var DRIVERSCOPE_KDNET_HOST)"

    return status


def _check_dynamic_flag() -> ComponentStatus:
    """Check if the DRIVERSCOPE_DYNAMIC feature flag is enabled."""
    enabled = os.environ.get("DRIVERSCOPE_DYNAMIC", "0") == "1"
    status = ComponentStatus(
        name="Feature Flag (DRIVERSCOPE_DYNAMIC)",
        available=enabled,
    )
    if enabled:
        status.details = "Dynamic analysis is enabled -- validation will run"
    else:
        status.details = "Dynamic analysis is disabled (set DRIVERSCOPE_DYNAMIC=1 to enable)"
        status.hint = "Set DRIVERSCOPE_DYNAMIC=1 in your environment to activate dynamic validation"
    return status


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def check_environment() -> EnvCheckResult:
    """Run all environment checks and return aggregated results.

    Returns:
        EnvCheckResult with component statuses and overall readiness.
    """
    checks = [
        _check_qemu,
        _check_vm_image,
        _check_windbg,
        _check_kdnet,
        _check_dynamic_flag,
    ]

    result = EnvCheckResult()
    for check in checks:
        result.components.append(check())

    # Overall: ready if all core components (QEMU + VM image + WinDbg) are available
    core = [c for c in result.components if c.name in ("QEMU", "VM Image", "WinDbg")]
    result.overall_ready = all(c.available for c in core)

    return result


def cli_main() -> int:
    """CLI entry point -- print environment check and return exit code."""
    result = check_environment()
    print(result.summary())
    return 0 if result.overall_ready else 1


if __name__ == "__main__":
    import sys
    sys.exit(cli_main())
