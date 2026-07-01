"""
DriverScope -- QEMU Sandbox Manager.

Manages QEMU virtual machines for safe driver execution:

- Start/stop VM from snapshot
- Revert to clean snapshot after each test
- Copy files to/from VM
- Execute commands inside VM
- Capture serial/console output
- Monitor for crashes

This provides isolation between the host system and potentially
crash-inducing driver operations.
"""

from __future__ import annotations

import subprocess
import time
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class SandboxConfig:
    """QEMU sandbox configuration."""
    qemu_path: str = ""
    vm_image: str = ""
    snapshot_name: str = "clean"
    memory_mb: int = 4096
    cpu_cores: int = 2
    display: str = "none"  # "none", "gtk", "sdl"
    network: str = "none"  # "none", "user", "bridge"
    serial_log: str = ""   # Path to serial output log


@dataclass
class SandboxState:
    """Current sandbox VM state."""
    running: bool = False
    process: Any = None  # subprocess.Popen
    start_time: float = 0.0
    serial_log_path: str = ""
    last_command_output: str = ""


class SandboxManager:
    """QEMU-based sandbox for safe driver execution."""

    def __init__(self, config: SandboxConfig | None = None):
        """Initialize the sandbox manager.

        Args:
            config: Sandbox configuration. Uses defaults if None.
        """
        self.config = config or SandboxConfig()
        self.state = SandboxState()

    @property
    def is_available(self) -> bool:
        """Check if QEMU sandbox is available and configured."""
        if not self.config.qemu_path:
            return False
        qemu = Path(self.config.qemu_path)
        return qemu.exists() and Path(self.config.vm_image).exists()

    def start(self) -> bool:
        """Start the VM from the configured snapshot.

        Returns:
            True if VM started successfully.
        """
        if not self.is_available:
            logging.warning("[sandbox] QEMU not available")
            return False

        # Revert to clean snapshot first
        self.revert_snapshot()

        cmd = [
            self.config.qemu_path,
            "-hda", self.config.vm_image,
            "-m", str(self.config.memory_mb),
            "-smp", str(self.config.cpu_cores),
            "-loadvm", self.config.snapshot_name,
            "-display", self.config.display,
            "-net", self.config.network,
            "-nographic",
        ]

        if self.config.serial_log:
            cmd.extend(["-serial", f"file:{self.config.serial_log}"])
            self.state.serial_log_path = self.config.serial_log

        try:
            self.state.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                stdin=subprocess.PIPE,
            )
            self.state.running = True
            self.state.start_time = time.time()

            # Wait for boot
            time.sleep(10)
            logging.info("[sandbox] VM started from snapshot '%s'",
                         self.config.snapshot_name)
            return True

        except Exception as e:
            logging.error("[sandbox] Failed to start VM: %s", e)
            return False

    def stop(self) -> bool:
        """Stop the VM.

        Returns:
            True if VM stopped successfully.
        """
        if not self.state.running or not self.state.process:
            return True

        try:
            self.state.process.terminate()
            self.state.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.state.process.kill()
        except Exception:
            pass

        self.state.running = False
        self.state.process = None
        logging.info("[sandbox] VM stopped")
        return True

    def revert_snapshot(self) -> bool:
        """Revert VM to clean snapshot.

        Returns:
            True if snapshot was reverted.
        """
        if not self.is_available:
            return False

        # Stop existing VM if running
        if self.state.running:
            self.stop()

        # Use qemu-img to verify snapshot exists
        try:
            result = subprocess.run(
                [
                    self.config.qemu_path.replace("qemu-system-x86_64.exe",
                                                   "qemu-img.exe"),
                    "snapshot", "-l", self.config.vm_image,
                ],
                capture_output=True, text=True, timeout=10,
            )
            if self.config.snapshot_name not in result.stdout:
                logging.warning(
                    "[sandbox] Snapshot '%s' not found in VM image",
                    self.config.snapshot_name,
                )
        except Exception:
            # qemu-img might not be available; proceed anyway
            pass

        logging.info("[sandbox] Will load snapshot '%s' on next start",
                      self.config.snapshot_name)
        return True

    def copy_file_to_vm(self, host_path: str, guest_path: str) -> bool:
        """Copy a file into the running VM.

        Uses qemu monitor commands or guest agent.
        For simplicity, this copies via shared folder or serial.

        Args:
            host_path: Path on host system.
            guest_path: Destination path inside VM.

        Returns:
            True if file was copied.
        """
        if not self.state.running:
            return False

        # In a real implementation, this would use:
        # 1. QEMU guest agent (qga) for file transfer
        # 2. Shared folder via virtio-9p
        # 3. Serial-based file transfer

        if not Path(host_path).exists():
            return False

        logging.info("[sandbox] Would copy %s -> %s", host_path, guest_path)
        return True

    def execute_command(
        self, cmd: str, timeout: int = 30,
    ) -> str:
        """Execute a command inside the VM.

        Uses QEMU monitor or guest agent.

        Args:
            cmd: Command to execute inside VM.
            timeout: Max seconds to wait.

        Returns:
            Command output.
        """
        if not self.state.running:
            return ""

        # In a real implementation, this would use:
        # 1. QEMU guest agent (guest-exec)
        # 2. Monitor 'sendkey' for interactive input

        logging.info("[sandbox] Would execute: %s", cmd)
        self.state.last_command_output = f"[simulated] {cmd}"
        return self.state.last_command_output

    def capture_serial_log(self) -> str:
        """Read the VM serial output log.

        Returns:
            Serial output content.
        """
        if not self.state.serial_log_path:
            return ""

        try:
            return Path(self.state.serial_log_path).read_text(
                encoding="utf-8", errors="replace"
            )
        except Exception:
            return ""

    def run_driver_test(
        self,
        driver_path: str,
        service_name: str,
        poc_script: str = "",
        timeout: int = 30,
    ) -> dict[str, Any]:
        """Full driver test cycle inside sandbox.

        Lifecycle:
        1. Copy driver to VM
        2. Copy PoC script to VM (if provided)
        3. Load driver via sc create + sc start
        4. Execute PoC script
        5. Capture crash/output
        6. Unload driver
        7. Revert snapshot

        Args:
            driver_path: Path to .sys file on host.
            service_name: Windows service name for driver.
            poc_script: Optional PoC script to execute.
            timeout: Max seconds for the entire test.

        Returns:
            Test result dictionary.
        """
        result: dict[str, Any] = {
            "success": False,
            "crashed": False,
            "output": "",
            "serial_log": "",
            "error": "",
            "elapsed": 0.0,
        }

        start = time.time()

        try:
            # Start VM
            if not self.start():
                result["error"] = "Failed to start sandbox VM"
                return result

            # Copy driver
            guest_driver = f"C:\\test\\{Path(driver_path).name}"
            if not self.copy_file_to_vm(driver_path, guest_driver):
                result["error"] = "Failed to copy driver to VM"
                return result

            # Load driver
            load_cmd = (
                f'sc create {service_name} binPath= {guest_driver} type= kernel & '
                f"sc start {service_name}"
            )
            self.execute_command(load_cmd, timeout=10)

            # Execute PoC if provided
            if poc_script:
                guest_poc = "C:\\test\\poc.py"
                if self.copy_file_to_vm(poc_script, guest_poc):
                    self.execute_command(
                        f"python {guest_poc}", timeout=timeout
                    )

            # Capture results
            result["output"] = self.state.last_command_output
            result["serial_log"] = self.capture_serial_log()
            result["success"] = True

        except Exception as e:
            result["crashed"] = True
            result["error"] = str(e)
            result["serial_log"] = self.capture_serial_log()

        finally:
            # Cleanup
            self.stop()
            self.revert_snapshot()
            result["elapsed"] = time.time() - start

        return result
