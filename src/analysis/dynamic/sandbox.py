"""
DriverScope -- QEMU Sandbox Manager.

Manages QEMU virtual machines for safe driver execution:

- Start/stop VM from snapshot
- Revert to clean snapshot after each test
- Copy files to/from VM (via QEMU Guest Agent or 9p shared folder)
- Execute commands inside VM (via QEMU Guest Agent)
- Capture serial/console output
- Monitor for crashes

This provides isolation between the host system and potentially
crash-inducing driver operations.

File Transfer Methods (in priority order):
1. QEMU Guest Agent (qga) — most reliable, needs qemu-ga.msi in guest
2. 9p virtio shared folder — fast, needs VirtIO-Win drivers in guest
3. WinRM/SSH — fallback, needs network configuration in guest
"""

from __future__ import annotations

import json
import os
import socket
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
    network: str = "user"  # "none", "user", "bridge"
    serial_log: str = ""   # Path to serial output log
    # Guest Agent configuration
    qga_socket: str = ""   # Path to QGA Unix socket or TCP port
    qga_timeout: int = 30  # Seconds to wait for QGA responses
    # 9p shared folder
    shared_dir: str = ""   # Host directory to share with guest
    guest_mount_tag: str = "host0"  # 9p mount tag
    guest_share_path: str = r"\\??\\virtio-9p\\host0"  # Windows guest path
    # WinRM fallback
    winrm_host: str = "127.0.0.1"
    winrm_port: int = 55985  # Host port forwarded to guest 5985
    winrm_user: str = "tester"
    winrm_password: str = "password123"


@dataclass
class SandboxState:
    """Current sandbox VM state."""
    running: bool = False
    process: Any = None  # subprocess.Popen
    start_time: float = 0.0
    serial_log_path: str = ""
    last_command_output: str = ""
    # Guest Agent state
    qga_connected: bool = False
    qga_socket_path: str = ""
    # Transfer method used
    transfer_method: str = ""  # "qga", "9p", "winrm", "none"


class SandboxManager:
    """QEMU-based sandbox for safe driver execution.

    Supports three file transfer methods:
    1. QEMU Guest Agent (qga) — most reliable
    2. 9p virtio shared folder — fast
    3. WinRM — fallback when QGA unavailable
    """

    def __init__(self, config: SandboxConfig | None = None):
        self.config = config or SandboxConfig()
        self.state = SandboxState()
        self._qga_sock: socket.socket | None = None

    # ── availability ──────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        """Check if QEMU sandbox is available and configured."""
        if not self.config.qemu_path:
            return False
        qemu = Path(self.config.qemu_path)
        return qemu.exists() and Path(self.config.vm_image).exists()

    # ── VM lifecycle ──────────────────────────────────────────

    def start(self) -> bool:
        """Start the VM from the configured snapshot."""
        if not self.is_available:
            logging.warning("[sandbox] QEMU not available")
            return False

        self.revert_snapshot()

        cmd = [
            self.config.qemu_path,
            "-hda", self.config.vm_image,
            "-m", str(self.config.memory_mb),
            "-smp", str(self.config.cpu_cores),
            "-loadvm", self.config.snapshot_name,
            "-display", self.config.display,
        ]

        # Network
        if self.config.network == "user":
            # User-mode networking with port forwarding for WinRM
            cmd.extend([
                "-netdev", f"user,id=net0,hostfwd=tcp::{self.config.winrm_port}-:5985",
                "-device", "e1000,netdev=net0",
            ])
        elif self.config.network != "none":
            cmd.extend(["-net", self.config.network])
        else:
            cmd.extend(["-nic", "none"])

        # Serial logging
        if self.config.serial_log:
            cmd.extend(["-serial", f"file:{self.config.serial_log}"])
            self.state.serial_log_path = self.config.serial_log

        # 9p shared folder
        if self.config.shared_dir and Path(self.config.shared_dir).is_dir():
            cmd.extend([
                "-virtfs",
                f"local,id=host_share,path={self.config.shared_dir},"
                f"mount_tag={self.config.guest_mount_tag},security_model=none",
            ])

        # QEMU Guest Agent channel (virtio-serial)
        if self.config.qga_socket:
            qga_path = self.config.qga_socket
            if os.name == "nt":
                # Windows: use TCP socket
                cmd.extend([
                    "-chardev", f"socket,id=qga,port={qga_path},host=127.0.0.1,server=on,wait=off",
                ])
            else:
                # Linux: use Unix socket
                cmd.extend([
                    "-chardev", f"socket,id=qga,path={qga_path},server=on,wait=off",
                ])
            cmd.extend([
                "-device", "virtio-serial",
                "-device", "virtserialport,chardev=qga,name=org.qemu.guest_agent.0",
            ])
            self.state.qga_socket_path = qga_path

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
            boot_wait = self._wait_for_guest_ready(timeout=60)
            if boot_wait:
                logging.info("[sandbox] VM started, guest ready (%.1fs)", boot_wait)
            else:
                logging.warning("[sandbox] VM started but guest not responding")

            # Try connecting to Guest Agent
            self._connect_qga()

            return True

        except Exception as e:
            logging.error("[sandbox] Failed to start VM: %s", e)
            return False

    def stop(self) -> bool:
        """Stop the VM."""
        # Disconnect QGA
        self._disconnect_qga()

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
        self.state.transfer_method = ""
        logging.info("[sandbox] VM stopped")
        return True

    def revert_snapshot(self) -> bool:
        """Revert VM to clean snapshot."""
        if not self.is_available:
            return False

        if self.state.running:
            self.stop()

        # Verify snapshot exists
        qemu_img = self.config.qemu_path.replace(
            "qemu-system-x86_64.exe", "qemu-img.exe"
        ).replace(
            "qemu-system-x86_64", "qemu-img"
        )
        try:
            result = subprocess.run(
                [qemu_img, "snapshot", "-l", self.config.vm_image],
                capture_output=True, text=True, timeout=10,
            )
            if self.config.snapshot_name not in result.stdout:
                logging.warning(
                    "[sandbox] Snapshot '%s' not found in VM image",
                    self.config.snapshot_name,
                )
        except Exception:
            pass

        logging.info("[sandbox] Will load snapshot '%s' on next start",
                      self.config.snapshot_name)
        return True

    # ── file transfer ─────────────────────────────────────────

    def copy_file_to_vm(self, host_path: str, guest_path: str) -> bool:
        """Copy a file into the running VM.

        Tries methods in order:
        1. 9p shared folder (fastest — just place file in host dir)
        2. QEMU Guest Agent (guest-file-write)
        3. WinRM (PowerShell remoting)

        Args:
            host_path: Path on host system.
            guest_path: Destination path inside VM.

        Returns:
            True if file was copied.
        """
        if not self.state.running:
            logging.warning("[sandbox] VM not running, cannot copy file")
            return False

        if not Path(host_path).exists():
            logging.warning("[sandbox] Source file not found: %s", host_path)
            return False

        # Method 1: 9p shared folder
        if self.config.shared_dir and Path(self.config.shared_dir).is_dir():
            if self._copy_via_9p(host_path, guest_path):
                self.state.transfer_method = "9p"
                return True

        # Method 2: QEMU Guest Agent
        if self.state.qga_connected:
            if self._copy_via_qga(host_path, guest_path):
                self.state.transfer_method = "qga"
                return True

        # Method 3: WinRM
        if self._copy_via_winrm(host_path, guest_path):
            self.state.transfer_method = "winrm"
            return True

        logging.error("[sandbox] All file transfer methods failed")
        return False

    def copy_file_from_vm(self, guest_path: str, host_path: str) -> bool:
        """Copy a file from the VM to the host.

        Args:
            guest_path: Path inside VM.
            host_path: Destination path on host.

        Returns:
            True if file was copied.
        """
        if not self.state.running:
            return False

        # Method 1: 9p shared folder
        if self.config.shared_dir and Path(self.config.shared_dir).is_dir():
            if self._copy_from_9p(guest_path, host_path):
                return True

        # Method 2: QGA
        if self.state.qga_connected:
            if self._copy_from_qga(guest_path, host_path):
                return True

        # Method 3: WinRM
        if self._copy_from_winrm(guest_path, host_path):
            return True

        return False

    # ── command execution ─────────────────────────────────────

    def execute_command(
        self, cmd: str, timeout: int = 30,
    ) -> str:
        """Execute a command inside the VM.

        Tries methods in order:
        1. QEMU Guest Agent (guest-exec)
        2. WinRM

        Args:
            cmd: Command to execute inside VM.
            timeout: Max seconds to wait.

        Returns:
            Command output.
        """
        if not self.state.running:
            return ""

        # Method 1: QGA
        if self.state.qga_connected:
            result = self._exec_via_qga(cmd, timeout)
            if result is not None:
                self.state.last_command_output = result
                return result

        # Method 2: WinRM
        result = self._exec_via_winrm(cmd, timeout)
        if result is not None:
            self.state.last_command_output = result
            return result

        logging.warning("[sandbox] All command execution methods failed for: %s", cmd)
        self.state.last_command_output = ""
        return ""

    def capture_serial_log(self) -> str:
        """Read the VM serial output log."""
        if not self.state.serial_log_path:
            return ""

        try:
            return Path(self.state.serial_log_path).read_text(
                encoding="utf-8", errors="replace"
            )
        except Exception:
            return ""

    # ── high-level driver testing ─────────────────────────────

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
            "transfer_method": "",
        }

        start = time.time()

        try:
            if not self.start():
                result["error"] = "Failed to start sandbox VM"
                return result

            # Copy driver
            guest_driver = f"C:\\test\\{Path(driver_path).name}"
            if not self.copy_file_to_vm(driver_path, guest_driver):
                result["error"] = "Failed to copy driver to VM"
                return result

            result["transfer_method"] = self.state.transfer_method

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

            result["output"] = self.state.last_command_output
            result["serial_log"] = self.capture_serial_log()
            result["success"] = True

        except Exception as e:
            result["crashed"] = True
            result["error"] = str(e)
            result["serial_log"] = self.capture_serial_log()

        finally:
            self.stop()
            self.revert_snapshot()
            result["elapsed"] = time.time() - start

        return result

    # ── guest readiness ───────────────────────────────────────

    def _wait_for_guest_ready(self, timeout: int = 60) -> float | None:
        """Wait until the guest OS is ready to accept connections.

        Tries WinRM port probe as a boot indicator.

        Returns:
            Seconds waited, or None on timeout.
        """
        start = time.time()
        while time.time() - start < timeout:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((self.config.winrm_host, self.config.winrm_port))
                sock.close()
                return time.time() - start
            except (ConnectionRefusedError, OSError):
                time.sleep(2)
        return None

    # ── QEMU Guest Agent methods ──────────────────────────────

    def _connect_qga(self) -> bool:
        """Connect to QEMU Guest Agent socket."""
        if not self.state.qga_socket_path:
            return False

        # Retry a few times — QGA might not be ready immediately
        for attempt in range(5):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.config.qga_timeout)

                if os.name == "nt":
                    sock.connect(("127.0.0.1", int(self.state.qga_socket_path)))
                else:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.settimeout(self.config.qga_timeout)
                    sock.connect(self.state.qga_socket_path)

                self._qga_sock = sock
                self.state.qga_connected = True
                logging.info("[sandbox] Connected to QEMU Guest Agent")
                return True

            except Exception as e:
                logging.debug("[sandbox] QGA connect attempt %d failed: %s", attempt + 1, e)
                time.sleep(2)

        logging.warning("[sandbox] Could not connect to QEMU Guest Agent")
        return False

    def _disconnect_qga(self) -> None:
        """Disconnect from QEMU Guest Agent."""
        if self._qga_sock:
            try:
                self._qga_sock.close()
            except Exception:
                pass
            self._qga_sock = None
        self.state.qga_connected = False

    def _qga_command(self, command: str, arguments: dict | None = None) -> dict | None:
        """Send a command to QEMU Guest Agent and return the response."""
        if not self._qga_sock or not self.state.qga_connected:
            return None

        payload = {"execute": command}
        if arguments:
            payload["arguments"] = arguments

        try:
            data = json.dumps(payload).encode("utf-8") + b"\n"
            self._qga_sock.sendall(data)

            # Read response (QGA sends JSON lines)
            buf = b""
            while True:
                chunk = self._qga_sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if b"\n" in buf:
                    break

            return json.loads(buf.decode("utf-8").strip())

        except Exception as e:
            logging.warning("[sandbox] QGA command failed: %s", e)
            self.state.qga_connected = False
            return None

    def _exec_via_qga(self, cmd: str, timeout: int = 30) -> str | None:
        """Execute command via QEMU Guest Agent."""
        import base64

        # guest-exec requires base64-encoded command
        # Use cmd.exe /c for Windows guests
        full_cmd = f"cmd.exe /c {cmd}"
        encoded_cmd = base64.b64encode(full_cmd.encode("utf-16-le")).decode("ascii")

        # Execute
        exec_resp = self._qga_command("guest-exec", {
            "path": "C:\\Windows\\System32\\cmd.exe",
            "arg": ["/c", cmd],
            "capture-output": True,
        })

        if not exec_resp or "return" not in exec_resp:
            return None

        pid = exec_resp.get("return", {}).get("pid")
        if not pid:
            return None

        # Wait for completion
        for _ in range(timeout * 2):
            status_resp = self._qga_command("guest-exec-status", {"pid": pid})
            if not status_resp:
                break

            ret = status_resp.get("return", {})
            if ret.get("exited"):
                # Decode output
                out_b64 = ret.get("out-data", "")
                if out_b64:
                    try:
                        return base64.b64decode(out_b64).decode("utf-8", errors="replace")
                    except Exception:
                        return ""
                err_b64 = ret.get("err-data", "")
                if err_b64:
                    return f"[stderr] {base64.b64decode(err_b64).decode('utf-8', errors='replace')}"
                return ""

            time.sleep(0.5)

        return None

    def _copy_via_qga(self, host_path: str, guest_path: str) -> bool:
        """Copy file via QEMU Guest Agent (guest-file-write)."""
        import base64

        # Read file
        try:
            data = Path(host_path).read_bytes()
        except Exception:
            return False

        # Open file in guest
        open_resp = self._qga_command("guest-file-open", {
            "path": guest_path,
            "mode": "wb",
        })
        if not open_resp or "return" not in open_resp:
            return False
        handle = open_resp["return"]

        # Write in chunks (QGA has message size limits)
        chunk_size = 1024 * 1024  # 1MB chunks
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + chunk_size]
            encoded = base64.b64encode(chunk).decode("ascii")
            write_resp = self._qga_command("guest-file-write", {
                "handle": handle,
                "buf-b64": encoded,
            })
            if not write_resp or "return" not in write_resp:
                break
            offset += chunk_size

        # Close file
        self._qga_command("guest-file-close", {"handle": handle})

        return offset >= len(data)

    def _copy_from_qga(self, guest_path: str, host_path: str) -> bool:
        """Copy file from VM via QEMU Guest Agent (guest-file-read)."""
        import base64

        # Open file in guest
        open_resp = self._qga_command("guest-file-open", {
            "path": guest_path,
            "mode": "rb",
        })
        if not open_resp or "return" not in open_resp:
            return False
        handle = open_resp["return"]

        # Read file
        data = b""
        while True:
            read_resp = self._qga_command("guest-file-read", {
                "handle": handle,
                "count": 1024 * 1024,
            })
            if not read_resp or "return" not in read_resp:
                break
            ret = read_resp["return"]
            chunk_b64 = ret.get("buf-b64", "")
            if not chunk_b64:
                break
            data += base64.b64decode(chunk_b64)
            if ret.get("eof"):
                break

        # Close
        self._qga_command("guest-file-close", {"handle": handle})

        try:
            Path(host_path).write_bytes(data)
            return True
        except Exception:
            return False

    # ── 9p shared folder methods ──────────────────────────────

    def _copy_via_9p(self, host_path: str, guest_path: str) -> bool:
        """Copy file via 9p shared folder.

        The guest must have the shared folder mounted.
        File is placed in the host's shared_dir, and the guest
        accesses it via the virtio-9p mount.
        """
        try:
            shared = Path(self.config.shared_dir)
            dest_name = Path(guest_path).name
            dest = shared / dest_name
            Path(host_path).copy(dest)  # type: ignore[attr-defined]
            import shutil
            shutil.copy2(str(host_path), str(dest))
            logging.info("[sandbox] File placed in 9p share: %s → %s", host_path, dest)
            return True
        except Exception as e:
            logging.warning("[sandbox] 9p copy failed: %s", e)
            return False

    def _copy_from_9p(self, guest_path: str, host_path: str) -> bool:
        """Copy file from 9p shared folder."""
        try:
            shared = Path(self.config.shared_dir)
            src_name = Path(guest_path).name
            src = shared / src_name
            if not src.exists():
                return False
            import shutil
            shutil.copy2(str(src), str(host_path))
            return True
        except Exception as e:
            logging.warning("[sandbox] 9p read-back failed: %s", e)
            return False

    # ── WinRM methods ─────────────────────────────────────────

    def _exec_via_winrm(self, cmd: str, timeout: int = 30) -> str | None:
        """Execute command via WinRM (PowerShell remoting)."""
        try:
            import winrm
            session = winrm.Session(
                f"http://{self.config.winrm_host}:{self.config.winrm_port}/wsman",
                auth=(self.config.winrm_user, self.config.winrm_password),
                transport="ntlm",
            )
            result = session.run_cmd(cmd)
            return result.std_out.decode("utf-8", errors="replace")
        except ImportError:
            logging.debug("[sandbox] pywinrm not installed, WinRM unavailable")
        except Exception as e:
            logging.warning("[sandbox] WinRM exec failed: %s", e)
        return None

    def _copy_via_winrm(self, host_path: str, guest_path: str) -> bool:
        """Copy file via WinRM (base64 over PowerShell)."""
        try:
            import base64
            import winrm

            data = Path(host_path).read_bytes()
            encoded = base64.b64encode(data).decode("ascii")

            session = winrm.Session(
                f"http://{self.config.winrm_host}:{self.config.winrm_port}/wsman",
                auth=(self.config.winrm_user, self.config.winrm_password),
                transport="ntlm",
            )

            # Ensure directory exists
            guest_dir = str(Path(guest_path).parent)
            session.run_cmd(f"mkdir -Force '{guest_dir}'")

            # Write file via PowerShell (base64 decode)
            ps_cmd = f"[IO.File]::WriteAllBytes('{guest_path}', [Convert]::FromBase64String('{encoded}'))"
            result = session.run_ps(ps_cmd)
            return result.status_code == 0

        except ImportError:
            logging.debug("[sandbox] pywinrm not installed")
        except Exception as e:
            logging.warning("[sandbox] WinRM copy failed: %s", e)
        return False

    def _copy_from_winrm(self, guest_path: str, host_path: str) -> bool:
        """Copy file from VM via WinRM."""
        try:
            import base64
            import winrm

            session = winrm.Session(
                f"http://{self.config.winrm_host}:{self.config.winrm_port}/wsman",
                auth=(self.config.winrm_user, self.config.winrm_password),
                transport="ntlm",
            )

            ps_cmd = f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{guest_path}'))"
            result = session.run_ps(ps_cmd)
            if result.status_code != 0:
                return False

            data = base64.b64decode(result.std_out.decode("ascii").strip())
            Path(host_path).write_bytes(data)
            return True

        except ImportError:
            logging.debug("[sandbox] pywinrm not installed")
        except Exception as e:
            logging.warning("[sandbox] WinRM read-back failed: %s", e)
        return False
