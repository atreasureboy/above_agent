"""
DriverScope -- WinDbg/KD Debugger Integration.

Interfaces with WinDbg (windbgx.exe) or Kernel Debugger (kd.exe) via
command-line --command mode or named pipe for:

- Kernel/user-mode attachment
- Breakpoint management
- Register/memory dumping
- Stack trace capture
- Crash/exception detection
- Live API call monitoring

This module provides both interactive session management and
batch-style command execution for automated debugging.
"""

from __future__ import annotations

import subprocess
import time
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class BreakpointInfo:
    """A debugger breakpoint."""
    address: int = 0
    api_name: str = ""
    condition: str = ""
    hit_count: int = 0
    is_hardware: bool = False  # True for hardware breakpoints


@dataclass
class CrashInfo:
    """Information about a detected crash."""
    exception_code: int = 0
    exception_address: int = 0
    exception_record: str = ""
    registers: dict[str, int] = field(default_factory=dict)
    stack_trace: list[str] = field(default_factory=list)
    bugcheck_code: int = 0
    bugcheck_params: list[int] = field(default_factory=list)

    @property
    def is_bsod(self) -> bool:
        return self.bugcheck_code != 0

    @property
    def description(self) -> str:
        if self.is_bsod:
            return f"BSOD 0x{self.bugcheck_code:08X}"
        return f"Exception 0x{self.exception_code:08X} at 0x{self.exception_address:X}"


@dataclass
class DebuggerSession:
    """An active debugger session."""
    process_id: int = 0
    kernel_mode: bool = False
    attached: bool = False
    breakpoints: list[BreakpointInfo] = field(default_factory=list)


class WinDbgController:
    """Control WinDbg/KD for driver debugging."""

    def __init__(self, windbg_path: str = "", symbol_path: str = ""):
        """Initialize the debugger controller.

        Args:
            windbg_path: Path to windbgx.exe or kd.exe.
            symbol_path: Symbol server path (e.g., srv*https://msdl...).
        """
        self.windbg_path = windbg_path or self._find_windbg()
        self.symbol_path = symbol_path or "srv*https://msdl.microsoft.com/download/symbols"
        self.session = DebuggerSession()

    @staticmethod
    def _find_windbg() -> str:
        """Find WinDbg installation path."""
        candidates = [
            r"C:\Program Files\Windows Kits\10\Debuggers\x64\windbgx.exe",
            r"C:\Program Files\Windows Kits\10\Debuggers\x64\windbg.exe",
            r"C:\Program Files\Windows Kits\10\Debuggers\x86\windbg.exe",
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbgx.exe",
            r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe",
        ]
        for path in candidates:
            if Path(path).exists():
                return path
        return ""

    @property
    def is_available(self) -> bool:
        """Check if WinDbg is available."""
        return bool(self.windbg_path) and Path(self.windbg_path).exists()

    def attach_kernel(self, transport: str = "local") -> bool:
        """Attach to kernel debugger.

        Args:
            transport: "local", "serial", "1394", "usb", or "net".

        Returns:
            True if attachment succeeded.
        """
        if not self.is_available:
            return False

        transport_map = {
            "local": "-kl",
            "kernel": "-kl",
        }
        flag = transport_map.get(transport, transport)

        cmd = [
            self.windbg_path, flag,
            "-y", self.symbol_path,
            "-c", ".echo ATTACHED",
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            self.session.kernel_mode = True
            self.session.attached = "ATTACHED" in result.stdout
            return self.session.attached
        except Exception:
            return False

    def attach_process(self, pid: int) -> bool:
        """Attach to a user-mode process.

        Args:
            pid: Process ID to attach to.

        Returns:
            True if attachment succeeded.
        """
        if not self.is_available:
            return False

        cmd = [
            self.windbg_path, "-p", str(pid),
            "-y", self.symbol_path,
            "-c", ".echo ATTACHED; q",
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            self.session.process_id = pid
            self.session.attached = "ATTACHED" in result.stdout
            return self.session.attached
        except Exception:
            return False

    def execute(self, command: str, timeout: int = 10) -> str:
        """Execute a debugger command.

        Args:
            command: WinDbg command string.
            timeout: Max seconds to wait.

        Returns:
            Command output string.
        """
        if not self.is_available:
            return ""

        cmd = [
            self.windbg_path, "-c", command,
            "-y", self.symbol_path,
        ]

        if self.session.kernel_mode:
            cmd.insert(1, "-kl")
        elif self.session.process_id:
            cmd.insert(1, "-p")
            cmd.insert(2, str(self.session.process_id))

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
            return result.stdout
        except subprocess.TimeoutExpired:
            return f"[timeout after {timeout}s]"
        except Exception as e:
            return f"[error: {e}]"

    def set_breakpoint(
        self, address: int, condition: str = "",
    ) -> BreakpointInfo | None:
        """Set a breakpoint at the given address.

        Args:
            address: Target address.
            condition: Optional breakpoint condition.

        Returns:
            BreakpointInfo or None on failure.
        """
        bp_cmd = f"bp 0x{address:X}"
        if condition:
            bp_cmd += f' "{condition}"'

        output = self.execute(bp_cmd)
        if "error" not in output.lower():
            bp = BreakpointInfo(address=address, condition=condition)
            self.session.breakpoints.append(bp)
            return bp
        return None

    def set_api_breakpoint(self, api_name: str) -> BreakpointInfo | None:
        """Set a breakpoint on a specific API.

        Args:
            api_name: API name (e.g., "nt!MmMapIoSpaceEx").

        Returns:
            BreakpointInfo or None on failure.
        """
        output = self.execute(f"bp {api_name}")
        if "error" not in output.lower():
            bp = BreakpointInfo(api_name=api_name)
            self.session.breakpoints.append(bp)
            return bp
        return None

    def get_registers(self) -> dict[str, int]:
        """Dump all CPU registers.

        Returns:
            Dict mapping register name to value.
        """
        output = self.execute("r")
        registers = {}

        # Parse register output: "rax=0000000000000000 rbx=..."
        pattern = re.compile(
            r"([a-z]{2,3})=([0-9a-f]+)", re.IGNORECASE
        )
        for match in pattern.finditer(output):
            name = match.group(1).lower()
            value = int(match.group(2), 16)
            registers[name] = value

        return registers

    def get_stack_trace(self, depth: int = 20) -> list[str]:
        """Get current stack trace.

        Args:
            depth: Maximum number of frames.

        Returns:
            List of stack frame strings.
        """
        output = self.execute(f"kv {depth}")
        frames = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("Child-SP"):
                frames.append(line)
        return frames[:depth]

    def dump_memory(self, address: int, size: int) -> bytes:
        """Dump memory at the given address.

        Args:
            address: Target memory address.
            size: Number of bytes to read.

        Returns:
            Raw bytes from memory.
        """
        output = self.execute(f"db 0x{address:X} L{size}")
        result = bytearray()

        # Parse hex dump: "00007fff`12345678  00 11 22 33 ..."
        for line in output.strip().splitlines():
            parts = line.strip().split()
            for part in parts[1:]:
                try:
                    result.append(int(part, 16))
                except ValueError:
                    pass
                if len(result) >= size:
                    break
            if len(result) >= size:
                break

        return bytes(result[:size])

    def detect_crash(self) -> CrashInfo:
        """Analyze current debugger state for crash information.

        Returns:
            CrashInfo with exception details.
        """
        info = CrashInfo()

        # Check for bugcheck (BSOD)
        output = self.execute("!analyze -v")
        if "BUGCHECK_CODE" in output:
            for line in output.splitlines():
                if "BUGCHECK_CODE:" in line:
                    try:
                        info.bugcheck_code = int(
                            line.split(":")[-1].strip(), 16
                        )
                    except ValueError:
                        pass
                elif "BUGCHECK_PARAMETER" in line:
                    try:
                        val = int(line.split(":")[-1].strip(), 16)
                        info.bugcheck_params.append(val)
                    except ValueError:
                        pass

        # Get registers
        info.registers = self.get_registers()

        # Get stack trace
        info.stack_trace = self.get_stack_trace()

        return info

    def run_and_wait(
        self, commands: list[str], timeout: int = 30,
    ) -> str:
        """Execute a series of commands and wait for completion.

        Args:
            commands: List of WinDbg commands.
            timeout: Max seconds to wait.

        Returns:
            Combined output.
        """
        cmd_str = "; ".join(commands) + "; q"
        return self.execute(cmd_str, timeout=timeout)

    def detach(self) -> bool:
        """Detach from the current debug target."""
        self.execute("qd")
        self.session.attached = False
        self.session.process_id = 0
        self.session.kernel_mode = False
        self.session.breakpoints.clear()
        return True
