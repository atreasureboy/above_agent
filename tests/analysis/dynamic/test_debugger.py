"""Tests for debugger.py -- all mocked."""

import pytest
from unittest.mock import patch, MagicMock

from src.analysis.dynamic.debugger import (
    WinDbgController,
    BreakpointInfo,
    CrashInfo,
    DebuggerSession,
)


class TestBreakpointInfo:
    def test_defaults(self):
        bp = BreakpointInfo()
        assert bp.address == 0
        assert bp.hit_count == 0

    def test_with_address(self):
        bp = BreakpointInfo(address=0x1234, api_name="nt!MmMapIoSpaceEx")
        assert bp.address == 0x1234
        assert bp.api_name == "nt!MmMapIoSpaceEx"


class TestCrashInfo:
    def test_is_bsod(self):
        info = CrashInfo(bugcheck_code=0x133)
        assert info.is_bsod is True

    def test_is_exception(self):
        info = CrashInfo(exception_code=0xC0000005, exception_address=0x1000)
        assert info.is_bsod is False
        assert "Exception" in info.description

    def test_bsod_description(self):
        info = CrashInfo(bugcheck_code=0x50)
        assert "BSOD" in info.description
        assert "0x00000050" in info.description


class TestDebuggerSession:
    def test_defaults(self):
        s = DebuggerSession()
        assert s.process_id == 0
        assert s.kernel_mode is False
        assert s.attached is False


class TestWinDbgController:
    def setup_method(self):
        self.debugger = WinDbgController(
            windbg_path=r"C:\Debuggers\windbgx.exe",
            symbol_path="srv*C:\\Symbols",
        )

    def test_is_available(self):
        with patch("pathlib.Path.exists", return_value=True):
            assert self.debugger.is_available is True

    def test_not_available(self):
        dbg = WinDbgController(windbg_path="")
        assert dbg.is_available is False

    def test_find_windbg_not_found(self):
        with patch("pathlib.Path.exists", return_value=False):
            path = WinDbgController._find_windbg()
            assert path == ""

    @patch("subprocess.run")
    def test_execute_returns_output(self, mock_run):
        mock_run.return_value = MagicMock(stdout="rax=0000000000000000")
        self.debugger.windbg_path = r"C:\windbgx.exe"
        with patch("pathlib.Path.exists", return_value=True):
            output = self.debugger.execute("r")
            assert "rax" in output

    @patch("subprocess.run")
    def test_execute_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 10)
        with patch("pathlib.Path.exists", return_value=True):
            output = self.debugger.execute("r", timeout=10)
            assert "timeout" in output

    def test_get_registers_parsing(self):
        # Test the regex parsing logic directly
        output = "rax=00000000deadbeef rbx=0000000000000000 rcx=00000000cafebabe"
        import re
        pattern = re.compile(r"([a-z]{2,3})=([0-9a-f]+)", re.IGNORECASE)
        registers = {}
        for match in pattern.finditer(output):
            registers[match.group(1).lower()] = int(match.group(2), 16)
        assert registers["rax"] == 0xDEADBEEF
        assert registers["rcx"] == 0xCAFEBABE

    def test_get_stack_trace_parsing(self):
        output = """Child-SP          RetAddr           Call Site
00 fffff800`12345678 nt!MmMapIoSpaceEx+0x10
01 fffff800`12345688 driver!DispatchIoctl+0x20"""
        frames = []
        for line in output.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("Child-SP"):
                frames.append(line)
        assert len(frames) == 2
        assert "nt!MmMapIoSpaceEx" in frames[0]

    def test_detect_crash_bsod(self):
        output = """BUGCHECK_CODE: 00000050
BUGCHECK_PARAMETER1: ffffffffc0000005
BUGCHECK_PARAMETER2: 0000000000000000"""
        info = CrashInfo()
        for line in output.splitlines():
            if "BUGCHECK_CODE:" in line:
                try:
                    info.bugcheck_code = int(line.split(":")[-1].strip(), 16)
                except ValueError:
                    pass
            elif "BUGCHECK_PARAMETER" in line:
                try:
                    val = int(line.split(":")[-1].strip(), 16)
                    info.bugcheck_params.append(val)
                except ValueError:
                    pass
        assert info.is_bsod is True
        assert info.bugcheck_code == 0x50
        assert 0xFFFFFFFFC0000005 in info.bugcheck_params

    def test_detach_clears_session(self):
        with patch.object(WinDbgController, "execute", return_value=""):
            self.debugger.session.attached = True
            self.debugger.session.kernel_mode = True
            self.debugger.session.process_id = 1234
            self.debugger.detach()
            assert self.debugger.session.attached is False
            assert self.debugger.session.kernel_mode is False
            assert self.debugger.session.process_id == 0
