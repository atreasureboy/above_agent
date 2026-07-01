"""Tests for sandbox.py -- all mocked."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from src.analysis.dynamic.sandbox import SandboxManager, SandboxConfig, SandboxState


class TestSandboxConfig:
    def test_defaults(self):
        cfg = SandboxConfig()
        assert cfg.qemu_path == ""
        assert cfg.memory_mb == 4096
        assert cfg.display == "none"

    def test_custom_config(self):
        cfg = SandboxConfig(
            qemu_path=r"C:\qemu\qemu-system-x86_64.exe",
            vm_image=r"C:\vms\win10.qcow2",
            snapshot_name="test_snapshot",
            memory_mb=8192,
        )
        assert cfg.snapshot_name == "test_snapshot"
        assert cfg.memory_mb == 8192


class TestSandboxState:
    def test_defaults(self):
        s = SandboxState()
        assert s.running is False
        assert s.process is None


class TestSandboxManager:
    def setup_method(self):
        self.config = SandboxConfig(
            qemu_path=r"C:\qemu\qemu-system-x86_64.exe",
            vm_image=r"C:\vms\win10.qcow2",
            snapshot_name="clean",
        )
        self.manager = SandboxManager(self.config)

    def test_is_available_false_no_paths(self):
        mgr = SandboxManager()
        assert mgr.is_available is False

    @patch("pathlib.Path.exists", return_value=True)
    def test_is_available_true(self, mock_exists):
        assert self.manager.is_available is True

    @patch("pathlib.Path.exists", return_value=False)
    def test_is_available_false_qemu_missing(self, mock_exists):
        assert self.manager.is_available is False

    def test_start_not_available(self):
        mgr = SandboxManager()
        assert mgr.start() is False

    @patch("pathlib.Path.exists", return_value=True)
    @patch("subprocess.Popen")
    @patch.object(SandboxManager, "revert_snapshot", return_value=True)
    def test_start_success(self, mock_revert, mock_popen, mock_exists):
        mock_popen.return_value = MagicMock()
        with patch("time.sleep"):
            result = self.manager.start()
        assert result is True
        assert self.manager.state.running is True

    @patch("pathlib.Path.exists", return_value=True)
    def test_stop_running(self, mock_exists):
        mock_proc = MagicMock()
        self.manager.state.running = True
        self.manager.state.process = mock_proc
        result = self.manager.stop()
        mock_proc.terminate.assert_called_once()
        assert result is True

    def test_stop_not_running(self):
        assert self.manager.stop() is True

    def test_revert_not_available(self):
        mgr = SandboxManager()
        assert mgr.revert_snapshot() is False

    def test_copy_file_not_running(self):
        assert self.manager.copy_file_to_vm("host", "guest") is False

    def test_execute_command_not_running(self):
        assert self.manager.execute_command("cmd") == ""

    def test_capture_serial_log_no_path(self):
        assert self.manager.capture_serial_log() == ""

    @patch("pathlib.Path.exists", return_value=True)
    @patch.object(SandboxManager, "start", return_value=True)
    @patch.object(SandboxManager, "stop", return_value=True)
    @patch.object(SandboxManager, "revert_snapshot", return_value=True)
    @patch.object(SandboxManager, "copy_file_to_vm", return_value=False)
    def test_run_driver_test_copy_failure(
        self, mock_copy, mock_revert, mock_stop, mock_start, mock_exists,
    ):
        with patch("time.time", return_value=1000):
            result = self.manager.run_driver_test(
                "driver.sys", "TestSvc",
            )
        assert result["success"] is False
        assert "Failed to copy driver" in result["error"]

    def test_capture_serial_log_with_path(self, tmp_path):
        log_file = tmp_path / "serial.log"
        log_file.write_text("Serial output line 1\nSerial output line 2")
        self.manager.state.serial_log_path = str(log_file)
        output = self.manager.capture_serial_log()
        assert "Serial output" in output
