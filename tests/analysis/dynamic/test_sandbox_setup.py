"""Tests for sandbox_setup.py -- environment checker."""

import os
import pytest
from unittest.mock import patch

from src.analysis.dynamic.sandbox_setup import (
    check_environment,
    cli_main,
    _check_qemu,
    _check_vm_image,
    _check_windbg,
    _check_kdnet,
    _check_dynamic_flag,
    ComponentStatus,
    EnvCheckResult,
)


class TestComponentStatus:
    def test_defaults(self):
        cs = ComponentStatus(name="Test")
        assert cs.name == "Test"
        assert cs.available is False
        assert cs.path == ""
        assert cs.version == ""
        assert cs.hint == ""


class TestEnvCheckResult:
    def test_summary_format(self):
        result = EnvCheckResult(
            components=[
                ComponentStatus(name="QEMU", available=True, path="/usr/bin/qemu", version="QEMU 8.0"),
                ComponentStatus(name="VM Image", available=False, hint="Set DRIVERSCOPE_VM_IMAGE"),
            ],
            overall_ready=False,
        )
        summary = result.summary()
        assert "[OK] QEMU" in summary
        assert "[MISSING] VM Image" in summary
        assert "Hint: Set DRIVERSCOPE_VM_IMAGE" in summary
        assert "Overall ready: NO" in summary

    def test_summary_ready(self):
        result = EnvCheckResult(
            components=[
                ComponentStatus(name="QEMU", available=True),
                ComponentStatus(name="VM Image", available=True),
                ComponentStatus(name="WinDbg", available=True),
            ],
            overall_ready=True,
        )
        assert "Overall ready: YES" in result.summary()


class TestCheckQemu:
    def test_not_found(self):
        with patch("src.analysis.dynamic.sandbox_setup._find_in_path", return_value=""):
            with patch.dict(os.environ, {}, clear=True):
                status = _check_qemu()
                assert status.available is False
                assert status.hint != ""

    def test_found_in_path(self):
        with patch("src.analysis.dynamic.sandbox_setup._find_in_path", return_value="/usr/bin/qemu-system-x86_64"):
            with patch("src.analysis.dynamic.sandbox_setup._run", return_value="QEMU emulator version 8.0.0"):
                status = _check_qemu()
                assert status.available is True
                assert "8.0.0" in status.version


class TestCheckVmImage:
    def test_not_configured(self):
        with patch.dict(os.environ, {}, clear=True):
            status = _check_vm_image()
            assert status.available is False
            assert "DRIVERSCOPE_VM_IMAGE" in status.details

    def test_file_exists(self, tmp_path):
        image = tmp_path / "win10.qcow2"
        image.write_bytes(b"\x00" * 1024)
        with patch.dict(os.environ, {"DRIVERSCOPE_VM_IMAGE": str(image)}, clear=True):
            status = _check_vm_image()
            assert status.available is True
            assert "MB" in status.details

    def test_file_not_found(self):
        with patch.dict(os.environ, {"DRIVERSCOPE_VM_IMAGE": "/nonexistent/image.qcow2"}, clear=True):
            status = _check_vm_image()
            assert status.available is False
            assert "not found" in status.hint.lower()


class TestCheckWinDbg:
    def test_not_found(self):
        with patch("src.analysis.dynamic.sandbox_setup._find_in_path", return_value=""):
            with patch.dict(os.environ, {}, clear=True):
                with patch("pathlib.Path.exists", return_value=False):
                    status = _check_windbg()
                    assert status.available is False
                    assert status.hint != ""


class TestCheckKdnet:
    def test_not_configured(self):
        with patch.dict(os.environ, {}, clear=True):
            status = _check_kdnet()
            assert status.available is False
            assert "KDNET_HOST" in status.details

    def test_configured(self):
        with patch.dict(os.environ, {"DRIVERSCOPE_KDNET_HOST": "192.168.1.100", "DRIVERSCOPE_KDNET_PORT": "50000"}, clear=True):
            status = _check_kdnet()
            assert status.available is True
            assert "192.168.1.100" in status.details


class TestCheckDynamicFlag:
    def test_disabled_by_default(self):
        with patch.dict(os.environ, {}, clear=True):
            status = _check_dynamic_flag()
            assert status.available is False
            assert "disabled" in status.details.lower()

    def test_enabled(self):
        with patch.dict(os.environ, {"DRIVERSCOPE_DYNAMIC": "1"}, clear=True):
            status = _check_dynamic_flag()
            assert status.available is True
            assert "enabled" in status.details.lower()


class TestCheckEnvironment:
    def test_overall_not_ready_when_core_missing(self):
        with patch("src.analysis.dynamic.sandbox_setup._check_qemu") as m:
            m.return_value = ComponentStatus(name="QEMU", available=False)
            with patch("src.analysis.dynamic.sandbox_setup._check_vm_image") as m2:
                m2.return_value = ComponentStatus(name="VM Image", available=False)
                with patch("src.analysis.dynamic.sandbox_setup._check_windbg") as m3:
                    m3.return_value = ComponentStatus(name="WinDbg", available=False)
                    with patch("src.analysis.dynamic.sandbox_setup._check_kdnet") as m4:
                        m4.return_value = ComponentStatus(name="KDNET", available=False)
                        with patch("src.analysis.dynamic.sandbox_setup._check_dynamic_flag") as m5:
                            m5.return_value = ComponentStatus(name="Feature Flag", available=False)

                            result = check_environment()
                            assert result.overall_ready is False
                            assert len(result.components) == 5

    def test_overall_ready_when_core_present(self):
        with patch("src.analysis.dynamic.sandbox_setup._check_qemu") as m:
            m.return_value = ComponentStatus(name="QEMU", available=True)
            with patch("src.analysis.dynamic.sandbox_setup._check_vm_image") as m2:
                m2.return_value = ComponentStatus(name="VM Image", available=True)
                with patch("src.analysis.dynamic.sandbox_setup._check_windbg") as m3:
                    m3.return_value = ComponentStatus(name="WinDbg", available=True)
                    with patch("src.analysis.dynamic.sandbox_setup._check_kdnet") as m4:
                        m4.return_value = ComponentStatus(name="KDNET", available=False)
                        with patch("src.analysis.dynamic.sandbox_setup._check_dynamic_flag") as m5:
                            m5.return_value = ComponentStatus(name="Feature Flag", available=False)

                            result = check_environment()
                            # Core (QEMU + VM + WinDbg) are ready, KDNET/flag optional
                            assert result.overall_ready is True


class TestCliMain:
    def test_returns_zero_when_ready(self):
        mock_result = EnvCheckResult(overall_ready=True)
        with patch("src.analysis.dynamic.sandbox_setup.check_environment", return_value=mock_result):
            rc = cli_main()
            assert rc == 0

    def test_returns_one_when_not_ready(self):
        mock_result = EnvCheckResult(overall_ready=False)
        with patch("src.analysis.dynamic.sandbox_setup.check_environment", return_value=mock_result):
            rc = cli_main()
            assert rc == 1
