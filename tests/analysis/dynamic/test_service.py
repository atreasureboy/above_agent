"""Tests for service.py -- all mocked, no real SCM calls."""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from src.analysis.dynamic.service import (
    DriverServiceController,
    ServiceStatus,
    DriverServiceInfo,
    SERVICE_RUNNING,
    SERVICE_STOPPED,
)


class TestServiceStatus:
    def test_is_running(self):
        s = ServiceStatus(state=SERVICE_RUNNING)
        assert s.is_running is True

    def test_is_stopped(self):
        s = ServiceStatus(state=SERVICE_STOPPED)
        assert s.is_stopped is True

    def test_state_name(self):
        s = ServiceStatus(state=SERVICE_RUNNING)
        assert s.state_name == "RUNNING"

    def test_unknown_state(self):
        s = ServiceStatus(state=999)
        assert "UNKNOWN" in s.state_name


class TestServiceAvailability:
    @patch("ctypes.windll")
    def test_is_available_windows(self, mock_windll):
        mock_windll.shell32.IsUserAnAdmin.return_value = True
        assert DriverServiceController.is_available() is True

    def test_is_not_available_non_windows(self):
        with patch("ctypes.windll", None):
            assert DriverServiceController.is_available() is False


class TestDriverServiceController:
    def setup_method(self):
        self.controller = DriverServiceController()

    @patch.object(DriverServiceController, "__init__", lambda self: None)
    def test_create_service_file_not_found(self):
        ctrl = DriverServiceController()
        with pytest.raises(FileNotFoundError):
            ctrl.create_service("/nonexistent/driver.sys", "TestSvc")

    @patch.object(DriverServiceController, "__init__", lambda self: None)
    def test_open_device_invalid(self):
        ctrl = DriverServiceController()
        ctrl._kernel32 = MagicMock()
        ctrl._kernel32.CreateFileA.return_value = -1
        result = ctrl.open_device("\\\\.\\TestDevice")
        assert result is None

    @patch.object(DriverServiceController, "__init__", lambda self: None)
    def test_close_device(self):
        ctrl = DriverServiceController()
        ctrl._kernel32 = MagicMock()
        ctrl._kernel32.CloseHandle.return_value = 1
        assert ctrl.close_device(1234) is True

    @patch.object(DriverServiceController, "__init__", lambda self: None)
    def test_unload_stops_and_deletes(self):
        ctrl = DriverServiceController()
        ctrl.stop_service = MagicMock(return_value=True)
        ctrl.delete_service = MagicMock(return_value=True)
        result = ctrl.unload("TestSvc")
        ctrl.stop_service.assert_called_once_with("TestSvc")
        ctrl.delete_service.assert_called_once()
        assert result is True
