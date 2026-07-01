"""Tests for monitor.py -- mocked WMI."""

import pytest
from unittest.mock import patch, MagicMock

from src.analysis.dynamic.monitor import SystemMonitor, SystemState, SystemDiff


class TestSystemState:
    def test_empty_state(self):
        s = SystemState()
        assert s.timestamp == 0.0
        assert s.devices == []
        assert not SystemDiff().has_changes


class TestSystemDiff:
    def test_no_changes(self):
        d = SystemDiff()
        assert d.has_changes is False

    def test_has_new_devices(self):
        d = SystemDiff(new_devices=["NewDevice"])
        assert d.has_changes is True

    def test_has_new_symlinks(self):
        d = SystemDiff(new_symlinks=["\\DosDevices\\X"])
        assert d.has_changes is True


class TestSystemMonitor:
    def setup_method(self):
        self.monitor = SystemMonitor()

    def test_snapshot_without_wmi(self):
        """Snapshot should work even without WMI (returns empty data)."""
        self.monitor._has_wmi = False
        state = self.monitor.snapshot()
        assert state.timestamp > 0
        assert state.devices == []
        assert state.processes == []

    def test_diff_new_devices(self):
        before = SystemState(devices=["DeviceA", "DeviceB"])
        after = SystemState(devices=["DeviceA", "DeviceB", "DeviceC"])
        d = self.monitor.diff(before, after)
        assert "DeviceC" in d.new_devices
        assert d.removed_devices == []

    def test_diff_removed_devices(self):
        before = SystemState(devices=["DeviceA", "DeviceB"])
        after = SystemState(devices=["DeviceA"])
        d = self.monitor.diff(before, after)
        assert "DeviceB" in d.removed_devices
        assert d.new_devices == []

    def test_diff_new_processes(self):
        before = SystemState(processes=[{"ProcessId": 1, "Name": "a.exe"}])
        after = SystemState(processes=[
            {"ProcessId": 1, "Name": "a.exe"},
            {"ProcessId": 2, "Name": "b.exe"},
        ])
        d = self.monitor.diff(before, after)
        assert len(d.new_processes) == 1
        assert d.new_processes[0]["Name"] == "b.exe"

    def test_diff_new_services(self):
        before = SystemState(services=[{"Name": "svc1", "State": "Running"}])
        after = SystemState(services=[
            {"Name": "svc1", "State": "Running"},
            {"Name": "svc2", "State": "Running"},
        ])
        d = self.monitor.diff(before, after)
        assert len(d.new_services) == 1
        assert d.new_services[0]["Name"] == "svc2"

    def test_get_new_devices(self):
        before = SystemState(devices=["A", "B"])
        after = SystemState(devices=["A", "B", "C"])
        new = self.monitor.get_new_devices(before, after)
        assert "C" in new

    def test_get_new_symlinks(self):
        before = SystemState(symlinks=["\\DosDevices\\A"])
        after = SystemState(symlinks=["\\DosDevices\\A", "\\DosDevices\\B"])
        new = self.monitor.get_new_symlinks(before, after)
        assert "\\DosDevices\\B" in new

    def test_get_new_handles(self):
        before = SystemState(handles={"kernel": 100, "user": 50})
        after = SystemState(handles={"kernel": 105, "user": 50})
        changes = self.monitor.get_new_handles(before, after)
        assert changes.get("kernel") == 5
        assert "user" not in changes

    def test_handle_changes_negative(self):
        before = SystemState(handles={"h": 10})
        after = SystemState(handles={"h": 5})
        changes = self.monitor.get_new_handles(before, after)
        assert changes.get("h") == -5

    def test_monitor_device_appearance_timeout(self):
        """Should return False when device never appears."""
        self.monitor._has_wmi = False
        result = self.monitor.monitor_device_appearance(
            "TestDevice", timeout=1, interval=0.2,
        )
        assert result is False
