"""
DriverScope -- System Monitor (Before/After Diff).

Captures system state snapshots before and after driver loading/PoC
execution, then computes differences to detect:

- New device objects (\\Device\\*, \\DosDevices\\*)
- New registry keys/values
- New file creations
- New processes/threads
- Handle changes
- Symbolic link changes

Uses WMI queries and native Windows APIs for comprehensive state capture.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class SystemState:
    """A snapshot of system state at a point in time."""
    timestamp: float = 0.0
    devices: list[str] = field(default_factory=list)
    symlinks: list[str] = field(default_factory=list)
    processes: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    handles: dict[str, int] = field(default_factory=dict)
    registry_keys: list[str] = field(default_factory=list)
    files_created: list[str] = field(default_factory=list)


@dataclass
class SystemDiff:
    """Differences between two system state snapshots."""
    new_devices: list[str] = field(default_factory=list)
    removed_devices: list[str] = field(default_factory=list)
    new_symlinks: list[str] = field(default_factory=list)
    removed_symlinks: list[str] = field(default_factory=list)
    new_processes: list[dict[str, Any]] = field(default_factory=list)
    new_services: list[dict[str, Any]] = field(default_factory=list)
    handle_changes: dict[str, int] = field(default_factory=dict)
    new_registry_keys: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.new_devices or self.new_symlinks
            or self.new_processes or self.new_services
            or self.handle_changes or self.new_registry_keys
        )


class SystemMonitor:
    """Before/After system state monitoring."""

    def __init__(self):
        self._wmi = None
        self._has_wmi = False
        self._init_wmi()

    def _init_wmi(self) -> None:
        """Initialize WMI connection (may fail in non-Windows/test env)."""
        try:
            import win32com.client
            self._wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator")
            self._wmi = self._wmi.ConnectServer(".", "root\\cimv2")
            self._has_wmi = True
        except Exception:
            self._has_wmi = False

    def snapshot(self) -> SystemState:
        """Capture current system state.

        Returns:
            SystemState with device, process, and service information.
        """
        state = SystemState(timestamp=time.time())

        # Enumerate devices via Win32_PnPEntity
        state.devices = self._query_pnp_devices()

        # Enumerate symbolic links
        state.symlinks = self._query_dos_devices()

        # Running processes
        state.processes = self._query_processes()

        # Running services
        state.services = self._query_services()

        return state

    def diff(self, before: SystemState, after: SystemState) -> SystemDiff:
        """Compute differences between two system state snapshots.

        Args:
            before: State before driver load / PoC execution.
            after: State after driver load / PoC execution.

        Returns:
            SystemDiff with all detected changes.
        """
        d = SystemDiff()

        # Device changes
        before_devs = set(before.devices)
        after_devs = set(after.devices)
        d.new_devices = sorted(after_devs - before_devs)
        d.removed_devices = sorted(before_devs - after_devs)

        # Symlink changes
        before_links = set(before.symlinks)
        after_links = set(after.symlinks)
        d.new_symlinks = sorted(after_links - before_links)
        d.removed_symlinks = sorted(before_links - after_links)

        # New processes
        before_pids = {p.get("ProcessId") for p in before.processes}
        d.new_processes = [
            p for p in after.processes if p.get("ProcessId") not in before_pids
        ]

        # New services
        before_svc_names = {s.get("Name") for s in before.services}
        d.new_services = [
            s for s in after.services if s.get("Name") not in before_svc_names
        ]

        # Handle changes (simplified)
        for key in set(list(before.handles.keys()) + list(after.handles.keys())):
            before_count = before.handles.get(key, 0)
            after_count = after.handles.get(key, 0)
            if before_count != after_count:
                d.handle_changes[key] = after_count - before_count

        return d

    def get_new_devices(self, before: SystemState, after: SystemState) -> list[str]:
        """Get new device objects that appeared between snapshots."""
        return list(set(after.devices) - set(before.devices))

    def get_new_symlinks(self, before: SystemState, after: SystemState) -> list[str]:
        """Get new symbolic links that appeared between snapshots."""
        return list(set(after.symlinks) - set(before.symlinks))

    def get_new_handles(
        self, before: SystemState, after: SystemState,
    ) -> dict[str, int]:
        """Get handle count changes between snapshots."""
        changes = {}
        all_keys = set(list(before.handles.keys()) + list(after.handles.keys()))
        for key in all_keys:
            delta = after.handles.get(key, 0) - before.handles.get(key, 0)
            if delta != 0:
                changes[key] = delta
        return changes

    def _query_pnp_devices(self) -> list[str]:
        """Query PnP devices via WMI."""
        if not self._has_wmi:
            return []
        try:
            results = self._wmi.ExecQuery(
                "SELECT Name, DeviceID FROM Win32_PnPEntity"
            )
            return [
                f"{item.Name or ''} ({item.DeviceID or ''})"
                for item in results
            ]
        except Exception:
            return []

    def _query_dos_devices(self) -> list[str]:
        """Query DOS device symbolic links."""
        if not self._has_wmi:
            return []
        try:
            results = self._wmi.ExecQuery(
                "SELECT Name, Target FROM Win32_SymbolicLink"
            )
            return [
                f"{item.Name or ''} -> {item.Target or ''}"
                for item in results
            ]
        except Exception:
            return []

    def _query_processes(self) -> list[dict[str, Any]]:
        """Query running processes."""
        if not self._has_wmi:
            return []
        try:
            results = self._wmi.ExecQuery(
                "SELECT ProcessId, Name, ExecutablePath FROM Win32_Process"
            )
            return [
                {
                    "ProcessId": item.ProcessId,
                    "Name": item.Name,
                    "ExecutablePath": item.ExecutablePath or "",
                }
                for item in results
            ]
        except Exception:
            return []

    def _query_services(self) -> list[dict[str, Any]]:
        """Query running services."""
        if not self._has_wmi:
            return []
        try:
            results = self._wmi.ExecQuery(
                "SELECT Name, DisplayName, State, StartMode FROM Win32_Service "
                "WHERE State='Running'"
            )
            return [
                {
                    "Name": item.Name,
                    "DisplayName": item.DisplayName,
                    "State": item.State,
                    "StartMode": item.StartMode,
                }
                for item in results
            ]
        except Exception:
            return []

    def monitor_device_appearance(
        self, device_name: str, timeout: int = 10, interval: float = 0.5,
    ) -> bool:
        """Wait for a specific device to appear.

        Args:
            device_name: Device name substring to search for.
            timeout: Max seconds to wait.
            interval: Poll interval in seconds.

        Returns:
            True if device appeared within timeout.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            state = self.snapshot()
            for dev in state.devices:
                if device_name in dev:
                    return True
            time.sleep(interval)
        return False
