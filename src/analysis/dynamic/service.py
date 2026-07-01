"""
DriverScope -- Driver Service Controller (SCM).

Manages Windows Service Control Manager operations for loading and
unloading kernel drivers:

- Create service (type=kernel)
- Start/stop service
- Delete service
- Wait for device appearance/disappearance
- Query service status

Requires administrator privileges.
"""

from __future__ import annotations

import ctypes
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# SCM constants
SC_MANAGER_ALL_ACCESS = 0xF003F
SERVICE_ALL_ACCESS = 0xF003F
SERVICE_KERNEL_DRIVER = 0x00000001
SERVICE_DEMAND_START = 0x00000003
SERVICE_ERROR_NORMAL = 0x00000001

SERVICE_CONTROL_STOP = 0x00000001
SERVICE_CONTROL_PAUSE = 0x00000002
SERVICE_CONTROL_CONTINUE = 0x00000003

SERVICE_STATE_ALL = 0x00000003

SERVICE_STOPPED = 0x00000001
SERVICE_START_PENDING = 0x00000002
SERVICE_STOP_PENDING = 0x00000003
SERVICE_RUNNING = 0x00000004
SERVICE_CONTINUE_PENDING = 0x00000005
SERVICE_PAUSE_PENDING = 0x00000006
SERVICE_PAUSED = 0x00000007

DELETE = 0x00010000

SERVICE_STATUS_PROCESS_SIZE = 48

GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
FILE_SHARE_READ = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING = 3

SERVICE_QUERY_STATUS = 0x0004
SERVICE_QUERY_CONFIG = 0x0001


@dataclass
class ServiceStatus:
    """Windows service status."""
    state: int = 0
    win32_exit_code: int = 0
    service_specific_exit_code: int = 0
    checkpoint: int = 0
    wait_hint: int = 0
    process_id: int = 0

    @property
    def is_running(self) -> bool:
        return self.state == SERVICE_RUNNING

    @property
    def is_stopped(self) -> bool:
        return self.state == SERVICE_STOPPED

    @property
    def state_name(self) -> str:
        names = {
            SERVICE_STOPPED: "STOPPED",
            SERVICE_START_PENDING: "START_PENDING",
            SERVICE_STOP_PENDING: "STOP_PENDING",
            SERVICE_RUNNING: "RUNNING",
            SERVICE_CONTINUE_PENDING: "CONTINUE_PENDING",
            SERVICE_PAUSE_PENDING: "PAUSE_PENDING",
            SERVICE_PAUSED: "PAUSED",
        }
        return names.get(self.state, f"UNKNOWN({self.state})")


@dataclass
class DriverServiceInfo:
    """Information about a loaded driver service."""
    service_name: str
    display_name: str
    driver_path: str
    status: ServiceStatus = field(default_factory=ServiceStatus)
    load_time: float = 0.0
    device_paths: list[str] = field(default_factory=list)
    error: str = ""


class DriverServiceController:
    """Manage kernel driver services via Windows SCM."""

    def __init__(self):
        self._advapi32 = ctypes.windll.advapi32
        self._kernel32 = ctypes.windll.kernel32
        self._services: dict[str, DriverServiceInfo] = {}

    @staticmethod
    def is_available() -> bool:
        """Check if SCM operations are available (admin + Windows)."""
        if ctypes.windll is None:
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def create_service(
        self,
        driver_path: Path | str,
        service_name: str,
        display_name: str = "",
    ) -> DriverServiceInfo:
        """Create a kernel driver service.

        Args:
            driver_path: Absolute path to the .sys file.
            service_name: Internal service name.
            display_name: Human-readable display name.

        Returns:
            DriverServiceInfo with service details.

        Raises:
            RuntimeError: If service creation fails.
        """
        driver_path_str = str(Path(driver_path).resolve())
        if not Path(driver_path_str).exists():
            raise FileNotFoundError(f"Driver not found: {driver_path_str}")

        if not display_name:
            display_name = service_name

        sc_handle = None
        svc_handle = None

        try:
            # Open SCM
            sc_handle = self._advapi32.OpenSCManagerA(
                None, None, SC_MANAGER_ALL_ACCESS
            )
            if not sc_handle:
                err = self._kernel32.GetLastError()
                raise RuntimeError(f"OpenSCManager failed: error {err}")

            # Create service
            svc_handle = self._advapi32.CreateServiceA(
                sc_handle,
                service_name.encode("utf-8"),
                display_name.encode("utf-8"),
                SERVICE_ALL_ACCESS,
                SERVICE_KERNEL_DRIVER,
                SERVICE_DEMAND_START,
                SERVICE_ERROR_NORMAL,
                driver_path_str.encode("utf-8"),
                None,  # lpLoadOrderGroup
                None,  # lpdwTagId
                None,  # lpDependencies
                None,  # lpServiceStartName
                None,  # lpPassword
            )

            if not svc_handle:
                err = self._kernel32.GetLastError()
                if err == 1073:  # ERROR_SERVICE_EXISTS
                    logging.info(
                        "[service] Service '%s' already exists, will use existing",
                        service_name,
                    )
                else:
                    raise RuntimeError(
                        f"CreateService failed: error {err}"
                    )

            info = DriverServiceInfo(
                service_name=service_name,
                display_name=display_name,
                driver_path=driver_path_str,
            )
            self._services[service_name] = info
            return info

        finally:
            if svc_handle:
                self._advapi32.CloseServiceHandle(svc_handle)
            if sc_handle:
                self._advapi32.CloseServiceHandle(sc_handle)

    def start_service(self, service_name: str, timeout: int = 10) -> bool:
        """Start a driver service and wait for it to enter RUNNING state.

        Args:
            service_name: Service name to start.
            timeout: Max seconds to wait for RUNNING state.

        Returns:
            True if service entered RUNNING state.
        """
        sc_handle = None
        svc_handle = None

        try:
            sc_handle = self._advapi32.OpenSCManagerA(
                None, None, SC_MANAGER_ALL_ACCESS
            )
            if not sc_handle:
                raise RuntimeError(
                    f"OpenSCManager failed: error {self._kernel32.GetLastError()}"
                )

            svc_handle = self._advapi32.OpenServiceA(
                sc_handle, service_name.encode("utf-8"), SERVICE_ALL_ACCESS
            )
            if not svc_handle:
                raise RuntimeError(
                    f"OpenService failed: error {self._kernel32.GetLastError()}"
                )

            result = self._advapi32.StartServiceA(
                svc_handle, 0, None
            )

            if not result:
                err = self._kernel32.GetLastError()
                if err == 1056:  # ERROR_SERVICE_ALREADY_RUNNING
                    return True
                raise RuntimeError(f"StartService failed: error {err}")

            # Wait for RUNNING state
            return self._wait_for_status(svc_handle, SERVICE_RUNNING, timeout)

        finally:
            if svc_handle:
                self._advapi32.CloseServiceHandle(svc_handle)
            if sc_handle:
                self._advapi32.CloseServiceHandle(sc_handle)

    def stop_service(self, service_name: str, timeout: int = 10) -> bool:
        """Stop a driver service.

        Args:
            service_name: Service name to stop.
            timeout: Max seconds to wait for STOPPED state.

        Returns:
            True if service entered STOPPED state.
        """
        sc_handle = None
        svc_handle = None

        try:
            sc_handle = self._advapi32.OpenSCManagerA(
                None, None, SC_MANAGER_ALL_ACCESS
            )
            if not sc_handle:
                return False

            svc_handle = self._advapi32.OpenServiceA(
                sc_handle, service_name.encode("utf-8"), SERVICE_ALL_ACCESS
            )
            if not svc_handle:
                return False

            result = self._advapi32.ControlService(
                svc_handle, SERVICE_CONTROL_STOP, ctypes.byref(
                    ctypes.create_string_buffer(SERVICE_STATUS_PROCESS_SIZE)
                )
            )

            if not result:
                err = self._kernel32.GetLastError()
                if err == 1062:  # ERROR_SERVICE_NOT_ACTIVE
                    return True
                return False

            return self._wait_for_status(svc_handle, SERVICE_STOPPED, timeout)

        finally:
            if svc_handle:
                self._advapi32.CloseServiceHandle(svc_handle)
            if sc_handle:
                self._advapi32.CloseServiceHandle(sc_handle)

    def delete_service(self, service_name: str) -> bool:
        """Delete a driver service.

        Args:
            service_name: Service name to delete.

        Returns:
            True if service was deleted.
        """
        sc_handle = None
        svc_handle = None

        try:
            sc_handle = self._advapi32.OpenSCManagerA(
                None, None, SC_MANAGER_ALL_ACCESS
            )
            if not sc_handle:
                return False

            svc_handle = self._advapi32.OpenServiceA(
                sc_handle, service_name.encode("utf-8"), DELETE | SERVICE_QUERY_STATUS
            )
            if not svc_handle:
                return False

            result = self._advapi32.DeleteService(svc_handle)
            return bool(result)

        finally:
            if svc_handle:
                self._advapi32.CloseServiceHandle(svc_handle)
            if sc_handle:
                self._advapi32.CloseServiceHandle(sc_handle)

    def get_service_status(self, service_name: str) -> ServiceStatus | None:
        """Query current service status."""
        sc_handle = None
        svc_handle = None

        try:
            sc_handle = self._advapi32.OpenSCManagerA(
                None, None, SC_MANAGER_ALL_ACCESS
            )
            if not sc_handle:
                return None

            svc_handle = self._advapi32.OpenServiceA(
                sc_handle, service_name.encode("utf-8"), SERVICE_QUERY_STATUS
            )
            if not svc_handle:
                return None

            buf = ctypes.create_string_buffer(SERVICE_STATUS_PROCESS_SIZE)
            size_needed = ctypes.c_ulong(0)

            result = self._advapi32.QueryServiceStatusEx(
                svc_handle, 0, buf, SERVICE_STATUS_PROCESS_SIZE,
                ctypes.byref(size_needed)
            )
            if not result:
                return None

            status = ServiceStatus()
            status.state = ctypes.c_ulong.from_buffer(buf, offset=4).value
            status.win32_exit_code = ctypes.c_ulong.from_buffer(buf, offset=8).value
            status.service_specific_exit_code = ctypes.c_ulong.from_buffer(buf, offset=12).value
            status.checkpoint = ctypes.c_ulong.from_buffer(buf, offset=16).value
            status.wait_hint = ctypes.c_ulong.from_buffer(buf, offset=20).value
            status.process_id = ctypes.c_ulong.from_buffer(buf, offset=28).value
            return status

        finally:
            if svc_handle:
                self._advapi32.CloseServiceHandle(svc_handle)
            if sc_handle:
                self._advapi32.CloseServiceHandle(sc_handle)

    def _wait_for_status(
        self, svc_handle, target_status: int, timeout: int
    ) -> bool:
        """Wait for a service to reach the target status."""
        deadline = time.time() + timeout
        buf = ctypes.create_string_buffer(SERVICE_STATUS_PROCESS_SIZE)

        while time.time() < deadline:
            size_needed = ctypes.c_ulong(0)
            result = self._advapi32.QueryServiceStatusEx(
                svc_handle, 0, buf, SERVICE_STATUS_PROCESS_SIZE,
                ctypes.byref(size_needed)
            )
            if result:
                state = ctypes.c_ulong.from_buffer(buf, offset=4).value
                if state == target_status:
                    return True

            time.sleep(0.5)

        return False

    def open_device(self, device_name: str) -> int | None:
        """Open a handle to a kernel device.

        Args:
            device_name: Device path (e.g., \\\\.\\TestDevice).

        Returns:
            Device handle or None on failure.
        """
        h_device = self._kernel32.CreateFileA(
            device_name.encode("utf-8"),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            0,
            None,
        )

        if h_device and h_device != 0xFFFFFFFF and h_device != -1:
            return h_device
        return None

    def close_device(self, handle: int) -> bool:
        """Close a device handle."""
        return bool(self._kernel32.CloseHandle(handle))

    def load_and_wait(
        self,
        driver_path: Path | str,
        service_name: str = "",
        wait_seconds: int = 5,
    ) -> DriverServiceInfo:
        """Full lifecycle: create, start, wait, return info.

        Args:
            driver_path: Path to .sys file.
            service_name: Service name (default: filename without extension).
            wait_seconds: Seconds to wait after start for device to appear.

        Returns:
            DriverServiceInfo with loaded driver details.
        """
        driver_path = Path(driver_path)
        if not service_name:
            service_name = driver_path.stem

        info = self.create_service(driver_path, service_name)
        started = self.start_service(service_name)

        if started:
            time.sleep(wait_seconds)
            info.status = self.get_service_status(service_name) or info.status
            info.load_time = time.time()

        return info

    def unload(self, service_name: str) -> bool:
        """Full unload: stop, delete, clean up."""
        self.stop_service(service_name)
        time.sleep(1)
        return self.delete_service(service_name)
