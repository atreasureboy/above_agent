"""
DriverScope — Shared utility functions.
"""

from __future__ import annotations

# Core Windows kernel device types for IOCTL codes (CTL_CODE macro).
# Only device types that are commonly used by drivers we actually
# analyse are included.  Rare/exotic types are intentionally excluded
# because random code constants trivially decode to them.
_KNOWN_DEVICE_TYPES: set[int] = {
    # Storage / file system
    0x0007,  # FILE_DEVICE_DISK
    0x0008,  # FILE_DEVICE_DISK_FILE_SYSTEM
    0x0009,  # FILE_DEVICE_FILE_SYSTEM
    0x0015,  # FILE_DEVICE_NETWORK_FILE_SYSTEM

    # Communication / networking
    0x0012,  # FILE_DEVICE_NAMED_PIPE
    0x0013,  # FILE_DEVICE_NETWORK
    0x0014,  # FILE_DEVICE_NETWORK_BROWSER

    # Human interface / port drivers
    0x000a,  # FILE_DEVICE_INPORT_PORT
    0x000b,  # FILE_DEVICE_KEYBOARD
    0x0010,  # FILE_DEVICE_MOUSE
    0x0017,  # FILE_DEVICE_PARALLEL_PORT
    0x0018,  # FILE_DEVICE_PHYSICAL_NETCARD
    0x001b,  # FILE_DEVICE_SERIAL_MOUSE_PORT
    0x001c,  # FILE_DEVICE_SERIAL_PORT
    0x0028,  # FILE_DEVICE_8042_PORT
    0x0029,  # FILE_DEVICE_NETWORK_REDIRECTOR
    0x002b,  # FILE_DEVICE_BUS_EXTENDER

    # Common system drivers
    0x0022,  # FILE_DEVICE_UNKNOWN  (most common for custom/vulnerable drivers)
    0x002e,  # FILE_DEVICE_MASS_STORAGE
    0x0033,  # FILE_DEVICE_ACPI
    0x0039,  # FILE_DEVICE_TERMSRV
    0x0047,  # FILE_DEVICE_VMBUS
    0x0049,  # FILE_DEVICE_CRYPTO
    0xA000,  # FILE_DEVICE_BTHPORT
    0xAA55,  # FILE_DEVICE_HID

    # User-defined (very common for third-party / vulnerable drivers)
    0x8000,  # FILE_DEVICE_USER_DEFINED
}


def looks_like_ioctl_code(val: int) -> bool:
    """Check if a value looks like an IOCTL code (CTL_CODE macro).

    IOCTL codes have structure:
    - bits 1-0: Method (0=BUFFERED, 1=IN_DIRECT, 2=OUT_DIRECT, 3=NEITHER)
    - bits 15-14: Access (0=ANY, 1=READ, 2=WRITE, 3=READ|WRITE)
    - bits 13-2: Function (0x000-0xFFF)
    - bits 31-16: DeviceType — must match a known Windows device type.

    Additional heuristics to reduce false positives:
    - Function field must be in a realistic range (0-0x800).  Real drivers
      rarely use function numbers above 0x800; higher values are usually
      random code constants that happen to match a valid device type.
    - Kernel pointer ranges are explicitly rejected.
    """
    function = (val >> 2) & 0xFFF
    device_type = (val >> 16) & 0xFFFF

    # Must be large enough to have a device type.
    if val < 0x10000:
        return False

    # Reject kernel pointers (0xFFFFxxxx or 0xFxxxxxxx ranges).
    if val >= 0xF0000000:
        return False

    # Function field should be in a realistic range.
    if function > 0x800:
        return False

    # Device type must be in the known whitelist.
    return device_type in _KNOWN_DEVICE_TYPES
