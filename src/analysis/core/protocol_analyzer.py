"""
DriverScope — Shared IOCTL Protocol Analyzer.

Analyzes IOCTL codes, access types, and method types across multiple
drivers to identify shared protocols and potential attack surface
amplification.

Key analysis:
1. IOCTL code collision detection (same code, different drivers)
2. Access type correlation (FILE_ANY_ACCESS, FILE_READ_ACCESS, etc.)
3. Method type correlation (METHOD_BUFFERED, METHOD_IN_DIRECT, etc.)
4. Attack surface amplification scoring
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from src.models import (
    Confidence, DisassemblyResult, Evidence, Finding, FindingCategory,
    Sample, Severity,
)


# IOCTL decoding constants
FILE_DEVICE_UNKNOWN = 0x00000022
METHOD_BUFFERED = 0
METHOD_IN_DIRECT = 1
METHOD_OUT_DIRECT = 2
METHOD_NEITHER = 3

FILE_ANY_ACCESS = 0
FILE_READ_ACCESS = 1
FILE_WRITE_ACCESS = 2


def decode_ioctl(ioctl_code: int) -> dict[str, Any]:
    """Decode a Windows IOCTL code into its components."""
    device_type = (ioctl_code >> 16) & 0xFFFF
    access = (ioctl_code >> 14) & 0x3
    function = (ioctl_code >> 2) & 0xFFF
    method = ioctl_code & 0x3

    method_names = {
        METHOD_BUFFERED: "METHOD_BUFFERED",
        METHOD_IN_DIRECT: "METHOD_IN_DIRECT",
        METHOD_OUT_DIRECT: "METHOD_OUT_DIRECT",
        METHOD_NEITHER: "METHOD_NEITHER",
    }
    access_names = {
        FILE_ANY_ACCESS: "FILE_ANY_ACCESS",
        FILE_READ_ACCESS: "FILE_READ_ACCESS",
        FILE_WRITE_ACCESS: "FILE_WRITE_ACCESS",
    }

    return {
        "device_type": hex(device_type),
        "function": function,
        "method": method_names.get(method, f"UNKNOWN({method})"),
        "access": access_names.get(access, f"UNKNOWN({access})"),
        "raw": hex(ioctl_code),
    }


@dataclass
class ProtocolGroup:
    """A group of drivers sharing the same IOCTL protocol."""
    function_range: tuple[int, int]  # (min, max) function codes
    device_type: str
    members: list[str] = field(default_factory=list)
    shared_codes: list[int] = field(default_factory=list)


class ProtocolAnalyzer:
    """Analyze shared IOCTL protocols across multiple drivers."""

    def analyze(self, samples: list[Sample]) -> list[Finding]:
        """Analyze cross-driver IOCTL protocol sharing."""
        findings: list[Finding] = []

        if len(samples) < 2:
            return findings

        # Group IOCTLs by (device_type, function_code)
        ioctl_groups: dict[tuple[int, int], list[str]] = defaultdict(list)
        method_groups: dict[int, list[tuple[str, str]]] = defaultdict(list)

        for sample in samples:
            if sample.disassembly_result is None:
                continue
            driver_name = sample.name

            for code in sample.disassembly_result.ioctl_codes:
                decoded = decode_ioctl(code)
                device_type = int(decoded["device_type"], 16)
                function = decoded["function"]
                ioctl_groups[(device_type, function)].append(driver_name)

                method = self._method_from_name(decoded["method"])
                method_groups[code].append((driver_name, decoded["method"]))

        # Findings for shared device type + function
        for (device_type, function), drivers in ioctl_groups.items():
            unique_drivers = list(set(drivers))
            if len(unique_drivers) >= 2:
                findings.append(Finding(
                    category=FindingCategory.SHARED_IOCTL_PROTOCOL,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Shared IOCTL protocol: device_type=0x{device_type:X}, "
                        f"function={function}, shared by: {', '.join(unique_drivers)}"
                    ),
                    context={
                        "device_type": hex(device_type),
                        "function": function,
                        "drivers": unique_drivers,
                    },
                    evidence=[Evidence(
                        type="instruction_pattern",
                        location="IOCTL_DISPATCH",
                        snippet=f"device_type=0x{device_type:X}, func={function}",
                        rule_id="PROTO001",
                    )],
                ))

        # Findings for exact IOCTL code collisions
        for code, driver_methods in method_groups.items():
            unique_drivers = list(set(dm[0] for dm in driver_methods))
            if len(unique_drivers) >= 2:
                methods = list(set(dm[1] for dm in driver_methods))
                findings.append(Finding(
                    category=FindingCategory.CROSS_DRIVER_ATTACK_CHAIN,
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"IOCTL code collision: 0x{code:08X} in {', '.join(unique_drivers)} "
                        f"(methods: {', '.join(methods)})"
                    ),
                    context={
                        "ioctl_code": hex(code),
                        "drivers": unique_drivers,
                        "methods": methods,
                    },
                    evidence=[Evidence(
                        type="instruction_pattern",
                        location="IOCTL_DISPATCH",
                        snippet=f"0x{code:08X}",
                        rule_id="PROTO002",
                    )],
                ))

        return findings

    def _method_from_name(self, method_name: str) -> int:
        names = {
            "METHOD_BUFFERED": METHOD_BUFFERED,
            "METHOD_IN_DIRECT": METHOD_IN_DIRECT,
            "METHOD_OUT_DIRECT": METHOD_OUT_DIRECT,
            "METHOD_NEITHER": METHOD_NEITHER,
        }
        return names.get(method_name, -1)

    def build_protocol_groups(self, samples: list[Sample]) -> list[ProtocolGroup]:
        """Group drivers by shared IOCTL protocol ranges."""
        groups: list[ProtocolGroup] = []

        # Group by device type
        device_drivers: dict[int, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        for sample in samples:
            if sample.disassembly_result is None:
                continue
            for code in sample.disassembly_result.ioctl_codes:
                decoded = decode_ioctl(code)
                device_type = int(decoded["device_type"], 16)
                function = decoded["function"]
                device_drivers[device_type][sample.name].add(function)

        for device_type, driver_funcs in device_drivers.items():
            if len(driver_funcs) < 2:
                continue

            # Find overlapping function ranges
            all_functions: set[int] = set()
            for funcs in driver_funcs.values():
                all_functions.update(funcs)

            if all_functions:
                groups.append(ProtocolGroup(
                    function_range=(min(all_functions), max(all_functions)),
                    device_type=hex(device_type),
                    members=list(driver_funcs.keys()),
                    shared_codes=list(all_functions),
                ))

        return groups
