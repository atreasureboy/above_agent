"""
DriverScope -- Multi-Driver Correlator.

Detects cross-driver communication patterns and builds attack chains
across multiple driver binaries:

1. ALPC port name correlation (server/client across drivers)
2. Named pipe correlation (shared pipe names)
3. Shared device object references (Device, DosDevices)
4. Shared IOCTL protocol analysis
5. Cross-driver attack chain construction
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.models import (
    Confidence, DisassemblyResult, Evidence, Finding, FindingCategory,
    Sample, Severity,
)


@dataclass
class DriverCluster:
    """A group of drivers that communicate with each other."""
    name: str
    members: list[str] = field(default_factory=list)
    communication_channels: list[dict] = field(default_factory=list)
    attack_chains: list[dict] = field(default_factory=list)


# Match Windows device paths: \Device\Something, \GLOBAL??\Something
DEVICE_PATH_RE = re.compile(r"\\[A-Za-z_]+\\[A-Za-z_][^\s\"']*", re.IGNORECASE)
# Match ALPC ports: \RPC Control\PortName
ALPC_PORT_RE = re.compile(r"\\RPC Control\\[^\s\"']+", re.IGNORECASE)
# Match named pipes: \\.\pipe\Name
NAMED_PIPE_RE = re.compile(r"\\\\\.\\pipe\\[^\s\"']+", re.IGNORECASE)


class MultiDriverCorrelator:
    """Cross-driver communication and dependency analysis."""

    def analyze_cluster(self, samples: list[Sample]) -> list[Finding]:
        """Analyze a group of drivers for cross-driver patterns."""
        findings: list[Finding] = []

        if len(samples) < 2:
            return findings

        device_map: dict[str, list[str]] = defaultdict(list)
        alpc_map: dict[str, list[str]] = defaultdict(list)
        pipe_map: dict[str, list[str]] = defaultdict(list)

        for sample in samples:
            if sample.disassembly_result is None:
                continue
            ir = sample.disassembly_result
            driver_name = sample.name

            for s in ir.strings:
                if not s or len(s) < 8:
                    continue

                for m in DEVICE_PATH_RE.finditer(s):
                    path = m.group(0)
                    if "\\Device\\" in path or "\\GLOBAL??" in path:
                        device_map[path].append(driver_name)

                for m in ALPC_PORT_RE.finditer(s):
                    port = m.group(0)
                    alpc_map[port].append(driver_name)

                for m in NAMED_PIPE_RE.finditer(s):
                    pipe = m.group(0)
                    pipe_map[pipe].append(driver_name)

            if sample.debug_path:
                device_map[f"PDB:{sample.debug_path}"].append(driver_name)

        findings.extend(self._find_shared_devices(device_map))
        findings.extend(self._find_shared_alpc(alpc_map))
        findings.extend(self._find_shared_pipes(pipe_map))
        findings.extend(self._find_shared_ioctl_protocols(samples))
        findings.extend(self._build_attack_chains(samples, device_map, alpc_map, pipe_map))

        return findings

    def _find_shared_devices(
        self, device_map: dict[str, list[str]],
    ) -> list[Finding]:
        findings = []
        for path, drivers in device_map.items():
            unique_drivers = list(set(drivers))
            if len(unique_drivers) >= 2:
                findings.append(Finding(
                    category=FindingCategory.CROSS_DRIVER_SHARED_DEVICE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=f"Shared device path '{path}' referenced by: {', '.join(unique_drivers)}",
                    context={"device_path": path, "drivers": unique_drivers},
                    evidence=[Evidence(
                        type="string", location=".rdata", snippet=path, rule_id="CORR001",
                    )],
                ))
        return findings

    def _find_shared_alpc(
        self, alpc_map: dict[str, list[str]],
    ) -> list[Finding]:
        findings = []
        for port, drivers in alpc_map.items():
            unique_drivers = list(set(drivers))
            if len(unique_drivers) >= 2:
                findings.append(Finding(
                    category=FindingCategory.CROSS_DRIVER_ALPC,
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"Shared ALPC port '{port}' used by: {', '.join(unique_drivers)}",
                    context={"alpc_port": port, "drivers": unique_drivers},
                    evidence=[Evidence(
                        type="string", location=".rdata", snippet=port, rule_id="CORR002",
                    )],
                ))
        return findings

    def _find_shared_pipes(
        self, pipe_map: dict[str, list[str]],
    ) -> list[Finding]:
        findings = []
        for pipe, drivers in pipe_map.items():
            unique_drivers = list(set(drivers))
            if len(unique_drivers) >= 2:
                findings.append(Finding(
                    category=FindingCategory.CROSS_DRIVER_NAMED_PIPE,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=f"Shared named pipe '{pipe}' used by: {', '.join(unique_drivers)}",
                    context={"pipe_name": pipe, "drivers": unique_drivers},
                    evidence=[Evidence(
                        type="string", location=".rdata", snippet=pipe, rule_id="CORR003",
                    )],
                ))
        return findings

    def _find_shared_ioctl_protocols(
        self, samples: list[Sample],
    ) -> list[Finding]:
        findings = []
        ioctl_map: dict[int, list[str]] = defaultdict(list)

        for sample in samples:
            if sample.disassembly_result is None:
                continue
            for code in sample.disassembly_result.ioctl_codes:
                ioctl_map[code].append(sample.name)

        for code, drivers in ioctl_map.items():
            unique_drivers = list(set(drivers))
            if len(unique_drivers) >= 2:
                findings.append(Finding(
                    category=FindingCategory.SHARED_IOCTL_PROTOCOL,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=f"Shared IOCTL code 0x{code:08X} found in: {', '.join(unique_drivers)}",
                    context={"ioctl_code": hex(code), "drivers": unique_drivers},
                    evidence=[Evidence(
                        type="instruction_pattern", location="IOCTL_DISPATCH",
                        snippet=f"IOCTL 0x{code:08X}", rule_id="CORR004",
                    )],
                ))

        return findings

    def _build_attack_chains(
        self,
        samples: list[Sample],
        device_map: dict[str, list[str]],
        alpc_map: dict[str, list[str]],
        pipe_map: dict[str, list[str]],
    ) -> list[Finding]:
        findings = []

        edges: list[tuple[str, str, str]] = []
        for path, drivers in device_map.items():
            unique = list(set(drivers))
            for i in range(len(unique)):
                for j in range(i + 1, len(unique)):
                    edges.append((unique[i], unique[j], f"device:{path}"))

        for port, drivers in alpc_map.items():
            unique = list(set(drivers))
            for i in range(len(unique)):
                for j in range(i + 1, len(unique)):
                    edges.append((unique[i], unique[j], f"alpc:{port}"))

        for pipe, drivers in pipe_map.items():
            unique = list(set(drivers))
            for i in range(len(unique)):
                for j in range(i + 1, len(unique)):
                    edges.append((unique[i], unique[j], f"pipe:{pipe}"))

        if edges:
            adj: dict[str, set[str]] = defaultdict(set)
            for a, b, _ in edges:
                adj[a].add(b)
                adj[b].add(a)

            visited = set()
            for node in adj:
                if node not in visited:
                    component = set()
                    stack = [node]
                    while stack:
                        n = stack.pop()
                        if n in visited:
                            continue
                        visited.add(n)
                        component.add(n)
                        stack.extend(adj[n] - visited)

                    if len(component) >= 2:
                        chain_edges = [
                            {"from": a, "to": b, "via": ch}
                            for a, b, ch in edges
                            if a in component and b in component
                        ]
                        findings.append(Finding(
                            category=FindingCategory.CROSS_DRIVER_ATTACK_CHAIN,
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM,
                            description=(
                                f"Cross-driver attack chain: {len(component)} drivers connected "
                                f"({', '.join(sorted(component))})"
                            ),
                            context={
                                "cluster": sorted(component),
                                "edges": chain_edges,
                            },
                            evidence=[Evidence(
                                type="cfg_path", location="CROSS_DRIVER",
                                snippet=f"{len(component)}-driver cluster", rule_id="CORR005",
                            )],
                        ))

        return findings

    def build_clusters(self, samples: list[Sample]) -> list[DriverCluster]:
        """Group drivers into communication-based clusters."""
        clusters = []

        device_map: dict[str, list[str]] = defaultdict(list)
        alpc_map: dict[str, list[str]] = defaultdict(list)
        pipe_map: dict[str, list[str]] = defaultdict(list)

        for sample in samples:
            if sample.disassembly_result is None:
                continue
            name = sample.name
            for s in sample.disassembly_result.strings:
                if not s or len(s) < 8:
                    continue
                for m in DEVICE_PATH_RE.finditer(s):
                    if "\\Device\\" in m.group(0):
                        device_map[m.group(0)].append(name)
                for m in ALPC_PORT_RE.finditer(s):
                    alpc_map[m.group(0)].append(name)
                for m in NAMED_PIPE_RE.finditer(s):
                    pipe_map[m.group(0)].append(name)

        adj: dict[str, set[str]] = defaultdict(set)
        channels: dict[tuple[str, str], list[str]] = {}

        for path, drivers in {**device_map, **alpc_map, **pipe_map}.items():
            unique = list(set(drivers))
            for i in range(len(unique)):
                for j in range(i + 1, len(unique)):
                    pair = (unique[i], unique[j])
                    adj[unique[i]].add(unique[j])
                    adj[unique[j]].add(unique[i])
                    channels.setdefault(pair, []).append(path)

        visited = set()
        cluster_idx = 0
        for node in adj:
            if node in visited:
                continue
            component = set()
            stack = [node]
            while stack:
                n = stack.pop()
                if n in visited:
                    continue
                visited.add(n)
                component.add(n)
                stack.extend(adj[n] - visited)

            if len(component) >= 2:
                cluster_idx += 1
                comm_channels = []
                for (a, b), paths in channels.items():
                    if a in component and b in component:
                        comm_channels.append({"drivers": [a, b], "shared": paths})
                clusters.append(DriverCluster(
                    name=f"cluster_{cluster_idx}",
                    members=sorted(component),
                    communication_channels=comm_channels,
                ))

        return clusters


def get_correlator() -> MultiDriverCorrelator:
    """Factory function."""
    return MultiDriverCorrelator()
