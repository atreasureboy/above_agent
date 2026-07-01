"""
DriverScope — Driver Dependency Graph.

Builds a topological dependency graph across multiple drivers based on:
- Shared device objects
- ALPC port server/client relationships
- Named pipe server/client relationships
- Import/export relationships (user-mode components)

Supports DOT/Graphviz export for visualization.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.models import Sample


@dataclass
class DependencyNode:
    """A node in the driver dependency graph."""
    sample: Sample
    risk_score: float = 0.0
    device_paths: list[str] = field(default_factory=list)
    alpc_ports: list[str] = field(default_factory=list)
    pipe_names: list[str] = field(default_factory=list)
    ioctl_codes: list[int] = field(default_factory=list)


@dataclass
class DependencyEdge:
    """A directed dependency edge between two drivers."""
    source: str        # Driver name (depends on)
    target: str        # Driver name (depended upon)
    relationship: str  # "shared_device", "alpc_client", "pipe_client", "shared_ioctl"
    detail: str = ""   # Specific shared resource


class DependencyGraph:
    """Build and query driver dependency graphs."""

    def __init__(self):
        self.nodes: dict[str, DependencyNode] = {}
        self.edges: list[DependencyEdge] = []

    def add_driver(self, sample: Sample) -> DependencyNode:
        node = DependencyNode(sample=sample, risk_score=sample.risk_score)

        if sample.disassembly_result:
            ir = sample.disassembly_result
            for s in ir.strings:
                if not s or len(s) < 8:
                    continue
                if "\\Device\\" in s:
                    node.device_paths.append(s)
                if "\\RPC Control\\" in s:
                    node.alpc_ports.append(s)
                if "\\pipe\\" in s:
                    node.pipe_names.append(s)
            node.ioctl_codes = list(ir.ioctl_codes)

        self.nodes[sample.name] = node
        return node

    def build_edges(self) -> list[DependencyEdge]:
        """Detect dependency edges between all driver pairs."""
        self.edges.clear()
        node_names = list(self.nodes.keys())

        for i in range(len(node_names)):
            for j in range(i + 1, len(node_names)):
                a = self.nodes[node_names[i]]
                b = self.nodes[node_names[j]]

                # Shared devices
                shared_devices = set(a.device_paths) & set(b.device_paths)
                for dev in shared_devices:
                    self.edges.append(DependencyEdge(
                        source=a.sample.name,
                        target=b.sample.name,
                        relationship="shared_device",
                        detail=dev,
                    ))

                # Shared ALPC ports
                shared_alpc = set(a.alpc_ports) & set(b.alpc_ports)
                for port in shared_alpc:
                    self.edges.append(DependencyEdge(
                        source=a.sample.name,
                        target=b.sample.name,
                        relationship="alpc_client",
                        detail=port,
                    ))

                # Shared pipes
                shared_pipes = set(a.pipe_names) & set(b.pipe_names)
                for pipe in shared_pipes:
                    self.edges.append(DependencyEdge(
                        source=a.sample.name,
                        target=b.sample.name,
                        relationship="pipe_client",
                        detail=pipe,
                    ))

                # Shared IOCTL codes
                shared_ioctls = set(a.ioctl_codes) & set(b.ioctl_codes)
                for code in shared_ioctls:
                    self.edges.append(DependencyEdge(
                        source=a.sample.name,
                        target=b.sample.name,
                        relationship="shared_ioctl",
                        detail=f"IOCTL 0x{code:08X}",
                    ))

        return self.edges

    def topological_sort(self) -> list[str]:
        """Topological sort of drivers by dependency order."""
        adj: dict[str, set[str]] = {name: set() for name in self.nodes}
        in_degree: dict[str, int] = {name: 0 for name in self.nodes}

        for edge in self.edges:
            if edge.source in adj and edge.target in adj:
                if edge.target not in adj[edge.source]:
                    adj[edge.source].add(edge.target)
                    in_degree[edge.target] = in_degree.get(edge.target, 0) + 1

        queue = [n for n in self.nodes if in_degree.get(n, 0) == 0]
        result = []

        while queue:
            queue.sort(key=lambda n: -self.nodes[n].risk_score)
            node = queue.pop(0)
            result.append(node)
            for neighbor in adj.get(node, set()):
                in_degree[neighbor] -= 1
                if in_degree[neighbor] == 0:
                    queue.append(neighbor)

        # Add remaining nodes (cycles)
        for name in self.nodes:
            if name not in result:
                result.append(name)

        return result

    def to_dot(self, output_path: Path | None = None) -> str:
        """Export as DOT/Graphviz format."""
        lines = [
            "digraph DriverDependency {",
            "  rankdir=LR;",
            "  node [shape=box, style=filled];",
        ]

        # Color by risk score
        for name, node in self.nodes.items():
            score = node.risk_score
            if score >= 9.0:
                color = "red"
            elif score >= 7.0:
                color = "orange"
            elif score >= 4.0:
                color = "yellow"
            else:
                color = "lightgreen"
            label = name.replace('"', "'")
            lines.append(f'  "{label}" [fillcolor={color}, label="{label}\\nrisk={score:.1f}"];')

        # Edges with labels
        rel_colors = {
            "shared_device": "blue",
            "alpc_client": "purple",
            "pipe_client": "green",
            "shared_ioctl": "darkorange",
        }
        for edge in self.edges:
            src = edge.source.replace('"', "'")
            tgt = edge.target.replace('"', "'")
            color = rel_colors.get(edge.relationship, "black")
            label = edge.detail.replace('"', "'")[:40]
            lines.append(f'  "{src}" -> "{tgt}" [color={color}, label="{label}"];')

        lines.append("}")
        dot = "\n".join(lines)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(dot, encoding="utf-8")

        return dot

    def to_dict(self) -> dict[str, Any]:
        """Export as serializable dictionary."""
        return {
            "nodes": {
                name: {
                    "risk_score": n.risk_score,
                    "device_paths": n.device_paths[:5],
                    "alpc_ports": n.alpc_ports[:5],
                    "pipe_names": n.pipe_names[:5],
                    "ioctl_codes": [hex(c) for c in n.ioctl_codes[:10]],
                }
                for name, n in self.nodes.items()
            },
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "relationship": e.relationship,
                    "detail": e.detail,
                }
                for e in self.edges
            ],
            "topological_order": self.topological_sort(),
        }
