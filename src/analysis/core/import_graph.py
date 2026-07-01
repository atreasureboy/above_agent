"""
DriverScope — Import/Export dependency graph.

Builds a directed graph of DLL imports/exports across multiple PE files.
Used by UserModeAnalyzer and MultiDriverCorrelator to identify
inter-module dependencies and potential attack surfaces.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ModuleNode:
    """A node in the import/export graph (one PE file)."""
    path: Path
    name: str
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    is_driver: bool = False
    is_usermode: bool = False


@dataclass
class DependencyEdge:
    """A directed edge: source imports from target."""
    source: str       # Module name
    target: str       # DLL/module name
    shared_apis: list[str] = field(default_factory=list)


class ImportGraph:
    """Build and query import/export dependency graphs."""

    def __init__(self):
        self.nodes: dict[str, ModuleNode] = {}
        self.edges: list[DependencyEdge] = []

    def add_module(self, node: ModuleNode) -> None:
        self.nodes[node.name] = node

    def build_edges(self) -> list[DependencyEdge]:
        """Build edges where module A imports a DLL that module B exports."""
        self.edges.clear()

        all_exports: dict[str, list[str]] = {}
        for name, node in self.nodes.items():
            exports_lower = {e.lower(): e for e in node.exports}
            all_exports[name.lower()] = exports_lower

        for node in self.nodes.values():
            imports_lower = [imp.lower() for imp in node.imports]
            for target_name, exports_map in all_exports.items():
                shared = []
                for imp_lower in imports_lower:
                    if imp_lower in exports_map:
                        shared.append(exports_map[imp_lower])
                if shared:
                    self.edges.append(DependencyEdge(
                        source=node.name,
                        target=target_name,
                        shared_apis=shared,
                    ))
        return self.edges

    def get_dependencies(self, module_name: str) -> list[str]:
        """Get all modules that `module_name` depends on."""
        return [e.target for e in self.edges if e.source == module_name]

    def get_dependents(self, module_name: str) -> list[str]:
        """Get all modules that depend on `module_name`."""
        return [e.source for e in self.edges if e.target == module_name]

    def find_bridge_modules(self) -> list[str]:
        """Find modules that import AND export APIs used by others.

        Bridge modules are potential attack surface multipliers: they
        consume capabilities from one module and expose them to others.
        """
        bridge = []
        importers = {e.source for e in self.edges}
        exporters = {e.target for e in self.edges}
        for name in importers & exporters:
            bridge.append(name)
        return bridge

    def to_dot(self) -> str:
        """Export the graph as DOT/Graphviz format."""
        lines = ["digraph ImportGraph {", "  rankdir=LR;", "  node [shape=box];"]
        for node_name in self.nodes:
            label = node_name.replace('"', "'")
            is_driver = self.nodes[node_name].is_driver
            shape = "cylinder" if is_driver else "box"
            lines.append(f'  "{label}" [shape={shape}];')
        for edge in self.edges:
            src = edge.source.replace('"', "'")
            tgt = edge.target.replace('"', "'")
            label = ", ".join(edge.shared_apis[:3])
            if len(edge.shared_apis) > 3:
                label += f" (+{len(edge.shared_apis) - 3})"
            label = label.replace('"', "'")
            lines.append(f'  "{src}" -> "{tgt}" [label="{label}"];')
        lines.append("}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Export as a serializable dictionary."""
        return {
            "nodes": {
                name: {
                    "path": str(n.path),
                    "name": n.name,
                    "imports": n.imports,
                    "exports": n.exports,
                    "is_driver": n.is_driver,
                    "is_usermode": n.is_usermode,
                }
                for name, n in self.nodes.items()
            },
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "shared_apis": e.shared_apis,
                }
                for e in self.edges
            ],
            "bridge_modules": self.find_bridge_modules(),
        }
