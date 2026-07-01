"""Shared CFG utilities used across analyzers."""

from __future__ import annotations

from src.models import DisassemblyResult


def cfg_reachable_funcs(handler_addrs: set[int], ir: DisassemblyResult) -> set[int]:
    """BFS from handler(s) through call graph to find all reachable functions."""
    reachable: set[int] = set()
    queue = list(handler_addrs)
    visited: set[int] = set()

    while queue:
        func_addr = queue.pop(0)
        if func_addr in visited:
            continue
        visited.add(func_addr)
        reachable.add(func_addr)

        func = ir.functions.get(func_addr)
        if func:
            for callee in func.calls:
                if callee not in visited:
                    queue.append(callee)

    return reachable
