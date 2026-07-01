# AgentOS — DriverScope Project Context

## Project Overview
**DriverScope** is a domain-specific predictive Windows driver vulnerability scanner.
- **Goal:** Input unknown `.sys` files, output risk-scored vulnerability reports identifying exposed kernel primitives.
- **Use Cases:** Interview project, research paper, 0-day discovery.
- **Current Focus:** WDM drivers exposing arbitrary memory primitives (depth-first approach).

## Architecture (4-Layer Pipeline)

### Layer 1: Ingestion (`src/ingestion/`)
- PE parsing, signature verification, metadata extraction
- Output: standardized `Sample` objects
- Future: VT API integration, archive.org crawler, ARM64 support

### Layer 2: Disassembly & IR (`src/disassembly/`)
- Abstract interface for disassembly backends
- Primary: Ghidra (free, headless mode, Python API)
- Planned: IDA Pro, radare2, Binary Ninja
- Output: function list, CFG, call graph, pseudo-code/IR

### Layer 3: Analysis Core (`src/analysis/`)
- **Structure Analyzer:** Entry points, IOCTL dispatchers, IRP handler call graphs
- **Dangerous Primitive Analyzer:** Suspicious API calls on IOCTL-reachable paths
- **Data Flow Analyzer:** User input → dangerous sink validation completeness
- Each analyzer is an independent plugin with unified interface

### Layer 4: Scoring & Reporting (`src/scoring/`, `src/report/`)
- Aggregate analyzer outputs into scored reports
- Risk algorithm: primitives × count × validation completeness × signature status
- Output: JSON (SIEM), HTML (researcher), SARIF (CodeQL ecosystem)

## Key Design Decisions

1. **Static-first, dynamic-reserved:** Main analysis is static, with预留 dynamic validation interface
2. **Recall over precision:** Better to flag 50 candidates with 10 true positives than miss vulnerabilities
3. **CLI-first, pipeline-ready:** Start as CLI, architect for distributed scheduling
4. **Open framework, proprietary rules:** Open-source the engine, keep heuristic rulesets as proprietary assets

## Tech Stack
- Python 3.10+
- Ghidra (headless) as primary disassembly backend
- pefile for PE parsing
- Optional: angr/binaryninja for advanced analysis

## Current Status
- Project initialized, skeleton created
- MVP not yet started
