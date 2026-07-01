# Contributing to DriverScope

> Three-tier documentation structure:
> 1. **User docs** — How to use the tool (see README.md)
> 2. **Researcher docs** — How to write rules (see rules/README.md)
> 3. **Contributor docs** — How to extend the architecture (this file)

## Architecture Overview

DriverScope follows a four-layer unidirectional pipeline:

```
Sample (raw .sys)
    │
    ▼
┌─────────────────┐  Sample (enriched metadata)
│  Ingestion      │──────────────────────────────┐
│  (pe_parser.py) │                              │
└─────────────────┘                              ▼
                            ┌──────────────────────┐  Sample + DisassemblyResult
                            │  Disassembly & IR    │─────────────────────────────┐
                            │  (backend.py)        │                             │
                            └──────────────────────┘                             ▼
                                                    ┌───────────────────┐  Sample + Findings
                                                    │  Analysis Core    │──────────────────────┐
                                                    │  (analyzer.py)    │                       │
                                                    └───────────────────┘                       ▼
                                                                            ┌──────────────────┐  Report
                                                                            │  Scoring & Report│──────────▶ Output
                                                                            │  (engine.py)     │
                                                                            └──────────────────┘
```

## Key Files

| File | Purpose |
|------|---------|
| `src/models.py` | Core data types — Sample, Finding, Report, RiskScore |
| `src/ingestion/pe_parser.py` | PE parsing, driver detection, metadata extraction |
| `src/disassembly/backend.py` | Abstract interface for disassembly backends |
| `src/analysis/analyzer.py` | Abstract base class for all analyzers |
| `src/scoring/engine.py` | Risk scoring with configurable weights |
| `src/cli.py` | CLI entry point with argparse |

## Adding a New Analyzer

1. Create a new file in `src/analysis/core/` (e.g., `msr_analyzer.py`)
2. Subclass `Analyzer` from `src/analysis/analyzer.py`
3. Implement `name`, `description`, and `analyze()` methods
4. Register the analyzer in `src/analysis/core/__init__.py`
5. Add test cases in `tests/analysis/`

## Adding a New Disassembly Backend

1. Create a new file in `src/disassembly/` (e.g., `ida_backend.py`)
2. Subclass `DisassemblyBackend` from `src/disassembly/backend.py`
3. Implement all abstract methods
4. Ensure `is_available()` checks for the backend's dependencies
5. Add to the backend registry

## Adding a New Rule

See `rules/README.md` for the rule file format and process.

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run smoke tests
pytest tests/test_smoke.py -v

# Run all tests with coverage
pytest --cov=src tests/
```

## Code Style

```bash
# Lint with ruff
ruff check src/ tests/

# Format
ruff format src/ tests/
```
