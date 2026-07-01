# DriverScope

> **Predictive Windows Driver Vulnerability Scanner v0.1.1**
> 517 tests · 11-phase analysis pipeline · Zero false-negative BYOVD detection

## Value Stream

```
[未知 .sys 集合] ──► [DriverScope] ──► [按风险排序的漏洞清单]
                         │
                  区别于:
                  • LOLDrivers = 哈希查表（已知漏洞）
                  • CodeQL   = 源码分析（需编译链）
                  • IDA 脚本 = 单次手工
                  • DriverScope = 二进制 + 预测性 + 批量 + 领域专用
```

## What Is DriverScope?

DriverScope ingests unknown Windows kernel driver (`.sys`) files, performs
multi-phase static reverse engineering analysis, identifies exposed kernel
primitives and exploitable attack chains, and produces a **risk-scored
vulnerability report**.

Unlike LOLDrivers (hash lookup of *known* vulnerabilities), DriverScope
**predictively** scans binary code for *dangerous patterns* — even in
previously unseen drivers.

## Architecture

### 11-Phase Analysis Pipeline

```
Phase 0 ──► Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 4
 Ingestion   PE Parse    Strings    Light Disasm   Filter Funnel

Phase 5 ──► Phase 6 ──► Phase 7 ──► Phase 8 ──► Phase 9 ──► Phase 10 ──► Phase 11
 Ghidra      Capstone    Data Flow   Semantic       Structure     Coverage      Anti-Obfuscation
 Backend     Backend     + Taint     Analysis       + Primitives  Fixes         + Anti-Debug
                                      ├─ Input Validation                       ├─ CFG Flattening
                                      ├─ Constraint Solver (Z3)                 ├─ Dead Code/Junk
                                      ├─ Indirect Call Resolution               ├─ PE Packer Detection
                                      ├─ Struct Field Taint Tracking            ├─ API Hashing
                                      └─ OVOIDA Deep Analysis                   └─ Anti-Debug (RDTSC/CPUID/INT3)
```

### Layer Details

| Phase | Component | What It Does |
|-------|-----------|-------------|
| 0-4 | Ingestion + Funnel | PE parsing, signature check, threat intel, progressive filtering |
| 5 | Ghidra Backend | Full decompilation, parameter recovery, CFG from pseudocode |
| 6 | Capstone Backend | Quick disassembly, pattern matching, API import resolution |
| 7 | Data Flow | User input taint tracking through IOCTL buffers to dangerous APIs |
| 8 | Semantic | Privileged instruction detection (wrmsr, mov drX, lgdt, etc.) |
| 9 | Structure + Primitive | IOCTL dispatchers, dangerous APIs, attack chain correlation |
| 10 | Coverage Fixes | Z3 branch constraints, API unification, Unicode extraction, WDF fixes |
| 11 | Anti-Obfuscation | Anti-debug (RDTSC/CPUID/INT3), CFG flattening, junk code, PE packers, API hashing |

### Analysis Capabilities

- **IOCTL Surface Mapping** — Extract all IOCTL codes, handlers, and transfer methods (METHOD_BUFFERED/NEITHER)
- **Dangerous Primitive Detection** — 50+ kernel APIs across 12 categories (memory mapping, MSR access, DMA, callback registration, etc.)
- **Taint Flow Analysis** — Track user-controlled input from SystemBuffer through to dangerous API sinks
- **Z3 Constraint Solving** — Path feasibility via BitVec constraints for cmp/test/jcc instructions
- **Privileged Instruction Detection** — `wrmsr`, `mov dr0-dr7`, `lgdt`, `lidt`, `ltr`, `lmsw`, `clts`, `invlpg`
- **Anti-Debug Detection** — `rdtsc` timing check, `cpuid` hypervisor detection, `int 3`/`icebp` traps, `sidt`/`sgdt`/`str` Red Pill, SEH setup
- **Anti-Obfuscation Analysis** — Control flow flattening, dead code/junk injection, PE packer signatures (UPX/VMProtect/Themida), API hashing
- **OVOIDA Deep Analysis** — Ghidra-backed exploit chain extraction with pseudocode generation
- **Attack Chain Correlation** — Link primitives + validation gaps into complete BYOVD chains
- **WDF Support** — WDF driver dispatch identification and analysis

## Quick Start

```bash
# Analyze a single driver
python -m src scan path/to/driver.sys

# Scan local system drivers (C:\Windows\System32\drivers)
python -m src scan --local

# Batch scan with limit, output as SARIF
python -m src scan path/to/drivers/ -n 5 -o report.sarif --format sarif

# Batch scan with JSON report
python -m src scan path/to/drivers/ --output report.json

# List registered analyzers
python -m src list-analyzers
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `--local` | Scan `C:\Windows\System32\drivers` |
| `-n, --limit N` | Max drivers to analyze (0 = unlimited) |
| `--min-score N` | Only report findings with risk >= N |
| `--timeout N` | Timeout per driver in seconds (0 = unlimited) |
| `-o, --output` | Output report path |
| `--format json\|sarif\|html\|pdf` | Report format (default: json) |

## Threat Intel

DriverScope auto-fetches the [LOLDrivers](https://www.loldrivers.io/)
vulnerable driver database on first run and caches it locally in
`~/.driverscope/intel/loldrivers.db` (TTL: 24 hours).

Matching uses 3-level priority:
1. **SHA256 exact match** → confidence 1.0
2. **Filename + Company match** → confidence 0.7
3. **Filename-only match** → confidence 0.5

## Output Formats

- **JSON** — Default, human-readable with full findings and evidence
- **SARIF** — OASIS v2.1.0 standard, importable into GitHub Security,
  Azure DevOps, VS Code, and other DevSecOps tools
- **HTML** — Self-contained report with attack chain visualization,
  severity-colored findings, expandable details, print-to-PDF support

## Real-World Validation

Tested against **360AntiHacker64.sys** (360 Security anti-cheat driver):

| Metric | Result |
|--------|--------|
| Functions analyzed | 649 |
| IOCTL codes found | 4 |
| Dangerous APIs detected | 28 |
| Total findings | 435 |
| Critical findings | 11 |
| Risk score | **10.0/10 (CRITICAL)** |
| Time | 2.0s (Capstone) |

Key findings: 5 functions calling `MmMapLockedPagesSpecifyCache` without
validation, complete BYOVD attack chains with confirmed taint flow
(`UserBuffer → MmMapLockedPagesSpecifyCache`), and `ObReferenceObjectByHandle`
exposure — all matching known public disclosures.

## Roadmap

| Version | Milestone | Status |
|---------|-----------|--------|
| **v0.0.1** | Single driver, 5-10 rules, CLI output | Done |
| **v0.0.2** | Filter chain + threat intel + SARIF + evidence | Done |
| **v0.0.3** | Data flow + IOCTL precision + input validation | Done |
| **v0.1.0** | Ghidra + Z3 + OVOIDA + full coverage (482 tests) | **Done** |
| **v0.3** | Pluggable rules + IDA Pro backend | Planned |
| **v0.5** | Web Dashboard + sample management | Planned |
| **v1.0** | Dynamic validation + continuous monitoring | Planned |

**Current focus:** WDM drivers exposing arbitrary memory primitives.

## Why This Matters

- **For interviews:** Demonstrates deep Windows kernel understanding + engineering rigor
- **For research:** Novel predictive approach to driver vulnerability assessment
- **For 0-day hunting:** Focused scanning on high-value primitive exposure patterns

## License

MIT — Framework is open source. Vulnerability pattern rulesets may be maintained as proprietary assets.
