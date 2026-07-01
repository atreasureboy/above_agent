# Architecture Design Decisions

> Records the key architectural decisions and their rationale.
> This is the "why" behind the "what" — essential for interviews.

## ADR-001: Four-Layer Pipeline Architecture

**Decision:** Use a four-layer pipeline (Ingestion → Disassembly → Analysis → Scoring/Reporting).

**Alternatives considered:**
- Monolithic script: Rejected — impossible to swap backends or add analyzers
- Microservices: Rejected — overkill for MVP, adds deployment complexity

**Rationale:** Single-responsibility per layer enables independent testing, backend swapping, and analyzer plugin architecture. Pipeline flow is unidirectional — no circular dependencies.

**Trade-off:** More files and interfaces upfront vs. flexibility later. Worth it for a research tool that will evolve.

## ADR-002: Ghidra as Primary Backend

**Decision:** Ghidra headless mode is the default disassembly backend.

**Alternatives considered:**
- IDA Pro: Superior decompilation but commercial license required
- radare2: Free but steeper learning curve, less mature decompiler
- Binary Ninja: Good API but commercial license

**Rationale:** Free, open-source, headless mode works in CI, Python API via ghidra_bridge, active community. Interface is abstracted so IDA/Binja can be added later.

**Trade-off:** Ghidra's decompilation quality is slightly below IDA's for heavily optimized drivers. Acceptable for pattern matching.

## ADR-003: Static-First Analysis

**Decision:** Primary analysis is static. Dynamic validation is a secondary, optional layer.

**Alternatives considered:**
- Dynamic-only (IOCTL fuzzing): Rejected — too slow, needs VM infrastructure
- Hybrid from day one: Rejected — increases MVP complexity

**Rationale:** Static analysis has higher coverage, works on any sample without execution, and enables batch processing. Dynamic validation is reserved for high-confidence candidates.

**Trade-off:** Higher false positive rate initially. Mitigated by data flow analysis that checks validation completeness.

## ADR-004: Recall-Over-Precision Scoring

**Decision:** Scoring system prioritizes recall — flag more candidates, rank by risk.

**Alternatives considered:**
- Binary classification (vulnerable/safe): Rejected — misses nuances
- High-precision only: Rejected — would miss novel vulnerability patterns

**Rationale:** In vulnerability discovery, missing a true positive is worse than investigating a false positive. The Top-10 ranking ensures researchers see the most critical candidates first.

**Trade-off:** More manual triage required. The scoring system mitigates this by surfacing the most likely candidates to the top.

## ADR-005: Depth-First Driver Coverage

**Decision:** Start with WDM drivers exposing arbitrary memory primitives. Expand breadth later.

**Alternatives considered:**
- Cover all driver types shallowly: Rejected — demonstrates no depth
- Random driver type: Rejected — arbitrary memory is most common BYOVD primitive

**Rationale:** Arbitrary memory mapping is the most common vulnerability in exploitable drivers (LOLDrivers database confirms this). Deep coverage of one type demonstrates research capability better than shallow coverage of many.

**Trade-off:** Cannot scan WDF/KMDF drivers initially. Planned for v0.3+.

## ADR-006: Open Framework, Proprietary Rules

**Decision:** The analysis framework is open-source (MIT). Vulnerability pattern rulesets may be maintained as proprietary assets.

**Alternatives considered:**
- Fully open-source: Rejected — loses competitive advantage for research
- Fully closed-source: Rejected — loses credibility for interviews

**Rationale:** Open framework demonstrates engineering capability. Proprietary rules represent ongoing research investment. This mirrors commercial tool business models (e.g., Semgrep core is open, Pro rules are paid).

**Trade-off:** Slightly more complex licensing. Clear separation between `src/` (open) and `rules/` (mixed) is needed.

## ADR-007: Python as Implementation Language

**Decision:** Python 3.10+ for all layers.

**Alternatives considered:**
- Rust: Faster but longer development time, steeper learning curve
- C++: Traditional for security tools but slower development
- Go: Good concurrency but weaker ecosystem for binary analysis

**Rationale:** Python has the richest binary analysis ecosystem (pefile, angr, capstone, unicorn). Fast prototyping is critical for a research tool. Performance bottlenecks (disassembly) are delegated to external tools (Ghidra).

**Trade-off:** Slower execution for large batch scans. Acceptable — disassembly is the bottleneck, not Python overhead.
