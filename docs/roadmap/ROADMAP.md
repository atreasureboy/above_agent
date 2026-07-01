# Roadmap

> Phased development plan for DriverScope.
> Each version builds on the previous — no parallel tracks.

## MVP — Single Driver Scanner

**Goal:** Input a single `.sys` file, output a basic analysis report.

### Tasks
- [x] Project skeleton created
- [ ] Implement Ghidra headless backend integration (or use `angr`/`capstone` as lighter alternative)
- [ ] Implement WDM IOCTL dispatcher detection
- [ ] Implement 5-10 basic dangerous API pattern rules for WDM arbitrary memory mapping
- [ ] CLI outputs finding list with severity
- [ ] Basic smoke tests pass

**Exit Criteria:** `python -m driverscope scan known_vulnerable.sys` outputs at least 3 correct findings.

---

## v0.2 — Batch Scanning + JSON Report + Scoring

**Goal:** Scan a directory of drivers, output scored JSON reports.

### Tasks
- [ ] Directory scanning support
- [ ] Scoring engine with configurable weights
- [ ] JSON report output with finding details
- [ ] Deduplication by SHA256
- [ ] Batch regression tests (safe vs vulnerable corpus)
- [ ] Basic benchmark tracking

**Exit Criteria:** Can scan 50+ drivers, output JSON, and demonstrate >70% TP rate on known samples.

---

## v0.3 — Pluggable Rules + Dual Backend

**Goal:** YAML-based rule definitions, Ghidra + IDA backend support.

### Tasks
- [ ] YAML rule file format + parser
- [ ] Rule engine that reads YAML and generates analyzers
- [ ] IDA Pro backend implementation
- [ ] Backend selection via CLI flag
- [ ] Data flow analysis (user input → dangerous sink validation check)
- [ ] HTML report generation

**Exit Criteria:** New rules can be added by writing YAML only, no code changes.

---

## v0.5 — Web Dashboard + Sample Management

**Goal:** Web interface for browsing results, managing samples, and monitoring.

### Tasks
- [ ] SQLite/PostgreSQL result database
- [ ] Web dashboard (FastAPI + HTMX or Flask)
- [ ] Sample upload and management
- [ ] Result filtering and search
- [ ] Trend visualization
- [ ] SARIF output for CodeQL integration

**Exit Criteria:** Can upload a driver via web UI and view analysis results in browser.

---

## v1.0 — Dynamic Validation + Continuous Monitoring

**Goal:** Optional dynamic validation layer, automated driver monitoring.

### Tasks
- [ ] IOCTL fuzzer integration (kAFL / custom)
- [ ] VM management for dynamic analysis
- [ ] Automated driver harvesting (cron-based)
- [ ] Alert system for new high-risk findings
- [ ] ARM64 architecture support
- [ ] WDF/KMDF full support

**Exit Criteria:** Can automatically discover, analyze, and validate new driver vulnerabilities with minimal human intervention.

---

## Future / Stretch Goals

- Machine learning-assisted rule discovery
- Integration with Windows Driver Kit (WDK) symbol server
- Comparison mode: diff two driver versions for regression analysis
- Plugin marketplace for community-contributed rules
