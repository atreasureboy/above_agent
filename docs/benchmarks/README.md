# Benchmarks

> Benchmark results comparing DriverScope detection rates against known driver corpora.

## Methodology

- **Corpus:** `samples/vulnerable/` (known vulnerable) + `samples/safe/` (known safe)
- **Metrics:** True Positive Rate, False Positive Rate, Top-10 Precision
- **Baseline:** LOLDrivers hash database

## Results

*(To be populated as rules are implemented)*

| Rule Set | TP Rate | FP Rate | Top-10 Precision | Date |
|----------|---------|---------|------------------|------|
| *(empty)* | — | — | — | — |

## Tracking Progress

Run `scripts/benchmark.sh` after each rule update to track:
- New detections vs. previous run
- False positive changes
- Performance (time per sample)
