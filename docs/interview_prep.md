# Interview Prep — Anticipated Questions & Answers

> Quick reference for common interview questions about this project.
> Updated as the project matures.

## "What's the difference between this and LOLDrivers?"

> LOLDrivers is a retrospective hash database — it tells you "this specific driver is known vulnerable." DriverScope is predictive — it analyzes an unknown driver's code patterns, identifies exposed kernel primitives, and scores risk even if the driver has never been seen before. LOLDrivers is a blocklist; DriverScope is a behavioral analyzer.

## "Why not use CodeQL / Joern / BinDiff?"

> Those are general-purpose tools. DriverScope has Windows driver domain knowledge built in — it knows what `MmMapIoSpace` means in context, how WDM IOCTL dispatch works, which MSRs are critical, and what validation a safe driver should perform. CodeQL could theoretically do this, but you'd need to write all the domain-specific queries yourself. DriverScope ships with them pre-built.

## "How do you handle obfuscation and packing?"

> Three-layer approach:
> 1. **Pre-processing:** Detect packing signatures. A packed driver is itself a signal — flag it for manual review.
> 2. **IR normalization:** The disassembly layer works on decoded instructions, so simple obfuscation (junk code, dead branches) is partially normalized by the CFG construction.
> 3. **API-level analysis:** We track API calls, not instruction sequences. API import addresses are harder to obfuscate than control flow.
>
> Acknowledged limitation: Sophisticated packers may defeat static analysis. This is where the dynamic validation layer (planned) would kick in.

## "How do you handle WDM vs WDF drivers?"

> They have fundamentally different IOCTL dispatch mechanisms. WDM uses `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]` — a direct function pointer. WDF/KMDF uses `EvtIoDeviceControl` callbacks registered through `WdfIoQueueCreate`. The disassembly layer must identify which framework is used, then apply the correct pattern-matching rules. Currently WDM is in focus; WDF support is planned for v0.3.

## "What's your false positive rate? How did you measure it?"

> *(To be answered with real numbers after benchmarking.)* Methodology: Run the tool against a corpus of known-safe drivers (Microsoft-signed, well-reviewed open-source drivers) and known-vulnerable drivers (LOLDrivers database samples). FP rate = safe drivers incorrectly flagged / total safe drivers. TP rate = vulnerable drivers correctly flagged / total vulnerable drivers. Target: <20% FP rate, >80% TP rate.

## "Why static analysis instead of dynamic fuzzing?"

> Static analysis has higher coverage — you can analyze a driver in seconds without setting up a VM. It works on any sample, even ones you can't safely execute. The trade-off is higher false positive rates, which we mitigate through data flow analysis (checking if user input is validated before reaching dangerous APIs). Dynamic fuzzing is planned as a secondary validation layer for high-confidence candidates.

## "What's your proudest design decision?"

> *(Recommended answer:)* The abstracted disassembly backend interface. I could have hardcoded Ghidra and moved faster, but I knew that locking into one backend would limit the project's credibility. The interface means I can swap in IDA, radare2, or Binary Ninja without changing any analysis code. It also means if Ghidra's decompiler struggles with a particular driver, I can cross-reference with another backend. This design choice cost extra upfront but pays dividends in flexibility and credibility.

## "How would you scale this to analyze thousands of drivers?"

> The pipeline architecture is designed for this:
> 1. **Ingestion** is I/O-bound — can parallelize across files
> 2. **Disassembly** is CPU-bound — Ghidra headless can run in parallel across multiple cores/VMs
> 3. **Analysis** is CPU-bound — each analyzer runs independently per sample
> 4. **Scoring/Reporting** is lightweight
>
> Would add: a task queue (Celery/RQ), sample database (SQLite/PostgreSQL), and a web dashboard for result browsing. The pipeline's unidirectional flow makes this natural — each layer is a stage in a DAG.
