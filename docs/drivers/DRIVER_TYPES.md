# DriverScope — Driver Type Coverage Matrix

> This document tracks all Windows driver types the project aims to support.
> Each entry serves as a placeholder for future implementation work.
> **Current focus: WDM drivers exposing arbitrary memory primitives (depth-first).**

---

## P0 — In Focus / Highest Priority

### WDM — Arbitrary Memory Mapping (In Focus)

- **Architecture:** WDM (Windows Driver Model)
- **IOCTL Dispatch:** `IRP_MJ_DEVICE_CONTROL` via `DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL]`
- **Key Patterns:**
  - `MmMapIoSpace` / `MmMapIoSpaceEx` — maps physical memory to kernel space
  - `MmMapLockedPagesSpecifyCache` — user-mode accessible mapped pages
  - `ZwMapViewOfSection` — arbitrary section mapping
  - Direct pointer manipulation from user-supplied addresses
- **Why First:** Most common BYOVD primitive. Many vulnerable drivers expose direct memory mapping with insufficient validation. Deep coverage here demonstrates research capability.
- **Validation Requirements:** Check if input address is validated (user vs kernel space), size bounds checking, caller privilege verification.
- **Known Examples:** (to be populated with test samples)

### WDM — Arbitrary Code Execution

- **Architecture:** WDM
- **IOCTL Dispatch:** `IRP_MJ_DEVICE_CONTROL`
- **Key Patterns:**
  - Writing to executable memory regions
  - `ZwCreateThreadEx` with user-supplied start address
  - Modifying page table entries (PTE) to make memory executable
  - `HalDispatchTable` exploitation primitives
- **Why P0:** Highest impact primitive. Direct code execution = system compromise.
- **Validation Requirements:** None can truly mitigate this — any exposure is critical.
- **Status:** Planned after arbitrary memory coverage is solid.

---

## P1 — High Priority (After P0 Coverage)

### WDM — MSR Access

- **Architecture:** WDM
- **IOCTL Dispatch:** `IRP_MJ_DEVICE_CONTROL`
- **Key Patterns:**
  - `__readmsr` / `__writemsr` intrinsics
  - `Rdmsr` / `Wrmsr` wrapper calls
  - Direct MSR access via model-specific registers
- **Critical MSRs:**
  - `IA32_LSTAR (0xC0000082)` — syscall handler (direct kernel code exec)
  - `IA32_EFER (0xC0000080)` — enable/disable syscall
  - `IA32_SYSENTER_EIP (0x176)` — sysenter handler
  - `IA32_KERNEL_GS_BASE (0xC0000102)` — KPCR access
- **Validation Requirements:** MSR index whitelist, caller privilege (ring 0 only).
- **Status:** Planned

### WDM — Physical Memory Access

- **Architecture:** WDM
- **IOCTL Dispatch:** `IRP_MJ_DEVICE_CONTROL`
- **Key Patterns:**
  - `MmGetPhysicalAddress` / `MmGetPhysicalMemoryRanges`
  - `\Device\PhysicalMemory` section access
  - `HalTranslateBusAddress`
  - Direct PCI/PCIe configuration space access
- **Validation Requirements:** Physical address range validation, DMA protection checks.
- **Status:** Planned

### WDM — Kernel Arbitrary Read/Write

- **Architecture:** WDM
- **IOCTL Dispatch:** `IRP_MJ_DEVICE_CONTROL`
- **Key Patterns:**
  - `ZwReadVirtualMemory` / `ZwWriteVirtualMemory` to arbitrary processes
  - Direct kernel memory dereference from user input
  - `MmCopyVirtualMemory` without validation
  - Pool allocation with user-controlled size (overflow potential)
- **Validation Requirements:** Address space validation, size limits, process handle validation.
- **Status:** Planned

### WDF — KMDF (Kernel-Mode Driver Framework)

- **Architecture:** WDF/KMDF v1.x
- **IOCTL Dispatch:** `EvtIoDeviceControl` callback
- **Key Differences from WDM:**
  - Uses `WDFIOQUEUE` and `WDFREQUEST` objects instead of raw IRPs
  - IOCTL handling through framework callbacks, not direct MajorFunction table
  - Request completion via `WdfRequestComplete` instead of `IoCompleteRequest`
  - Memory management through WDF memory objects
- **Analysis Challenges:**
  - Must identify WDF initialization patterns (`WdfDriverCreate`, `WdfIoQueueCreate`)
  - Callback registration differs from WDM MajorFunction assignment
  - IRP details abstracted behind WDFREQUEST handles
- **Status:** Planned after WDM patterns are mature

---

## P2 — Medium Priority

### WDM — Process/Thread Manipulation

- **Architecture:** WDM
- **IOCTL Dispatch:** `IRP_MJ_DEVICE_CONTROL`
- **Key Patterns:**
  - `ZwOpenProcess` / `ZwOpenThread` with user-supplied PID/TID
  - `ZwSuspendProcess` / `ZwResumeProcess`
  - `ZwTerminateProcess` to arbitrary processes
  - APC injection primitives (`ZwQueueApcThread`)
  - Token manipulation (`ZwSetInformationProcess` for token swap)
- **Validation Requirements:** PID/TID validation, privilege checks, cross-process access policies.
- **Status:** Planned

### WDF — UMDF (User-Mode Driver Framework)

- **Architecture:** WDF/UMDF v2.x
- **IOCTL Dispatch:** `EvtIoDeviceControl` callback (user-mode)
- **Key Differences:**
  - Runs in user-mode (UMDF host process)
  - Lower privilege impact but still a security boundary crossing point
  - Access to kernel via framework marshaling
- **Analysis Challenges:**
  - Different binary structure (DLL rather than .sys in some cases)
  - Framework marshaling adds indirection
- **Status:** Planned

### Legacy NT Drivers

- **Architecture:** Pre-WDM NT drivers
- **IOCTL Dispatch:** Direct `IRP_MJ_*` handling, often minimal structure
- **Key Characteristics:**
  - No PnP manager integration
  - Often lack proper cleanup routines
  - May use deprecated APIs with known issues
- **Status:** Planned

---

## P3 — Lower Priority / Specialized

### WDM — Filter Drivers

- **Architecture:** WDM (filter stack)
- **Key Characteristics:**
  - Pass-through behavior — forwards IRPs up/down the stack
  - May intercept and modify IOCTLs in transit
  - Often sits between class driver and port driver
- **Analysis Challenges:**
  - Must track data flow through filter chain
  - IOCTLs may be transformed, not just passed through
- **Status:** Planned

### ACPI Drivers

- **Architecture:** WDM (ACPI-specific)
- **IOCTL Dispatch:** ACPI-specific IOCTLs (`IOCTL_ACPI_*`)
- **Key Characteristics:**
  - Interface to ACPI BIOS tables and methods
  - `ACPI_EVAL_METHOD` structures
- **Status:** Planned

### NDIS Drivers

- **Architecture:** NDIS (Network Driver Interface Specification)
- **IOCTL Dispatch:** NDIS-specific OIDs and IOCTLs
- **Key Characteristics:**
  - Network packet processing
  - OID request handling
  - Miniport vs protocol driver distinction
- **Status:** Planned

### File System Drivers

- **Architecture:** WDM (file system)
- **IOCTL Dispatch:** `IRP_MJ_FILE_SYSTEM_CONTROL` and related
- **Key Characteristics:**
  - FSCTL handling
  - Volume mount/unmount operations
  - Filter manager integration
- **Status:** Planned

### Graphics / Display Drivers

- **Architecture:** WDDM (Windows Display Driver Model)
- **IOCTL Dispatch:** DXGKRNL-mediated calls
- **Key Characteristics:**
  - GPU memory management
  - DMA buffer handling
  - Command submission primitives
- **Status:** Planned (complex, GPU-specific knowledge required)

---

## Implementation Priority Guide

When implementing support for a new driver type:

1. **Identify the dispatch mechanism** — How does this driver type receive and route IOCTLs?
2. **Catalog dangerous primitives** — What APIs, if exposed without validation, create vulnerabilities?
3. **Define validation requirements** — What checks would a "safe" driver perform?
4. **Create analysis rules** — Write pattern-matching rules for the analysis engine
5. **Collect test samples** — Both vulnerable and safe examples
6. **Benchmark** — Measure detection rate and false positive rate against known samples
