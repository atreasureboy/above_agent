# Rules — Vulnerability Pattern Catalog

> Each rule file in this directory defines a pattern that the analysis engine
> searches for in disassembled driver code.
>
> Rules are organized by driver type and primitive category.

## Current Rules (MVP Target)

### WDM — Arbitrary Memory Mapping

| Rule ID | Pattern | API | Severity |
|---------|---------|-----|----------|
| WDM-MEM-001 | Direct physical-to-virtual mapping | `MmMapIoSpace` / `MmMapIoSpaceEx` | HIGH |
| WDM-MEM-002 | User-accessible page mapping | `MmMapLockedPagesSpecifyCache` | CRITICAL |
| WDM-MEM-003 | Arbitrary section mapping | `ZwMapViewOfSection` | HIGH |
| WDM-MEM-004 | Unvalidated pointer from IOCTL buffer | Direct dereference of user address | CRITICAL |

### WDM — MSR Access

| Rule ID | Pattern | API | Severity |
|---------|---------|-----|----------|
| WDM-MSR-001 | Model-specific register read | `__readmsr` / `Rdmsr` | MEDIUM |
| WDM-MSR-002 | Model-specific register write | `__writemsr` / `Wrmsr` | CRITICAL |
| WDM-MSR-003 | LSTAR syscall hijack | Write to `0xC0000082` | CRITICAL |

### WDM — Physical Memory

| Rule ID | Pattern | API | Severity |
|---------|---------|-----|----------|
| WDM-PHY-001 | Physical address translation | `MmGetPhysicalAddress` | MEDIUM |
| WDM-PHY-002 | Physical memory section access | `\Device\PhysicalMemory` | HIGH |

### WDM — Kernel R/W

| Rule ID | Pattern | API | Severity |
|---------|---------|-----|----------|
| WDM-KRW-001 | Cross-process virtual memory read | `MmCopyVirtualMemory` | HIGH |
| WDM-KRW-002 | Arbitrary kernel write | Direct kernel pointer write | CRITICAL |
| WDM-KRW-003 | User-mode write via ZwWriteVirtualMemory | `ZwWriteVirtualMemory` | HIGH |

### WDM — Code Execution

| Rule ID | Pattern | API | Severity |
|---------|---------|-----|----------|
| WDM-EXEC-001 | Thread creation with user address | `ZwCreateThreadEx` | CRITICAL |
| WDM-EXEC-002 | HalDispatchTable manipulation | Write to `HalDispatchTable` | CRITICAL |
| WDM-EXEC-003 | PTE modification for executable | Direct PTE write | CRITICAL |

### WDM — Process Manipulation

| Rule ID | Pattern | API | Severity |
|---------|---------|-----|----------|
| WDM-PROC-001 | Open arbitrary process | `ZwOpenProcess` | MEDIUM |
| WDM-PROC-002 | APC queue injection | `ZwQueueApcThread` | HIGH |
| WDM-PROC-003 | Token manipulation | `ZwSetInformationProcess` | CRITICAL |

## Rule File Format (Planned)

Each rule will be defined in YAML:

```yaml
rule_id: WDM-MEM-001
name: "Arbitrary Memory Mapping via MmMapIoSpace"
category: arbitrary_memory_map
severity: high
driver_types: [WDM]
description: >
  The driver calls MmMapIoSpace with an address potentially derived
  from user-controlled IOCTL input without sufficient validation.

patterns:
  - type: api_call
    api: "MmMapIoSpace"
    or: ["MmMapIoSpaceEx"]
  - type: data_flow
    source: "ioctl_buffer"
    sink: "MmMapIoSpace"
    validation_required:
      - "user_mode_address_check"
      - "size_bounds_check"

mitigations:
  - "Validate that the address is not in user space"
  - "Verify caller has appropriate privileges"
  - "Limit the size of mapped region"

references:
  - "https://www.loldrivers.io/drivers/..."
```

## Adding a New Rule

1. Create a YAML rule file in the appropriate category directory
2. Implement the corresponding pattern matcher in `src/analysis/`
3. Add test fixtures (vulnerable + safe driver samples) to `tests/fixtures/`
4. Run regression suite to verify no new false positives on safe samples
5. Update this catalog
