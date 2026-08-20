# QEMU Runtime Plan

Phase 9B0's backend-neutral runtime contract is sealed. Phase 9B1 R2 replaces
the pre-stable plugin-boolean MMIO rule with topology-grounded classification
without changing RuntimeEventKind, RuntimeObservation, persistence, scoring,
RelationType, or Phase 9A-R verification.

## Implemented R2 path

```text
Owned ARM32 ELF
  → qemu-system-arm / virt / cortex-a15 / TCG / 1 vCPU
  → same process paused with -S and QMP
  ├─ info mtree -f → exact topology artifact + SHA-256
  └─ cont → passive TCG plugin raw v2
       ├─ instruction_exec
       └─ memory_read / memory_write + physical address
  → unique resolved FlatView classifier
  → Phase 9B0 instruction/MMIO RuntimeTrace
  → detached revalidation
  → interaction-agnostic Dynamic Evidence
```

Capabilities remain instruction execution, memory access, physical address,
and I/O classification. Their sources are respectively the TCG callbacks,
memory callbacks, hardware-address API, and captured machine topology. No
memory value, register, discontinuity, DMA, or active capability is claimed.

## Completion gates

The offline gate covers raw v2, QMP IDs/order, exact topology SHA, semantic map
ID, unique I/O/RAM/boundary/overflow/ambiguous handling, sequence gaps, ELF
header cleanup, RuntimeTrace revalidation, Dynamic Evidence, and security
boundaries. Firmware input provenance is checked against exact bytes before any
QEMU process executes and checked again after a successful run before a
RuntimeTrace can be constructed.

The real gate must independently establish all of the following in QEMU 11.0.3:

1. matching plugin loads and reports API 2..6/build 6;
2. the six expected owned-fixture instruction PCs execute;
3. target PC `0x40200008` emits raw `memory_write`, paddr `0x09000000`, width 1,
   including the observed `plugin_is_io=false`/`RAM` diagnostics;
4. the same-process FlatView uniquely maps the target to I/O leaf `pl011`;
5. RuntimeTrace promotes it to `MMIO_WRITE`, `is_io=true`, with map provenance;
6. trace revalidation and Dynamic Evidence succeed;
7. independent `pl011_write` confirms offset 0, value `0x41`, register `DR`;
8. QEMU exits cleanly and the opt-in real integration test passes without skip.

This development host cannot execute that gate because the matching external
components are unavailable. Reference evidence motivated and validates the
design, but no local rerun is fabricated.

The repository's current topology text is a reconstructed FlatView contract
fixture, not a retained real `info mtree -f` capture. Ubuntu QEMU 11.0.3
same-process acceptance must generate the complete real output before its exact
bytes, SHA-256, and real-capture provenance can be committed as such.

## Next stage

Phase 9B2 may begin only after a real R2 smoke PASS and human audit. Its scope
would be explicit Dynamic Evidence binding, fact verification, and
Static/Dynamic aggregation/conflict policy. A single MMIO observation or event
order still cannot establish Type III propagation or causality.
