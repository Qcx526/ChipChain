# QEMU MMIO Classification Contract

This note records the Phase 9B1 R2 production rule:

```text
Physical access observed by the TCG plugin
+ resolved machine topology captured from the same QEMU process
= topology-grounded MMIO observation
```

`qemu_plugin_hwaddr_is_io()` and the plugin device name are diagnostic
provenance only. They neither veto nor create MMIO. No ARM peripheral address,
fixture address, opcode heuristic, PL011 string, or device trace is used by the
classifier.

The topology source is QEMU 11.0.3 `info mtree -f` obtained through ID-matched
QMP before `cont`. The parser selects exactly one FlatView containing AS
`memory`, stores exact source SHA-256, and derives a path-neutral semantic map
ID from the selected root and resolved regions.

Only a full access range inside one unique `i/o` leaf is promoted. RAM and RAM
device ranges are omitted from RuntimeTrace but remain auditable in raw v2.
Unmapped, boundary-crossing, overflowing, ambiguous, or malformed inputs fail
closed. Runtime `is_io=true` therefore means topology-classified I/O, not
plugin boolean true.

The version-pinned PL011 trace is an independent owned-fixture oracle only. It
confirms actual dispatch in the reference run but does not affect production
classification, topology identity, RuntimeObservation identity, or Evidence.
