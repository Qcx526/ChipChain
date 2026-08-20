# Owned QEMU topology fixture

This is an owned, sanitized, reconstructed QEMU 11.0.3 FlatView contract
fixture for `virt`, `cortex-a15`, and `smp=1`. Its text shape follows the QEMU
11.0.3 `memory.c` FlatView printer contract. Its PL011 and RAM facts come from
the validated reference topology/configuration. It is **not yet a retained real
`info mtree -f` capture**, an ARM address rule, a benchmark, or a claim about
other QEMU versions or machines.

The retained resolved FlatView ranges cover the owned fixture code RAM and the
PL011 I/O leaf used by the reference fixture. Production classification always
parses the same-process QMP/HMP artifact and never imports addresses from this
file.

A retained real sanitized FlatView may replace or supplement this contract
fixture only after Ubuntu QEMU 11.0.3 same-process QMP acceptance actually
generates it; its SHA-256 and provenance must then be updated from those bytes.
