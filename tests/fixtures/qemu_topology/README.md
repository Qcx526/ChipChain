# Owned QEMU topology fixture

This is an owned, sanitized fixture derived from the relevant lines of a real
QEMU 11.0.3 `info mtree -f` capture for `virt`, `cortex-a15`, and `smp=1`.
It is test evidence for this version-pinned configuration, not an ARM address
rule, a benchmark, or a claim about other QEMU versions or machines.

The retained resolved FlatView ranges cover the owned fixture code RAM and the
PL011 I/O leaf used by the reference fixture. Production classification always
parses the same-process QMP/HMP artifact and never imports addresses from this
file.
