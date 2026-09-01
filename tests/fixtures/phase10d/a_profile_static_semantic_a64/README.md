# Owned synthetic AArch64 static-semantic fixture

This directory is owned, synthetic regression data for Phase 10D Step
8B-2B2-B. It is not a real vulnerability, affected Cortex-A77 reproduction,
CVE trigger/reproducer, exploit, benchmark Ground Truth, triggerability
demonstration, or PRIMARY case.

The executable section contains four isolated functions that do not call one
another: an ordinary `LDR`, a `STXR`, a `MRS PAR_EL1`, and a function containing
only classifier near misses. The near misses are `STR`, `LDXR`, `MSR PAR_EL1`,
`MRS FAR_EL1`, and the intentionally unsupported v1 load family `LDUR`.

The non-executable `.data` section contains separated exact byte copies of the
three positive instruction words. Static extraction must ignore them. No test
asserts path order, proximity, runtime execution, effective memory type,
hardware effect, or case satisfaction.

`generate_fixture.py` directly emits a deterministic ELF64 file from the
audited words documented in `source.S`; no compiler, network, public binary, or
cross-toolchain is required. Rebuild with:

```bash
bash build.sh
```

`SHA256SUMS` is authoritative for the committed ELF.
`expected_static_semantics.json` contains extractor regression expectations,
not benchmark Ground Truth.
