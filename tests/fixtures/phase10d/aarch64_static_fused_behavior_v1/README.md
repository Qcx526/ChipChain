# Owned AArch64 static fused-behavior fixture

This directory contains one deterministic, manually encoded ELF64 AArch64
fixture for Phase 10D Step 8B-2D2-C2-C.

The benign synthetic function contains four intended function-local basic
blocks, four audited semantic instruction families and a diamond-shaped static
CFG. `generate_fixture.py` constructs the ELF without a compiler. Pytest reads
the committed ELF and never regenerates it implicitly.

`expected_fixture_design.json` records only independently auditable fixture
design constants. It is not serialized fusion output or Benchmark Ground
Truth. Actual semantic, structure and fused IDs are derived by production code.

To explicitly regenerate the committed fixture:

```bash
.venv/bin/python tests/fixtures/phase10d/aarch64_static_fused_behavior_v1/generate_fixture.py
```

This fixture is not a hardware vulnerability, triggerability demonstration,
runtime observation, exploit or verified attack chain.
