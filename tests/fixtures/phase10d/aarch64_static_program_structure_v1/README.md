# Owned AArch64 static program-structure fixture v1

This directory contains a byte-deterministic, manually encoded ELF64/AArch64
fixture for the Phase 10D C2-B structure extractor. It is owned and synthetic.
It models benign branching, leaf, and self-loop CFG shapes plus non-executable
decoy bytes.

The checked-in ELF is consumed directly by pytest; no compiler is required.
`generate_fixture.py` reconstructs the exact ELF and the design-derived expected
structure. The expected structure is based on the intentionally encoded control
flow in `source.S`, not on extractor output.

This fixture is not a real vulnerability, runtime execution evidence,
triggerability evidence, or benchmark Ground Truth. CFG recovery remains a
partial objective view under the declared CFGFast profile.
