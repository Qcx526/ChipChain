# Owned synthetic B2-A state source

This is an owned, synthetic fixture, not a real vulnerability, benchmark, QEMU
trace, silicon observation, or runtime measurement. All normalized values are
explicitly authored synthetic source claims; no instruction-based inference occurs.

Artifact identity/hash and instruction addresses come from the frozen
`aarch64_static_fused_behavior_v1/expected_fixture_design.json` and `source.S`:
`0x400000` is a system-register read, `0x400008` a memory barrier, and `0x400010`
a TLB operation. The frozen diamond has **no load/store instruction**. The two
memory records associate synthetic addressed-location state with these existing
instruction addresses; they do not claim those instructions accessed these
locations, executed, or satisfied a candidate obligation. Context IDs are authored,
not inferred from `PAR_EL1`. Access addresses do not imply a VA-to-PA translation.
This fixture is a B2-A typed-source contract demonstration only. It is not a
future positive B2-B memory-access binding fixture, proof of an instruction
access, or proof that an effective-memory-type requirement is satisfied.

Normalization profile `owned-synthetic-explicit-state-v1` copies explicit values,
canonicalizes hexadecimal addresses, and sorts unique context IDs. Producer profile
`owned-synthetic-state-record-author`, version `1`, describes manual fixture authorship,
not trust strength. Each `record:NNNNNN` locator identifies exactly one global record
within its observation family, independent of JSON formatting or array order. A
memory and context fact may share a locator when one producer record reports both.

The typed materialization is the authoritative normalized source (option A).
The core IR checks declared source SHA format/identity, not external raw-file truth.
The owned runner can additionally hash its available fixture bytes, using the same
immutable byte snapshot for hashing and parsing. A rehashed changed normalized
value is a valid different source claim, not independently authenticated raw data.

Rebuild only the new text bundle:

```bash
.venv/bin/python scripts/export_candidate_state_observations.py --output-dir examples/phase10d/candidate_state_observations/owned_diamond
```

No requirement binding, evaluation, proximity, timing, hardware effect, or public
A77 positive fixture is produced.
