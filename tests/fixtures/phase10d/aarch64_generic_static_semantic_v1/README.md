# Owned synthetic generic AArch64 static-semantic fixture

This directory is auditable, deterministic test data for Phase 10D Step
8B-2D2-B. It is not a real vulnerability, affected-hardware reproduction,
executable attack, benchmark Ground Truth, runtime observation, triggerability
demonstration, or PRIMARY case.

The single isolated function contains exact audited examples of ordinary load
and store, exclusive load and store, generic system-register read and write,
memory and instruction barriers, TLB invalidation and exception return. `NOP`
and `ADD` are negative classifier examples. These adjacent instructions are
fixture inventory samples only; their textual order is not runtime execution,
causality, proximity, a hardware trigger or an attack chain.

`generate_fixture.py` directly emits a deterministic ELF64 image using the
instruction bytes documented by `source.S`. Fixture regeneration therefore
does not require a cross compiler. Run it only when intentionally updating the
fixture:

```bash
PYTHON=.venv/bin/python bash build.sh
```

`SHA256SUMS` binds the committed ELF bytes. The expected JSON records generic
decoder outputs only and is not evaluation Ground Truth. The non-executable
`.data` section contains zero-separated copies of semantic instruction words
to prove executable filtering.
