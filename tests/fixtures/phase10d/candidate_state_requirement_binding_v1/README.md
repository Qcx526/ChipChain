# Owned synthetic B2-B relevance-binding source

This fixture is owned, synthetic, benign, not a real vulnerability, and not a
benchmark. It is a normalized B2-A source input for demonstrating B2-B exact
program-location relevance only. It is not a runtime trace or independently
verified raw-source truth.

The synthetic program artifact is built in the B2-B export runner exclusively
through frozen production static-analysis contracts. Its two candidate subject
locations are `0x500000` and `0x500004`. The memory and context observations at
those locations deliberately use values different from the source-declared
requirement values. They still produce relevance bindings because B2-B does not
evaluate value equality. The memory observation at `0x500100` is deliberately
unrelated and must not produce a binding.

Program-location association does not establish runtime execution, a memory
access by the instruction, requirement satisfaction, or a verification result.
The access address is retained source provenance and is not a B2-B binding key.

Rebuild the B2-B-owned deterministic artifact bundle with:

```bash
.venv/bin/python scripts/export_candidate_state_requirement_bindings.py \
  --mode owned --output-dir \
  examples/phase10d/candidate_state_requirement_bindings/owned
```
