# Phase 10D 2D4-B1 owned runtime evidence fixture

`owned_diamond_runtime_trace.json` is an owned, synthetic, benign
`RuntimeTrace` created entirely from frozen runtime contracts. It records only
deterministic `instruction_exec` observations for the owned diamond artifact.

The fixture is not a QEMU capture, benchmark result, hardware observation,
vulnerability reproduction, triggerability result, or requirement evaluation.
Regenerate it offline with:

```bash
PYTHONPATH=$PWD .venv/bin/python \
  tests/fixtures/phase10d/candidate_runtime_evidence_v1/generate_fixture.py
```
