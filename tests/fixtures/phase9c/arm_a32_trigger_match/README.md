# Owned synthetic ARM A32 static-trigger fixture

This directory is owned, synthetic contract data for Phase 9C Step 2. It is not
a CVE, production firmware, exploit, benchmark result, or claim that real ARM
hardware is vulnerable.

`source.S` documents the harmless A32 source. `generate_fixture.py` directly
encodes those audited words into a deterministic ELF32 file so normal tests do
not need a compiler or cross-toolchain. `linker.ld` documents the equivalent
memory layout. Rebuild from this directory with:

```bash
bash build.sh
```

The executable `.text` section contains one exact occurrence of the synthetic
three-word trigger and one near miss with a changed word. The non-executable
`.data` section contains the same raw byte pattern as the exact trigger. Static
matching must report only the decoded executable occurrence.

`ground_truth.json` is derived from the generated layout and records the
artifact SHA-256, signature ID, expected function, exact instruction addresses,
logical instruction words and expected basic-block path.
