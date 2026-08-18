# Synthetic ARM MMIO fixture

This directory is owned, auditable synthetic / fixture test data. It is not a
vulnerability sample, production firmware, or benchmark result.

arm_mmio.S documents every A32 instruction. Because the validated Windows
environment has no ARM cross-compiler, generate_fixture.py writes those
commented words into a deterministic ELF32 executable with its own symbol and
string tables. It does not contain downloaded executable bytes.

Build from the repository root:

    & .\tests\fixtures\angr\arm_mmio\build.ps1

memory_map.json is an explicit analyzer input. Only address 0x40000000 is
declared as FIXTURE_MMIO_REGISTER; no broad SoC address rule exists in code.
The same machine-code function also accesses ordinary RAM at 0x20001000 and
unknown addresses held in r3/r5, providing negative controls.

ground_truth.json records functions, CALLS, resolved MMIO accesses, ordinary
RAM accesses, and unresolved accesses. SHA256SUMS records the reproducible ELF
digest. The fixture's purpose is program-observation validation only.

Current SHA-256:
b9e28ba895fe49a3688362d9e76cee4d98d66ed06265f72cff88adea4e53e4ca.
