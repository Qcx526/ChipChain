# Owned synthetic ARM A32 runtime trigger fixture

This Phase 9C Step 3A fixture is owned, synthetic, not a real vulnerability,
and not a benchmark. It is linked at `0x40200000` for QEMU 11.0.3 `virt` / 
`cortex-a15` / one-vCPU TCG system emulation.

The exact harmless three-word sequence occurs in both `executed_trigger` and
`not_called_trigger`. `_start` calls only `executed_trigger`, then exits through
ARM semihosting. Therefore Step 2 should find two static structural occurrences,
while Step 3A should confirm only the called function's concrete execution.

`generate_fixture.py` deterministically creates the checked-in ELF, empty-P
synthetic signature, SHA256SUMS, and ground truth from audited A32 words. Normal
tests use these checked-in files and need no compiler. Run `./build.sh` only to
regenerate and audit them.
