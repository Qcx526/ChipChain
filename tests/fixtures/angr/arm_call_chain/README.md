# Synthetic ARM call-chain fixture

This directory contains an owned, auditable, non-vulnerability test artifact.
It is `synthetic` test data and is not a CVE, benchmark result, production
firmware, or third-party binary.

`arm_call_chain.S` is the human-readable ARM A32 source. The validated Windows
environment did not contain an ARM GCC or Clang toolchain, so
`generate_fixture.py` deterministically encodes the commented A32 words and a
minimal ELF32 header, program header, sections, string tables, and function
symbols. No downloaded or unknown executable bytes are used.

Build from the repository root:

```powershell
& .\tests\fixtures\angr\arm_call_chain\build.ps1
```

The build writes:

- `arm_call_chain.elf`: 32-bit little-endian ARM executable;
- `ground_truth.json`: expected functions, calls, and exact call sites;
- `SHA256SUMS`: expected fixture digest.

Rebuilding must reproduce the committed digest and Ground Truth. Its only
resolved behavior is
`main → parse_command → helper_function → driver_like_function`. A separate,
unreached `indirect_dispatch` function contains `blx r3` so the adapter can
prove that unresolved register-indirect calls are counted but never fabricated
as resolved `CALLS` edges.

Current SHA-256:
`89783e273a5c569d290c1bee22a2a2a6eabf6febc2cfce3ac5cc59103b5a7ac8`.
