# ChipChain Project Status

## Stable Baseline

- Branch: `main`
- Stable tag: `phase-9b2b-stable`
- Stable commit: `7477fd8426fdfddf53076ba859696d2b0f4bc995`
- Baseline: Phase 9B2C Step 1～3 complete
- Canonical environment: Ubuntu; Windows is secondary portability regression

## Completed Capabilities

- ARM-only same-architecture cross-layer modeling and deterministic analysis
- Phase 9A-R interaction-centered static verification with Type III objective propagation still `not_implemented`
- Phase 9B1 passive QEMU RuntimeObservation and interaction-agnostic Runtime Evidence
- Phase 9B2A explicit dynamic trigger observation verification and read-only static/dynamic aggregation
- Phase 9B2B non-verifying Hypothesis, EvidenceRequest, ReasoningResult, knowledge retrieval, feedback, deterministic four-role mock workflow, and dynamic reasoning context binding
- Phase 9B2C strict real-provider bridge, fixed four-role provider-backed workflow, reduced semantic v2 contract, and observed release acceptance

## Current Work

Phase 9B2C is complete. Its current reduced semantic provider contract is
`phase9b2c_reasoning_semantic_output_v2`; the incompatible old v1 identifier is rejected. The fixed
CODE → HARDWARE → VULNERABILITY → ATTACK_CHAIN provider-backed workflow makes one call per role
over the same detached context. Typed Context and role contracts deterministically supply immutable
bindings after provider-output validation. Real `qwen3.8-max` Chat Completions provider connection,
single-role reasoning, and observed strict-schema four-role acceptance passed in release order.

## Remaining Work

- Phase 10 evaluation
- Phase 11 API and visualization, only after core evaluation
- Phase 12 additional architectures, only after the ARM loop is stable and evaluated

## Boundaries and Non-Goals

Real or mock LLM output is reasoning only. It does not create Evidence, VerificationRecord,
AttackChain, causality, verification status, scoring changes, or vulnerability verdicts. The Phase
9B2C provider-backed path has no retry loop, dynamic routing, voting, automatic evidence collection,
API/GUI, or exploit generation.
Strict-schema or role failures do not retry, downgrade to JSON Object, switch providers, or fall back
to a mock provider. AttackChain remains hypothesis-only and prior-agent free text is not chained.
The Step 3 observer records only role and Context ID; it stores no prompt, raw response, secret,
endpoint, or header and does not change failure propagation. Type III objective propagation and
Verified AttackChain projection remain unimplemented and outside Phase 9B2C.
No secrets or machine-specific paths belong in this document.
