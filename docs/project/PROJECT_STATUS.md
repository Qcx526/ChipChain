# ChipChain Project Status

## Stable Baseline

- Branch: `main`
- Stable tag: `phase-9b2c-stable`
- Stable commit: `07b059eb65d65fe47991ed8783d513be6b1d4b74`
- Baseline: Phase 9B2C complete
- Canonical environment: Ubuntu; Windows is secondary portability regression

## Completed Capabilities

- ARM-only same-architecture cross-layer modeling and deterministic analysis
- Phase 9A-R interaction-centered static verification with Type III objective propagation still `not_implemented`
- Phase 9B1 passive QEMU RuntimeObservation and interaction-agnostic Runtime Evidence
- Phase 9B2A explicit dynamic trigger observation verification and read-only static/dynamic aggregation
- Phase 9B2B non-verifying Hypothesis, EvidenceRequest, ReasoningResult, knowledge retrieval, feedback, deterministic four-role mock workflow, and dynamic reasoning context binding
- Phase 9B2C strict real-provider bridge, fixed four-role provider-backed workflow, reduced semantic v2 contract, and observed release acceptance
- Phase 9C Step 1 exact ARM A32 HardwareTriggerSignature contract with typed preconditions, hardware failure effect, and prior proof provenance
- Phase 9C Step 2 content-bound exact A32 executable sequence matching over function-local structural CFG paths

## Current Work

Phase 9C Step 2 is complete. It establishes only whether an authorized ARM ELF contains an exact
decoded A32 trigger sequence on a recovered, function-local, structurally reachable executable CFG
path. Results bind actual artifact bytes by SHA-256 and exclude raw data matching. Static matches do
not establish runtime execution, concrete path feasibility, precondition satisfaction, hardware
failure reproduction, triggerability, verification, or a confirmed AttackChain.

## Remaining Work

- Phase 9C Step 3 dynamic trigger execution confirmation
- Phase 9C Step 4 triggerability aggregation
- Phase 10 evaluation, after the triggerability pipeline exists
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
