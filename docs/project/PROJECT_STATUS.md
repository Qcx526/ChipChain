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
- Phase 9C Step 3A passive QEMU instruction-byte trace and exact contiguous runtime T confirmation

## Current Work

Phase 9C Step 3A is complete. It binds a complete dedicated QEMU instruction trace to the same ELF
artifact ID/SHA-256 as Step 2, then confirms only consecutive exact `(PC, logical A32 word)` execution
for one `StaticFirmwareTriggerMatch.id`. The observer copies instruction bytes from translated QEMU
instruction metadata but emits events only on actual execution. This does not observe declared
register/memory/privilege preconditions and does not reproduce the vulnerable RTL hardware failure.
R1 removes invented fixture/synthetic provenance from the generic runner and adds bounded secret/path
redaction for failed-QEMU stderr. A32 remains a declared runner/fixture scope rather than a dynamic
CPSR.T observation; instrumentation overhead may affect timing, so no timing non-interference claim
is made.

## Remaining Work

- Phase 9C Step 3B precondition-state confirmation, only if required by real samples
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

Phase 9C Step 3A does not modify Phase 9B1 raw v2, RuntimeObservation, DynamicTriggerFact,
verification, scoring or reasoning. It creates no Evidence, VerificationRecord, BehaviorEdge,
AttackChain or vulnerability/triggerability verdict.
