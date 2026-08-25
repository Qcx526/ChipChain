# ChipChain Project Status

## Stable Baseline

- Branch: `main`
- Stable tag: `phase-9c-stable`
- Stable commit: `88c8c53a72e2c7e4e8775093c8bcab74a8032992`
- Baseline: Phase 9C ARM triggerability MVP complete
- Canonical environment: Ubuntu; Windows is secondary portability regression

## Completed Capabilities

- ARM-only same-architecture cross-layer modeling and deterministic analysis
- Phase 9A-R interaction-centered static verification with Type III objective propagation still `not_implemented`
- Phase 9B1 passive QEMU RuntimeObservation and interaction-agnostic Runtime Evidence
- Phase 9B2A explicit dynamic trigger observation verification and read-only static/dynamic aggregation
- Phase 9B2B non-verifying Hypothesis, EvidenceRequest, ReasoningResult, knowledge retrieval, feedback, deterministic four-role mock workflow, and dynamic reasoning context binding
- Phase 9B2C strict real-provider bridge, fixed four-role provider-backed workflow, and observed release acceptance; Phase 10A Step 3 supersedes its v2 transport with explicit model-claim v3
- Phase 9C Step 1 exact ARM A32 HardwareTriggerSignature contract with typed preconditions, hardware failure effect, and prior proof provenance
- Phase 9C Step 2 content-bound exact A32 executable sequence matching over function-local structural CFG paths
- Phase 9C Step 3A passive QEMU instruction-byte trace and exact contiguous runtime T confirmation
- Phase 9C Step 4 detached triggerability aggregation with typed declared-precondition policy
- Phase 10A Step 1 finalized candidate, typed Ground Truth, predeclared scope, and manifest contracts
- Phase 10A Step 2 Ground-Truth-free candidate-side objective chain feasibility oracle
- Phase 10A Step 3 explicit model-authored chain claim and Ground-Truth-free candidate binding assessment
- Phase 10A Step 3-R1 strict required-null provider transport, optional-reference subset binding, and actual source-role provenance hardening

## Current Work

Phase 10A Step 3 is complete. The existing oracle still assesses one finalized candidate using only candidate-side
typed interaction, artifact identity, Phase 9C triggerability, and optional explicit infrastructure
failure. Ground Truth is not an input. Only the current exact-bound Type II path can become
`CONFIRMED_FEASIBLE`; Type I remains `UNRESOLVED`, and Type III remains `UNSUPPORTED`. A separate
`ModelClaimBinder` now distinguishes `ALIGNED`, `INCOMPLETE`, `MISMATCHED`, `UNBOUND`, and `MISSING`
explicit model proposals without reading Ground Truth. Context interaction is not model authorship,
and `CONFIRMED_FEASIBLE` alone is not future numerator eligibility. No benchmark
runner, metric, Ground Truth recall, or >=80% result exists yet. Phase 9C Step 3B remains deferred.

## Remaining Work

- Phase 9C Step 3B precondition-state confirmation, only if required by real samples
- Phase 10B evaluation runner and metrics
- Phase 10C ablations
- Phase 10D real-model comparison and report
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

Step 4 triggerability is one firmware-to-hardware-contract component and is not a generic
`CONFIRMED_FEASIBLE` chain outcome without exact Type II candidate-side binding. Ground Truth never
enriches candidate records or enters the oracle; model confidence does not determine assessment
identity/status, and internal role hypotheses are not denominator candidates. Context-bound interaction
fields are not automatically LLM-authored. No “关联漏洞命中率 >= 80%” calculation has been performed.

Only ATTACK_CHAIN provider output may carry one optional model-authored claim. ChipChain owns claim
architecture, role, and identity; wrong participant IDs are retained for assessment rather than
repaired. Strict transport requires `chain_claim`: null means no authorship and is emitted by the
deterministic Mock; non-null participant objects carry all list properties. Required references remain
exact, while non-empty optional references must be candidate-side subsets. The coordinator retains at
most one claim and independently rejects one returned by an actual non-ATTACK_CHAIN Agent. No claim
creates Evidence, VerificationRecord, AttackChain, vulnerability truth, causality, or score.
