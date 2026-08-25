# ChipChain Project Status

## Stable Baseline

- Branch: `main`
- Stable tag: `phase-10b-stable`
- Stable commit: `f030449a7b9c2480f22afce8038d4b4cfc56ea05`
- Baseline: Phase 10B frozen deterministic benchmark evaluation complete
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
- Phase 10A Step 3-R2 strict structured-output schema default removal
- Phase 10B deterministic all-case benchmark accounting, exact Ground Truth comparison, recovery, coverage, and metric aggregation
- Phase 10C four-condition ablation protocol, prompt visibility firewall, leakage audit, context/objective upper bound, and deterministic comparison contracts

## Current Work

Phase 10C is complete as an offline contract layer. It predeclares full-context, masked-chain-context,
no-model, and context/objective-upper-bound conditions; keeps Phase 10B reports unchanged; makes prompt
visibility and condition failures auditable; and compares exact cohorts only on the same manifest.
FULL_CONTEXT_MODEL is not independent interaction discovery. The upper bound is neither a model metric
nor VerificationHitRate, and no ablation delta is a causal estimate. The owned synthetic Phase 10B
acceptance remains `1/2`, `1/1`, `0/1`, `2/2`; no real-model run or >=80% conclusion was performed.
Phase 9C Step 3B remains deferred.

## Remaining Work

- Phase 9C Step 3B precondition-state confirmation, only if required by real samples
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
