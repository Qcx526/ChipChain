# ChipChain Project Status

## Stable Baseline

- Branch: `main`
- Stable tag: `phase-10d-step5-stable`
- Stable commit: `9148aceeb3844f2239805467a06bbf0c63219f69`
- Baseline: Phase 10D Step 5 final accepted and frozen
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
- Phase 10D Step 1 sanitized provider descriptor, frozen case×four-role execution matrix, hash-only per-role invocation provenance, fail-stop accounting, and canonical offline artifact envelope
- Phase 10D Step 2 explicit opt-in execution harness, detached input cohort, pre-transport MASKED audit, case-local failure accounting, and canonical session/case-run archive
- Phase 10D Step 6 GT-firewalled objective triggerability materialization, persistent source provenance, and REAL_PROVIDER completeness gates
- Phase 10D Step 7 collision-safe MASKED projection, centralized hidden-reference policy, and projection-protocol provenance

## Current Work

Phase 10D Step 7 is implemented over the frozen Phase 9C and Phase 10D contracts. It binds one detached
candidate-side input cohort to FULL/MASKED/NO_MODEL/UPPER, delegates to the frozen reasoning workflow,
projects and audits MASKED prompts through one collision-safe hidden-reference policy before transport,
continues later cases after case-local failure, and archives
parsed sessions, exact Phase 10B case runs, and persistent objective source/materialization provenance.
Historical Step 1–6 archives reconstruct their legacy MASKED bytes from the archived optional protocol
without weakening exact prompt-hash validation or reopening legacy REAL_PROVIDER execution.
NO_MODEL/UPPER make zero provider calls. The CLI is
fail-closed unless `--execute-real-provider` is explicit. No raw prompt, raw response, API key,
endpoint, or host path belongs in canonical artifacts. Every automated fixture is `OFFLINE_CONTRACT`;
no Phase 10D real-model run or >=80% conclusion was performed. Phase 9C Step 3B remains deferred.

## Remaining Work

- Phase 9C Step 3B precondition-state confirmation, only if required by real samples
- code review/freeze, then one explicit owned-synthetic real-provider experiment through the opt-in CLI
- Phase 10D later real-model result review and report
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
