# ChipChain Project Status

## Stable Baseline

- Branch: `main`
- Stable tag: `phase-10d-step8b2b1-stable`
- Stable commit: `00810a132bdc0285c80c6f13088fac99159b932c`
- Baseline: Phase 10D Step 8B-2B1 final accepted and frozen
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
- Phase 10D Step 8A public CVE research intake, profile-aware admission staging, and issue-level deduplication
- Phase 10D Step 8B-0 single-source public corpus build and byte-stable generated snapshot workflow
- Phase 10D Step 8B-1A five-case public-documented SECONDARY materialization and exact prompt-readiness audit
- Phase 10D Step 8B-1B versioned neutral public-knowledge projection and structured prompt leakage audit
- Phase 10D Step 8B-1C explicit public execution binding, exact pre-transport provenance gates, and wrapper archive
- Phase 10D Step 8B-1D frozen five-case public-provider one-shot hash-only archive
- Phase 10D Step 8B-1E deterministic retrospective MASKED semantic/content recovery diagnostic
- Phase 10D Step 8B-2B0 authoritative documented semantics contract for Cortex-A77 erratum 1508412
- Phase 10D Step 8B-2B1 versioned ARM A-profile semantic trigger-pattern predicates
- Phase 10D Step 8B-2B2-A A-profile static semantic extraction contracts and deterministic plan (implemented, pending final review)

## Current Work

Phase 10D Step 8B-2B2-A translates the exact frozen Step 8B-2B1 artifact into one deterministic,
artifact-neutral `AProfileStaticSemanticExtractionPlan`. It also freezes independent contracts for a future
AArch64 decoder's objective instruction facts, exact fact-to-predicate candidates, and a cross-bound extraction
result. No ELF occurrence is produced in this step.

Step 8B-1E adds Axis B as a supplemental offline diagnostic while leaving Axis A (the exact
`ModelClaimBinder`) and Axis C (the objective `ChainFeasibilityOracle`) unchanged. Current frozen sessions use
the Phase 9B2B hypothesis-only ATTACK_CHAIN contract: the exact claim-carrying source hypothesis description is
the only scored model-authored text, and all five cases record no same-hypothesis ATTACK_CHAIN
`ReasoningResult`. Merged/final results, other roles, FULL condition text, parser-bound fields, and raw response
reconstruction are excluded.

The diagnostic uses one frozen generic lexical contract to report exact trigger/precondition/hardware-effect
content coverage and public-summary-subtracted held-out coverage. It has no threshold, weighted score,
PASS/FAIL, semantic-success field, or model-confidence interpretation. The current artifact is explicitly
`RETROSPECTIVE_DIAGNOSTIC` and not prospectively metric-eligible because the contract was defined after the
one-shot output had been observed. Its current structural distributions are 4 type MATCH / 1 MISMATCH,
3 exact-binding INCOMPLETE / 2 MISMATCHED, and 5 objective-feasibility UNRESOLVED; these are independent
descriptive axes, not a semantic success percentage.

These documented Ground Truth annotations are SECONDARY reasoning-evaluation inputs, not objective
verification. They contain no HardwareTriggerSignature, runtime observation, Evidence, triggerability or
objective materialization. Existing oracle results remain `UNRESOLVED`, and existing PRIMARY metrics are
unchanged.
Manual owned-synthetic real-provider smoke/evaluation runs have occurred, but no final benchmark-scale
accepted performance result or >=80% conclusion exists. DS5 remained incomplete because its MASKED
firewall failed closed. Phase 9C Step 3B remains deferred.

The new documented-erratum object is not a `HardwareTriggerSignature`, `HardwareTriggerProof`, experimental
result, runtime observation, Evidence, VerificationRecord, triggerability result, or feasibility assessment.
It preserves exact program order but explicitly records qualitative-only proximity with no numeric bound,
possible core deadlock, and additional timing conditions unspecified by the public source. Its objective use is
`SEMANTIC_PATTERN_REFERENCE_ONLY`; CVE-2023-34320 remains `NEXT_OBJECTIVE_CANDIDATE` and `SECONDARY_ONLY`.

The Step 8B-2B1 pattern is also not an occurrence, runtime observation, `HardwareTriggerSignature`, proof, or
triggerability result. Step 8B-2B2-A preserves that boundary: static instruction existence is not runtime
execution, a decoded load does not establish Device/Normal-NC, and a static predicate candidate does not mean
the predicate is satisfied. Program order remains only source-plan structure; no Case A/B pair, CFG path outcome,
proximity result, triggerability, verification, or feasibility is represented. The AArch64 extractor (2B2-B),
case/program-order assembly (2B2-C), and runtime semantic observation (2B3) remain unimplemented.

## Remaining Work

- Phase 9C Step 3B precondition-state confirmation, only if required by real samples
- final review/freeze of the Step 8B-2B2-A static semantic extraction contracts
- Step 8B-2B2-B AArch64 decoded-event extraction and Step 8B-2B2-C case/order assembly, each only after separate review
- objective evidence review and explicit PRIMARY admission decisions for eligible public CVE records
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
