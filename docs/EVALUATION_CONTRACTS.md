# Phase 10 Evaluation Contracts

## Scope

Phase 10A Step 1 freezes evaluation inputs and identities. Step 2 adds one Ground-Truth-free,
candidate-side objective feasibility assessment at a time. Step 3 adds an explicit model-authored
proposal and a separate Ground-Truth-free binding assessment. These steps add no benchmark runner,
metric calculation, Evidence, VerificationRecord, or AttackChain projection.
The initial scope is ARM-only. Phase 9C Step 3B and objective Type III HW→SW propagation remain not
implemented.

## Phase 10B Post-Finalization Evaluation

Phase 10B is aggregation-only and is the first layer allowed to read frozen Ground Truth together with
finalized candidate outputs. It never invokes a Provider, AgentWorkflow, Binder, Oracle, angr, QEMU,
or trigger matching. Every manifest case has exactly one run record: finalized candidate bundle,
bounded pre-finalization execution failure, or a predeclared exclusion legal only for
`excluded_unsupported` scope.

The five evaluation layers are:

1. `ReasoningSession -> FinalizedCandidateRecord`;
2. explicit model claim -> `ModelClaimBindingAssessment`;
3. candidate-side objective facts -> `ChainFeasibilityAssessment`;
4. exact frozen Ground Truth comparison -> `BenchmarkCandidateAssessment`;
5. manifest aggregation -> `BenchmarkEvaluationReport`.

A strict hit requires a PRIMARY_TARGET positive case, `ALIGNED`, `CONFIRMED_FEASIBLE`, exact
CrossLayerInteraction ID, exact declared attack-pattern reference, and exact declared hardware-trigger
signature through the supplied frozen triggerability result. Negative controls never become hits;
aligned+confirmed negative candidates are benchmark false positives. Pre-candidate failure is not a
fabricated denominator candidate and instead lowers `PrimaryCaseCoverage` and
`primary_scope_complete`.

## Finalized Candidate Boundary

One complete `ReasoningSession` produces exactly one `FinalizedCandidateRecord`. The proposition is
exactly `ReasoningSession.merged_hypothesis`. Role-specific hypotheses, AgentMessage objects,
ReasoningResult objects, EvidenceRequest objects, prompts, and provider responses are internal to
one collaborative generation process and are not independent denominator candidates.

The builder accepts only `benchmark_case_id` and `ReasoningSession`, detached-revalidates the session,
and copies the merged hypothesis plus permitted typed Context semantics. If Context contains a
CrossLayerInteraction, its deterministic ID/type/direction are retained. If it does not, these fields
remain absent. Ground Truth is never an input and cannot repair or enrich a weak candidate.

Candidate identity binds case, architecture, session, Context, workflow, merged proposition, subject,
typed interaction fields, attack-pattern reference and affected components. Confidence and metadata
are excluded. When an explicit model claim exists, candidate and merged-hypothesis identity
conditionally bind its ID; when absent, prior identity material is unchanged. Confidence may be
retained for analysis but cannot change identity or feasibility.

## Three Independent Candidate Layers

1. `ReasoningContext.cross_layer_interaction` is candidate-side typed context supplied to reasoning.
   It is not automatically model-authored.
2. `ModelAuthoredChainClaim` is an ATTACK_CHAIN-role, proposal-shaped output. The provider authors only
   interaction type and participant/reference lists; ChipChain binds ARM architecture, role and ID.
   It deliberately permits incomplete and wrong semantics so model errors remain measurable.
3. `ChainFeasibilityAssessment` remains the Step 2 objective candidate-side result and is unchanged.

The v3 strict transport requires `chain_claim` for every role and represents no claim as `null`.
Every strict-schema object requires all declared properties and rejects additional properties. Null
is transport-level absence, not authorship: CODE, HARDWARE, and VULNERABILITY must emit null, while
ATTACK_CHAIN may emit null or one structured claim. The ordinary constrained parser remains compatible
with an omitted field. Other roles with a non-null claim,
unknown fields, provider-authored metadata/identity/architecture/role, and forbidden verdict/score
fields fail closed. A missing claim does not abort reasoning or drop the finalized candidate. The
default deterministic Mock does not copy Context into a claim. The coordinator retains zero or one
source claim, rejects multiple claims, and independently checks that the actual contributing Agent is
ATTACK_CHAIN rather than trusting only the claim's bound author role.

`ModelClaimBinder` compares the detached finalized claim with an exactly bound candidate interaction
without accepting Ground Truth. Its closed statuses are:

- `ALIGNED`: complete required model fields exactly match the candidate interaction;
- `INCOMPLETE`: required fields for the claimed type are missing;
- `MISMATCHED`: type shape, interaction type, required references, or explicitly supplied optional
  references conflict;
- `UNBOUND`: a claim exists but the candidate has no typed interaction;
- `MISSING`: the model emitted no claim.

Type I requires model-authored initiating vulnerability, target vulnerability, and trigger behavior.
Type II requires target vulnerability and trigger behavior and forbids an initiating vulnerability.
Type III requires initiating hardware vulnerability and affected software execution. Required lists
remain exact. An empty optional list means that category was not explicitly claimed; a non-empty
optional list is compatible exactly when it is a subset of the candidate interaction's corresponding
list. Any out-of-set optional identifier is a mismatch. These are claim-alignment
outcomes, not feasibility, vulnerability, causality, verification, or AttackChain verdicts.

## Benchmark and Ground Truth

`BenchmarkArtifactReference` is path-neutral and binds canonical lowercase SHA-256. It stores no host
absolute path. `BenchmarkSourceKind` distinguishes `owned_synthetic`, `public_benchmark`,
`public_documented`, and `fixture`; public sources require stable references.

`GroundTruthChain` does not reuse domain AttackChain. It contains a detached CrossLayerInteraction
snapshot with empty metadata and optional stable hardware-trigger/attack-pattern references. Existing
three-class semantics remain authoritative:

- Type I requires initiating software vulnerability plus target hardware vulnerability.
- Type II forbids an invented initiating software vulnerability.
- Type III preserves hardware-to-software direction; no reversed software path may substitute.

Positive cases require at least one GroundTruthChain. Negative controls require zero feasible chains.
`EvaluationScope` is declared as `primary_target`, `secondary_only`, or `excluded_unsupported` before
candidate or verifier outcomes exist. Difficulty or failure cannot change it later.

`BenchmarkManifest` binds benchmark version, ARM architecture scope, and a deterministic ordered case
set. Case IDs and Ground Truth chain IDs are unique. Metadata never affects chain, case, candidate, or
manifest identity.

The initial manifest contains only two small contract-validation cases: one owned synthetic Type II
positive reusing the Phase 9C A32 runtime fixture and empty-P signature, and one owned synthetic
negative control. Both remain explicitly fixture/synthetic/owned and are not real ARM vulnerabilities,
real CVEs, or public benchmark samples. This is not the separate >=100 vulnerability sample library.

## Implemented Metric Boundary

The strict metric contract is:

```text
VerificationHitRate
= N(PRIMARY_TARGET finalized candidates with ALIGNED + CONFIRMED_FEASIBLE + exact GT match)
  / N(all finalized candidates produced in predeclared primary benchmark scope)
```

A poorly structured candidate or one lacking typed binding remains in the strict denominator.
The denominator is not limited to successful, convenient, or post-selected cases. A secondary
verifier-conditioned rate may later use a predeclared objectively-verifiable subset, but must be
reported separately. `GroundTruthChainRecall` must accompany hit rate so emitting very few candidates
cannot trivially inflate it.

## Candidate-Side Objective Oracle

`ChainFeasibilityOracle` accepts only `FinalizedCandidateRecord`, path-neutral
`BenchmarkArtifactReference`, optional candidate-side `CrossLayerInteraction`, optional Phase 9C
`TriggerabilityAggregationResult`, and optional explicit `ObjectiveEvaluationFailure`. It does not
accept GroundTruthChain, BenchmarkCase, Manifest, or EvaluationScope and cannot repair a candidate
from an answer key.

The merged hypothesis is the finalized reasoning proposition; only its explicit
`ModelAuthoredChainClaim` records model-authored chain semantics. Candidate interaction ID/type/direction are
copied from ReasoningContext when present and are deterministic candidate-side Context bindings; they
must not be reported as fields independently invented or correctly predicted by the LLM. The oracle
evaluates the whole finalized candidate under this explicit binding.

The closed current matrix is:

- Type II + exact candidate/interaction/artifact/target-vulnerability binding + `TRIGGERABLE` gives
  `CONFIRMED_FEASIBLE`.
- Type II `NO_STATIC_TRIGGER_MATCH` gives `NOT_SUPPORTED` for the exact tested target.
- Type II runtime-not-observed, insufficient declared-P evidence, or missing triggerability gives
  `UNRESOLVED`.
- Type I `NO_STATIC_TRIGGER_MATCH` gives `NOT_SUPPORTED`; every other current Type I path remains
  `UNRESOLVED` because objective software-vulnerability→exact-T enabling linkage is not implemented.
- Type III gives `UNSUPPORTED`; Phase 9C software→hardware triggerability cannot be attached to it.
- `INFRA_FAILURE` requires an explicit, bounded, correctly bound ObjectiveEvaluationFailure. Invalid
  objects or contradictory bindings raise typed errors and are never outcomes.

Only a candidate that is both `CONFIRMED_FEASIBLE` and independently `ALIGNED` may later enter a
strict numerator. `CONFIRMED_FEASIBLE` alone is insufficient. This assessment does not mean QEMU
reproduced a hardware failure, that the LLM authored every typed binding, or that an AttackChain domain
object was verified.

`TriggerabilityAggregationResult.TRIGGERABLE` is one objective component: firmware executed exact T
for a prevalidated hardware-trigger contract with no additional declared P. It does not automatically
bind the finalized candidate, establish the Type I initiating software vulnerability, verify complete
CrossLayerInteraction truth or Type III propagation, or confirm an AttackChain. Therefore
`TRIGGERABLE == CONFIRMED_FEASIBLE` is not a valid generic rule.

Phase 10A itself calculates no metric. Phase 10B also reports `GroundTruthChainRecall`,
`NegativeControlFalsePositiveRate`, and `PrimaryCaseCoverage` as exact ID cohorts with explicit
undefined zero-denominator results. The owned synthetic contract fixture yields `1/2`, `1/1`, `0/1`,
and `2/2`; this is not a project performance result and no >=80% threshold conclusion is produced.

## Phase 10C Ablation Contracts

`AblationExperimentPlan` freezes exactly four conditions before outputs: full-context model,
masked-chain-context model, no-model baseline, and context/objective upper bound. Version 1 fixes one
repetition and does not add seeds or statistical inference. Full, masked, and no-model conditions
consume an ordinary frozen Phase 10B `BenchmarkEvaluationReport`; Phase 10C neither copies nor
recomputes its metrics.

The full condition is the existing prompt control. It may expose candidate-side typed chain Context,
so an aligned full-context claim is not evidence that the model independently discovered the
interaction. The masked condition changes only provider-visible serialization. It hides the typed
interaction, attack-pattern reference, dynamic-trigger-fact reference, and the full Context ID, while
the trusted session, finalized candidate, binder, oracle, and constrained parser retain the complete
Context. Wrong or absent provider claims remain wrong or absent and flow through existing
`MISMATCHED`, `INCOMPLETE`, `UNBOUND`, or `MISSING` semantics. The no-model baseline never synthesizes
Context into authorship.

`ContextObjectiveUpperBoundRate` has all finalized PRIMARY_TARGET candidates as its denominator. Its
numerator is restricted to positive candidates with `CONFIRMED_FEASIBLE` and the same exact
interaction/optional attack-pattern/declared signature Ground Truth match used by Phase 10B. It
removes only model-claim alignment. Negative controls cannot be hits. It is a Context/verifier
diagnostic, not a model metric and not `VerificationHitRate`.

`AblationComparisonReport` requires one explicit success or bounded execution failure for every plan
condition, the same manifest/version and frozen Phase 10B runner contract, and exact integer cohort
components for each delta. Coverage is comparable only when all conditions have identical, complete
PRIMARY_TARGET case coverage. Prompt visibility audits search only exact separately supplied hidden
references after construction; they do not modify prompts or evaluation and are not verification.
Reported differences are observed ablation differences, never causal effects. Phase 10C performs no
real-model run and produces no >=80% project conclusion.
