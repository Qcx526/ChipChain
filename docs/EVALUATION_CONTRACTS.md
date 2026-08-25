# Phase 10A Evaluation Contracts

## Scope

Phase 10A Step 1 freezes evaluation inputs and identities. Step 2 adds one Ground-Truth-free,
candidate-side objective feasibility assessment at a time. Neither step adds a benchmark runner,
metric calculation, LLM schema change, Evidence, VerificationRecord, or AttackChain projection.
The initial scope is ARM-only. Phase 9C Step 3B and objective Type III HW→SW propagation remain not
implemented.

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
are excluded. Confidence may be retained for analysis but cannot change identity or feasibility.

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

## Future Metric Boundary

The future strict project metric is defined as:

```text
VerificationHitRate
= N(finalized candidates objectively confirmed feasible)
  / N(all finalized candidates produced in predeclared primary benchmark scope)
```

A poorly structured candidate or one lacking typed binding remains in the future strict denominator.
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

The merged hypothesis is the model-authored proposition. Candidate interaction ID/type/direction are
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

Only `CONFIRMED_FEASIBLE` may later enter a strict numerator. This assessment does not mean QEMU
reproduced a hardware failure, that the LLM authored every typed binding, or that an AttackChain domain
object was verified.

`TriggerabilityAggregationResult.TRIGGERABLE` is one objective component: firmware executed exact T
for a prevalidated hardware-trigger contract with no additional declared P. It does not automatically
bind the finalized candidate, establish the Type I initiating software vulnerability, verify complete
CrossLayerInteraction truth or Type III propagation, or confirm an AttackChain. Therefore
`TRIGGERABLE == CONFIRMED_FEASIBLE` is not a valid generic rule.

No >=80% hit rate is calculated in Phase 10A Step 1 or Step 2.
