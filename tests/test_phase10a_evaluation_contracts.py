"""Phase 10A Step 1 benchmark and finalized-candidate contract tests."""

from __future__ import annotations

import inspect
import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.agents import AgentWorkflow, ReasoningContext, ReasoningSession
from chipchain.evaluation import (
    BenchmarkArtifactReference,
    BenchmarkCaseLabel,
    BenchmarkManifest,
    BenchmarkSourceKind,
    EvaluationBenchmarkCase,
    EvaluationScope,
    FinalizedCandidateBuilder,
    FinalizedCandidateRecord,
    GroundTruthChain,
)
from chipchain.models import (
    Architecture,
    AttackChain,
    CrossLayerDirection,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Layer,
)
from chipchain.reasoning import AttackHypothesis, ReasoningResult
from chipchain.verification.models import VerificationRecord


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "evaluation" / "phase10a_owned_arm.json"
BENCHMARK_VERSION = "phase10a-owned-arm-contract-v1"
POSITIVE_ARTIFACT_SHA256 = (
    "b02e525665617cf623bafed5092d4a1c82a07a6120f5e89a8872341c09da2b81"
)
NEGATIVE_ARTIFACT_SHA256 = (
    "cfb388c8ce10305faa6fe4c0be1333e7efe2bec2dd0b94c1f64ab12a36207ede"
)


def _interaction(
    interaction_type: CrossLayerInteractionType = (
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
    ),
) -> CrossLayerInteraction:
    if (
        interaction_type
        is CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
    ):
        return CrossLayerInteraction.create(
            architecture=Architecture.ARM,
            interaction_type=interaction_type,
            source_layer=Layer.FIRMWARE,
            target_layer=Layer.HARDWARE,
            initiating_vulnerability_ids=["synthetic-firmware-vulnerability"],
            target_vulnerability_ids=["synthetic-hardware-vulnerability"],
            trigger_behavior_ids=["synthetic-trigger-behavior"],
            referenced_architectures=[Architecture.ARM],
            metadata={"discarded_by_ground_truth_snapshot": True},
        )
    if (
        interaction_type
        is CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
    ):
        return CrossLayerInteraction.create(
            architecture=Architecture.ARM,
            interaction_type=interaction_type,
            source_layer=Layer.HARDWARE,
            target_layer=Layer.FIRMWARE,
            initiating_vulnerability_ids=["synthetic-hardware-vulnerability"],
            affected_execution_ids=["synthetic-affected-firmware-execution"],
            referenced_architectures=[Architecture.ARM],
        )
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=interaction_type,
        source_layer=Layer.FIRMWARE,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["synthetic-phase9c-runtime-trigger-contract"],
        trigger_behavior_ids=["synthetic-owned-arm-a32-exact-trigger-sequence"],
        hardware_resource_ids=["synthetic-owned-arm-execution-core"],
        referenced_architectures=[Architecture.ARM],
        metadata={"discarded_by_candidate_snapshot": True},
    )


def _context(
    *,
    subject_id: str = "synthetic-phase10a-candidate-subject",
    interaction: CrossLayerInteraction | None = None,
) -> ReasoningContext:
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id=subject_id,
        affected_components=[
            "synthetic-owned-arm-firmware",
            "synthetic-owned-arm-hardware",
        ],
        observed_fact_ids=["synthetic-static-trigger-fact"],
        available_evidence_ids=["synthetic-reference-only-evidence"],
        attack_pattern_reference="synthetic-attack-pattern",
        cross_layer_interaction=interaction,
        metadata={"fixture": True},
    )


def _session(
    *,
    subject_id: str = "synthetic-phase10a-candidate-subject",
    interaction: CrossLayerInteraction | None = None,
) -> ReasoningSession:
    return AgentWorkflow().execute(
        _context(subject_id=subject_id, interaction=interaction)
    )


def _artifact(*, positive: bool = True) -> BenchmarkArtifactReference:
    if positive:
        return BenchmarkArtifactReference(
            artifact_id="synthetic-owned-arm-a32-trigger-runtime-elf",
            architecture=Architecture.ARM,
            artifact_type="elf",
            artifact_sha256=POSITIVE_ARTIFACT_SHA256,
            artifact_reference=(
                "tests/fixtures/phase9c/arm_a32_trigger_runtime/"
                "arm_a32_trigger_runtime.elf"
            ),
        )
    return BenchmarkArtifactReference(
        artifact_id="synthetic-owned-arm-negative-control-spec",
        architecture=Architecture.ARM,
        artifact_type="fixture_spec",
        artifact_sha256=NEGATIVE_ARTIFACT_SHA256,
        artifact_reference="tests/fixtures/program_analysis/arm_demo_program.json",
    )


def _ground_truth(
    interaction_type: CrossLayerInteractionType = (
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
    ),
    *,
    metadata: dict[str, object] | None = None,
) -> GroundTruthChain:
    return GroundTruthChain.create(
        cross_layer_interaction=_interaction(interaction_type),
        hardware_trigger_signature_id=(
            "hardware-trigger-signature:"
            "6c40f20a04baf56570c4f2994f1859e4b4012371300c78b43143829d16bd26ba"
            if interaction_type
            is CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
            else None
        ),
        expected_attack_pattern_reference="synthetic-attack-pattern",
        source_reference_ids=["fixture:phase9c:arm-a32-trigger-runtime"],
        metadata=metadata,
    )


def _positive_case(
    *, metadata: dict[str, object] | None = None
) -> EvaluationBenchmarkCase:
    return EvaluationBenchmarkCase.create(
        benchmark_version=BENCHMARK_VERSION,
        architecture=Architecture.ARM,
        source_kind=BenchmarkSourceKind.OWNED_SYNTHETIC,
        label=BenchmarkCaseLabel.POSITIVE_FEASIBLE,
        artifact=_artifact(),
        ground_truth_chains=[_ground_truth()],
        source_reference_ids=[
            "fixture:phase9c:arm-a32-trigger-runtime",
            "fixture:owned-synthetic:not-real-vulnerability",
        ],
        evaluation_scope=EvaluationScope.PRIMARY_TARGET,
        metadata=metadata
        or {
            "fixture": True,
            "owned": True,
            "synthetic": True,
            "not_real_vulnerability": True,
        },
    )


def _negative_case(
    *, metadata: dict[str, object] | None = None
) -> EvaluationBenchmarkCase:
    return EvaluationBenchmarkCase.create(
        benchmark_version=BENCHMARK_VERSION,
        architecture=Architecture.ARM,
        source_kind=BenchmarkSourceKind.OWNED_SYNTHETIC,
        label=BenchmarkCaseLabel.NEGATIVE_CONTROL,
        artifact=_artifact(positive=False),
        ground_truth_chains=[],
        source_reference_ids=[
            "fixture:program-analysis:arm-demo-negative-control",
            "fixture:owned-synthetic:not-real-vulnerability",
        ],
        evaluation_scope=EvaluationScope.PRIMARY_TARGET,
        metadata=metadata
        or {
            "fixture": True,
            "owned": True,
            "synthetic": True,
            "not_real_vulnerability": True,
        },
    )


def _manifest(*, metadata: dict[str, object] | None = None) -> BenchmarkManifest:
    return BenchmarkManifest.create(
        benchmark_version=BENCHMARK_VERSION,
        architecture_scope=[Architecture.ARM],
        cases=[_negative_case(), _positive_case()],
        metadata=metadata,
    )


def test_one_reasoning_session_produces_one_finalized_merged_candidate() -> None:
    session = _session(interaction=_interaction())
    candidate = FinalizedCandidateBuilder().from_reasoning_session(
        _positive_case().id,
        session,
    )

    assert type(candidate) is FinalizedCandidateRecord
    assert candidate.reasoning_session_id == session.session_id
    assert candidate.reasoning_context_id == session.reasoning_context.id
    assert candidate.merged_hypothesis_id == session.merged_hypothesis.id
    assert len(session.hypotheses) == 4
    assert not any(
        item.id == candidate.merged_hypothesis_id for item in session.hypotheses
    )
    assert candidate.metadata["role_hypotheses_counted_as_candidates"] is False


def test_model_confidence_change_does_not_change_candidate_identity() -> None:
    session = _session()
    changed_values = session.model_dump(mode="json")
    changed_values["merged_hypothesis"]["confidence"] = 0.75
    changed = ReasoningSession.model_validate(changed_values)
    builder = FinalizedCandidateBuilder()

    first = builder.from_reasoning_session("fixture-case", session)
    second = builder.from_reasoning_session("fixture-case", changed)

    assert first.id == second.id
    assert first.model_confidence == 0.0
    assert second.model_confidence == 0.75


def test_merged_proposition_and_context_changes_change_candidate_identity() -> None:
    session = _session()
    new_hypothesis = AttackHypothesis.create(
        source=session.merged_hypothesis.source,
        architecture=session.merged_hypothesis.architecture,
        description="Changed merged proposition for identity testing",
        affected_components=session.merged_hypothesis.affected_components,
        required_evidence_types=(
            session.merged_hypothesis.required_evidence_types
        ),
        confidence=session.merged_hypothesis.confidence,
        attack_pattern_reference=(
            session.merged_hypothesis.attack_pattern_reference
        ),
        metadata=session.merged_hypothesis.metadata,
    )
    new_result = ReasoningResult.create(
        new_hypothesis,
        reasoning_steps=session.final_reasoning_result.reasoning_steps,
        supporting_evidence_ids=(
            session.final_reasoning_result.supporting_evidence_ids
        ),
        missing_evidence=session.final_reasoning_result.missing_evidence,
        confidence=session.final_reasoning_result.confidence,
        metadata=session.final_reasoning_result.metadata,
    )
    proposition_values = session.model_dump(mode="json")
    proposition_values["merged_hypothesis"] = new_hypothesis.model_dump(mode="json")
    proposition_values["final_reasoning_result"] = new_result.model_dump(mode="json")
    proposition_changed = ReasoningSession.model_validate(proposition_values)
    context_changed = _session(subject_id="synthetic-different-subject")
    builder = FinalizedCandidateBuilder()
    original = builder.from_reasoning_session("fixture-case", session)

    assert builder.from_reasoning_session(
        "fixture-case", proposition_changed
    ).id != original.id
    assert builder.from_reasoning_session(
        "fixture-case", context_changed
    ).id != original.id


def test_missing_interaction_remains_missing_and_is_not_invented() -> None:
    candidate = FinalizedCandidateBuilder().from_reasoning_session(
        "fixture-case",
        _session(),
    )

    assert candidate.cross_layer_interaction_id is None
    assert candidate.interaction_type is None
    assert candidate.direction is None


def test_candidate_builder_interface_cannot_receive_ground_truth() -> None:
    parameters = inspect.signature(
        FinalizedCandidateBuilder.from_reasoning_session
    ).parameters

    assert list(parameters) == ["benchmark_case_id", "session"]
    assert "ground_truth" not in FinalizedCandidateBuilder.from_reasoning_session.__code__.co_names


def test_caller_mutation_cannot_mutate_finalized_candidate() -> None:
    session = _session(interaction=_interaction())
    candidate = FinalizedCandidateBuilder().from_reasoning_session(
        "fixture-case", session
    )
    original = candidate.model_dump_json()

    session.merged_hypothesis.affected_components.append("caller-mutation")
    session.reasoning_context.cross_layer_interaction.metadata["mutation"] = True

    assert candidate.model_dump_json() == original


def test_candidate_identity_rejects_changed_semantics_but_ignores_metadata() -> None:
    candidate = FinalizedCandidateBuilder().from_reasoning_session(
        "fixture-case", _session()
    )
    changed_metadata = candidate.model_dump(mode="json")
    changed_metadata["metadata"] = {"non_semantic": "changed"}
    assert FinalizedCandidateRecord.model_validate(changed_metadata).id == candidate.id

    changed_subject = candidate.model_dump(mode="json")
    changed_subject["subject_id"] = "changed-subject"
    with pytest.raises(ValidationError, match="ID is not deterministic"):
        FinalizedCandidateRecord.model_validate(changed_subject)


def test_positive_and_negative_case_truth_cardinality() -> None:
    assert len(_positive_case().ground_truth_chains) == 1
    assert _negative_case().ground_truth_chains == []

    positive = _positive_case().model_dump(mode="json")
    positive["ground_truth_chains"] = []
    with pytest.raises(ValidationError, match="positive feasible"):
        EvaluationBenchmarkCase.model_validate(positive)

    negative = _negative_case().model_dump(mode="json")
    negative["ground_truth_chains"] = [
        _ground_truth().model_dump(mode="json")
    ]
    with pytest.raises(ValidationError, match="negative control"):
        EvaluationBenchmarkCase.model_validate(negative)


def test_type_i_and_type_ii_ground_truth_preserve_participant_semantics() -> None:
    type_one = _ground_truth(
        CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
    )
    assert type_one.cross_layer_interaction.initiating_vulnerability_ids == [
        "synthetic-firmware-vulnerability"
    ]

    with pytest.raises(ValueError, match="must not invent"):
        CrossLayerInteraction.create(
            architecture=Architecture.ARM,
            interaction_type=(
                CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
            ),
            source_layer=Layer.FIRMWARE,
            target_layer=Layer.HARDWARE,
            initiating_vulnerability_ids=["invented-software-vulnerability"],
            target_vulnerability_ids=["synthetic-hardware-vulnerability"],
            trigger_behavior_ids=["synthetic-trigger"],
        )


def test_type_iii_ground_truth_preserves_hardware_to_software_direction() -> None:
    truth = _ground_truth(
        CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
    )
    assert truth.cross_layer_interaction.direction is (
        CrossLayerDirection.HARDWARE_TO_SOFTWARE
    )

    values = truth.model_dump(mode="json")
    values["cross_layer_interaction"]["direction"] = "software_to_hardware"
    with pytest.raises(ValidationError, match="direction"):
        GroundTruthChain.model_validate(values)


@pytest.mark.parametrize(
    "source_kind",
    [
        BenchmarkSourceKind.PUBLIC_BENCHMARK,
        BenchmarkSourceKind.PUBLIC_DOCUMENTED,
    ],
)
def test_public_sources_require_stable_references(
    source_kind: BenchmarkSourceKind,
) -> None:
    with pytest.raises(ValidationError, match="require stable references"):
        EvaluationBenchmarkCase.create(
            benchmark_version=BENCHMARK_VERSION,
            architecture=Architecture.ARM,
            source_kind=source_kind,
            label=BenchmarkCaseLabel.NEGATIVE_CONTROL,
            artifact=_artifact(positive=False),
            ground_truth_chains=[],
            source_reference_ids=[],
            evaluation_scope=EvaluationScope.SECONDARY_ONLY,
        )


def test_owned_synthetic_fixture_provenance_is_explicit() -> None:
    case = _positive_case()

    assert case.source_kind is BenchmarkSourceKind.OWNED_SYNTHETIC
    assert case.metadata == {
        "fixture": True,
        "not_real_vulnerability": True,
        "owned": True,
        "synthetic": True,
    }
    assert "public" not in case.model_dump_json()


def test_artifact_sha_and_reference_are_canonical_and_path_neutral() -> None:
    values = _artifact().model_dump(mode="json")
    values["artifact_sha256"] = POSITIVE_ARTIFACT_SHA256.upper()
    with pytest.raises(ValidationError, match="lowercase"):
        BenchmarkArtifactReference.model_validate(values)

    values = _artifact().model_dump(mode="json")
    values["artifact_reference"] = "/home/user/private/artifact.elf"
    with pytest.raises(ValidationError, match="host absolute path"):
        BenchmarkArtifactReference.model_validate(values)

    values["artifact_reference"] = "file:///home/user/private/artifact.elf"
    with pytest.raises(ValidationError, match="host absolute path"):
        BenchmarkArtifactReference.model_validate(values)


def test_owned_fixture_artifact_hashes_bind_repository_bytes() -> None:
    positive_path = ROOT / _artifact().artifact_reference
    negative_path = ROOT / _artifact(positive=False).artifact_reference

    assert hashlib.sha256(positive_path.read_bytes()).hexdigest() == (
        POSITIVE_ARTIFACT_SHA256
    )
    assert hashlib.sha256(negative_path.read_bytes()).hexdigest() == (
        NEGATIVE_ARTIFACT_SHA256
    )


def test_case_ground_truth_and_manifest_identities_are_deterministic() -> None:
    first_truth = _ground_truth(metadata={"note": "first"})
    second_truth = _ground_truth(metadata={"note": "second"})
    first_case = _positive_case(metadata={"note": "first"})
    second_case = _positive_case(metadata={"note": "second"})
    first_manifest = _manifest(metadata={"note": "first"})
    second_manifest = _manifest(metadata={"note": "second"})

    assert first_truth.id == second_truth.id
    assert first_case.id == second_case.id
    assert first_manifest.id == second_manifest.id
    assert [item.id for item in first_manifest.cases] == sorted(
        item.id for item in first_manifest.cases
    )
    reversed_manifest = BenchmarkManifest.create(
        benchmark_version=BENCHMARK_VERSION,
        architecture_scope=[Architecture.ARM],
        cases=list(reversed(first_manifest.cases)),
    )
    assert reversed_manifest.id == first_manifest.id
    assert reversed_manifest.cases == first_manifest.cases


@pytest.mark.parametrize(
    "model_factory",
    [_ground_truth, _positive_case, _manifest],
)
def test_semantic_model_id_tampering_is_rejected(model_factory) -> None:
    model = model_factory()
    values = model.model_dump(mode="json")
    values["id"] = "tampered-id"

    with pytest.raises(ValidationError, match="ID is not deterministic"):
        type(model).model_validate(values)


def test_manifest_rejects_duplicate_cases_and_ground_truth_chains() -> None:
    case = _positive_case()
    with pytest.raises(ValidationError, match="case IDs must be unique"):
        BenchmarkManifest.create(
            benchmark_version=BENCHMARK_VERSION,
            architecture_scope=[Architecture.ARM],
            cases=[case, case],
        )

    other_values = case.model_dump(mode="json")
    other = EvaluationBenchmarkCase.create(
        benchmark_version=other_values["benchmark_version"],
        architecture=other_values["architecture"],
        source_kind=other_values["source_kind"],
        label=other_values["label"],
        artifact=_artifact(positive=False),
        ground_truth_chains=[_ground_truth()],
        source_reference_ids=other_values["source_reference_ids"],
        evaluation_scope=other_values["evaluation_scope"],
        metadata=other_values["metadata"],
    )
    with pytest.raises(ValidationError, match="Ground Truth chain IDs"):
        BenchmarkManifest.create(
            benchmark_version=BENCHMARK_VERSION,
            architecture_scope=[Architecture.ARM],
            cases=[case, other],
        )


def test_manifest_scope_is_arm_only_and_predeclared_in_case_identity() -> None:
    case = _positive_case()
    changed = case.model_dump(mode="json")
    changed["evaluation_scope"] = EvaluationScope.SECONDARY_ONLY.value
    with pytest.raises(ValidationError, match="ID is not deterministic"):
        EvaluationBenchmarkCase.model_validate(changed)

    with pytest.raises(ValidationError, match="ARM-only"):
        BenchmarkManifest.create(
            benchmark_version=BENCHMARK_VERSION,
            architecture_scope=[Architecture.RISC_V],
            cases=[case],
        )


def test_json_roundtrip_unknown_fields_and_fixture_manifest() -> None:
    manifest = _manifest()
    assert BenchmarkManifest.model_validate_json(
        manifest.model_dump_json()
    ) == manifest

    values = manifest.model_dump(mode="json")
    values["future_metric"] = 0.8
    with pytest.raises(ValidationError, match="Extra inputs"):
        BenchmarkManifest.model_validate(values)

    loaded = BenchmarkManifest.model_validate_json(FIXTURE.read_text("utf-8"))
    assert loaded == manifest
    assert loaded.model_dump_json() == manifest.model_dump_json()


def test_contracts_create_no_attack_chain_verification_or_metric_outcome() -> None:
    candidate = FinalizedCandidateBuilder().from_reasoning_session(
        _positive_case().id,
        _session(interaction=_interaction()),
    )
    manifest = _manifest()
    outputs = [candidate, manifest, *manifest.cases]
    serialized = json.dumps(
        [item.model_dump(mode="json") for item in outputs],
        sort_keys=True,
    )

    assert not any(isinstance(item, AttackChain) for item in outputs)
    assert not any(isinstance(item, VerificationRecord) for item in outputs)
    for forbidden in (
        "feasibility_status",
        "verification_status",
        "verified",
        "hit_rate",
        "metric_result",
    ):
        assert forbidden not in serialized
