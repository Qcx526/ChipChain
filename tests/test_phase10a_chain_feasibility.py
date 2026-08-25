"""Phase 10A Step 2 candidate-side objective oracle tests."""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.agents import AgentWorkflow, ReasoningContext
from chipchain.evaluation import (
    BenchmarkArtifactReference,
    ChainFeasibilityAssessment,
    ChainFeasibilityBindingError,
    ChainFeasibilityOracle,
    ChainFeasibilityReason,
    ChainFeasibilityStatus,
    FinalizedCandidateBuilder,
    FinalizedCandidateRecord,
    GroundTruthChain,
    InvalidChainFeasibilityInputError,
    ObjectiveEvaluationFailure,
    ObjectiveFailureStage,
)
from chipchain.hardware_trigger import (
    ArmExecutionMode,
    HardwareTriggerSignature,
    RuntimeFirmwareTriggerMatcher,
    RuntimeInstructionOccurrence,
    RuntimeTriggerExecutionTrace,
    StaticFirmwareTriggerMatch,
    StaticFirmwareTriggerMatchResult,
    TriggerabilityAggregationResult,
    TriggerabilityAggregator,
    TriggerabilityStatus,
)
from chipchain.models import (
    Architecture,
    AttackChain,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Layer,
)
from chipchain.runtime.qemu import QemuTriggerRawTraceParser
from chipchain.verification.models import VerificationRecord


ROOT = Path(__file__).resolve().parents[1]
PHASE9C_FIXTURE = (
    ROOT / "tests" / "fixtures" / "phase9c" / "arm_a32_trigger_runtime"
)
RAW_TRACE = (
    ROOT
    / "tests"
    / "fixtures"
    / "qemu_trigger_raw"
    / "valid_arm_a32_trigger_trace.jsonl"
)
TRUTH = json.loads((PHASE9C_FIXTURE / "ground_truth.json").read_text("utf-8"))
SIGNATURE = HardwareTriggerSignature.model_validate_json(
    (PHASE9C_FIXTURE / "hardware_trigger_signature.json").read_text("utf-8")
)
CASE_ID = "evaluation-benchmark-case:owned-phase10a-positive"


def _artifact(
    *,
    artifact_id: str | None = None,
    artifact_sha256: str | None = None,
) -> BenchmarkArtifactReference:
    return BenchmarkArtifactReference(
        artifact_id=artifact_id or str(TRUTH["artifact_id"]),
        architecture=Architecture.ARM,
        artifact_type="elf",
        artifact_sha256=artifact_sha256 or str(TRUTH["artifact_sha256"]),
        artifact_reference=(
            "tests/fixtures/phase9c/arm_a32_trigger_runtime/"
            "arm_a32_trigger_runtime.elf"
        ),
    )


def _interaction(
    interaction_type: CrossLayerInteractionType = (
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
    ),
    *,
    target_hardware_vulnerability_id: str | None = None,
    suffix: str = "base",
) -> CrossLayerInteraction:
    hardware_vulnerability_id = (
        target_hardware_vulnerability_id
        or SIGNATURE.hardware_vulnerability_id
    )
    if (
        interaction_type
        is CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
    ):
        return CrossLayerInteraction.create(
            architecture=Architecture.ARM,
            interaction_type=interaction_type,
            source_layer=Layer.FIRMWARE,
            target_layer=Layer.HARDWARE,
            initiating_vulnerability_ids=[f"synthetic-firmware-vulnerability-{suffix}"],
            target_vulnerability_ids=[hardware_vulnerability_id],
            trigger_behavior_ids=[f"synthetic-exact-trigger-{suffix}"],
            referenced_architectures=[Architecture.ARM],
            metadata={"candidate_side_context": True},
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
            initiating_vulnerability_ids=[hardware_vulnerability_id],
            affected_execution_ids=[f"synthetic-affected-execution-{suffix}"],
            referenced_architectures=[Architecture.ARM],
            metadata={"candidate_side_context": True},
        )
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=interaction_type,
        source_layer=Layer.FIRMWARE,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=[hardware_vulnerability_id],
        trigger_behavior_ids=[f"synthetic-exact-trigger-{suffix}"],
        hardware_resource_ids=["synthetic-owned-arm-execution-core"],
        referenced_architectures=[Architecture.ARM],
        metadata={"candidate_side_context": True},
    )


def _candidate(
    interaction: CrossLayerInteraction | None,
    *,
    case_id: str = CASE_ID,
) -> FinalizedCandidateRecord:
    context = ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="synthetic-phase10a-objective-candidate",
        affected_components=[
            "synthetic-owned-arm-firmware",
            "synthetic-owned-arm-hardware",
        ],
        observed_fact_ids=["synthetic-candidate-side-fact"],
        available_evidence_ids=["synthetic-reference-only-evidence"],
        attack_pattern_reference="synthetic-attack-pattern",
        cross_layer_interaction=interaction,
        metadata={"fixture": True},
    )
    return FinalizedCandidateBuilder.from_reasoning_session(
        case_id,
        AgentWorkflow().execute(context),
    )


def _triggerability(
    status: TriggerabilityStatus,
    *,
    artifact_id: str | None = None,
    artifact_sha256: str | None = None,
    hardware_vulnerability_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> TriggerabilityAggregationResult:
    if status is TriggerabilityStatus.NO_STATIC_TRIGGER_MATCH:
        static_ids: list[str] = []
        runtime_ids: list[str] = []
        declared = False
    elif status is TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME:
        static_ids = ["static-firmware-trigger-match:fixture"]
        runtime_ids = []
        declared = False
    else:
        static_ids = ["static-firmware-trigger-match:fixture"]
        runtime_ids = ["runtime-firmware-trigger-occurrence:fixture"]
        declared = (
            status
            is TriggerabilityStatus.INSUFFICIENT_PRECONDITION_EVIDENCE
        )
    return TriggerabilityAggregationResult.create(
        signature_id=SIGNATURE.id,
        hardware_vulnerability_id=(
            hardware_vulnerability_id or SIGNATURE.hardware_vulnerability_id
        ),
        architecture=Architecture.ARM,
        execution_mode=ArmExecutionMode.A32,
        artifact_id=artifact_id or str(TRUTH["artifact_id"]),
        artifact_sha256=artifact_sha256 or str(TRUTH["artifact_sha256"]),
        trace_id="runtime-trigger-execution-trace:phase10a-fixture",
        raw_trace_sha256="1" * 64,
        static_result_sha256="2" * 64,
        runtime_result_sha256="3" * 64,
        static_match_ids=static_ids,
        runtime_occurrence_ids=runtime_ids,
        declared_preconditions_present=declared,
        metadata=metadata or {"fixture": True},
    )


def _owned_phase9c_triggerability() -> TriggerabilityAggregationResult:
    matches = [
        StaticFirmwareTriggerMatch.create(
            artifact_id=str(TRUTH["artifact_id"]),
            artifact_sha256=str(TRUTH["artifact_sha256"]),
            signature_id=SIGNATURE.id,
            hardware_vulnerability_id=SIGNATURE.hardware_vulnerability_id,
            architecture=Architecture.ARM,
            execution_mode=ArmExecutionMode.A32,
            function_address=item["function_address"],
            function_name=item["function"],
            instruction_locations=[
                {
                    "instruction_address": address,
                    "instruction_word": word,
                    "basic_block_address": item["function_address"],
                }
                for address, word in zip(
                    item["instruction_addresses"],
                    item["instruction_words"],
                    strict=True,
                )
            ],
            basic_block_path=[item["function_address"]],
            metadata={"fixture": True},
        )
        for item in TRUTH["static_occurrences"]
    ]
    static = StaticFirmwareTriggerMatchResult(
        artifact_id=str(TRUTH["artifact_id"]),
        artifact_sha256=str(TRUTH["artifact_sha256"]),
        signature_id=SIGNATURE.id,
        hardware_vulnerability_id=SIGNATURE.hardware_vulnerability_id,
        architecture=Architecture.ARM,
        execution_mode=ArmExecutionMode.A32,
        matches=matches,
        diagnostics=["owned_synthetic_phase10a_acceptance"],
    )
    parsed = QemuTriggerRawTraceParser().parse(RAW_TRACE)
    runtime_trace = RuntimeTriggerExecutionTrace.create(
        raw_trace_id=parsed.id,
        raw_trace_sha256=parsed.raw_trace_sha256,
        run_id=parsed.header.run_id,
        scenario_id="owned-phase10a-objective-scenario",
        artifact_id=static.artifact_id,
        artifact_sha256=static.artifact_sha256,
        architecture=static.architecture,
        execution_mode=static.execution_mode,
        instructions=[
            RuntimeInstructionOccurrence.create(
                sequence_index=item.sequence_index,
                pc=f"0x{int(item.pc.value, 16):08x}",
                instruction_size=item.instruction_size,
                instruction_bytes=item.instruction_bytes,
            )
            for item in parsed.events
        ],
        metadata={"fixture": True},
    )
    runtime = RuntimeFirmwareTriggerMatcher().match(static, runtime_trace)
    return TriggerabilityAggregator().aggregate(SIGNATURE, static, runtime)


def _assess(
    interaction_type: CrossLayerInteractionType,
    triggerability_status: TriggerabilityStatus | None,
) -> ChainFeasibilityAssessment:
    interaction = _interaction(interaction_type)
    return ChainFeasibilityOracle().assess(
        _candidate(interaction),
        _artifact(),
        candidate_interaction=interaction,
        triggerability=(
            _triggerability(triggerability_status)
            if triggerability_status is not None
            else None
        ),
    )


def test_owned_synthetic_type_ii_candidate_is_confirmed_feasible() -> None:
    """Confirmed only under owned synthetic declared candidate/trigger contracts."""

    interaction = _interaction()
    triggerability = _owned_phase9c_triggerability()
    assessment = ChainFeasibilityOracle().assess(
        _candidate(interaction),
        _artifact(),
        candidate_interaction=interaction,
        triggerability=triggerability,
    )

    assert assessment.status is ChainFeasibilityStatus.CONFIRMED_FEASIBLE
    assert assessment.reason_codes == [
        ChainFeasibilityReason.TYPE_II_OBJECTIVELY_TRIGGERABLE
    ]
    assert triggerability.status is TriggerabilityStatus.TRIGGERABLE
    assert assessment.triggerability_aggregation_id == triggerability.id


@pytest.mark.parametrize(
    ("triggerability_status", "expected_status", "expected_reason"),
    [
        (
            TriggerabilityStatus.NO_STATIC_TRIGGER_MATCH,
            ChainFeasibilityStatus.NOT_SUPPORTED,
            ChainFeasibilityReason.NO_STATIC_TRIGGER_MATCH,
        ),
        (
            TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME,
            ChainFeasibilityStatus.UNRESOLVED,
            ChainFeasibilityReason.RUNTIME_TRIGGER_NOT_OBSERVED,
        ),
        (
            TriggerabilityStatus.INSUFFICIENT_PRECONDITION_EVIDENCE,
            ChainFeasibilityStatus.UNRESOLVED,
            ChainFeasibilityReason.PRECONDITION_EVIDENCE_INSUFFICIENT,
        ),
    ],
)
def test_type_ii_non_success_mapping(
    triggerability_status: TriggerabilityStatus,
    expected_status: ChainFeasibilityStatus,
    expected_reason: ChainFeasibilityReason,
) -> None:
    assessment = _assess(
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        triggerability_status,
    )

    assert assessment.status is expected_status
    assert assessment.reason_codes == [expected_reason]


def test_typed_type_ii_missing_triggerability_is_unresolved() -> None:
    assessment = _assess(
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        None,
    )

    assert assessment.status is ChainFeasibilityStatus.UNRESOLVED
    assert assessment.reason_codes == [
        ChainFeasibilityReason.TRIGGERABILITY_RESULT_MISSING
    ]


def test_candidate_without_typed_interaction_is_unresolved() -> None:
    assessment = ChainFeasibilityOracle().assess(_candidate(None), _artifact())

    assert assessment.status is ChainFeasibilityStatus.UNRESOLVED
    assert assessment.interaction_id is None
    assert assessment.reason_codes == [
        ChainFeasibilityReason.CANDIDATE_TYPED_INTERACTION_MISSING
    ]


def test_untyped_candidate_cannot_silently_consume_triggerability() -> None:
    with pytest.raises(ChainFeasibilityBindingError, match="untyped candidate"):
        ChainFeasibilityOracle().assess(
            _candidate(None),
            _artifact(),
            triggerability=_triggerability(TriggerabilityStatus.TRIGGERABLE),
        )


def test_interaction_identity_mismatch_fails_closed() -> None:
    bound = _interaction(suffix="bound")
    different = _interaction(suffix="different")

    with pytest.raises(ChainFeasibilityBindingError, match="interaction binding"):
        ChainFeasibilityOracle().assess(
            _candidate(bound),
            _artifact(),
            candidate_interaction=different,
        )


def test_interaction_type_and_direction_mismatch_fails_closed() -> None:
    bound = _interaction()
    type_one = _interaction(
        CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
    )

    with pytest.raises(ChainFeasibilityBindingError, match="interaction binding"):
        ChainFeasibilityOracle().assess(
            _candidate(bound),
            _artifact(),
            candidate_interaction=type_one,
        )


def test_candidate_artifact_architecture_mismatch_fails_closed() -> None:
    interaction = _interaction()
    candidate = _candidate(interaction)
    candidate.__dict__["architecture"] = Architecture.RISC_V

    with pytest.raises(InvalidChainFeasibilityInputError, match="revalidation"):
        ChainFeasibilityOracle().assess(
            candidate,
            _artifact(),
            candidate_interaction=interaction,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [("artifact_id", "different-artifact"), ("artifact_sha256", "f" * 64)],
)
def test_triggerability_artifact_mismatch_fails_closed(
    field: str,
    value: str,
) -> None:
    interaction = _interaction()
    changes = {field: value}

    with pytest.raises(ChainFeasibilityBindingError, match="artifact binding"):
        ChainFeasibilityOracle().assess(
            _candidate(interaction),
            _artifact(),
            candidate_interaction=interaction,
            triggerability=_triggerability(
                TriggerabilityStatus.TRIGGERABLE,
                **changes,
            ),
        )


def test_triggerability_target_hardware_vulnerability_must_be_explicit() -> None:
    interaction = _interaction()

    with pytest.raises(ChainFeasibilityBindingError, match="interaction target"):
        ChainFeasibilityOracle().assess(
            _candidate(interaction),
            _artifact(),
            candidate_interaction=interaction,
            triggerability=_triggerability(
                TriggerabilityStatus.TRIGGERABLE,
                hardware_vulnerability_id="different-hardware-vulnerability",
            ),
        )


@pytest.mark.parametrize(
    "triggerability_status",
    [
        TriggerabilityStatus.TRIGGERABLE,
        TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME,
        TriggerabilityStatus.INSUFFICIENT_PRECONDITION_EVIDENCE,
        None,
    ],
)
def test_type_i_never_confirms_from_triggerability_alone(
    triggerability_status: TriggerabilityStatus | None,
) -> None:
    assessment = _assess(
        CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
        triggerability_status,
    )

    assert assessment.status is ChainFeasibilityStatus.UNRESOLVED
    assert assessment.status is not ChainFeasibilityStatus.CONFIRMED_FEASIBLE
    assert (
        ChainFeasibilityReason.TYPE_I_SOFTWARE_VULNERABILITY_TO_TRIGGER_LINK_NOT_IMPLEMENTED
        in assessment.reason_codes
    )


def test_type_i_no_static_trigger_match_is_not_supported() -> None:
    assessment = _assess(
        CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
        TriggerabilityStatus.NO_STATIC_TRIGGER_MATCH,
    )

    assert assessment.status is ChainFeasibilityStatus.NOT_SUPPORTED
    assert assessment.reason_codes == [
        ChainFeasibilityReason.NO_STATIC_TRIGGER_MATCH
    ]


def test_type_iii_is_unsupported_and_cannot_consume_triggerability() -> None:
    interaction = _interaction(
        CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE
    )
    candidate = _candidate(interaction)
    oracle = ChainFeasibilityOracle()

    assessment = oracle.assess(
        candidate,
        _artifact(),
        candidate_interaction=interaction,
    )
    assert assessment.status is ChainFeasibilityStatus.UNSUPPORTED
    assert assessment.reason_codes == [
        ChainFeasibilityReason.TYPE_III_OBJECTIVE_PROPAGATION_NOT_IMPLEMENTED
    ]

    with pytest.raises(ChainFeasibilityBindingError, match="Type III"):
        oracle.assess(
            candidate,
            _artifact(),
            candidate_interaction=interaction,
            triggerability=_triggerability(TriggerabilityStatus.TRIGGERABLE),
        )


def test_explicit_valid_infrastructure_failure_is_distinct() -> None:
    interaction = _interaction()
    candidate = _candidate(interaction)
    failure = ObjectiveEvaluationFailure.create(
        candidate_id=candidate.id,
        benchmark_case_id=candidate.benchmark_case_id,
        architecture=candidate.architecture,
        stage=ObjectiveFailureStage.RUNTIME_TRIGGER_EXECUTION,
        failure_code="QEMU_EXECUTION_TIMEOUT",
        metadata={"bounded_diagnostic_code": "timeout"},
    )

    assessment = ChainFeasibilityOracle().assess(
        candidate,
        _artifact(),
        candidate_interaction=interaction,
        infrastructure_failure=failure,
    )

    assert assessment.status is ChainFeasibilityStatus.INFRA_FAILURE
    assert assessment.infrastructure_failure_id == failure.id
    assert assessment.reason_codes == [
        ChainFeasibilityReason.OBJECTIVE_INFRASTRUCTURE_FAILURE
    ]


def test_invalid_failure_or_programmer_error_does_not_become_infra_failure() -> None:
    interaction = _interaction()
    candidate = _candidate(interaction)
    failure = ObjectiveEvaluationFailure.create(
        candidate_id=candidate.id,
        benchmark_case_id=candidate.benchmark_case_id,
        architecture=candidate.architecture,
        stage=ObjectiveFailureStage.STATIC_TRIGGER_MATCHING,
        failure_code="TOOL_START_FAILED",
    )
    failure.__dict__["id"] = "tampered-failure"

    with pytest.raises(InvalidChainFeasibilityInputError, match="revalidation"):
        ChainFeasibilityOracle().assess(
            candidate,
            _artifact(),
            candidate_interaction=interaction,
            infrastructure_failure=failure,
        )
    with pytest.raises(InvalidChainFeasibilityInputError):
        ChainFeasibilityOracle().assess(
            candidate,
            _artifact(),
            candidate_interaction=interaction,
            triggerability=object(),
        )


@pytest.mark.parametrize(
    "metadata",
    [
        {"raw_stderr": "unbounded output"},
        {"stack_trace": "trace"},
        {"api_key": "secret"},
        {"diagnostic": "/home/user/private/path"},
    ],
)
def test_infrastructure_failure_rejects_sensitive_diagnostics(
    metadata: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="forbidden|host paths"):
        ObjectiveEvaluationFailure.create(
            candidate_id="finalized-candidate:fixture",
            benchmark_case_id=CASE_ID,
            architecture=Architecture.ARM,
            stage=ObjectiveFailureStage.OTHER_OBJECTIVE_INFRASTRUCTURE,
            failure_code="BOUNDED_FAILURE",
            metadata=metadata,
        )


def test_caller_mutation_and_confidence_do_not_change_assessment() -> None:
    interaction = _interaction()
    candidate = _candidate(interaction)
    changed_values = candidate.model_dump(mode="json")
    changed_values["model_confidence"] = 0.95
    confidence_changed = FinalizedCandidateRecord.model_validate(changed_values)
    triggerability = _triggerability(TriggerabilityStatus.TRIGGERABLE)
    oracle = ChainFeasibilityOracle()
    first = oracle.assess(
        candidate,
        _artifact(),
        candidate_interaction=interaction,
        triggerability=triggerability,
    )
    second = oracle.assess(
        confidence_changed,
        _artifact(),
        candidate_interaction=interaction,
        triggerability=triggerability,
    )
    original = first.model_dump_json()

    candidate.metadata["caller_mutation"] = True
    interaction.metadata["caller_mutation"] = True
    triggerability.metadata["caller_mutation"] = True

    assert first.id == second.id
    assert first.status is second.status
    assert first.model_dump_json() == original


def test_assessment_metadata_identity_tamper_and_status_validation() -> None:
    assessment = _assess(
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        TriggerabilityStatus.TRIGGERABLE,
    )
    metadata_changed = assessment.model_dump(mode="json")
    metadata_changed["metadata"] = {"non_semantic": "changed"}
    assert ChainFeasibilityAssessment.model_validate(metadata_changed).id == (
        assessment.id
    )

    forbidden_metadata = assessment.model_dump(mode="json")
    forbidden_metadata["metadata"] = {"verification_score": 1.0}
    with pytest.raises(ValidationError, match="verdict or metric"):
        ChainFeasibilityAssessment.model_validate(forbidden_metadata)

    tampered_id = assessment.model_dump(mode="json")
    tampered_id["id"] = "chain-feasibility-assessment:tampered"
    with pytest.raises(ValidationError, match="ID is not deterministic"):
        ChainFeasibilityAssessment.model_validate(tampered_id)

    changed_status = assessment.model_dump(mode="json")
    changed_status["status"] = ChainFeasibilityStatus.NOT_SUPPORTED.value
    with pytest.raises(ValidationError, match="oracle-derived"):
        ChainFeasibilityAssessment.model_validate(changed_status)


def test_repeated_assessment_json_roundtrip_and_unknown_fields() -> None:
    interaction = _interaction()
    candidate = _candidate(interaction)
    triggerability = _triggerability(TriggerabilityStatus.TRIGGERABLE)
    oracle = ChainFeasibilityOracle()
    first = oracle.assess(
        candidate,
        _artifact(),
        candidate_interaction=interaction,
        triggerability=triggerability,
    )
    second = oracle.assess(
        candidate,
        _artifact(),
        candidate_interaction=interaction,
        triggerability=triggerability,
    )

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert ChainFeasibilityAssessment.model_validate_json(
        first.model_dump_json()
    ) == first
    values = first.model_dump(mode="json")
    values["hit_rate"] = 1.0
    with pytest.raises(ValidationError, match="Extra inputs"):
        ChainFeasibilityAssessment.model_validate(values)


def test_ground_truth_is_outside_oracle_signature_imports_and_behavior() -> None:
    signature = inspect.signature(ChainFeasibilityOracle.assess)
    assert list(signature.parameters) == [
        "self",
        "candidate",
        "artifact",
        "candidate_interaction",
        "triggerability",
        "infrastructure_failure",
    ]
    source_path = ROOT / "src" / "chipchain" / "evaluation" / "oracle.py"
    tree = ast.parse(source_path.read_text("utf-8"))
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert {
        "GroundTruthChain",
        "EvaluationBenchmarkCase",
        "BenchmarkManifest",
    }.isdisjoint(imported_names)

    interaction = _interaction()
    candidate = _candidate(interaction)
    triggerability = _triggerability(TriggerabilityStatus.TRIGGERABLE)
    first_truth = GroundTruthChain.create(
        cross_layer_interaction=_interaction(suffix="truth-one"),
        source_reference_ids=["fixture:truth-one"],
    )
    second_truth = GroundTruthChain.create(
        cross_layer_interaction=_interaction(suffix="truth-two"),
        source_reference_ids=["fixture:truth-two"],
    )
    assert first_truth.id != second_truth.id
    oracle = ChainFeasibilityOracle()
    first = oracle.assess(
        candidate,
        _artifact(),
        candidate_interaction=interaction,
        triggerability=triggerability,
    )
    second = oracle.assess(
        candidate,
        _artifact(),
        candidate_interaction=interaction,
        triggerability=triggerability,
    )
    assert first == second
    with pytest.raises(TypeError):
        oracle.assess(
            candidate,
            _artifact(),
            candidate_interaction=interaction,
            triggerability=triggerability,
            ground_truth=first_truth,
        )


def test_assessment_creates_no_domain_truth_scoring_or_metrics() -> None:
    assessment = _assess(
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
        TriggerabilityStatus.TRIGGERABLE,
    )
    serialized = assessment.model_dump(mode="json")

    assert not isinstance(assessment, AttackChain)
    assert not isinstance(assessment, VerificationRecord)
    assert {
        "confidence",
        "score",
        "verified",
        "attack_chain",
        "verification_record",
        "vulnerability_status",
        "probability",
        "hit_rate",
        "recall",
        "coverage",
    }.isdisjoint(serialized)
    assert {item.value for item in ChainFeasibilityStatus} == {
        "confirmed_feasible",
        "not_supported",
        "unresolved",
        "unsupported",
        "infra_failure",
    }
