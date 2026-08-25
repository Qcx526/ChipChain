"""Phase 10A Step 3 model-authored claim and binding contract tests."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.agents import (
    AgentWorkflow,
    HypothesisMergeConflict,
    MultiAgentReasoningCoordinator,
    ProviderBackedAgentWorkflow,
    ReasoningContext,
)
from chipchain.evaluation import (
    BenchmarkArtifactReference,
    ChainFeasibilityOracle,
    ChainFeasibilityStatus,
    FinalizedCandidateBuilder,
    InvalidModelClaimBindingInputError,
    ModelClaimBinder,
    ModelClaimBindingAssessment,
    ModelClaimBindingError,
    ModelClaimBindingReason,
    ModelClaimBindingStatus,
    model_claim_binding_assessment_id,
)
from chipchain.hardware_trigger import (
    ArmExecutionMode,
    TriggerabilityAggregationResult,
    TriggerabilityStatus,
)
from chipchain.models import (
    Architecture,
    AttackChain,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Layer,
)
from chipchain.reasoning import (
    AttackHypothesis,
    ConstrainedReasoningOutputParser,
    EvidenceCategory,
    HypothesisSource,
    LLMOutputValidationError,
    MockReasoningProvider,
    ModelAuthoredChainClaim,
    ReasoningAgentType,
    ReasoningEngine,
    ReasoningProvider,
    RoleBasedReasoningPromptBuilder,
    StructuredPromptRequest,
)
from chipchain.verification.models import VerificationRecord


ROOT = Path(__file__).resolve().parents[1]
CASE_ID = "evaluation-benchmark-case:owned-phase10a-step3"
ARTIFACT_ID = "synthetic-phase10a-step3-arm-elf"
ARTIFACT_SHA256 = "a" * 64


def _interaction(
    interaction_type: CrossLayerInteractionType = (
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
    ),
    *,
    suffix: str = "a",
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
            initiating_vulnerability_ids=[f"synthetic-sw-vulnerability-{suffix}"],
            target_vulnerability_ids=[f"synthetic-hw-vulnerability-{suffix}"],
            trigger_behavior_ids=[f"synthetic-trigger-{suffix}"],
            propagation_behavior_ids=[f"synthetic-propagation-{suffix}"],
            hardware_resource_ids=[f"synthetic-resource-{suffix}"],
            referenced_architectures=[Architecture.ARM],
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
            initiating_vulnerability_ids=[f"synthetic-hw-vulnerability-{suffix}"],
            affected_execution_ids=[f"synthetic-execution-{suffix}"],
            fault_state_ids=[f"synthetic-fault-{suffix}"],
            referenced_architectures=[Architecture.ARM],
        )
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=interaction_type,
        source_layer=Layer.FIRMWARE,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=[f"synthetic-hw-vulnerability-{suffix}"],
        trigger_behavior_ids=[f"synthetic-trigger-{suffix}"],
        propagation_behavior_ids=[f"synthetic-propagation-{suffix}"],
        hardware_resource_ids=[f"synthetic-resource-{suffix}"],
        security_mechanism_ids=[f"synthetic-mechanism-{suffix}"],
        referenced_architectures=[Architecture.ARM],
    )


def _claim_payload(
    interaction: CrossLayerInteraction,
    **overrides: object,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "interaction_type": interaction.interaction_type.value,
        "initiating_vulnerability_ids": list(
            interaction.initiating_vulnerability_ids
        ),
        "target_vulnerability_ids": list(interaction.target_vulnerability_ids),
        "trigger_behavior_ids": list(interaction.trigger_behavior_ids),
        "propagation_behavior_ids": list(
            interaction.propagation_behavior_ids
        ),
        "affected_execution_ids": list(interaction.affected_execution_ids),
        "fault_state_ids": list(interaction.fault_state_ids),
        "hardware_resource_ids": list(interaction.hardware_resource_ids),
        "security_mechanism_ids": list(interaction.security_mechanism_ids),
    }
    payload.update(overrides)
    return payload


def _claim(
    interaction: CrossLayerInteraction,
    **overrides: object,
) -> ModelAuthoredChainClaim:
    payload = _claim_payload(interaction, **overrides)
    return ModelAuthoredChainClaim.create(
        architecture=Architecture.ARM,
        author_role=ReasoningAgentType.ATTACK_CHAIN,
        **payload,
    )


def _context(
    interaction: CrossLayerInteraction | None,
) -> ReasoningContext:
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="synthetic-phase10a-step3-subject",
        affected_components=["synthetic-arm-firmware", "synthetic-arm-core"],
        observed_fact_ids=["synthetic-context-fact"],
        available_evidence_ids=["synthetic-reference-only-evidence"],
        attack_pattern_reference="synthetic-attack-pattern",
        cross_layer_interaction=interaction,
        metadata={"fixture": True, "owned": True, "synthetic": True},
    )


class _ClaimProvider(ReasoningProvider):
    """Offline provider that authors an optional fixture claim at one role."""

    def __init__(
        self,
        claim_payload: dict[str, object] | None,
        *,
        claim_role: ReasoningAgentType = ReasoningAgentType.ATTACK_CHAIN,
        hypothesis_confidence: float = 0.0,
    ) -> None:
        self.claim_payload = claim_payload
        self.claim_role = claim_role
        self.hypothesis_confidence = hypothesis_confidence
        self.delegate = MockReasoningProvider()

    def generate(self, request: StructuredPromptRequest) -> str:
        payload = json.loads(self.delegate.generate(request))
        role = ReasoningAgentType(request.role)
        payload["hypothesis"]["confidence"] = self.hypothesis_confidence
        if self.claim_payload is not None and role is self.claim_role:
            payload["hypothesis"]["chain_claim"] = self.claim_payload
        return json.dumps(payload, sort_keys=True)


def _session(
    interaction: CrossLayerInteraction | None,
    claim_payload: dict[str, object] | None,
    *,
    confidence: float = 0.0,
):
    return ProviderBackedAgentWorkflow(
        engine=ReasoningEngine(
            provider=_ClaimProvider(
                claim_payload,
                hypothesis_confidence=confidence,
            )
        )
    ).execute(_context(interaction))


def _candidate(
    interaction: CrossLayerInteraction | None,
    claim_payload: dict[str, object] | None,
    *,
    confidence: float = 0.0,
):
    return FinalizedCandidateBuilder.from_reasoning_session(
        CASE_ID,
        _session(interaction, claim_payload, confidence=confidence),
    )


def _legacy_hash(prefix: str, payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(serialized).hexdigest()}"


def test_claim_is_proposal_shaped_deterministic_and_metadata_neutral() -> None:
    interaction = _interaction()
    incomplete = _claim(interaction, trigger_behavior_ids=[])
    metadata_changed = ModelAuthoredChainClaim.create(
        architecture=Architecture.ARM,
        author_role=ReasoningAgentType.ATTACK_CHAIN,
        metadata={"fixture_note": "nonsemantic"},
        **_claim_payload(interaction, trigger_behavior_ids=[]),
    )
    changed_participant = _claim(
        interaction,
        target_vulnerability_ids=["synthetic-hw-vulnerability-b"],
    )

    assert incomplete.trigger_behavior_ids == []
    assert incomplete.id == metadata_changed.id
    assert changed_participant.id != _claim(interaction).id
    assert not isinstance(incomplete, CrossLayerInteraction)
    assert not isinstance(incomplete, AttackChain)


def test_claim_rejects_system_or_verdict_fields_but_not_semantic_errors() -> None:
    interaction = _interaction()
    type_two_with_initiator = _claim(
        interaction,
        initiating_vulnerability_ids=["synthetic-wrong-initiator"],
    )
    assert type_two_with_initiator.initiating_vulnerability_ids

    with pytest.raises(ValidationError, match="attack_chain role"):
        ModelAuthoredChainClaim.create(
            architecture=Architecture.ARM,
            author_role=ReasoningAgentType.CODE,
            **_claim_payload(interaction),
        )
    with pytest.raises(ValidationError, match="verdict fields"):
        ModelAuthoredChainClaim.create(
            architecture=Architecture.ARM,
            author_role=ReasoningAgentType.ATTACK_CHAIN,
            metadata={"verification_status": "verified"},
            **_claim_payload(interaction),
        )
    values = _claim(interaction).model_dump(mode="json")
    values["score"] = 1.0
    with pytest.raises(ValidationError, match="Extra inputs"):
        ModelAuthoredChainClaim.model_validate(values)


def test_attack_chain_provider_authors_exact_claim_without_reference_repair() -> None:
    interaction = _interaction(suffix="context-a")
    wrong_id = "synthetic-model-selected-hw-vulnerability-b"
    payload = _claim_payload(
        interaction,
        target_vulnerability_ids=[wrong_id],
    )
    session = _session(interaction, payload)
    attack_claims = [
        item.model_authored_chain_claim
        for item in session.hypotheses
        if item.model_authored_chain_claim is not None
    ]

    assert len(attack_claims) == 1
    assert attack_claims[0].target_vulnerability_ids == [wrong_id]
    assert interaction.target_vulnerability_ids != [wrong_id]
    assert attack_claims[0].architecture is Architecture.ARM
    assert attack_claims[0].author_role is ReasoningAgentType.ATTACK_CHAIN
    assert session.merged_hypothesis.model_authored_chain_claim == attack_claims[0]


def test_missing_provider_claim_remains_none_and_workflow_completes() -> None:
    interaction = _interaction()
    session = _session(interaction, None)

    assert all(
        item.model_authored_chain_claim is None for item in session.hypotheses
    )
    assert session.merged_hypothesis.model_authored_chain_claim is None
    assert len(session.hypotheses) == 4
    assert len(session.reasoning_results) == 3


def test_non_attack_role_claim_and_forbidden_claim_fields_fail_closed() -> None:
    context = _context(_interaction())
    parser = ConstrainedReasoningOutputParser()
    code_prompt = RoleBasedReasoningPromptBuilder().build(
        context,
        role=ReasoningAgentType.CODE,
    )
    raw = json.loads(MockReasoningProvider().generate(code_prompt))
    raw["hypothesis"]["chain_claim"] = _claim_payload(_interaction())
    with pytest.raises(LLMOutputValidationError) as role_error:
        parser.parse(
            json.dumps(raw),
            context=context,
            role=ReasoningAgentType.CODE,
        )
    assert role_error.value.stage == "role_authority"

    attack_prompt = RoleBasedReasoningPromptBuilder().build(
        context,
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    base = json.loads(MockReasoningProvider().generate(attack_prompt))
    for extra_field in ("verified", "score", "feasibility", "verdict"):
        invalid = json.loads(json.dumps(base))
        invalid["hypothesis"]["chain_claim"] = {
            **_claim_payload(_interaction()),
            extra_field: True,
        }
        with pytest.raises(LLMOutputValidationError) as truth_error:
            parser.parse(
                json.dumps(invalid),
                context=context,
                role=ReasoningAgentType.ATTACK_CHAIN,
            )
        assert truth_error.value.stage == "forbidden_truth_field"


def test_unknown_or_provider_controlled_claim_fields_fail_closed() -> None:
    context = _context(_interaction())
    parser = ConstrainedReasoningOutputParser()
    prompt = RoleBasedReasoningPromptBuilder().build(
        context,
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    base = json.loads(MockReasoningProvider().generate(prompt))
    for extra in (
        {"unknown_reference_kind": []},
        {"metadata": {"provider_authored": True}},
        {"architecture": "arm"},
        {"author_role": "attack_chain"},
        {"id": "provider-selected-id"},
    ):
        invalid = json.loads(json.dumps(base))
        invalid["hypothesis"]["chain_claim"] = {
            **_claim_payload(_interaction()),
            **extra,
        }
        with pytest.raises(LLMOutputValidationError) as exc_info:
            parser.parse(
                json.dumps(invalid),
                context=context,
                role=ReasoningAgentType.ATTACK_CHAIN,
            )
        assert exc_info.value.stage == "output_schema"


def test_prompt_exposes_claim_authority_only_to_attack_chain_role() -> None:
    context = _context(_interaction())
    builder = RoleBasedReasoningPromptBuilder()
    attack = builder.build(context, role=ReasoningAgentType.ATTACK_CHAIN)
    code = builder.build(context, role=ReasoningAgentType.CODE)
    attack_payload = json.loads(attack.user_prompt)
    code_payload = json.loads(code.user_prompt)

    assert "hypothesis.chain_claim.interaction_type" in (
        attack_payload["provider_authority"]["model_authored_fields"]
    )
    assert all(
        "chain_claim" not in item
        for item in code_payload["provider_authority"]["model_authored_fields"]
    )
    assert "unverified model proposal" in attack.system_prompt
    assert "must not emit hypothesis.chain_claim" in code.system_prompt
    assert "cross_layer_interaction" in attack_payload["reasoning_context"]


def test_provider_parser_has_no_ground_truth_input_or_import() -> None:
    parameters = inspect.signature(
        ConstrainedReasoningOutputParser.parse
    ).parameters
    assert list(parameters) == ["self", "raw_output", "context", "role"]
    tree = ast.parse(
        (ROOT / "src/chipchain/reasoning/parser.py").read_text("utf-8")
    )
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
        "EvaluationScope",
    }.isdisjoint(imported_names)


def test_coordinator_retains_exactly_one_claim_and_rejects_multiple() -> None:
    interaction = _interaction()
    claim = _claim(interaction)
    common = {
        "source": HypothesisSource.ANALYST,
        "architecture": Architecture.ARM,
        "affected_components": ["synthetic-arm-firmware"],
        "required_evidence_types": [EvidenceCategory.STATIC_BEHAVIOR],
        "confidence": 0.0,
    }
    with_claim = AttackHypothesis.create(
        **common,
        description="Synthetic claim-bearing hypothesis",
        model_authored_chain_claim=claim,
    )
    without_claim = AttackHypothesis.create(
        **common,
        description="Synthetic no-claim hypothesis",
    )
    coordinator = MultiAgentReasoningCoordinator()

    merged = coordinator.merge_hypotheses([without_claim, with_claim])
    assert merged.model_authored_chain_claim == claim
    with pytest.raises(HypothesisMergeConflict, match="at most one"):
        coordinator.merge_hypotheses([with_claim, with_claim])


def test_default_workflow_does_not_copy_context_into_model_authorship() -> None:
    interaction = _interaction()
    first = AgentWorkflow().execute(_context(interaction))
    second = AgentWorkflow().execute(_context(interaction))

    assert first == second
    assert first.reasoning_context.cross_layer_interaction is not None
    assert all(
        item.model_authored_chain_claim is None for item in first.hypotheses
    )
    assert first.merged_hypothesis.model_authored_chain_claim is None


def test_no_claim_hypothesis_identity_preserves_legacy_algorithm() -> None:
    hypothesis = AttackHypothesis.create(
        source=HypothesisSource.ANALYST,
        architecture=Architecture.ARM,
        description="Synthetic legacy identity hypothesis",
        affected_components=["synthetic-arm-core"],
        attack_pattern_reference="synthetic-attack-pattern",
        required_evidence_types=[EvidenceCategory.RUNTIME_OBSERVATION],
        confidence=0.7,
    )
    expected = _legacy_hash(
        "attack-hypothesis",
        {
            "architecture": "arm",
            "attack_pattern_reference": "synthetic-attack-pattern",
            "affected_components": ["synthetic-arm-core"],
            "description": "Synthetic legacy identity hypothesis",
            "required_evidence_types": ["runtime_observation"],
            "source": "analyst",
        },
    )

    assert hypothesis.model_authored_chain_claim is None
    assert hypothesis.id == expected


def test_no_claim_candidate_identity_preserves_legacy_algorithm() -> None:
    candidate = FinalizedCandidateBuilder.from_reasoning_session(
        CASE_ID,
        AgentWorkflow().execute(_context(_interaction())),
    )
    expected = _legacy_hash(
        "finalized-candidate",
        {
            "affected_components": candidate.affected_components,
            "architecture": candidate.architecture.value,
            "attack_pattern_reference": candidate.attack_pattern_reference,
            "benchmark_case_id": candidate.benchmark_case_id,
            "cross_layer_interaction_id": (
                candidate.cross_layer_interaction_id
            ),
            "direction": candidate.direction.value,
            "interaction_type": candidate.interaction_type.value,
            "merged_hypothesis_id": candidate.merged_hypothesis_id,
            "reasoning_context_id": candidate.reasoning_context_id,
            "reasoning_session_id": candidate.reasoning_session_id,
            "subject_id": candidate.subject_id,
            "workflow_contract": candidate.workflow_contract,
        },
    )

    assert candidate.model_authored_chain_claim is None
    assert candidate.id == expected


def test_finalized_candidate_retains_detached_claim_and_binds_identity() -> None:
    interaction = _interaction()
    first_payload = _claim_payload(interaction)
    second_payload = _claim_payload(
        interaction,
        target_vulnerability_ids=["synthetic-model-selected-other-target"],
    )
    session = _session(interaction, first_payload)
    first = FinalizedCandidateBuilder.from_reasoning_session(CASE_ID, session)
    second = _candidate(interaction, second_payload)
    original = first.model_dump_json()

    assert first.model_authored_chain_claim == (
        session.merged_hypothesis.model_authored_chain_claim
    )
    assert first.model_authored_chain_claim is not (
        session.merged_hypothesis.model_authored_chain_claim
    )
    assert first.id != second.id
    session.merged_hypothesis.model_authored_chain_claim.target_vulnerability_ids.append(
        "caller-mutation"
    )
    assert first.model_dump_json() == original


def test_candidate_confidence_is_nonsemantic_and_missing_claim_keeps_candidate() -> None:
    interaction = _interaction()
    payload = _claim_payload(interaction)
    low = _candidate(interaction, payload, confidence=0.1)
    high = _candidate(interaction, payload, confidence=0.9)
    missing = _candidate(interaction, None)

    assert low.id == high.id
    assert low.model_confidence == 0.1
    assert high.model_confidence == 0.9
    assert missing.model_authored_chain_claim is None


@pytest.mark.parametrize(
    ("interaction_type", "expected_status"),
    [
        (
            CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
            ModelClaimBindingStatus.ALIGNED,
        ),
        (
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
            ModelClaimBindingStatus.ALIGNED,
        ),
        (
            CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE,
            ModelClaimBindingStatus.ALIGNED,
        ),
    ],
)
def test_complete_type_i_ii_iii_claims_align(
    interaction_type: CrossLayerInteractionType,
    expected_status: ModelClaimBindingStatus,
) -> None:
    interaction = _interaction(interaction_type)
    candidate = _candidate(interaction, _claim_payload(interaction))
    result = ModelClaimBinder().assess(candidate, interaction)

    assert result.status is expected_status
    assert result.reason_codes == [ModelClaimBindingReason.CLAIM_ALIGNED]


def test_missing_claim_and_unbound_claim_remain_measurable() -> None:
    interaction = _interaction()
    missing = ModelClaimBinder().assess(_candidate(interaction, None))
    unbound_payload = _claim_payload(interaction)
    unbound = ModelClaimBinder().assess(_candidate(None, unbound_payload))

    assert missing.status is ModelClaimBindingStatus.MISSING
    assert missing.reason_codes == [
        ModelClaimBindingReason.MODEL_AUTHORED_CLAIM_MISSING
    ]
    assert unbound.status is ModelClaimBindingStatus.UNBOUND
    assert unbound.reason_codes == [
        ModelClaimBindingReason.CANDIDATE_TYPED_INTERACTION_MISSING
    ]


@pytest.mark.parametrize(
    ("interaction_type", "overrides"),
    [
        (
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
            {"target_vulnerability_ids": []},
        ),
        (
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE,
            {"trigger_behavior_ids": []},
        ),
        (
            CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
            {"initiating_vulnerability_ids": []},
        ),
        (
            CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE,
            {"affected_execution_ids": []},
        ),
    ],
)
def test_required_claim_omissions_are_incomplete(
    interaction_type: CrossLayerInteractionType,
    overrides: dict[str, object],
) -> None:
    interaction = _interaction(interaction_type)
    candidate = _candidate(
        interaction,
        _claim_payload(interaction, **overrides),
    )
    result = ModelClaimBinder().assess(candidate, interaction)

    assert result.status is ModelClaimBindingStatus.INCOMPLETE
    assert result.reason_codes == [
        ModelClaimBindingReason.CLAIM_REQUIRED_FIELDS_MISSING
    ]


def test_type_two_initiator_and_wrong_type_are_mismatched() -> None:
    interaction = _interaction()
    shape_conflict = _candidate(
        interaction,
        _claim_payload(
            interaction,
            initiating_vulnerability_ids=["synthetic-invented-sw-vulnerability"],
        ),
    )
    wrong_type_interaction = _interaction(
        CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
        suffix="wrong-type",
    )
    wrong_type = _candidate(
        interaction,
        _claim_payload(wrong_type_interaction),
    )

    shape_result = ModelClaimBinder().assess(shape_conflict, interaction)
    type_result = ModelClaimBinder().assess(wrong_type, interaction)
    assert shape_result.status is ModelClaimBindingStatus.MISMATCHED
    assert shape_result.reason_codes == [
        ModelClaimBindingReason.CLAIM_TYPE_SHAPE_CONFLICT
    ]
    assert type_result.status is ModelClaimBindingStatus.MISMATCHED
    assert type_result.reason_codes == [
        ModelClaimBindingReason.CLAIM_INTERACTION_TYPE_MISMATCH
    ]


@pytest.mark.parametrize(
    ("field", "reason"),
    [
        (
            "target_vulnerability_ids",
            ModelClaimBindingReason.CLAIM_TARGET_VULNERABILITY_MISMATCH,
        ),
        (
            "trigger_behavior_ids",
            ModelClaimBindingReason.CLAIM_TRIGGER_BEHAVIOR_MISMATCH,
        ),
    ],
)
def test_wrong_required_type_two_references_are_mismatched(
    field: str,
    reason: ModelClaimBindingReason,
) -> None:
    interaction = _interaction()
    candidate = _candidate(
        interaction,
        _claim_payload(interaction, **{field: [f"synthetic-wrong-{field}"]}),
    )
    result = ModelClaimBinder().assess(candidate, interaction)

    assert result.status is ModelClaimBindingStatus.MISMATCHED
    assert result.reason_codes == [reason]


def test_wrong_optional_reference_is_not_silently_ignored() -> None:
    interaction = _interaction()
    candidate = _candidate(
        interaction,
        _claim_payload(
            interaction,
            hardware_resource_ids=["synthetic-wrong-resource"],
        ),
    )
    result = ModelClaimBinder().assess(candidate, interaction)

    assert result.status is ModelClaimBindingStatus.MISMATCHED
    assert result.reason_codes == [
        ModelClaimBindingReason.CLAIM_OPTIONAL_REFERENCE_MISMATCH
    ]


def test_binding_rejects_invalid_or_contradictory_inputs() -> None:
    interaction = _interaction()
    candidate = _candidate(interaction, _claim_payload(interaction))
    candidate.__dict__["id"] = "tampered-candidate"
    with pytest.raises(InvalidModelClaimBindingInputError, match="revalidation"):
        ModelClaimBinder().assess(candidate, interaction)

    valid_candidate = _candidate(interaction, _claim_payload(interaction))
    with pytest.raises(ModelClaimBindingError, match="identity mismatch"):
        ModelClaimBinder().assess(valid_candidate, _interaction(suffix="other"))
    with pytest.raises(InvalidModelClaimBindingInputError, match="requires"):
        ModelClaimBinder().assess(valid_candidate)


def test_binding_identity_metadata_roundtrip_and_tamper_rejection() -> None:
    interaction = _interaction()
    candidate = _candidate(interaction, _claim_payload(interaction))
    first = ModelClaimBinder().assess(candidate, interaction)
    second = ModelClaimBinder().assess(candidate, interaction)
    metadata_changed = first.model_dump(mode="json")
    metadata_changed["metadata"] = {"fixture_note": "changed"}
    status_changed = first.model_dump(mode="json")
    status_changed["status"] = ModelClaimBindingStatus.MISMATCHED.value
    id_changed = first.model_dump(mode="json")
    id_changed["id"] = "model-claim-binding-assessment:tampered"

    assert first == second
    assert ModelClaimBindingAssessment.model_validate_json(
        first.model_dump_json()
    ) == first
    assert ModelClaimBindingAssessment.model_validate(metadata_changed).id == first.id
    with pytest.raises(ValidationError, match="status/reasons|deterministic"):
        ModelClaimBindingAssessment.model_validate(status_changed)
    with pytest.raises(ValidationError, match="ID is not deterministic"):
        ModelClaimBindingAssessment.model_validate(id_changed)


def test_binding_has_no_ground_truth_verification_or_metric_authority() -> None:
    signature = inspect.signature(ModelClaimBinder.assess)
    assert list(signature.parameters) == [
        "self",
        "candidate",
        "candidate_interaction",
    ]
    tree = ast.parse(
        (ROOT / "src/chipchain/evaluation/claim_binding.py").read_text("utf-8")
    )
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
        "EvaluationScope",
        "AttackChain",
        "VerificationRecord",
    }.isdisjoint(imported_names)
    interaction = _interaction()
    result = ModelClaimBinder().assess(
        _candidate(interaction, _claim_payload(interaction)),
        interaction,
    )
    serialized = result.model_dump(mode="json")
    assert not isinstance(result, (AttackChain, VerificationRecord))
    assert "confidence" not in serialized
    assert "score" not in serialized
    assert "feasibility" not in serialized
    assert "ground_truth" not in serialized


def test_objective_feasible_and_model_claim_mismatched_remain_independent() -> None:
    interaction = _interaction(suffix="objective-a")
    wrong_target = "synthetic-model-selected-hw-vulnerability-b"
    candidate = _candidate(
        interaction,
        _claim_payload(interaction, target_vulnerability_ids=[wrong_target]),
    )
    artifact = BenchmarkArtifactReference(
        artifact_id=ARTIFACT_ID,
        architecture=Architecture.ARM,
        artifact_type="elf",
        artifact_sha256=ARTIFACT_SHA256,
        artifact_reference="tests/fixtures/evaluation/phase10a_owned_arm.json",
    )
    triggerability = TriggerabilityAggregationResult.create(
        signature_id="hardware-trigger-signature:synthetic-step3",
        hardware_vulnerability_id=interaction.target_vulnerability_ids[0],
        architecture=Architecture.ARM,
        execution_mode=ArmExecutionMode.A32,
        artifact_id=ARTIFACT_ID,
        artifact_sha256=ARTIFACT_SHA256,
        trace_id="runtime-trigger-execution-trace:synthetic-step3",
        raw_trace_sha256="1" * 64,
        static_result_sha256="2" * 64,
        runtime_result_sha256="3" * 64,
        static_match_ids=["static-firmware-trigger-match:synthetic-step3"],
        runtime_occurrence_ids=[
            "runtime-firmware-trigger-occurrence:synthetic-step3"
        ],
        declared_preconditions_present=False,
        metadata={"fixture": True, "owned": True, "synthetic": True},
    )

    feasibility = ChainFeasibilityOracle().assess(
        candidate,
        artifact,
        candidate_interaction=interaction,
        triggerability=triggerability,
    )
    binding = ModelClaimBinder().assess(candidate, interaction)

    assert triggerability.status is TriggerabilityStatus.TRIGGERABLE
    assert feasibility.status is ChainFeasibilityStatus.CONFIRMED_FEASIBLE
    assert binding.status is ModelClaimBindingStatus.MISMATCHED
    assert binding.reason_codes == [
        ModelClaimBindingReason.CLAIM_TARGET_VULNERABILITY_MISMATCH
    ]
    assert wrong_target not in interaction.target_vulnerability_ids


def test_binding_id_helper_excludes_metadata_and_has_no_metric_semantics() -> None:
    interaction = _interaction()
    candidate = _candidate(interaction, _claim_payload(interaction))
    result = ModelClaimBinder().assess(candidate, interaction)
    assert result.id == model_claim_binding_assessment_id(
        candidate_id=result.candidate_id,
        benchmark_case_id=result.benchmark_case_id,
        architecture=result.architecture,
        model_authored_chain_claim_id=result.model_authored_chain_claim_id,
        candidate_interaction_id=result.candidate_interaction_id,
        claimed_interaction_type=result.claimed_interaction_type,
        candidate_interaction_type=result.candidate_interaction_type,
        status=result.status,
        reason_codes=result.reason_codes,
    )
