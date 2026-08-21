"""Offline tests for the Phase 9B2B Step 1 reasoning contracts."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.agents import ReasoningAgent
from chipchain.models import Architecture
from chipchain.reasoning import (
    AttackHypothesis,
    EvidenceCategory,
    EvidencePriority,
    EvidenceRequest,
    HypothesisSource,
    REASONING_RESULT_BOUNDARY,
    ReasoningAgentType,
    ReasoningResult,
)


ROOT = Path(__file__).resolve().parents[1]


def _hypothesis(
    *,
    metadata: dict[str, object] | None = None,
    architecture: Architecture = Architecture.ARM,
) -> AttackHypothesis:
    return AttackHypothesis.create(
        source=HypothesisSource.LLM,
        architecture=architecture,
        description=(
            "Synthetic MMIO access may expose a cross-layer security condition"
        ),
        affected_components=["fixture-arm-driver", "fixture-mmio-register"],
        attack_pattern_reference="CAPEC-fixture-reference",
        required_evidence_types=[
            EvidenceCategory.STATIC_BEHAVIOR,
            EvidenceCategory.RUNTIME_OBSERVATION,
        ],
        confidence=0.6,
        metadata=metadata,
    )


def _request(
    hypothesis: AttackHypothesis,
    *,
    metadata: dict[str, object] | None = None,
) -> EvidenceRequest:
    return EvidenceRequest.create(
        hypothesis,
        evidence_type=EvidenceCategory.RUNTIME_OBSERVATION,
        required_fact="Observe the declared MMIO access in an owned runtime",
        dynamic_trigger_fact_reference="dynamic-trigger-fact:fixture-reference",
        priority=EvidencePriority.HIGH,
        metadata=metadata,
    )


def _result(
    hypothesis: AttackHypothesis,
    *,
    metadata: dict[str, object] | None = None,
) -> ReasoningResult:
    return ReasoningResult.create(
        hypothesis,
        reasoning_steps=[
            "Compare the static trigger reference with available observations",
            "Record unresolved privilege-transition evidence",
        ],
        supporting_evidence_ids=["fixture-runtime-evidence"],
        missing_evidence=["fixture-privilege-transition-request"],
        confidence=0.55,
        metadata=metadata,
    )


def test_contract_ids_are_deterministic_and_semantic() -> None:
    hypothesis = _hypothesis()
    assert hypothesis == AttackHypothesis.model_validate_json(
        hypothesis.model_dump_json()
    )
    assert hypothesis.id == _hypothesis().id
    assert _request(hypothesis).id == _request(hypothesis).id
    assert _result(hypothesis).id == _result(hypothesis).id

    changed = AttackHypothesis.create(
        source=HypothesisSource.LLM,
        architecture=Architecture.ARM,
        description="A different synthetic hypothesis",
        affected_components=["fixture-arm-driver"],
        required_evidence_types=[EvidenceCategory.STATIC_BEHAVIOR],
        confidence=0.6,
    )
    assert changed.id != hypothesis.id


def test_metadata_does_not_affect_contract_identity() -> None:
    first = _hypothesis(metadata={"fixture_order": 1})
    second = _hypothesis(metadata={"fixture_order": 2})

    assert first.id == second.id
    assert _request(first, metadata={"fixture_order": 1}).id == _request(
        second, metadata={"fixture_order": 2}
    ).id
    assert _result(first, metadata={"fixture_order": 1}).id == _result(
        second, metadata={"fixture_order": 2}
    ).id


@pytest.mark.parametrize(
    "field",
    [
        "vulnerability_status",
        "verification_status",
        "interaction_verification_status",
        "attack_chain_status",
    ],
)
def test_hypothesis_cannot_contain_verdict_fields(field: str) -> None:
    values = _hypothesis().model_dump(mode="json")
    values[field] = "verified"

    with pytest.raises(ValidationError):
        AttackHypothesis.model_validate(values)
    with pytest.raises(ValidationError, match="verdict fields"):
        _hypothesis(metadata={field: "verified"})
    with pytest.raises(ValidationError, match="verdict fields"):
        _hypothesis(metadata={"nested": [{field.title(): "verified"}]})


def test_evidence_request_references_but_does_not_create_evidence() -> None:
    hypothesis = _hypothesis()
    request = _request(hypothesis)

    request.validate_against(hypothesis)
    assert request.dynamic_trigger_fact_reference == (
        "dynamic-trigger-fact:fixture-reference"
    )
    assert not hasattr(request, "create_evidence")
    assert "verified" not in request.model_dump(mode="json")

    with pytest.raises(ValueError, match="outside hypothesis requirements"):
        EvidenceRequest.create(
            hypothesis,
            evidence_type=EvidenceCategory.MMIO_ACCESS,
            required_fact="Collect another fixture fact",
            priority=EvidencePriority.LOW,
        )


def test_reasoning_result_requires_the_exact_non_verification_boundary() -> None:
    result = _result(_hypothesis())
    assert result.boundary_statement == REASONING_RESULT_BOUNDARY

    values = result.model_dump(mode="json")
    values["boundary_statement"] = "This vulnerability is verified."
    with pytest.raises(ValidationError):
        ReasoningResult.model_validate(values)

    for field in (
        "vulnerability_status",
        "verification_status",
        "interaction_verification_status",
        "attack_chain_verified",
    ):
        with pytest.raises(ValidationError):
            ReasoningResult.model_validate({**result.model_dump(), field: True})


def test_non_arm_hypothesis_is_rejected_by_current_architecture_boundary() -> None:
    with pytest.raises(ValidationError):
        _hypothesis(architecture=Architecture.RISC_V)


def test_all_contracts_round_trip_without_creating_domain_truth() -> None:
    hypothesis = _hypothesis()
    request = _request(hypothesis)
    result = _result(hypothesis)

    assert AttackHypothesis.model_validate_json(
        hypothesis.model_dump_json()
    ) == hypothesis
    assert EvidenceRequest.model_validate_json(request.model_dump_json()) == request
    assert ReasoningResult.model_validate_json(result.model_dump_json()) == result
    assert {
        "vulnerability_status",
        "verification_status",
        "interaction_verification_status",
        "attack_chain_verified",
    }.isdisjoint(result.model_dump(mode="json"))


def test_reasoning_agent_is_an_interface_only() -> None:
    with pytest.raises(TypeError):
        ReasoningAgent(
            agent_id="fixture-agent",
            agent_type=ReasoningAgentType.SECURITY_REASONER,
        )

    class FixtureAgent(ReasoningAgent):
        def analyze(self, input_data: object) -> ReasoningResult:
            assert isinstance(input_data, AttackHypothesis)
            return _result(input_data)

        def produce_hypothesis(self) -> AttackHypothesis:
            return _hypothesis()

        def request_evidence(self) -> list[EvidenceRequest]:
            hypothesis = self.produce_hypothesis()
            return [_request(hypothesis)]

    agent = FixtureAgent(
        agent_id="fixture-agent",
        agent_type=ReasoningAgentType.SECURITY_REASONER,
    )
    hypothesis = agent.produce_hypothesis()
    assert agent.analyze(hypothesis).hypothesis_id == hypothesis.id
    assert agent.request_evidence()[0].hypothesis_id == hypothesis.id


def test_dependency_direction_does_not_allow_runtime_to_import_reasoning() -> None:
    runtime_root = ROOT / "src" / "chipchain" / "runtime"
    for path in runtime_root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        assert not any(
            module.startswith(("chipchain.reasoning", "chipchain.agents"))
            for module in imported_modules
        ), path

    forbidden_imported_names = {
        "AttackChain",
        "BehaviorEdge",
        "Evidence",
        "InteractionVerificationStatus",
        "VerificationRecord",
        "VerificationStatus",
    }
    contract_paths = [
        ROOT / "src" / "chipchain" / "reasoning" / "hypothesis.py",
        ROOT / "src" / "chipchain" / "reasoning" / "evidence_request.py",
        ROOT / "src" / "chipchain" / "reasoning" / "reasoning_result.py",
        ROOT / "src" / "chipchain" / "agents" / "base.py",
    ]
    for path in contract_paths:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        assert forbidden_imported_names.isdisjoint(imported_names), path
