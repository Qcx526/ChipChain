"""Phase 9B2B deterministic multi-agent architecture contract tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from chipchain.agents import (
    AttackChainAgent,
    CodeAgent,
    HardwareAgent,
    MultiAgentReasoningOrchestrator,
    ReasoningContext,
    VulnerabilityAgent,
)
from chipchain.models import Architecture
from chipchain.reasoning import (
    AttackHypothesis,
    EvidenceRequest,
    ReasoningAgentType,
    ReasoningResult,
)


ROOT = Path(__file__).resolve().parents[1]
AGENT_TYPES = (CodeAgent, HardwareAgent, VulnerabilityAgent, AttackChainAgent)


def _context(
    *,
    subject_id: str = "fixture-phase9b2b-subject",
    metadata: dict[str, object] | None = None,
) -> ReasoningContext:
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id=subject_id,
        affected_components=["fixture-arm-driver", "fixture-mmio-register"],
        observed_fact_ids=["fixture-static-fact", "fixture-dynamic-fact"],
        available_evidence_ids=[
            "fixture-static-evidence",
            "fixture-runtime-evidence",
        ],
        dynamic_trigger_fact_reference="dynamic-trigger-fact:fixture-reference",
        attack_pattern_reference="CAPEC-fixture-reference",
        metadata=metadata,
    )


def test_agent_identity_is_deterministic_and_role_specific() -> None:
    context = _context()
    first = [agent_type(context) for agent_type in AGENT_TYPES]
    second = [agent_type(context) for agent_type in AGENT_TYPES]

    assert [agent.agent_id for agent in first] == [
        agent.agent_id for agent in second
    ]
    assert len({agent.agent_id for agent in first}) == len(AGENT_TYPES)
    assert [agent.agent_type for agent in first] == [
        ReasoningAgentType.CODE,
        ReasoningAgentType.HARDWARE,
        ReasoningAgentType.VULNERABILITY,
        ReasoningAgentType.ATTACK_CHAIN,
    ]
    assert _context(metadata={"order": 1}).id == _context(
        metadata={"order": 2}
    ).id


def test_roles_are_isolated_and_emit_only_reasoning_contracts() -> None:
    context = _context()
    hypotheses: list[AttackHypothesis] = []

    for agent_type in AGENT_TYPES:
        agent = agent_type(context)
        hypothesis = agent.produce_hypothesis()
        requests = agent.request_evidence()
        result = agent.analyze(context)
        hypotheses.append(hypothesis)

        assert type(hypothesis) is AttackHypothesis
        assert requests and all(type(item) is EvidenceRequest for item in requests)
        assert type(result) is ReasoningResult
        assert result.hypothesis_id == hypothesis.id
        assert all(request.hypothesis_id == hypothesis.id for request in requests)
        assert result.metadata["agent_type"] == agent.agent_type.value

    assert len({item.id for item in hypotheses}) == len(AGENT_TYPES)
    with pytest.raises(ValueError, match="context identity mismatch"):
        CodeAgent(context).analyze(_context(subject_id="different-subject"))


def test_orchestrator_order_and_result_are_deterministic() -> None:
    context = _context()
    orchestrator = MultiAgentReasoningOrchestrator()
    first = orchestrator.reason(context)
    second = orchestrator.reason(context)

    assert first == second
    assert first.metadata["execution_order"] == [
        "code",
        "hardware",
        "vulnerability",
        "attack_chain",
    ]
    assert first.reasoning_steps == [
        "CodeAgent considered static and runtime references for fixture-phase9b2b-subject",
        "HardwareAgent considered MMIO and runtime references for fixture-phase9b2b-subject",
        "VulnerabilityAgent kept weakness references unresolved for fixture-phase9b2b-subject",
        "AttackChainAgent retained the sequence as a hypothesis for fixture-phase9b2b-subject",
    ]
    assert first.supporting_evidence_ids == [
        "fixture-runtime-evidence",
        "fixture-static-evidence",
    ]


def test_agents_and_orchestrator_have_no_verification_leakage() -> None:
    context = _context()
    outputs: list[AttackHypothesis | EvidenceRequest | ReasoningResult] = []
    for agent_type in AGENT_TYPES:
        agent = agent_type(context)
        outputs.append(agent.produce_hypothesis())
        outputs.extend(agent.request_evidence())
        outputs.append(agent.analyze(context))
    outputs.append(MultiAgentReasoningOrchestrator().reason(context))

    forbidden_keys = {
        "attack_chain_status",
        "attack_chain_verified",
        "interaction_verification_status",
        "verification_record",
        "verification_status",
        "vulnerability_status",
        "vulnerability_verdict",
    }
    for output in outputs:
        assert forbidden_keys.isdisjoint(output.model_dump(mode="json"))

    forbidden_imported_names = {
        "AttackChain",
        "BehaviorEdge",
        "Evidence",
        "InteractionVerificationStatus",
        "VerificationRecord",
        "VerificationStatus",
    }
    agents_root = ROOT / "src" / "chipchain" / "agents"
    for path in agents_root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        assert forbidden_imported_names.isdisjoint(imported_names), path
