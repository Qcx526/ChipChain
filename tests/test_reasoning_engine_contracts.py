"""Phase 9B2B Step 4 reasoning-engine contract tests."""

from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

import pytest

from chipchain.agents import ReasoningContext
from chipchain.models import Architecture
from chipchain.reasoning import (
    AttackHypothesis,
    ConstrainedReasoningOutputParser,
    EvidenceRequest,
    LLMOutputValidationError,
    LLMProvider,
    MockReasoningProvider,
    REASONING_RESULT_BOUNDARY,
    ReasoningAgentType,
    ReasoningEngine,
    ReasoningProvider,
    ReasoningResult,
    RoleBasedReasoningPromptBuilder,
)
from chipchain.reasoning.models import CandidateSemanticAssessment, PromptRequest


ROOT = Path(__file__).resolve().parents[1]
ENGINE_ROLES = (
    ReasoningAgentType.CODE,
    ReasoningAgentType.HARDWARE,
    ReasoningAgentType.VULNERABILITY,
    ReasoningAgentType.ATTACK_CHAIN,
)


def _context(
    *,
    metadata: dict[str, object] | None = None,
) -> ReasoningContext:
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id="fixture-phase9b2b-step4-subject",
        affected_components=["fixture-arm-driver", "fixture-mmio-register"],
        observed_fact_ids=["fixture-static-fact", "fixture-dynamic-fact"],
        available_evidence_ids=[
            "fixture-static-evidence",
            "fixture-runtime-evidence",
        ],
        knowledge_entry_ids=["fixture-cwe-entry", "fixture-hardware-entry"],
        dynamic_trigger_fact_reference="dynamic-trigger-fact:fixture-reference",
        attack_pattern_reference="CAPEC-fixture-reference",
        metadata=metadata,
    )


def _prompt(role: ReasoningAgentType = ReasoningAgentType.CODE):
    return RoleBasedReasoningPromptBuilder().build(_context(), role=role)


def test_reasoning_provider_interface_and_mock_are_deterministic() -> None:
    with pytest.raises(TypeError):
        ReasoningProvider()

    provider = MockReasoningProvider()
    request = _prompt()
    first = provider.generate(request)
    second = provider.generate(request)

    assert first == second == provider.generate_reasoning(request)
    assert json.loads(first) == json.loads(second)
    assert first == json.dumps(
        json.loads(first),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def test_role_based_prompts_are_deterministic_and_context_bounded() -> None:
    builder = RoleBasedReasoningPromptBuilder()
    first = builder.build(
        _context(metadata={"non_semantic_order": 1}),
        role=ReasoningAgentType.HARDWARE,
    )
    second = builder.build(
        _context(metadata={"non_semantic_order": 2}),
        role=ReasoningAgentType.HARDWARE,
    )
    code_prompt = builder.build(_context(), role=ReasoningAgentType.CODE)

    assert first == second
    assert first != code_prompt
    payload = json.loads(first.user_prompt)
    assert payload["role"] == "hardware"
    assert payload["reasoning_context"]["knowledge_entry_ids"] == [
        "fixture-cwe-entry",
        "fixture-hardware-entry",
    ]
    assert "metadata" not in payload["reasoning_context"]
    assert payload["constraints"]["domain_truth_creation"] is False


def test_engine_and_parser_emit_only_existing_reasoning_contracts() -> None:
    context = _context()
    engine = ReasoningEngine(provider=MockReasoningProvider())

    for role in ENGINE_ROLES:
        hypothesis, requests, result = engine.reason(context, role=role)
        assert type(hypothesis) is AttackHypothesis
        assert requests and all(type(item) is EvidenceRequest for item in requests)
        assert type(result) is ReasoningResult
        assert result.boundary_statement == REASONING_RESULT_BOUNDARY
        assert result.hypothesis_id == hypothesis.id
        assert all(request.hypothesis_id == hypothesis.id for request in requests)
        assert result.missing_evidence == sorted(
            request.id for request in requests
        )
        assert result.metadata["confidence_semantics"] == (
            "reasoning_only_not_verification_score"
        )


def test_parser_rejects_illegal_fields_and_verification_verdicts() -> None:
    context = _context()
    parser = ConstrainedReasoningOutputParser()
    raw = json.loads(MockReasoningProvider().generate(_prompt()))

    invalid_outputs = [
        "not-json",
        json.dumps({**raw, "unexpected_field": True}),
        json.dumps({**raw, "verification_status": "verified"}),
        json.dumps(
            {
                **raw,
                "hypothesis": {
                    **raw["hypothesis"],
                    "vulnerability_verdict": "verified",
                },
            }
        ),
        json.dumps(
            {
                **raw,
                "reasoning_result": {
                    **raw["reasoning_result"],
                    "score": 1.0,
                },
            }
        ),
    ]
    for invalid_output in invalid_outputs:
        with pytest.raises(LLMOutputValidationError):
            parser.parse(
                invalid_output,
                context=context,
                role=ReasoningAgentType.CODE,
            )


def test_parser_rejects_invented_references_and_role_leakage() -> None:
    context = _context()
    parser = ConstrainedReasoningOutputParser()
    raw = json.loads(MockReasoningProvider().generate(_prompt()))

    invented_component = json.loads(json.dumps(raw))
    invented_component["hypothesis"]["affected_components"] = [
        "invented-component"
    ]
    invented_evidence = json.loads(json.dumps(raw))
    invented_evidence["reasoning_result"]["supporting_evidence_ids"].append(
        "invented-evidence"
    )
    leaked_role = json.loads(json.dumps(raw))
    leaked_role["evidence_requests"][0]["evidence_type"] = "mmio_access"

    for invalid_output in (invented_component, invented_evidence, leaked_role):
        with pytest.raises(LLMOutputValidationError):
            parser.parse(
                json.dumps(invalid_output),
                context=context,
                role=ReasoningAgentType.CODE,
            )


def test_confidence_remains_reasoning_only_and_does_not_change_identity() -> None:
    context = _context()
    parser = ConstrainedReasoningOutputParser()
    raw = json.loads(MockReasoningProvider().generate(_prompt()))
    high_confidence = json.loads(json.dumps(raw))
    high_confidence["hypothesis"]["confidence"] = 0.9
    high_confidence["reasoning_result"]["confidence"] = 0.8

    low = parser.parse(
        json.dumps(raw),
        context=context,
        role=ReasoningAgentType.CODE,
    )
    high = parser.parse(
        json.dumps(high_confidence),
        context=context,
        role=ReasoningAgentType.CODE,
    )
    assert low[0].id == high[0].id
    assert low[2].id == high[2].id
    assert low[0].confidence == 0.0
    assert high[0].confidence == 0.9
    assert "verification_score" not in high[2].model_dump(mode="json")


def test_reasoning_engine_has_no_verification_or_real_provider_leakage() -> None:
    context = _context()
    outputs = ReasoningEngine(provider=MockReasoningProvider()).reason(
        context,
        role=ReasoningAgentType.ATTACK_CHAIN,
    )
    forbidden_keys = {
        "attack_chain",
        "attack_chain_status",
        "evidence",
        "interaction_verification_status",
        "verification_record",
        "verification_score",
        "verification_status",
        "vulnerability_status",
        "vulnerability_verdict",
    }
    for output in (outputs[0], *outputs[1], outputs[2]):
        assert forbidden_keys.isdisjoint(output.model_dump(mode="json"))

    class LegacyProvider(LLMProvider):
        def generate(self, request: PromptRequest) -> CandidateSemanticAssessment:
            raise AssertionError("legacy provider must not be invoked")

    with pytest.raises(TypeError, match="ReasoningProvider"):
        ReasoningEngine(provider=LegacyProvider())  # type: ignore[arg-type]

    for relative_path in (
        "src/chipchain/reasoning/engine.py",
        "src/chipchain/reasoning/parser.py",
    ):
        tree = ast.parse((ROOT / relative_path).read_text(encoding="utf-8"))
        imported_modules = {
            node.module
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom) and node.module is not None
        }
        imported_names = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        assert not any(
            module.startswith(
                (
                    "chipchain.runtime",
                    "chipchain.verification",
                )
            )
            for module in imported_modules
        )
        assert {
            "AttackChain",
            "Evidence",
            "VerificationRecord",
        }.isdisjoint(imported_names)

    mock_source = inspect.getsource(MockReasoningProvider)
    assert all(
        token not in mock_source
        for token in (
            "httpx.",
            "openai.",
            "requests.get",
            "requests.post",
            "urllib.",
        )
    )
