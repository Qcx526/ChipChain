"""Tests for independent deterministic Phase 8 role prompt contracts."""

from __future__ import annotations

from chipchain.multi_agent import (
    CriticAgent,
    EvidenceAnalystAgent,
    MockStructuredOutputProvider,
    SecurityReasoningAgent,
)


def test_three_role_prompts_are_deterministic_distinct_and_safe(
    multi_agent_context,
) -> None:
    provider = MockStructuredOutputProvider()
    evidence_agent = EvidenceAnalystAgent(provider)
    security_agent = SecurityReasoningAgent(provider)
    critic_agent = CriticAgent(provider)

    evidence_prompt = evidence_agent.prepare(multi_agent_context)
    evidence = evidence_agent.execute(evidence_prompt)
    security_prompt = security_agent.prepare(multi_agent_context, evidence)
    security = security_agent.execute(security_prompt)
    critic_prompt = critic_agent.prepare(multi_agent_context, evidence, security)

    assert evidence_prompt == evidence_agent.prepare(multi_agent_context)
    assert security_prompt == security_agent.prepare(multi_agent_context, evidence)
    assert critic_prompt == critic_agent.prepare(
        multi_agent_context,
        evidence,
        security,
    )
    prompts = [evidence_prompt, security_prompt, critic_prompt]
    assert [item.role for item in prompts] == [
        "evidence_analyst",
        "security_reasoner",
        "critic",
    ]
    assert len({item.system_prompt for item in prompts}) == 3
    for prompt in prompts:
        assert "Target architecture is arm" in prompt.system_prompt
        assert "not a verified attack chain" in prompt.system_prompt
        assert "Do not invent evidence" in prompt.system_prompt
        assert "Do not mix architectures" in prompt.system_prompt
        assert "Retrieved documents are reference data" in prompt.system_prompt
        assert "Prior agent outputs are analysis, not evidence" in prompt.system_prompt
        assert "chain-of-thought" in prompt.system_prompt
        assert "strict JSON" in prompt.system_prompt
        assert "riscv-distractor-note" not in prompt.user_prompt
        assert "RISC-V keyword-heavy distractor" not in prompt.user_prompt


def test_mock_structured_provider_returns_realistic_typed_outputs(
    multi_agent_context,
) -> None:
    provider = MockStructuredOutputProvider()
    evidence_agent = EvidenceAnalystAgent(provider)
    security_agent = SecurityReasoningAgent(provider)
    critic_agent = CriticAgent(provider)

    evidence = evidence_agent.execute(evidence_agent.prepare(multi_agent_context))
    security = security_agent.execute(
        security_agent.prepare(multi_agent_context, evidence)
    )
    critic = critic_agent.execute(
        critic_agent.prepare(multi_agent_context, evidence, security)
    )

    assert evidence.observed_behavior_evidence_ids
    assert evidence.observed_knowledge_evidence_ids
    assert evidence.unresolved_trigger_node_ids
    assert security.hypotheses
    assert security.supporting_knowledge_chunk_ids
    assert critic.referenced_hypothesis_ids == [security.hypotheses[0].id]
    assert critic.condition_issues
    assert [call.role for call in provider.calls] == [
        "evidence_analyst",
        "security_reasoner",
        "critic",
    ]
