"""Manual Phase 9B2C four-role provider-backed reasoning acceptance."""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

from chipchain.agents import (
    ProviderBackedAgentWorkflow,
    ProviderBackedWorkflowExecutionError,
    ReasoningContext,
)
from chipchain.knowledge import (
    DeterministicKnowledgeRetriever,
    InMemoryKnowledgeEntryRepository,
    KnowledgeRetrievalQuery,
)
from chipchain.models import (
    Architecture,
    CrossLayerInteraction,
    CrossLayerInteractionType,
    Layer,
)
from chipchain.reasoning import (
    LLMProviderConfigurationError,
    OpenAICompatibleReasoningProvider,
    ReasoningAgentType,
    ReasoningEngine,
    ReasoningProvider,
    StructuredPromptRequest,
)
from chipchain.runtime import RuntimeEventKind, RuntimeObservation
from chipchain.verification import HardwareAddress, ProgramAddress


ROLE_ORDER = (
    ReasoningAgentType.CODE,
    ReasoningAgentType.HARDWARE,
    ReasoningAgentType.VULNERABILITY,
    ReasoningAgentType.ATTACK_CHAIN,
)
BOUNDARY_STATEMENT = (
    "This is reasoning output only, not verification or a confirmed vulnerability."
)


class ObservedReasoningProvider(ReasoningProvider):
    """Transparently record only role and context identity for each call."""

    __slots__ = ("_delegate", "_observed_calls")

    def __init__(self, delegate: ReasoningProvider) -> None:
        if not isinstance(delegate, ReasoningProvider):
            raise TypeError("observed provider delegate must be a ReasoningProvider")
        self._delegate = delegate
        self._observed_calls: list[tuple[str, str]] = []

    @property
    def observed_calls(self) -> tuple[tuple[str, str], ...]:
        """Return an immutable snapshot containing no prompts or responses."""

        return tuple(self._observed_calls)

    def generate(self, request: StructuredPromptRequest) -> str:
        """Record the attempted call, then return the delegate result unchanged."""

        self._observed_calls.append((request.role, request.candidate_id))
        return self._delegate.generate(request)


def _owned_synthetic_context() -> ReasoningContext:
    interaction = CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=(
            CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
        ),
        source_layer=Layer.FIRMWARE,
        target_layer=Layer.HARDWARE,
        target_vulnerability_ids=["synthetic-owned-hardware-condition"],
        trigger_behavior_ids=["synthetic-owned-mmio-trigger"],
        hardware_resource_ids=["synthetic-owned-mmio-register"],
        referenced_architectures=[Architecture.ARM],
        metadata={"demo": True, "synthetic": True, "owned": True},
    )
    observation = RuntimeObservation.create(
        trace_id="synthetic-owned-phase9b2c-step2-trace",
        architecture=Architecture.ARM,
        sequence_index=1,
        vcpu_index=0,
        event_kind=RuntimeEventKind.MMIO_WRITE,
        pc=ProgramAddress(value="0x10008"),
        physical_address=HardwareAddress(value="0x40000000"),
        is_io=True,
        access_size=4,
        address_space_id="synthetic-owned-system-memory",
        host_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
        metadata={"demo": True, "synthetic": True, "owned": True},
    )
    query = KnowledgeRetrievalQuery.create(
        architecture=Architecture.ARM,
        text="synthetic owned ARM MMIO reasoning context",
        metadata={"demo": True, "synthetic": True, "owned": True},
    )
    retrieval = DeterministicKnowledgeRetriever(
        InMemoryKnowledgeEntryRepository([])
    ).retrieve(query)
    return ReasoningContext.create(
        architecture=Architecture.ARM,
        subject_id=interaction.id,
        affected_components=[
            "synthetic-owned-arm-driver",
            "synthetic-owned-mmio-register",
        ],
        observed_fact_ids=["synthetic-owned-static-fact"],
        available_evidence_ids=["synthetic-owned-evidence-reference"],
        dynamic_trigger_fact_reference=(
            "dynamic-trigger-fact:synthetic-owned-step2-reference"
        ),
        attack_pattern_reference="CAPEC-synthetic-owned-step2-reference",
        cross_layer_interaction=interaction,
        runtime_observations=[observation],
        knowledge_retrieval_result=retrieval,
        metadata={"demo": True, "synthetic": True, "owned": True},
    )


def main() -> int:
    """Execute exactly four sequential roles and print bounded audit fields."""

    project_root = Path(__file__).resolve().parents[1]
    try:
        from dotenv import load_dotenv

        load_dotenv(project_root / ".env", override=False)
        transport_provider = OpenAICompatibleReasoningProvider.from_env()
        if not transport_provider.config.json_mode:
            raise LLMProviderConfigurationError(
                "Phase 9B2C four-role acceptance requires strict JSON mode"
            )
        provider = ObservedReasoningProvider(transport_provider)
        context = _owned_synthetic_context()
        session = ProviderBackedAgentWorkflow(
            engine=ReasoningEngine(provider=provider)
        ).execute(context)
        if len(session.hypotheses) != 4 or len(session.reasoning_results) != 3:
            raise RuntimeError("provider-backed session contract mismatch")
        observed_calls = provider.observed_calls
        observed_roles = tuple(role for role, _ in observed_calls)
        expected_roles = tuple(role.value for role in ROLE_ORDER)
        if observed_roles != expected_roles:
            raise RuntimeError("observed provider execution order mismatch")
        if len(observed_calls) != 4:
            raise RuntimeError("observed provider call count mismatch")
        if {context_id for _, context_id in observed_calls} != {context.id}:
            raise RuntimeError("provider roles did not share one reasoning context")
    except ProviderBackedWorkflowExecutionError as exc:
        print("Phase 9B2C four-role reasoning: FAILED")
        print(f"Failed role: {exc.failed_role.value}")
        print(
            "Completed roles: "
            + (
                " -> ".join(item.value for item in exc.completed_roles)
                if exc.completed_roles
                else "none"
            )
        )
        print(f"Error type: {exc.error_type}")
        print(f"Failure stage: {exc.stage}")
        print(
            "HTTP status: "
            f"{exc.status_code if exc.status_code is not None else 'unavailable'}"
        )
        print(BOUNDARY_STATEMENT)
        return 1
    except Exception as exc:
        print("Phase 9B2C four-role reasoning: FAILED")
        print("Failed role: unavailable")
        print("Completed roles: none")
        print(f"Error type: {type(exc).__name__}")
        print(f"Failure stage: {getattr(exc, 'stage', 'configuration')}")
        status_code = getattr(exc, "status_code", None)
        print(
            "HTTP status: "
            f"{status_code if status_code is not None else 'unavailable'}"
        )
        print(BOUNDARY_STATEMENT)
        return 1

    print("Phase 9B2C four-role reasoning: SUCCESS")
    print(f"Provider model: {transport_provider.config.model}")
    print(f"API style: {transport_provider.config.api_style.value}")
    print(f"Observed provider calls: {len(observed_calls)}")
    print("Observed execution order:")
    print(" -> ".join(role for role, _ in observed_calls))
    print("Same context across roles: yes")
    print(f"Session ID: {session.session_id}")
    print(f"Hypothesis count: {len(session.hypotheses)}")
    print(f"Evidence request count: {len(session.evidence_requests)}")
    print(f"Reasoning result count: {len(session.reasoning_results)}")
    print(f"Final reasoning result ID: {session.final_reasoning_result.id}")
    print(BOUNDARY_STATEMENT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
