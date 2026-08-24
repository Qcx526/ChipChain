"""Manual one-role Phase 9B2C real-provider reasoning smoke check."""

from __future__ import annotations

import sys
from pathlib import Path

from chipchain.agents import ReasoningContext
from chipchain.models import Architecture
from chipchain.reasoning import (
    OpenAICompatibleReasoningProvider,
    ReasoningAgentType,
    ReasoningEngine,
)


BOUNDARY_STATEMENT = (
    "This is reasoning output only, not verification or a confirmed vulnerability."
)


def main() -> int:
    """Execute exactly one CODE role and print only bounded summary fields."""

    project_root = Path(__file__).resolve().parents[1]
    role = ReasoningAgentType.CODE
    try:
        from dotenv import load_dotenv

        load_dotenv(project_root / ".env", override=False)
        provider = OpenAICompatibleReasoningProvider.from_env()
        context = ReasoningContext.create(
            architecture=Architecture.ARM,
            subject_id="synthetic-phase9b2c-step1-owned-arm-subject",
            affected_components=[
                "synthetic-owned-arm-driver",
                "synthetic-owned-mmio-register",
            ],
            observed_fact_ids=["synthetic-owned-static-fact"],
            available_evidence_ids=["synthetic-owned-evidence-reference"],
            dynamic_trigger_fact_reference=(
                "dynamic-trigger-fact:synthetic-owned-reference"
            ),
            attack_pattern_reference="CAPEC-synthetic-owned-reference",
            metadata={"demo": True, "synthetic": True, "owned": True},
        )
        hypothesis, requests, result = ReasoningEngine(
            provider=provider
        ).reason(context, role=role)
    except Exception as exc:
        failure_stage = (
            "optional_dependency"
            if isinstance(exc, ModuleNotFoundError)
            else getattr(exc, "stage", "configuration_or_parser")
        )
        print("Phase 9B2C reasoning: FAILED")
        print(f"Role: {role.value}")
        print(f"Error type: {type(exc).__name__}")
        print(f"Failure stage: {failure_stage}")
        status_code = getattr(exc, "status_code", None)
        print(
            "HTTP status: "
            f"{status_code if status_code is not None else 'unavailable'}"
        )
        print(BOUNDARY_STATEMENT)
        return 1

    print("Phase 9B2C reasoning: SUCCESS")
    print(f"Provider model: {provider.config.model}")
    print(f"API style: {provider.config.api_style.value}")
    print(f"Role: {role.value}")
    print(f"Hypothesis ID: {hypothesis.id}")
    print(f"Evidence Request Count: {len(requests)}")
    print(f"Reasoning result ID: {result.id}")
    print(BOUNDARY_STATEMENT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
