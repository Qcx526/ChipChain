"""Deterministic model-visible reasoning context views."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier
from chipchain.models.cross_layer import CrossLayerInteraction
from chipchain.models.enums import Architecture
from chipchain.reasoning.enums import ReasoningPromptVisibility
from chipchain.reasoning.hypothesis import _canonical_reasoning_id

if TYPE_CHECKING:
    from chipchain.agents.base import ReasoningContext


PHASE10D_MASKED_PROMPT_PROJECTION_CONTRACT = (
    "phase10d_collision_safe_masked_projection_v1"
)

_INTERACTION_HIDDEN_REFERENCE_FIELDS = (
    "initiating_vulnerability_ids",
    "target_vulnerability_ids",
    "trigger_behavior_ids",
    "propagation_behavior_ids",
    "affected_execution_ids",
    "fault_state_ids",
    "hardware_resource_ids",
    "security_mechanism_ids",
)


def masked_chain_hidden_reference_ids(
    context: "ReasoningContext",
) -> list[str]:
    """Return the frozen, deterministic MASKED chain-reference policy."""

    from chipchain.agents.base import _snapshot_context

    snapshot = _snapshot_context(context)
    values = {
        item
        for item in (
            snapshot.attack_pattern_reference,
            snapshot.dynamic_trigger_fact_reference,
        )
        if item is not None
    }
    interaction = snapshot.cross_layer_interaction
    if interaction is not None:
        values.add(interaction.id)
        for field_name in _INTERACTION_HIDDEN_REFERENCE_FIELDS:
            values.update(getattr(interaction, field_name))
    return sorted(values)


def _contains_hidden_reference(value: str, hidden: list[str]) -> bool:
    return any(reference in value for reference in hidden)


def _serialized_contains_hidden_reference(
    value: object,
    hidden: list[str],
) -> bool:
    serialized = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return _contains_hidden_reference(serialized, hidden)


def _legacy_masked_reasoning_prompt_visible_context(
    context: "ReasoningContext",
) -> dict[str, object]:
    """Reconstruct the exact Step 1-6 MASKED model-visible dictionary."""

    from chipchain.agents.base import _snapshot_context

    snapshot = _snapshot_context(context)
    visible: dict[str, object] = {
        "architecture": snapshot.architecture.value,
        "subject_id": snapshot.subject_id,
        "affected_components": snapshot.affected_components,
        "observed_fact_ids": snapshot.observed_fact_ids,
        "available_evidence_ids": snapshot.available_evidence_ids,
        "knowledge_entry_ids": snapshot.knowledge_entry_ids,
        "runtime_observations": [
            item.model_dump(mode="json")
            for item in snapshot.runtime_observations
        ],
    }
    if snapshot.knowledge_retrieval_result is not None:
        visible["knowledge_retrieval_result"] = (
            snapshot.knowledge_retrieval_result.model_dump(mode="json")
        )
    return {
        "id": reasoning_prompt_view_id(
            visibility=ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
            visible_context=visible,
        ),
        **visible,
    }


def reasoning_prompt_view_id(
    *,
    visibility: ReasoningPromptVisibility,
    visible_context: dict[str, object],
) -> str:
    """Build identity only from fields serialized into the provider prompt."""

    return _canonical_reasoning_id(
        "reasoning-prompt-view",
        {
            "visibility": ReasoningPromptVisibility(visibility).value,
            "visible_context": visible_context,
        },
    )


class ReasoningPromptView(DomainModel):
    """Detached prompt view; never replaces the trusted ReasoningContext."""

    id: Identifier
    visibility: ReasoningPromptVisibility
    architecture: Architecture
    subject_id: Identifier
    affected_components: list[Identifier] = Field(min_length=1)
    observed_fact_ids: list[Identifier] = Field(default_factory=list)
    available_evidence_ids: list[Identifier] = Field(default_factory=list)
    knowledge_entry_ids: list[Identifier] = Field(default_factory=list)
    runtime_observations: list[dict[str, object]] = Field(default_factory=list)
    knowledge_retrieval_result: dict[str, object] | None = None
    cross_layer_interaction: CrossLayerInteraction | None = None
    dynamic_trigger_fact_reference: Identifier | None = None
    attack_pattern_reference: Identifier | None = None

    @field_validator(
        "affected_components",
        "observed_fact_ids",
        "available_evidence_ids",
        "knowledge_entry_ids",
    )
    @classmethod
    def normalize_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("prompt-view identifier lists must be unique")
        return sorted(values)

    def visible_context(self) -> dict[str, object]:
        """Return the exact context dictionary intended for prompt serialization."""

        return self.model_dump(
            mode="json",
            exclude={"visibility"},
            exclude_none=True,
        )

    def _identity_context(self) -> dict[str, object]:
        return self.model_dump(
            mode="json",
            exclude={"id", "visibility"},
            exclude_none=True,
        )

    @model_validator(mode="after")
    def validate_visibility_and_identity(self) -> "ReasoningPromptView":
        if self.visibility is ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT and (
            self.cross_layer_interaction is not None
            or self.dynamic_trigger_fact_reference is not None
            or self.attack_pattern_reference is not None
        ):
            raise ValueError("masked prompt view contains hidden chain context")
        expected = reasoning_prompt_view_id(
            visibility=self.visibility,
            visible_context=self._identity_context(),
        )
        if self.id != expected:
            raise ValueError("ReasoningPromptView ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        context: "ReasoningContext",
        *,
        visibility: ReasoningPromptVisibility | str,
    ) -> "ReasoningPromptView":
        """Create a view without mutating or replacing full trusted context."""

        from chipchain.agents.base import _snapshot_context

        snapshot = _snapshot_context(context)
        policy = ReasoningPromptVisibility(visibility)
        masked = policy is ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
        runtime_observations = [
            item.model_dump(mode="json")
            for item in snapshot.runtime_observations
        ]
        knowledge_retrieval_result = (
            snapshot.knowledge_retrieval_result.model_dump(mode="json")
            if snapshot.knowledge_retrieval_result is not None
            else None
        )
        subject_id = snapshot.subject_id
        affected_components = snapshot.affected_components
        observed_fact_ids = snapshot.observed_fact_ids
        available_evidence_ids = snapshot.available_evidence_ids
        knowledge_entry_ids = snapshot.knowledge_entry_ids
        if masked:
            hidden = masked_chain_hidden_reference_ids(snapshot)
            if _contains_hidden_reference(subject_id, hidden):
                raise ValueError(
                    "masked prompt subject ID collides with hidden reference"
                )
            affected_components = [
                item
                for item in affected_components
                if not _contains_hidden_reference(item, hidden)
            ]
            if not affected_components:
                raise ValueError(
                    "masked prompt requires a non-hidden affected component"
                )
            observed_fact_ids = [
                item
                for item in observed_fact_ids
                if not _contains_hidden_reference(item, hidden)
            ]
            available_evidence_ids = [
                item
                for item in available_evidence_ids
                if not _contains_hidden_reference(item, hidden)
            ]
            knowledge_entry_ids = [
                item
                for item in knowledge_entry_ids
                if not _contains_hidden_reference(item, hidden)
            ]
            runtime_observations = [
                item
                for item in runtime_observations
                if not _serialized_contains_hidden_reference(item, hidden)
            ]
            if (
                knowledge_retrieval_result is not None
                and _serialized_contains_hidden_reference(
                    knowledge_retrieval_result, hidden
                )
            ):
                knowledge_retrieval_result = None
        values = {
            "architecture": snapshot.architecture,
            "subject_id": subject_id,
            "affected_components": affected_components,
            "observed_fact_ids": observed_fact_ids,
            "available_evidence_ids": available_evidence_ids,
            "knowledge_entry_ids": knowledge_entry_ids,
            "runtime_observations": runtime_observations,
            "knowledge_retrieval_result": knowledge_retrieval_result,
            "cross_layer_interaction": (
                None if masked else snapshot.cross_layer_interaction
            ),
            "dynamic_trigger_fact_reference": (
                None if masked else snapshot.dynamic_trigger_fact_reference
            ),
            "attack_pattern_reference": (
                None if masked else snapshot.attack_pattern_reference
            ),
        }
        serialized = {
            key: (
                value.model_dump(mode="json")
                if isinstance(value, DomainModel)
                else [
                    item.model_dump(mode="json")
                    if isinstance(item, DomainModel)
                    else item
                    for item in value
                ]
                if isinstance(value, list)
                else value.value
                if isinstance(value, Architecture)
                else value
            )
            for key, value in values.items()
            if value is not None
        }
        identity = reasoning_prompt_view_id(
            visibility=policy,
            visible_context=serialized,
        )
        return cls(id=identity, visibility=policy, **values)
