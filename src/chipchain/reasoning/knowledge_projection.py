"""Versioned provider-visible projection of neutral public knowledge."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING, Literal

from pydantic import Field, field_validator, model_validator

from chipchain.knowledge.models import (
    KnowledgeEntryKind,
    VulnerabilityKnowledgeEntry,
    vulnerability_knowledge_entry_id,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture

if TYPE_CHECKING:
    from chipchain.agents.base import ReasoningContext


PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT = (
    "phase10d_public_knowledge_content_projection_v1"
)


def _canonical_projection_id(prefix: str, payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(encoded).hexdigest()}"


class ProjectedKnowledgeEntry(DomainModel):
    """Only neutral fields already present on a CVE knowledge entry."""

    entry_id: Identifier
    entry_kind: Literal[KnowledgeEntryKind.CVE] = KnowledgeEntryKind.CVE
    external_id: Identifier
    architecture: Architecture
    title: Identifier
    summary: Identifier
    affected_components: list[Identifier] = Field(default_factory=list)
    references: list[Identifier] = Field(default_factory=list)

    @field_validator("affected_components", "references")
    @classmethod
    def normalize_lists(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("projected knowledge lists must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_entry_identity(self) -> "ProjectedKnowledgeEntry":
        expected = vulnerability_knowledge_entry_id(
            entry_kind=self.entry_kind,
            external_id=self.external_id,
            architecture=self.architecture,
            title=self.title,
            summary=self.summary,
            affected_components=self.affected_components,
            references=self.references,
        )
        if self.entry_id != expected:
            raise ValueError("projected knowledge entry ID/content mismatch")
        return self

    @classmethod
    def from_knowledge_entry(
        cls,
        entry: VulnerabilityKnowledgeEntry,
    ) -> "ProjectedKnowledgeEntry":
        """Detach and project one validated CVE entry without metadata."""

        if not isinstance(entry, VulnerabilityKnowledgeEntry):
            raise TypeError(
                "public knowledge projection requires VulnerabilityKnowledgeEntry"
            )
        snapshot = VulnerabilityKnowledgeEntry.model_validate(
            entry.model_dump(mode="json")
        )
        if snapshot.entry_kind is not KnowledgeEntryKind.CVE:
            raise ValueError("public knowledge projection accepts CVE entries only")
        if snapshot.architecture is None:
            raise ValueError("projected CVE knowledge requires architecture")
        return cls(
            entry_id=snapshot.id,
            entry_kind=snapshot.entry_kind,
            external_id=snapshot.external_id,
            architecture=snapshot.architecture,
            title=snapshot.title,
            summary=snapshot.summary,
            affected_components=snapshot.affected_components,
            references=snapshot.references,
        )


def knowledge_content_projection_id(
    *,
    contract: str,
    architecture: Architecture,
    reasoning_context_id: str,
    entries: list[ProjectedKnowledgeEntry],
) -> str:
    """Bind projection identity to exact neutral content and context."""

    return _canonical_projection_id(
        "knowledge-content-projection",
        {
            "architecture": architecture.value,
            "contract": contract,
            "entries": sorted(
                (
                    item.model_dump(mode="json")
                    for item in entries
                ),
                key=lambda item: item["entry_id"],
            ),
            "reasoning_context_id": reasoning_context_id,
        },
    )


class KnowledgeContentProjection(DomainModel):
    """Detached public reference content attached to one reasoning context."""

    id: Identifier
    contract: Literal[
        PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT
    ] = PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT
    architecture: Architecture
    reasoning_context_id: Identifier
    entries: list[ProjectedKnowledgeEntry] = Field(min_length=1)

    @field_validator("entries")
    @classmethod
    def normalize_entries(
        cls,
        values: list[ProjectedKnowledgeEntry],
    ) -> list[ProjectedKnowledgeEntry]:
        if len(values) != len({item.entry_id for item in values}):
            raise ValueError("projected knowledge entry IDs must be unique")
        return sorted(values, key=lambda item: item.entry_id)

    @model_validator(mode="after")
    def validate_projection_identity(self) -> "KnowledgeContentProjection":
        if any(item.architecture is not self.architecture for item in self.entries):
            raise ValueError("projected knowledge architecture mismatch")
        expected = knowledge_content_projection_id(
            contract=self.contract,
            architecture=self.architecture,
            reasoning_context_id=self.reasoning_context_id,
            entries=self.entries,
        )
        if self.id != expected:
            raise ValueError("KnowledgeContentProjection ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        context: "ReasoningContext",
        entries: list[VulnerabilityKnowledgeEntry],
    ) -> "KnowledgeContentProjection":
        """Project exactly the CVE entries referenced by a detached context."""

        from chipchain.agents.base import ReasoningContext

        if not isinstance(context, ReasoningContext):
            raise TypeError("knowledge projection requires ReasoningContext")
        context_snapshot = ReasoningContext.model_validate(
            context.model_dump(mode="json")
        )
        if len(entries) != len({item.id for item in entries}):
            raise ValueError("knowledge projection input entries must be unique")
        projected = [
            ProjectedKnowledgeEntry.from_knowledge_entry(item)
            for item in entries
        ]
        if {item.entry_id for item in projected} != set(
            context_snapshot.knowledge_entry_ids
        ):
            raise ValueError(
                "projected knowledge IDs must exactly match reasoning context"
            )
        if any(
            item.architecture is not context_snapshot.architecture
            for item in projected
        ):
            raise ValueError("projected knowledge architecture mismatch")
        identity = knowledge_content_projection_id(
            contract=PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT,
            architecture=context_snapshot.architecture,
            reasoning_context_id=context_snapshot.id,
            entries=projected,
        )
        return cls(
            id=identity,
            architecture=context_snapshot.architecture,
            reasoning_context_id=context_snapshot.id,
            entries=projected,
        )


def validate_knowledge_projection_binding(
    context: "ReasoningContext",
    projection: KnowledgeContentProjection,
) -> tuple["ReasoningContext", KnowledgeContentProjection]:
    """Detached-revalidate exact context/projection binding for prompt use."""

    from chipchain.agents.base import ReasoningContext

    if not isinstance(context, ReasoningContext):
        raise TypeError("knowledge-projected prompt requires ReasoningContext")
    if not isinstance(projection, KnowledgeContentProjection):
        raise TypeError(
            "knowledge-projected prompt requires KnowledgeContentProjection"
        )
    context_snapshot = ReasoningContext.model_validate(
        context.model_dump(mode="json")
    )
    projection_snapshot = KnowledgeContentProjection.model_validate(
        projection.model_dump(mode="json")
    )
    if (
        projection_snapshot.reasoning_context_id != context_snapshot.id
        or projection_snapshot.architecture is not context_snapshot.architecture
        or {item.entry_id for item in projection_snapshot.entries}
        != set(context_snapshot.knowledge_entry_ids)
    ):
        raise ValueError("knowledge projection and reasoning context mismatch")
    return context_snapshot, projection_snapshot
