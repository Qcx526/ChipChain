"""Detached Evidence catalog and interaction-scoped inventory."""

from collections.abc import Iterable

from chipchain.models import Evidence, EvidenceType
from chipchain.verification.enums import RequiredFactCategory
from chipchain.verification.errors import VerificationInputError
from chipchain.verification.models import ObjectiveEvidenceInventory


class EvidenceCatalog:
    """Resolve fresh Evidence objects without retaining mutable sources."""

    def __init__(self, evidence: Iterable[Evidence]) -> None:
        items = list(evidence)
        ids = [item.id for item in items]
        if len(ids) != len(set(ids)):
            raise ValueError("EvidenceCatalog IDs must be unique")
        self._catalog = {item.id: item.model_dump(mode="json") for item in items}

    def resolve(self, evidence_id: str) -> Evidence | None:
        data = self._catalog.get(evidence_id)
        return None if data is None else Evidence.model_validate(dict(data))

    def inventory(self, required_evidence_ids: Iterable[str], *,
                  required_fact_categories: Iterable[RequiredFactCategory] = (),
                  supporting_evidence_ids: Iterable[str] = (),
                  rejected_evidence_ids: Iterable[str] = ()) -> ObjectiveEvidenceInventory:
        required = sorted(set(required_evidence_ids))
        supporting = set(supporting_evidence_ids).intersection(required)
        rejected = sorted(set(rejected_evidence_ids).intersection(required))
        resolved: list[str] = []
        verified: list[str] = []
        unknown: list[str] = []
        for evidence_id in required:
            item = self.resolve(evidence_id)
            if item is None:
                unknown.append(evidence_id)
                continue
            resolved.append(evidence_id)
            if evidence_id in rejected:
                continue
            if (
                evidence_id not in supporting
                or item.type is EvidenceType.LLM_SEMANTIC
                or not item.verified
            ):
                unknown.append(evidence_id)
            else:
                verified.append(evidence_id)
        return ObjectiveEvidenceInventory(
            required_evidence_count=len(required), resolved_evidence_count=len(resolved),
            verified_non_llm_evidence_count=len(verified), unknown_evidence_count=len(unknown),
            rejected_evidence_count=len(rejected), required_evidence_ids=required,
            resolved_evidence_ids=resolved, verified_non_llm_evidence_ids=verified,
            unknown_evidence_ids=unknown, rejected_evidence_ids=rejected,
            required_fact_categories=sorted(set(required_fact_categories), key=lambda x: x.value),
        )


def merge_evidence(*collections: Iterable[Evidence]) -> list[Evidence]:
    """Deterministically deduplicate equal Evidence and reject ID collisions."""

    merged: dict[str, dict[str, object]] = {}
    for collection in collections:
        for item in collection:
            serialized = item.model_dump(mode="json")
            existing = merged.get(item.id)
            if existing is not None and existing != serialized:
                raise VerificationInputError(
                    f"conflicting Evidence objects share ID {item.id!r}"
                )
            merged[item.id] = serialized
    return [Evidence.model_validate(merged[item_id]) for item_id in sorted(merged)]
