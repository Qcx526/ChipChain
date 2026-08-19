"""Detached read-only Evidence catalog and objective inventory."""

from __future__ import annotations

from collections.abc import Iterable

from chipchain.models import Evidence, EvidenceType
from chipchain.verification.models import ObjectiveEvidenceInventory


class EvidenceCatalog:
    """Resolve detached Evidence without retaining mutable source objects."""

    def __init__(self, evidence: Iterable[Evidence]) -> None:
        items = list(evidence)
        ids = [item.id for item in items]
        if len(ids) != len(set(ids)):
            raise ValueError("EvidenceCatalog IDs must be unique")
        self._catalog = {
            item.id: item.model_dump(mode="json") for item in items
        }

    def resolve(self, evidence_id: str) -> Evidence | None:
        """Return a freshly validated Evidence or ``None`` when absent."""

        data = self._catalog.get(evidence_id)
        return None if data is None else Evidence.model_validate(dict(data))

    def inventory(
        self,
        required_evidence_ids: Iterable[str],
        *,
        rejected_evidence_ids: Iterable[str] = (),
    ) -> ObjectiveEvidenceInventory:
        """Recompute resolution/support counts without semantic Agent output."""

        required = sorted(set(required_evidence_ids))
        resolved: list[str] = []
        verified_non_llm: list[str] = []
        unknown: list[str] = []
        rejected = sorted(set(rejected_evidence_ids).intersection(required))
        for evidence_id in required:
            item = self.resolve(evidence_id)
            if item is None:
                unknown.append(evidence_id)
                continue
            resolved.append(evidence_id)
            if evidence_id in rejected:
                continue
            if item.type is EvidenceType.LLM_SEMANTIC or not item.verified:
                unknown.append(evidence_id)
            else:
                verified_non_llm.append(evidence_id)
        return ObjectiveEvidenceInventory(
            required_evidence_count=len(required),
            resolved_evidence_count=len(resolved),
            verified_non_llm_evidence_count=len(verified_non_llm),
            unknown_evidence_count=len(unknown),
            rejected_evidence_count=len(rejected),
            required_evidence_ids=required,
            resolved_evidence_ids=resolved,
            verified_non_llm_evidence_ids=verified_non_llm,
            unknown_evidence_ids=unknown,
            rejected_evidence_ids=rejected,
        )
