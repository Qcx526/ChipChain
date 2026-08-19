"""Strict exact-evidence Trigger and Precondition assessment."""

from __future__ import annotations

from chipchain.knowledge import KnowledgeNode, KnowledgeNodeKind
from chipchain.models import EvidenceType
from chipchain.verification.enums import ConditionKind, ConditionStatus, VerificationStatus
from chipchain.verification.evidence import EvidenceCatalog
from chipchain.verification.models import ConditionAssessment, VerificationRecord


class ConditionVerifier:
    """Assess only explicit condition assertions; absence remains UNKNOWN."""

    rule_id = "condition:exact-structured-evidence:v1"

    def verify(
        self,
        node: KnowledgeNode,
        catalog: EvidenceCatalog,
        *,
        behavior_records: list[VerificationRecord] | None = None,
        behavior_entrypoint_names: set[str] | None = None,
    ) -> ConditionAssessment:
        if node.kind is KnowledgeNodeKind.TRIGGER:
            kind = ConditionKind.TRIGGER
        elif node.kind is KnowledgeNodeKind.PRECONDITION:
            kind = ConditionKind.PRECONDITION
        else:
            raise ValueError("ConditionVerifier accepts Trigger or Precondition nodes")

        supporting: list[str] = []
        contradicting: list[str] = []
        messages: list[str] = []
        for evidence_id in node.evidence_ids:
            evidence = catalog.resolve(evidence_id)
            if evidence is None or evidence.type is EvidenceType.LLM_SEMANTIC or not evidence.verified:
                continue
            if evidence.metadata.get("condition_node_id") != node.id:
                continue
            assertion = evidence.metadata.get("condition_assertion")
            if assertion == "satisfied":
                supporting.append(evidence_id)
            elif assertion == "unsatisfied":
                contradicting.append(evidence_id)

        if supporting and contradicting:
            status = ConditionStatus.UNKNOWN
            messages.append("structured condition evidence conflicts")
        elif contradicting:
            status = ConditionStatus.UNSATISFIED
            messages.append("explicit structured Evidence says the condition is unsatisfied")
        elif supporting:
            status = ConditionStatus.SATISFIED
            messages.append("explicit structured Evidence says the condition is satisfied")
        else:
            status = ConditionStatus.UNKNOWN
            if kind is ConditionKind.TRIGGER:
                entrypoint = node.metadata.get("entrypoint")
                reachable = (
                    isinstance(entrypoint, str)
                    and entrypoint in (behavior_entrypoint_names or set())
                    and any(item.status is VerificationStatus.VERIFIED for item in (behavior_records or []))
                )
                if reachable:
                    messages.append("entrypoint reachability is supported, but full trigger facts are absent")
                else:
                    messages.append("trigger lacks exact execution evidence")
            else:
                messages.append("precondition lacks exact privilege/security/configuration evidence")
        return ConditionAssessment(
            condition_node_id=node.id,
            condition_kind=kind,
            status=status,
            supporting_evidence_ids=supporting,
            contradicting_evidence_ids=contradicting,
            rule_ids=[self.rule_id],
            messages=messages,
            metadata={"exact_evidence_only": True},
        )

