"""Exact-evidence assessment of explicitly scoped conditions."""

from chipchain.knowledge import KnowledgeNode, KnowledgeNodeKind
from chipchain.models import EvidenceType
from chipchain.verification.enums import ConditionKind, ConditionStatus
from chipchain.verification.evidence import EvidenceCatalog
from chipchain.verification.models import ConditionAssessment, InteractionConditionBinding


class ConditionVerifier:
    rule_id = "condition:exact-structured-evidence:v1"

    def verify(self, interaction_id: str, architecture, binding: InteractionConditionBinding,
               node: KnowledgeNode, catalog: EvidenceCatalog) -> ConditionAssessment:
        expected = KnowledgeNodeKind.TRIGGER if binding.condition_kind is ConditionKind.TRIGGER else KnowledgeNodeKind.PRECONDITION
        if node.kind is not expected:
            raise ValueError("condition binding kind does not match KnowledgeNode")
        if node.architecture is not architecture:
            raise ValueError("condition binding architecture mismatch")
        supporting, contradicting = [], []
        for evidence_id in node.evidence_ids:
            evidence = catalog.resolve(evidence_id)
            if evidence is None or evidence.type is EvidenceType.LLM_SEMANTIC or not evidence.verified:
                continue
            if evidence.metadata.get("condition_node_id") != node.id:
                continue
            assertion = evidence.metadata.get("condition_assertion")
            if assertion == "satisfied": supporting.append(evidence_id)
            elif assertion == "unsatisfied": contradicting.append(evidence_id)
        if supporting and contradicting:
            status, messages = ConditionStatus.UNKNOWN, ["structured condition evidence conflicts"]
        elif contradicting:
            status, messages = ConditionStatus.UNSATISFIED, ["explicit Evidence says condition is unsatisfied"]
        elif supporting:
            status, messages = ConditionStatus.SATISFIED, ["explicit Evidence says condition is satisfied"]
        else:
            status, messages = ConditionStatus.UNKNOWN, ["condition lacks exact structured evidence"]
        return ConditionAssessment(interaction_id=interaction_id, architecture=architecture,
            condition_node_id=node.id, condition_kind=binding.condition_kind,
            applies_to_role=binding.applies_to_role, required=binding.required, status=status,
            supporting_evidence_ids=supporting, contradicting_evidence_ids=contradicting,
            rule_ids=[self.rule_id], messages=messages, metadata={"exact_evidence_only": True})
