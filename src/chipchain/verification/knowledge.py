"""Objective verification of candidate-referenced knowledge relations."""

from __future__ import annotations

from chipchain.knowledge import (
    KnowledgeEdge,
    KnowledgeNode,
    KnowledgeNodeKind,
    KnowledgeRelationType,
)
from chipchain.models import EvidenceType
from chipchain.verification.enums import VerificationStatus, VerificationSubjectKind
from chipchain.verification.evidence import EvidenceCatalog
from chipchain.verification.models import VerificationRecord

_EXPECTED_TARGET_KIND = {
    KnowledgeRelationType.HAS_CWE: KnowledgeNodeKind.CWE,
    KnowledgeRelationType.HAS_CAPEC: KnowledgeNodeKind.CAPEC,
    KnowledgeRelationType.AFFECTS_COMPONENT: KnowledgeNodeKind.COMPONENT,
    KnowledgeRelationType.HAS_TRIGGER: KnowledgeNodeKind.TRIGGER,
    KnowledgeRelationType.REQUIRES_PRECONDITION: KnowledgeNodeKind.PRECONDITION,
    KnowledgeRelationType.INVOLVES_BEHAVIOR: KnowledgeNodeKind.BEHAVIOR,
    KnowledgeRelationType.USES_INTERFACE: KnowledgeNodeKind.INTERFACE,
    KnowledgeRelationType.TARGETS_RESOURCE: KnowledgeNodeKind.HARDWARE_RESOURCE,
    KnowledgeRelationType.INVOLVES_SECURITY_MECHANISM: KnowledgeNodeKind.SECURITY_MECHANISM,
    KnowledgeRelationType.LEADS_TO_IMPACT: KnowledgeNodeKind.IMPACT,
    KnowledgeRelationType.HAS_ROOT_CAUSE: KnowledgeNodeKind.ROOT_CAUSE,
}


class KnowledgeRelationVerifier:
    """Verify KG recording plus its attached non-LLM provenance."""

    verifier_name = "phase9a_knowledge_relation_v1"

    def verify(
        self,
        edge: KnowledgeEdge,
        source: KnowledgeNode,
        target: KnowledgeNode,
        catalog: EvidenceCatalog,
    ) -> VerificationRecord:
        messages: list[str] = []
        if edge.source_id != source.id or edge.target_id != target.id:
            return self._record(edge, VerificationStatus.REJECTED, [], ["knowledge edge endpoint mismatch"])
        if source.kind is not KnowledgeNodeKind.VULNERABILITY:
            return self._record(edge, VerificationStatus.REJECTED, [], ["candidate knowledge relation must originate at Vulnerability"])
        if target.kind is not _EXPECTED_TARGET_KIND.get(edge.relation):
            return self._record(edge, VerificationStatus.REJECTED, [], ["knowledge relation target kind mismatch"])
        for node in (source, target):
            if node.architecture is not None and node.architecture is not edge.architecture:
                return self._record(edge, VerificationStatus.REJECTED, [], ["knowledge relation architecture mismatch"])
        if not edge.evidence_ids:
            return self._record(edge, VerificationStatus.UNKNOWN, [], ["knowledge relation has no Evidence"])

        resolved: list[str] = []
        usable: list[str] = []
        derived_sample = edge.metadata.get("derived_from_sample")
        for evidence_id in edge.evidence_ids:
            evidence = catalog.resolve(evidence_id)
            if evidence is None:
                messages.append(f"Evidence {evidence_id} is unresolved")
                continue
            resolved.append(evidence_id)
            if evidence.type is EvidenceType.LLM_SEMANTIC or not evidence.verified:
                messages.append(f"Evidence {evidence_id} is not verified non-LLM evidence")
                continue
            if isinstance(derived_sample, str) and not evidence.id.startswith(
                f"sample:{derived_sample}:evidence:"
            ):
                return self._record(edge, VerificationStatus.REJECTED, resolved, ["knowledge Evidence source sample mismatch"])
            usable.append(evidence_id)
        if usable:
            messages.append("knowledge relation has source-consistent verified non-LLM Evidence")
            status = VerificationStatus.VERIFIED
        else:
            status = VerificationStatus.UNKNOWN
        return self._record(edge, status, resolved, messages)

    def _record(
        self,
        edge: KnowledgeEdge,
        status: VerificationStatus,
        evidence_ids: list[str],
        messages: list[str],
    ) -> VerificationRecord:
        return VerificationRecord.create(
            architecture=edge.architecture,
            subject_kind=VerificationSubjectKind.KNOWLEDGE_EDGE,
            subject_id=edge.id,
            status=status,
            verifier=self.verifier_name,
            evidence_ids=evidence_ids,
            rule_ids=[f"knowledge:{edge.relation.value}:record-and-evidence:v1"],
            messages=messages,
            metadata={"relation": edge.relation.value},
        )

