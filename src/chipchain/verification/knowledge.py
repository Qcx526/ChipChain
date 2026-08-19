"""Knowledge relation and explicitly bound vulnerability participant checks."""

from chipchain.knowledge import KnowledgeEdge, KnowledgeNode, KnowledgeNodeKind, KnowledgeRelationType
from chipchain.models import EvidenceType, HARDWARE_SIDE_LAYERS, SOFTWARE_SIDE_LAYERS, CrossLayerInteractionType
from chipchain.verification.enums import InteractionReferenceRole, VerificationStatus, VerificationSubjectKind
from chipchain.verification.evidence import EvidenceCatalog
from chipchain.verification.models import InteractionReferenceBinding, VerificationRecord

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
    verifier_name = "phase9ar_knowledge_relation_v1"

    def verify(self, interaction_id: str, edge: KnowledgeEdge, source: KnowledgeNode,
               target: KnowledgeNode, catalog: EvidenceCatalog) -> VerificationRecord:
        if edge.source_id != source.id or edge.target_id != target.id:
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["knowledge edge endpoint mismatch"])
        if target.kind is not _EXPECTED_TARGET_KIND.get(edge.relation):
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["knowledge relation target kind mismatch"])
        for node in (source, target):
            if node.architecture is not None and node.architecture is not edge.architecture:
                return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["knowledge relation architecture mismatch"])
        resolved, usable, messages = [], [], []
        for evidence_id in edge.evidence_ids:
            evidence = catalog.resolve(evidence_id)
            if evidence is None: continue
            resolved.append(evidence_id)
            if evidence.type is not EvidenceType.LLM_SEMANTIC and evidence.verified:
                derived = edge.metadata.get("derived_from_sample")
                if isinstance(derived, str) and not evidence.id.startswith(f"sample:{derived}:evidence:"):
                    return self._record(interaction_id, edge, VerificationStatus.REJECTED, resolved, ["knowledge Evidence source sample mismatch"])
                usable.append(evidence_id)
        status = VerificationStatus.VERIFIED if usable else VerificationStatus.UNKNOWN
        messages.append("knowledge relation provenance supported" if usable else "knowledge relation lacks verified non-LLM provenance")
        return self._record(interaction_id, edge, status, resolved, messages)

    def _record(self, interaction_id: str, edge: KnowledgeEdge, status: VerificationStatus,
                evidence_ids: list[str], messages: list[str]) -> VerificationRecord:
        return VerificationRecord.create(interaction_id=interaction_id, architecture=edge.architecture,
            subject_kind=VerificationSubjectKind.KNOWLEDGE_EDGE, subject_id=edge.id, status=status,
            verifier=self.verifier_name, evidence_ids=evidence_ids,
            rule_ids=[f"knowledge:{edge.relation.value}:record-and-provenance:v1"], messages=messages)


class VulnerabilityParticipantVerifier:
    """Validate role/layer identity, then require evidence for vulnerability support."""

    verifier_name = "phase9ar_vulnerability_participant_v1"

    def verify(self, interaction_id: str, interaction_type: CrossLayerInteractionType,
               architecture, binding: InteractionReferenceBinding, node: KnowledgeNode,
               catalog: EvidenceCatalog) -> VerificationRecord:
        messages: list[str] = []
        rejected = False
        if node.kind is not KnowledgeNodeKind.VULNERABILITY:
            rejected, messages = True, ["bound participant is not a Vulnerability"]
        elif node.architecture is not architecture:
            rejected, messages = True, ["bound vulnerability architecture mismatch"]
        else:
            expected = HARDWARE_SIDE_LAYERS if (
                binding.reference_role is InteractionReferenceRole.TARGET_VULNERABILITY
                and interaction_type in {CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE,
                                         CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE}
            ) or (binding.reference_role is InteractionReferenceRole.INITIATING_VULNERABILITY
                  and interaction_type is CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE) else SOFTWARE_SIDE_LAYERS
            if node.layer not in expected:
                rejected, messages = True, ["bound vulnerability layer does not match its interaction role"]
        resolved = []
        usable = []
        if not rejected:
            for evidence_id in node.evidence_ids:
                evidence = catalog.resolve(evidence_id)
                if evidence is not None:
                    resolved.append(evidence_id)
                    if evidence.verified and evidence.type is not EvidenceType.LLM_SEMANTIC:
                        usable.append(evidence_id)
            messages.append("participant reference resolved; independent vulnerability evidence is absent" if not usable else
                            "participant has verified non-LLM vulnerability evidence")
        status = VerificationStatus.REJECTED if rejected else (VerificationStatus.VERIFIED if usable else VerificationStatus.UNKNOWN)
        return VerificationRecord.create(interaction_id=interaction_id, architecture=architecture,
            subject_kind=VerificationSubjectKind.INTERACTION_PARTICIPANT,
            subject_id=f"{binding.reference_role.value}:{binding.interaction_reference_id}",
            status=status, verifier=self.verifier_name, evidence_ids=resolved,
            rule_ids=["participant:vulnerability-role-layer-evidence:v1"], messages=messages,
            metadata={"source_id": node.id, "reference_role": binding.reference_role.value})
