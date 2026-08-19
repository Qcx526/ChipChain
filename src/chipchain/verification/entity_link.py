"""Independent exact canonical-key EntityLink re-verification."""

from chipchain.candidate import EntityLink
from chipchain.knowledge import KnowledgeNode, hardware_resource_match_keys
from chipchain.models import BehaviorNode
from chipchain.verification.enums import VerificationStatus, VerificationSubjectKind
from chipchain.verification.models import VerificationRecord


class EntityLinkVerifier:
    verifier_name = "phase9ar_entity_link_exact_v1"

    def verify(self, interaction_id: str, link: EntityLink, behavior_anchor: BehaviorNode,
               knowledge_anchor: KnowledgeNode) -> VerificationRecord:
        messages: list[str] = []
        status = VerificationStatus.UNKNOWN
        if link.architecture is not behavior_anchor.architecture or knowledge_anchor.architecture is not link.architecture:
            status, messages = VerificationStatus.REJECTED, ["EntityLink endpoint architecture mismatch"]
        elif link.behavior_node_id != behavior_anchor.id or link.knowledge_node_id != knowledge_anchor.id:
            status, messages = VerificationStatus.REJECTED, ["EntityLink endpoint identity mismatch"]
        else:
            behavior_keys = set(hardware_resource_match_keys(behavior_anchor.architecture,
                address=behavior_anchor.address, metadata=behavior_anchor.metadata))
            knowledge_keys = set(knowledge_anchor.match_keys)
            if not behavior_keys or not knowledge_keys:
                messages = ["canonical keys could not be generated"]
            else:
                intersection = behavior_keys & knowledge_keys
                if not intersection:
                    status, messages = VerificationStatus.REJECTED, ["canonical key intersection is empty"]
                elif not set(link.match_keys).issubset(intersection):
                    status, messages = VerificationStatus.REJECTED, ["stored EntityLink keys are not in recomputed intersection"]
                else:
                    status, messages = VerificationStatus.VERIFIED, ["stored keys are contained in the recomputed exact intersection"]
        return VerificationRecord.create(interaction_id=interaction_id, architecture=link.architecture,
            subject_kind=VerificationSubjectKind.ENTITY_LINK, subject_id=link.id, status=status,
            verifier=self.verifier_name, rule_ids=["entity-link:exact-canonical-key:v1"], messages=messages)
