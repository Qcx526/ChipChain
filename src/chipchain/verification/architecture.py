"""ARM MVP architecture and candidate-structure rule verification."""

from __future__ import annotations

from collections.abc import Callable

from chipchain.candidate import CrossGraphCandidate
from chipchain.knowledge import KnowledgeNode
from chipchain.models import Architecture, BehaviorEdge, BehaviorNode, Layer, RelationType
from chipchain.verification.enums import VerificationStatus, VerificationSubjectKind
from chipchain.verification.models import VerificationRecord


class ARMArchitectureRuleVerifier:
    """Evaluate each ARM/structural invariant as an independent record."""

    verifier_name = "phase9a_arm_architecture_rules_v1"

    def verify(
        self,
        candidate: CrossGraphCandidate,
        behavior_nodes: list[BehaviorNode],
        behavior_edges: list[BehaviorEdge],
        knowledge_nodes: list[KnowledgeNode],
    ) -> list[VerificationRecord]:
        node_by_id = {item.id: item for item in behavior_nodes}
        knowledge_by_id = {item.id: item for item in knowledge_nodes}
        rules: list[tuple[str, Callable[[], bool | None]]] = [
            ("candidate-is-arm", lambda: candidate.architecture is Architecture.ARM),
            ("behavior-context-is-arm", lambda: all(item.architecture is Architecture.ARM for item in [*behavior_nodes, *behavior_edges])),
            ("entity-link-is-arm", lambda: candidate.entity_link.architecture is Architecture.ARM),
            ("knowledge-specific-context-is-arm", lambda: all(item.architecture in {None, Architecture.ARM} for item in knowledge_nodes)),
            ("path-crosses-two-layers", lambda: len({item.layer for item in behavior_nodes}) >= 2),
            ("path-contains-hardware", lambda: any(item.layer is Layer.HARDWARE for item in behavior_nodes)),
            ("path-ends-at-linked-behavior-anchor", lambda: bool(candidate.behavior_path.node_ids) and candidate.behavior_path.node_ids[-1] == candidate.entity_link.behavior_node_id and candidate.entity_link.behavior_node_id in node_by_id),
            ("knowledge-anchor-is-linked-anchor", lambda: candidate.knowledge_anchor_node_id == candidate.entity_link.knowledge_node_id and candidate.knowledge_anchor_node_id in knowledge_by_id),
            ("mmio-software-to-hardware-transition", lambda: self._valid_mmio_transitions(behavior_edges, node_by_id)),
        ]
        records: list[VerificationRecord] = []
        for rule_id, predicate in rules:
            try:
                passed = predicate()
            except (KeyError, TypeError, ValueError):
                passed = None
            if passed is None:
                status = VerificationStatus.UNKNOWN
                message = "rule input is incomplete"
            elif passed:
                status = VerificationStatus.VERIFIED
                message = "rule satisfied"
            else:
                status = VerificationStatus.REJECTED
                message = "explicit architecture/structure conflict"
            records.append(
                VerificationRecord.create(
                    architecture=candidate.architecture,
                    subject_kind=VerificationSubjectKind.ARCHITECTURE_RULE,
                    subject_id=rule_id,
                    status=status,
                    verifier=self.verifier_name,
                    rule_ids=[f"architecture:arm:{rule_id}:v1"],
                    messages=[message],
                )
            )
        return records

    @staticmethod
    def _valid_mmio_transitions(
        edges: list[BehaviorEdge], node_by_id: dict[str, BehaviorNode]
    ) -> bool | None:
        mmio_edges = [
            item for item in edges
            if item.relation in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}
        ]
        if not mmio_edges:
            return None
        for edge in mmio_edges:
            source = node_by_id.get(edge.source_id)
            target = node_by_id.get(edge.target_id)
            if source is None or target is None:
                return False
            if source.layer not in {Layer.FIRMWARE, Layer.DRIVER} or target.layer is not Layer.HARDWARE:
                return False
        return True
