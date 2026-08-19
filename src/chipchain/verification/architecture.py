"""Type-aware ARM interaction architecture rules."""

from collections.abc import Callable

from chipchain.models import Architecture, CrossLayerDirection, CrossLayerInteraction, Layer, RelationType
from chipchain.verification.adapter import LegacyCandidateEvidenceContext
from chipchain.verification.enums import VerificationStatus, VerificationSubjectKind
from chipchain.verification.models import InteractionReferenceBinding, VerificationRecord


class InteractionArchitectureRuleVerifier:
    verifier_name = "phase9ar_interaction_architecture_v1"

    def verify(self, interaction: CrossLayerInteraction, bindings: list[InteractionReferenceBinding],
               context: LegacyCandidateEvidenceContext | None = None) -> list[VerificationRecord]:
        software = {Layer.FIRMWARE, Layer.DRIVER, Layer.INTERFACE}
        rules: list[tuple[str, Callable[[], bool | None]]] = [
            ("interaction-is-arm", lambda: interaction.architecture is Architecture.ARM),
            ("direction-matches-type", lambda: interaction.direction.value.endswith("to_hardware")
                if interaction.interaction_type.value.endswith("to_hardware") else interaction.direction is CrossLayerDirection.HARDWARE_TO_SOFTWARE),
            ("source-layer-matches-direction", lambda: interaction.source_layer in (software if interaction.direction is CrossLayerDirection.SOFTWARE_TO_HARDWARE else {Layer.HARDWARE})),
            ("target-layer-matches-direction", lambda: interaction.target_layer in ({Layer.HARDWARE} if interaction.direction is CrossLayerDirection.SOFTWARE_TO_HARDWARE else software)),
            ("referenced-architectures-match", lambda: all(a is interaction.architecture for a in interaction.referenced_architectures)),
        ]
        if context is not None:
            candidate, nodes, edges = context.candidate, context.behavior_nodes, context.behavior_edges
            by_id = {n.id: n for n in nodes}
            rules.extend([
                ("legacy-candidate-is-arm", lambda: candidate.architecture is Architecture.ARM),
                ("legacy-path-is-arm", lambda: all(x.architecture is Architecture.ARM for x in [*nodes, *edges])),
                ("legacy-path-crosses-two-layers", lambda: len({n.layer for n in nodes}) >= 2),
                ("legacy-path-contains-hardware", lambda: any(n.layer is Layer.HARDWARE for n in nodes)),
                ("legacy-path-ends-at-linked-anchor", lambda: candidate.behavior_path.node_ids[-1] == candidate.entity_link.behavior_node_id),
                ("legacy-knowledge-anchor-is-linked-anchor", lambda: candidate.knowledge_anchor_node_id == candidate.entity_link.knowledge_node_id),
                ("legacy-mmio-software-to-hardware", lambda: _mmio_rule(edges, by_id)),
            ])
        records = []
        for rule_id, predicate in rules:
            try: passed = predicate()
            except (KeyError, TypeError, ValueError): passed = None
            status = VerificationStatus.UNKNOWN if passed is None else (VerificationStatus.VERIFIED if passed else VerificationStatus.REJECTED)
            records.append(VerificationRecord.create(interaction_id=interaction.id, architecture=interaction.architecture,
                subject_kind=VerificationSubjectKind.ARCHITECTURE_RULE, subject_id=rule_id, status=status,
                verifier=self.verifier_name, rule_ids=[f"architecture:arm:{rule_id}:v1"],
                messages=["rule input is incomplete" if passed is None else ("rule satisfied" if passed else "explicit architecture conflict")]))
        return records


def _mmio_rule(edges, nodes) -> bool | None:
    mmio = [e for e in edges if e.relation in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}]
    if not mmio: return None
    return all(nodes[e.source_id].layer in {Layer.FIRMWARE, Layer.DRIVER, Layer.INTERFACE}
               and nodes[e.target_id].layer is Layer.HARDWARE for e in mmio)
