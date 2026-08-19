"""Deterministic, explicitly scoped interaction feature extraction."""

from chipchain.knowledge import KnowledgeNodeKind
from chipchain.models import CrossLayerInteraction, Layer, RelationType
from chipchain.verification.adapter import LegacyCandidateEvidenceContext
from chipchain.verification.enums import (
    ConditionStatus,
    InteractionSourceKind,
)
from chipchain.verification.models import (
    ConditionAssessment,
    CrossLayerTriggerFeatureSet,
    HardwareAddress,
    InteractionReferenceBinding,
    TriggerFeatureProvenance,
)


class CrossLayerTriggerFeatureExtractor:
    """Extract only interaction-bound facts with provenance for every feature."""

    def extract(
        self,
        interaction: CrossLayerInteraction,
        bindings: list[InteractionReferenceBinding],
        conditions: list[ConditionAssessment],
        context: LegacyCandidateEvidenceContext | None = None,
    ) -> CrossLayerTriggerFeatureSet:
        provenance: list[TriggerFeatureProvenance] = []

        def add(feature_id: str, source_kind: str, source_id: str, field: str) -> None:
            provenance.append(
                TriggerFeatureProvenance(
                    feature_id=feature_id,
                    source_kind=source_kind,
                    source_id=source_id,
                    source_field=field,
                )
            )

        semantic_fields = (
            ("trigger_behavior", interaction.trigger_behavior_ids, "trigger_behavior_ids"),
            ("propagation_behavior", interaction.propagation_behavior_ids, "propagation_behavior_ids"),
            ("fault_state", interaction.fault_state_ids, "fault_state_ids"),
            ("affected_execution", interaction.affected_execution_ids, "affected_execution_ids"),
            ("security_mechanism", interaction.security_mechanism_ids, "security_mechanism_ids"),
        )
        for prefix, values, field in semantic_fields:
            for value in values:
                add(f"{prefix}:{value}", "cross_layer_interaction", interaction.id, field)

        for binding in bindings:
            add(
                f"binding:{binding.reference_role.value}:{binding.interaction_reference_id}",
                binding.source_kind.value,
                binding.source_id,
                "explicit_binding",
            )

        relations: list[RelationType] = []
        addresses: list[HardwareAddress] = []
        maps: list[str] = []
        regions: list[str] = []
        mmio: list[RelationType] = []
        interfaces: list[str] = []
        cwe: list[str] = []
        capec: list[str] = []
        trigger_inputs: list[str] = []
        trigger_events: list[str] = []
        privileges: list[str] = []
        states: list[str] = []
        configurations: list[str] = []

        if context is not None:
            behavior_nodes = {item.id: item for item in context.behavior_nodes}
            behavior_edges = {item.id: item for item in context.behavior_edges}
            knowledge_nodes = {item.id: item for item in context.knowledge_nodes}
            bound_node_ids = {
                item.source_id
                for item in bindings
                if item.source_kind is InteractionSourceKind.BEHAVIOR_NODE
            }
            bound_edge_ids = {
                item.source_id
                for item in bindings
                if item.source_kind is InteractionSourceKind.BEHAVIOR_EDGE
            }
            for edge_id in bound_edge_ids:
                edge = behavior_edges.get(edge_id)
                if edge is not None:
                    bound_node_ids.update({edge.source_id, edge.target_id})
            if any(
                item.source_kind is InteractionSourceKind.ENTITY_LINK
                and item.source_id == context.candidate.entity_link.id
                for item in bindings
            ):
                bound_node_ids.add(context.candidate.entity_link.behavior_node_id)

            for node_id in sorted(bound_node_ids):
                node = behavior_nodes.get(node_id)
                if node is None:
                    continue
                if node.layer is Layer.HARDWARE and node.address:
                    canonical = HardwareAddress(value=node.address)
                    addresses.append(canonical)
                    add(f"hardware_address:{canonical.value}", "behavior_node", node.id, "address")
                _metadata_feature(node.metadata, "memory_map_id", "memory_map_id", maps, add, "behavior_node", node.id)
                _metadata_feature(node.metadata, "memory_map_region", "memory_map_region", regions, add, "behavior_node", node.id)
                _metadata_feature(node.metadata, "interface_identifier", "interface", interfaces, add, "behavior_node", node.id)

            for edge_id in sorted(bound_edge_ids):
                edge = behavior_edges.get(edge_id)
                if edge is None:
                    continue
                relations.append(edge.relation)
                add(f"behavior_relation:{edge.relation.value}", "behavior_edge", edge.id, "relation")
                if edge.relation in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}:
                    mmio.append(edge.relation)
                    add(f"mmio_access:{edge.relation.value}", "behavior_edge", edge.id, "relation")
                _metadata_feature(edge.metadata, "memory_map_id", "memory_map_id", maps, add, "behavior_edge", edge.id)
                _metadata_feature(edge.metadata, "memory_map_region", "memory_map_region", regions, add, "behavior_edge", edge.id)
                _metadata_feature(edge.metadata, "interface_identifier", "interface", interfaces, add, "behavior_edge", edge.id)

            bound_knowledge_ids = {
                item.source_id
                for item in bindings
                if item.source_kind is InteractionSourceKind.KNOWLEDGE_NODE
            }
            bound_knowledge_ids.update(item.condition_node_id for item in conditions)
            for node_id in sorted(bound_knowledge_ids):
                node = knowledge_nodes.get(node_id)
                if node is None:
                    continue
                if node.kind is KnowledgeNodeKind.INTERFACE:
                    for value in node.external_ids or [node.id]:
                        interfaces.append(value)
                        add(f"interface:{value}", "knowledge_node", node.id, "external_ids")
                elif node.kind is KnowledgeNodeKind.CWE:
                    for value in node.external_ids or [node.label]:
                        cwe.append(value)
                        add(f"cwe:{value}", "knowledge_node", node.id, "external_ids")
                elif node.kind is KnowledgeNodeKind.CAPEC:
                    for value in node.external_ids or [node.label]:
                        capec.append(value)
                        add(f"capec:{value}", "knowledge_node", node.id, "external_ids")
                elif node.kind is KnowledgeNodeKind.TRIGGER:
                    _metadata_feature(node.metadata, "input", "trigger_input", trigger_inputs, add, "knowledge_node", node.id)
                    _metadata_feature(node.metadata, "event", "trigger_event", trigger_events, add, "knowledge_node", node.id)
                elif node.kind is KnowledgeNodeKind.PRECONDITION:
                    _metadata_feature(node.metadata, "privilege", "required_privilege", privileges, add, "knowledge_node", node.id)
                    _metadata_feature(node.metadata, "security_state", "required_security_state", states, add, "knowledge_node", node.id)
                    _metadata_feature(node.metadata, "configuration", "required_configuration", configurations, add, "knowledge_node", node.id)

        unresolved = []
        for condition in conditions:
            if condition.status is ConditionStatus.UNKNOWN:
                feature_id = f"condition:{condition.condition_node_id}"
                unresolved.append(feature_id)
                add(feature_id, "condition_assessment", condition.condition_node_id, "status")

        metadata = {
            "extractor": "phase9ar1_deterministic_v1",
            "features_are_not_verified_facts": True,
            "legacy_context_scope": "explicit_bindings_and_conditions_only",
            "initiating_software_vulnerability": (
                "not_required_by_interaction_type"
                if not interaction.initiating_vulnerability_ids
                else "referenced"
            ),
        }
        if interaction.direction.value == "hardware_to_software" and context is None:
            metadata["semantic_contract_only"] = True
        return CrossLayerTriggerFeatureSet(
            interaction_id=interaction.id,
            architecture=interaction.architecture,
            interaction_type=interaction.interaction_type,
            direction=interaction.direction,
            trigger_behavior_ids=interaction.trigger_behavior_ids,
            propagation_behavior_ids=interaction.propagation_behavior_ids,
            fault_state_ids=interaction.fault_state_ids,
            affected_execution_ids=interaction.affected_execution_ids,
            behavior_relation_sequence=relations,
            interface_identifiers=sorted(set(interfaces)),
            hardware_addresses=list({item.value: item for item in addresses}.values()),
            memory_map_ids=sorted(set(maps)),
            memory_map_regions=sorted(set(regions)),
            mmio_access_types=sorted(set(mmio), key=lambda item: item.value),
            trigger_inputs=sorted(set(trigger_inputs)),
            trigger_events=sorted(set(trigger_events)),
            required_privileges=sorted(set(privileges)),
            required_security_states=sorted(set(states)),
            required_configurations=sorted(set(configurations)),
            security_mechanism_ids=interaction.security_mechanism_ids,
            cwe_ids=sorted(set(cwe)),
            capec_ids=sorted(set(capec)),
            unresolved_feature_ids=unresolved,
            provenance=provenance,
            metadata=metadata,
        )


def _metadata_feature(metadata, field, prefix, destination, add, source_kind, source_id):
    value = metadata.get(field)
    if isinstance(value, str) and value.strip():
        destination.append(value)
        add(f"{prefix}:{value}", source_kind, source_id, field)
