"""Deterministic interaction trigger-feature extraction."""

from chipchain.knowledge import KnowledgeNodeKind
from chipchain.models import CrossLayerInteraction, Layer, RelationType
from chipchain.verification.adapter import LegacyCandidateEvidenceContext
from chipchain.verification.enums import ConditionStatus
from chipchain.verification.models import (ConditionAssessment, CrossLayerTriggerFeatureSet,
    HardwareAddress, InteractionReferenceBinding, TriggerFeatureProvenance)


class CrossLayerTriggerFeatureExtractor:
    def extract(self, interaction: CrossLayerInteraction, bindings: list[InteractionReferenceBinding],
                conditions: list[ConditionAssessment],
                context: LegacyCandidateEvidenceContext | None = None) -> CrossLayerTriggerFeatureSet:
        provenance = [TriggerFeatureProvenance(feature_id=f"{b.reference_role.value}:{b.interaction_reference_id}",
            source_kind=b.source_kind.value, source_id=b.source_id, source_field="explicit_binding") for b in bindings]
        relations, addresses, maps, regions, mmio, interfaces, cwe, capec = [], [], [], [], [], [], [], []
        trigger_inputs, trigger_events, privileges, states, configs = [], [], [], [], []
        if context:
            for node in context.behavior_nodes:
                if node.layer is Layer.HARDWARE and node.address:
                    addresses.append(HardwareAddress(value=node.address))
                if isinstance(node.metadata.get("memory_map_id"), str): maps.append(node.metadata["memory_map_id"])
                if isinstance(node.metadata.get("memory_map_region"), str): regions.append(node.metadata["memory_map_region"])
            for edge in context.behavior_edges:
                relations.append(edge.relation)
                if edge.relation in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}: mmio.append(edge.relation)
                if isinstance(edge.metadata.get("memory_map_id"), str): maps.append(edge.metadata["memory_map_id"])
                if isinstance(edge.metadata.get("memory_map_region"), str): regions.append(edge.metadata["memory_map_region"])
            for node in context.knowledge_nodes:
                if node.kind is KnowledgeNodeKind.INTERFACE: interfaces.extend(node.external_ids or [node.id])
                elif node.kind is KnowledgeNodeKind.CWE: cwe.extend(node.external_ids or [node.label])
                elif node.kind is KnowledgeNodeKind.CAPEC: capec.extend(node.external_ids or [node.label])
                elif node.kind is KnowledgeNodeKind.TRIGGER:
                    if isinstance(node.metadata.get("input"), str): trigger_inputs.append(node.metadata["input"])
                    if isinstance(node.metadata.get("event"), str): trigger_events.append(node.metadata["event"])
                elif node.kind is KnowledgeNodeKind.PRECONDITION:
                    if isinstance(node.metadata.get("privilege"), str): privileges.append(node.metadata["privilege"])
                    if isinstance(node.metadata.get("security_state"), str): states.append(node.metadata["security_state"])
                    if isinstance(node.metadata.get("configuration"), str): configs.append(node.metadata["configuration"])
        unresolved = [f"condition:{c.condition_node_id}" for c in conditions if c.status is ConditionStatus.UNKNOWN]
        metadata = {"extractor": "phase9ar_deterministic_v1", "features_are_not_verified_facts": True,
                    "initiating_software_vulnerability": "not_required_by_interaction_type" if not interaction.initiating_vulnerability_ids else "referenced"}
        if interaction.direction.value == "hardware_to_software" and not context:
            metadata["semantic_contract_only"] = True
        return CrossLayerTriggerFeatureSet(interaction_id=interaction.id, architecture=interaction.architecture,
            interaction_type=interaction.interaction_type, direction=interaction.direction,
            trigger_behavior_ids=interaction.trigger_behavior_ids,
            propagation_behavior_ids=interaction.propagation_behavior_ids,
            fault_state_ids=interaction.fault_state_ids, affected_execution_ids=interaction.affected_execution_ids,
            behavior_relation_sequence=relations, interface_identifiers=sorted(set(interfaces)),
            hardware_addresses=list({a.value: a for a in addresses}.values()), memory_map_ids=sorted(set(maps)),
            memory_map_regions=sorted(set(regions)), mmio_access_types=sorted(set(mmio), key=lambda x: x.value),
            trigger_inputs=sorted(set(trigger_inputs)), trigger_events=sorted(set(trigger_events)),
            required_privileges=sorted(set(privileges)), required_security_states=sorted(set(states)),
            required_configurations=sorted(set(configs)), security_mechanism_ids=interaction.security_mechanism_ids,
            cwe_ids=sorted(set(cwe)), capec_ids=sorted(set(capec)), unresolved_feature_ids=unresolved,
            provenance=provenance, metadata=metadata)
