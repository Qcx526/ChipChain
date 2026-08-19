"""Deterministic trigger-feature extraction with structured provenance."""

from __future__ import annotations

from chipchain.knowledge import KnowledgeNode, KnowledgeNodeKind
from chipchain.models import Architecture, BehaviorEdge, BehaviorNode, RelationType
from chipchain.verification.enums import ConditionStatus
from chipchain.verification.models import (
    ConditionAssessment,
    HardwareAddress,
    TriggerFeatureProvenance,
    TriggerFeatureSet,
)


class TriggerFeatureExtractor:
    """Extract source-backed features without deciding trigger satisfaction."""

    def extract(
        self,
        *,
        candidate_id: str,
        architecture: Architecture,
        behavior_nodes: list[BehaviorNode],
        behavior_edges: list[BehaviorEdge],
        knowledge_nodes: list[KnowledgeNode],
        trigger_assessments: list[ConditionAssessment],
        precondition_assessments: list[ConditionAssessment],
    ) -> TriggerFeatureSet:
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

        entrypoints: list[str] = []
        interfaces: list[str] = []
        hardware_addresses: list[HardwareAddress] = []
        map_ids: list[str] = []
        regions: list[str] = []
        trigger_inputs: list[str] = []
        trigger_events: list[str] = []
        privileges: list[str] = []
        states: list[str] = []
        configurations: list[str] = []
        mechanisms: list[str] = []
        cwe: list[str] = []
        capec: list[str] = []

        for node in knowledge_nodes:
            fields: list[tuple[str, list[str], str]] = []
            if node.kind is KnowledgeNodeKind.TRIGGER:
                fields = [
                    ("entrypoint", entrypoints, "entrypoint"),
                    ("input", trigger_inputs, "trigger_input"),
                    ("event", trigger_events, "trigger_event"),
                ]
            elif node.kind is KnowledgeNodeKind.PRECONDITION:
                fields = [
                    ("privilege", privileges, "required_privilege"),
                    ("security_state", states, "required_security_state"),
                    ("configuration", configurations, "required_configuration"),
                ]
            for field, destination, prefix in fields:
                value = node.metadata.get(field)
                if isinstance(value, str) and value.strip():
                    destination.append(value)
                    add(f"{prefix}:{value}", "knowledge_node", node.id, field)

            if node.kind is KnowledgeNodeKind.INTERFACE:
                values = [*node.external_ids]
                identifier = node.metadata.get("identifier")
                if isinstance(identifier, str) and identifier.strip():
                    values.append(identifier)
                for value in values:
                    interfaces.append(value)
                    add(f"interface:{value}", "knowledge_node", node.id, "identifier")
            elif node.kind is KnowledgeNodeKind.SECURITY_MECHANISM:
                for value in node.external_ids or [node.id]:
                    mechanisms.append(value)
                    add(f"security_mechanism:{value}", "knowledge_node", node.id, "external_ids")
            elif node.kind in {KnowledgeNodeKind.CWE, KnowledgeNodeKind.CAPEC}:
                destination = cwe if node.kind is KnowledgeNodeKind.CWE else capec
                prefix = node.kind.value
                for value in node.external_ids or [node.label]:
                    destination.append(value)
                    add(f"{prefix}:{value}", "knowledge_node", node.id, "external_ids")

        for node in behavior_nodes:
            if node.address is not None and node.layer.value == "hardware":
                hardware_addresses.append(HardwareAddress(value=node.address))
                add(f"hardware_address:{hex(int(node.address, 16))}", "behavior_node", node.id, "address")
            for field, destination, prefix in (
                ("memory_map_id", map_ids, "memory_map_id"),
                ("memory_map_region", regions, "memory_map_region"),
            ):
                value = node.metadata.get(field)
                if isinstance(value, str) and value.strip():
                    destination.append(value)
                    add(f"{prefix}:{value}", "behavior_node", node.id, field)

        mmio_types: list[RelationType] = []
        for edge in behavior_edges:
            if edge.relation in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}:
                mmio_types.append(edge.relation)
                add(f"mmio_access:{edge.relation.value}", "behavior_edge", edge.id, "relation")
            for field, destination, prefix in (
                ("memory_map_id", map_ids, "memory_map_id"),
                ("memory_map_region", regions, "memory_map_region"),
            ):
                value = edge.metadata.get(field)
                if isinstance(value, str) and value.strip():
                    destination.append(value)
                    add(f"{prefix}:{value}", "behavior_edge", edge.id, field)

        unresolved = [
            f"condition:{item.condition_node_id}"
            for item in [*trigger_assessments, *precondition_assessments]
            if item.status is ConditionStatus.UNKNOWN
        ]
        return TriggerFeatureSet(
            candidate_id=candidate_id,
            architecture=architecture,
            entrypoint_candidates=sorted(set(entrypoints)),
            behavior_relation_sequence=[item.relation for item in behavior_edges],
            interface_identifiers=sorted(set(interfaces)),
            hardware_addresses=list({item.value: item for item in hardware_addresses}.values()),
            memory_map_ids=sorted(set(map_ids)),
            memory_map_regions=sorted(set(regions)),
            mmio_access_types=sorted(set(mmio_types), key=lambda item: item.value),
            trigger_inputs=sorted(set(trigger_inputs)),
            trigger_events=sorted(set(trigger_events)),
            required_privileges=sorted(set(privileges)),
            required_security_states=sorted(set(states)),
            required_configurations=sorted(set(configurations)),
            security_mechanism_ids=sorted(set(mechanisms)),
            cwe_ids=sorted(set(cwe)),
            capec_ids=sorted(set(capec)),
            unresolved_feature_ids=unresolved,
            provenance=provenance,
            metadata={"extractor": "phase9a_deterministic_v1", "features_are_not_conditions": True},
        )

