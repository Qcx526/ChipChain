"""Deterministic conversion from domain vulnerability samples to KG bundles."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any

from chipchain.knowledge.enums import KnowledgeNodeKind, KnowledgeRelationType
from chipchain.knowledge.match_keys import (
    component_match_key,
    hardware_resource_match_keys,
    interface_match_key,
)
from chipchain.knowledge.models import (
    KnowledgeEdge,
    KnowledgeGraphBundle,
    KnowledgeNode,
)
from chipchain.models import Architecture, Evidence, Layer, VulnerabilitySample


class VulnerabilityKnowledgeBuilder:
    """Build semantic knowledge entities without graph-backend dependencies."""

    def build(self, sample: VulnerabilitySample) -> KnowledgeGraphBundle:
        """Convert one validated sample into a deterministic KG bundle."""

        evidence_map = {
            item.id: self.namespaced_evidence_id(sample.id, item.id)
            for item in sample.evidence
        }
        evidence = [
            Evidence.model_validate(
                {
                    **item.model_dump(mode="json"),
                    "id": evidence_map[item.id],
                }
            )
            for item in sample.evidence
        ]

        nodes: dict[str, KnowledgeNode] = {}
        edges: dict[str, KnowledgeEdge] = {}
        vulnerability_id = f"vulnerability:{sample.id}"
        self._insert_node(
            nodes,
            KnowledgeNode(
                id=vulnerability_id,
                kind=KnowledgeNodeKind.VULNERABILITY,
                label=sample.id,
                architecture=sample.architecture,
                layer=sample.layer,
                external_ids=sorted(sample.cve),
                metadata={
                    **sample.metadata,
                    "sample_id": sample.id,
                    "sample_type": sample.sample_type.value,
                    "source": sample.source,
                    "references": sorted(sample.references),
                    "verified": sample.verified,
                },
            ),
        )

        for identifier in sorted(set(sample.cwe)):
            taxonomy_id = self._taxonomy_id(identifier)
            node = KnowledgeNode(
                id=f"cwe:{taxonomy_id}",
                kind=KnowledgeNodeKind.CWE,
                label=taxonomy_id,
                architecture=None,
                external_ids=[taxonomy_id],
                metadata={"taxonomy": "CWE"},
            )
            self._add_related_node(
                sample=sample,
                vulnerability_id=vulnerability_id,
                node=node,
                relation=KnowledgeRelationType.HAS_CWE,
                evidence_ids=[],
                nodes=nodes,
                edges=edges,
            )

        for identifier in sorted(set(sample.capec)):
            taxonomy_id = self._taxonomy_id(identifier)
            node = KnowledgeNode(
                id=f"capec:{taxonomy_id}",
                kind=KnowledgeNodeKind.CAPEC,
                label=taxonomy_id,
                architecture=None,
                external_ids=[taxonomy_id],
                metadata={"taxonomy": "CAPEC"},
            )
            self._add_related_node(
                sample=sample,
                vulnerability_id=vulnerability_id,
                node=node,
                relation=KnowledgeRelationType.HAS_CAPEC,
                evidence_ids=[],
                nodes=nodes,
                edges=edges,
            )

        component = sample.component
        self._add_related_node(
            sample=sample,
            vulnerability_id=vulnerability_id,
            node=KnowledgeNode(
                id=(
                    f"component:{sample.architecture.value}:{sample.id}:"
                    f"{component.id}"
                ),
                kind=KnowledgeNodeKind.COMPONENT,
                label=component.name,
                architecture=sample.architecture,
                layer=component.layer,
                external_ids=[component.id],
                match_keys=[component_match_key(sample.architecture, component.id)],
                metadata={
                    **component.metadata,
                    "component_kind": component.kind,
                    "version": component.version,
                },
            ),
            relation=KnowledgeRelationType.AFFECTS_COMPONENT,
            evidence_ids=[],
            nodes=nodes,
            edges=edges,
        )

        for trigger in sample.triggers:
            local_id = self._semantic_id(trigger.model_dump(mode="json"))
            evidence_ids = self._map_evidence(trigger.evidence_ids, evidence_map)
            self._add_related_node(
                sample=sample,
                vulnerability_id=vulnerability_id,
                node=KnowledgeNode(
                    id=f"trigger:{sample.architecture.value}:{sample.id}:{local_id}",
                    kind=KnowledgeNodeKind.TRIGGER,
                    label=trigger.description,
                    architecture=sample.architecture,
                    layer=sample.layer,
                    evidence_ids=evidence_ids,
                    metadata={
                        "input": trigger.input,
                        "event": trigger.event,
                        "entrypoint": trigger.entrypoint,
                    },
                ),
                relation=KnowledgeRelationType.HAS_TRIGGER,
                evidence_ids=evidence_ids,
                nodes=nodes,
                edges=edges,
            )

        for precondition in sample.preconditions:
            local_id = self._semantic_id(precondition.model_dump(mode="json"))
            evidence_ids = self._map_evidence(
                precondition.evidence_ids, evidence_map
            )
            self._add_related_node(
                sample=sample,
                vulnerability_id=vulnerability_id,
                node=KnowledgeNode(
                    id=(
                        f"precondition:{sample.architecture.value}:"
                        f"{sample.id}:{local_id}"
                    ),
                    kind=KnowledgeNodeKind.PRECONDITION,
                    label=precondition.condition,
                    architecture=sample.architecture,
                    layer=sample.layer,
                    evidence_ids=evidence_ids,
                    metadata={
                        "privilege": precondition.privilege,
                        "security_state": precondition.security_state,
                        "configuration": precondition.configuration,
                    },
                ),
                relation=KnowledgeRelationType.REQUIRES_PRECONDITION,
                evidence_ids=evidence_ids,
                nodes=nodes,
                edges=edges,
            )

        for behavior in sample.behaviors:
            evidence_ids = self._map_evidence(behavior.evidence_ids, evidence_map)
            self._add_related_node(
                sample=sample,
                vulnerability_id=vulnerability_id,
                node=KnowledgeNode(
                    id=(
                        f"behavior:{sample.architecture.value}:{sample.id}:"
                        f"{behavior.id}"
                    ),
                    kind=KnowledgeNodeKind.BEHAVIOR,
                    label=behavior.id,
                    architecture=sample.architecture,
                    layer=behavior.layer,
                    external_ids=[behavior.id],
                    evidence_ids=evidence_ids,
                    metadata={
                        **behavior.metadata,
                        "behavior_type": behavior.type.value,
                        "subject": behavior.subject,
                        "object": behavior.object,
                        "address": behavior.address,
                    },
                ),
                relation=KnowledgeRelationType.INVOLVES_BEHAVIOR,
                evidence_ids=evidence_ids,
                nodes=nodes,
                edges=edges,
            )

        for interface in sample.interfaces:
            evidence_ids = self._map_evidence(interface.evidence_ids, evidence_map)
            match_keys = []
            if interface.identifier is not None:
                match_keys.append(
                    interface_match_key(
                        sample.architecture,
                        interface.kind,
                        interface.identifier,
                    )
                )
            self._add_related_node(
                sample=sample,
                vulnerability_id=vulnerability_id,
                node=KnowledgeNode(
                    id=(
                        f"interface:{sample.architecture.value}:{sample.id}:"
                        f"{interface.id}"
                    ),
                    kind=KnowledgeNodeKind.INTERFACE,
                    label=interface.name,
                    architecture=sample.architecture,
                    layer=Layer.INTERFACE,
                    external_ids=[interface.id],
                    match_keys=match_keys,
                    evidence_ids=evidence_ids,
                    metadata={
                        **interface.metadata,
                        "interface_kind": interface.kind,
                        "identifier": interface.identifier,
                        "source_layer": interface.source_layer.value,
                        "target_layer": interface.target_layer.value,
                    },
                ),
                relation=KnowledgeRelationType.USES_INTERFACE,
                evidence_ids=evidence_ids,
                nodes=nodes,
                edges=edges,
            )

        for resource in sample.hardware_resources:
            self._add_related_node(
                sample=sample,
                vulnerability_id=vulnerability_id,
                node=KnowledgeNode(
                    id=(
                        f"hardware-resource:{sample.architecture.value}:"
                        f"{sample.id}:"
                        f"{resource.id}"
                    ),
                    kind=KnowledgeNodeKind.HARDWARE_RESOURCE,
                    label=resource.name,
                    architecture=sample.architecture,
                    layer=Layer.HARDWARE,
                    external_ids=[resource.id],
                    match_keys=hardware_resource_match_keys(
                        sample.architecture,
                        address=resource.address,
                        metadata=resource.metadata,
                    ),
                    metadata={
                        **resource.metadata,
                        "resource_kind": resource.kind,
                        "device": resource.device,
                        "register_name": resource.register_name,
                        "address": resource.address,
                        "address_range": resource.address_range,
                        "owner": resource.owner,
                    },
                ),
                relation=KnowledgeRelationType.TARGETS_RESOURCE,
                evidence_ids=[],
                nodes=nodes,
                edges=edges,
            )

        for mechanism in sample.security_mechanisms:
            self._add_related_node(
                sample=sample,
                vulnerability_id=vulnerability_id,
                node=KnowledgeNode(
                    id=(
                        f"security-mechanism:{sample.architecture.value}:"
                        f"{sample.id}:"
                        f"{mechanism.id}"
                    ),
                    kind=KnowledgeNodeKind.SECURITY_MECHANISM,
                    label=mechanism.name,
                    architecture=sample.architecture,
                    layer=Layer.HARDWARE,
                    external_ids=[mechanism.id],
                    metadata={
                        **mechanism.metadata,
                        "mechanism_kind": mechanism.kind,
                        "protected_target": mechanism.protected_target,
                        "rule_ids": sorted(mechanism.rule_ids),
                    },
                ),
                relation=(
                    KnowledgeRelationType.INVOLVES_SECURITY_MECHANISM
                ),
                evidence_ids=[],
                nodes=nodes,
                edges=edges,
            )

        for impact in sample.impacts:
            self._add_related_node(
                sample=sample,
                vulnerability_id=vulnerability_id,
                node=KnowledgeNode(
                    id=(
                        f"impact:{sample.architecture.value}:{sample.id}:"
                        f"{impact.id}"
                    ),
                    kind=KnowledgeNodeKind.IMPACT,
                    label=impact.description,
                    architecture=sample.architecture,
                    layer=Layer.IMPACT,
                    external_ids=[impact.id],
                    metadata={
                        "impact_type": impact.type,
                        "target": impact.target,
                        "severity": impact.severity,
                        "scope": impact.scope,
                    },
                ),
                relation=KnowledgeRelationType.LEADS_TO_IMPACT,
                evidence_ids=[],
                nodes=nodes,
                edges=edges,
            )

        for root_cause in sample.root_causes:
            evidence_ids = self._map_evidence(
                root_cause.evidence_ids, evidence_map
            )
            self._add_related_node(
                sample=sample,
                vulnerability_id=vulnerability_id,
                node=KnowledgeNode(
                    id=(
                        f"root-cause:{sample.architecture.value}:"
                        f"{sample.id}:"
                        f"{root_cause.id}"
                    ),
                    kind=KnowledgeNodeKind.ROOT_CAUSE,
                    label=root_cause.description or root_cause.id,
                    architecture=sample.architecture,
                    layer=sample.layer,
                    external_ids=[root_cause.id],
                    evidence_ids=evidence_ids,
                    metadata={
                        **root_cause.model_dump(
                            mode="json",
                            exclude={"id", "architecture", "evidence_ids"},
                        ),
                    },
                ),
                relation=KnowledgeRelationType.HAS_ROOT_CAUSE,
                evidence_ids=evidence_ids,
                nodes=nodes,
                edges=edges,
            )

        return KnowledgeGraphBundle(
            architecture=sample.architecture,
            sample_ids=[sample.id],
            nodes=sorted(nodes.values(), key=lambda item: item.id),
            edges=sorted(edges.values(), key=lambda item: item.id),
            evidence=sorted(evidence, key=lambda item: item.id),
            metadata={
                "builder": "VulnerabilityKnowledgeBuilder",
                "fixture": sample.sample_type.value in {"fixture", "synthetic", "demo"},
            },
        )

    def build_many(
        self, samples: Iterable[VulnerabilitySample]
    ) -> KnowledgeGraphBundle:
        """Build one architecture bundle and deduplicate identical stable entities."""

        material = list(samples)
        if not material:
            raise ValueError("build_many requires at least one sample")
        sample_ids = [sample.id for sample in material]
        if len(sample_ids) != len(set(sample_ids)):
            raise ValueError("build_many sample IDs must be unique")
        architecture = material[0].architecture
        if any(sample.architecture is not architecture for sample in material):
            raise ValueError("build_many samples must share one architecture")

        nodes: dict[str, KnowledgeNode] = {}
        edges: dict[str, KnowledgeEdge] = {}
        evidence: dict[str, Evidence] = {}
        for sample in material:
            bundle = self.build(sample)
            for node in bundle.nodes:
                self._insert_node(nodes, node)
            for edge in bundle.edges:
                self._insert_edge(edges, edge)
            for item in bundle.evidence:
                existing = evidence.get(item.id)
                if existing is not None and existing != item:
                    raise ValueError(f"conflicting evidence ID {item.id!r}")
                evidence[item.id] = item

        return KnowledgeGraphBundle(
            architecture=architecture,
            sample_ids=sorted(sample_ids),
            nodes=sorted(nodes.values(), key=lambda item: item.id),
            edges=sorted(edges.values(), key=lambda item: item.id),
            evidence=sorted(evidence.values(), key=lambda item: item.id),
            metadata={
                "builder": "VulnerabilityKnowledgeBuilder",
                "sample_count": len(material),
            },
        )

    @staticmethod
    def namespaced_evidence_id(sample_id: str, local_id: str) -> str:
        """Return the stable collision-free evidence identity for a sample."""

        return f"sample:{sample_id}:evidence:{local_id}"

    def _add_related_node(
        self,
        *,
        sample: VulnerabilitySample,
        vulnerability_id: str,
        node: KnowledgeNode,
        relation: KnowledgeRelationType,
        evidence_ids: list[str],
        nodes: dict[str, KnowledgeNode],
        edges: dict[str, KnowledgeEdge],
    ) -> None:
        """Insert one node and its stable sample-scoped vulnerability relation."""

        self._insert_node(nodes, node)
        edge = KnowledgeEdge(
            id=f"knowledge-edge:{sample.id}:{relation.value}:{node.id}",
            source_id=vulnerability_id,
            target_id=node.id,
            relation=relation,
            architecture=sample.architecture,
            evidence_ids=evidence_ids,
            metadata={"derived_from_sample": sample.id},
        )
        self._insert_edge(edges, edge)

    @staticmethod
    def _insert_node(
        destination: dict[str, KnowledgeNode], node: KnowledgeNode
    ) -> None:
        existing = destination.get(node.id)
        if existing is not None and existing != node:
            raise ValueError(f"conflicting knowledge node ID {node.id!r}")
        destination[node.id] = node

    @staticmethod
    def _insert_edge(
        destination: dict[str, KnowledgeEdge], edge: KnowledgeEdge
    ) -> None:
        existing = destination.get(edge.id)
        if existing is not None and existing != edge:
            raise ValueError(f"conflicting knowledge edge ID {edge.id!r}")
        destination[edge.id] = edge

    @staticmethod
    def _map_evidence(
        local_ids: list[str], evidence_map: dict[str, str]
    ) -> list[str]:
        return sorted(evidence_map[item] for item in local_ids)

    @staticmethod
    def _taxonomy_id(identifier: str) -> str:
        return identifier.upper()

    @staticmethod
    def _semantic_id(value: dict[str, Any]) -> str:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()[:16]
