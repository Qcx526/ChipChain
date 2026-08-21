"""Storage-neutral vulnerability knowledge graph data contracts."""

from __future__ import annotations

import hashlib
import json
from enum import Enum
from typing import Literal, TypeAlias

from pydantic import Field, field_validator, model_validator

from chipchain.knowledge.enums import KnowledgeNodeKind, KnowledgeRelationType
from chipchain.models import Architecture, Evidence, Layer
from chipchain.models.common import (
    DomainModel,
    Identifier,
    Metadata,
    UnitInterval,
)

_GLOBAL_NODE_KINDS = frozenset(
    {KnowledgeNodeKind.CWE, KnowledgeNodeKind.CAPEC}
)


class KnowledgeEntryKind(str, Enum):
    """Kinds supported by the Phase 9B2B local retrieval contract."""

    CVE = "cve"
    CWE = "cwe"
    CAPEC = "capec"
    HARDWARE = "hardware"


_GLOBAL_ENTRY_KINDS = frozenset(
    {KnowledgeEntryKind.CWE, KnowledgeEntryKind.CAPEC}
)
_FORBIDDEN_RETRIEVAL_METADATA_FIELDS = frozenset(
    {
        "attackchain",
        "attackchainstatus",
        "attackchainverdict",
        "causalitystatus",
        "causalityverdict",
        "evidence",
        "evidenceid",
        "evidenceids",
        "interactionverificationstatus",
        "verificationrecord",
        "verificationstatus",
        "vulnerabilitystatus",
        "vulnerabilityverdict",
    }
)


def _canonical_knowledge_id(prefix: str, payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(serialized).hexdigest()}"


def _validate_retrieval_metadata(metadata: Metadata) -> Metadata:
    """Prevent extensible knowledge metadata from carrying domain verdicts."""

    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                normalized_key = "".join(
                    character
                    for character in str(key).lower()
                    if character.isalnum()
                )
                if normalized_key in _FORBIDDEN_RETRIEVAL_METADATA_FIELDS:
                    raise ValueError(
                        "retrieval metadata must not contain evidence or verdict fields"
                    )
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)

    visit(metadata)
    return metadata


class KnowledgeNode(DomainModel):
    """One semantic vulnerability-knowledge entity, separate from behavior nodes."""

    id: Identifier
    kind: KnowledgeNodeKind
    label: Identifier
    architecture: Architecture | None
    layer: Layer | None = None
    external_ids: list[Identifier] = Field(default_factory=list)
    match_keys: list[Identifier] = Field(default_factory=list)
    evidence_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("external_ids", "match_keys", "evidence_ids")
    @classmethod
    def require_unique_identifiers(cls, values: list[str]) -> list[str]:
        """Reject ambiguous repeated identifiers within one node."""

        if len(values) != len(set(values)):
            raise ValueError("knowledge node identifier lists must be unique")
        return values

    @model_validator(mode="after")
    def validate_architecture_scope(self) -> "KnowledgeNode":
        """Keep only global taxonomies architecture-neutral."""

        is_global_kind = self.kind in _GLOBAL_NODE_KINDS
        if is_global_kind and self.architecture is not None:
            raise ValueError("CWE and CAPEC knowledge nodes must be global")
        if not is_global_kind and self.architecture is None:
            raise ValueError(
                "only CWE and CAPEC knowledge nodes may omit architecture"
            )
        if is_global_kind and self.layer is not None:
            raise ValueError("global CWE and CAPEC nodes must not declare a layer")
        return self


class KnowledgeEdge(DomainModel):
    """A typed, architecture-scoped semantic relation between knowledge nodes."""

    id: Identifier
    source_id: Identifier
    target_id: Identifier
    relation: KnowledgeRelationType
    architecture: Architecture
    evidence_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("evidence_ids")
    @classmethod
    def require_unique_evidence_ids(cls, values: list[str]) -> list[str]:
        """Reject repeated evidence references on one edge."""

        if len(values) != len(set(values)):
            raise ValueError("knowledge edge evidence IDs must be unique")
        return values


class KnowledgeGraphBundle(DomainModel):
    """Validated knowledge graph material derived from one or more samples."""

    architecture: Architecture
    sample_ids: list[Identifier] = Field(min_length=1)
    nodes: list[KnowledgeNode] = Field(default_factory=list)
    edges: list[KnowledgeEdge] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("sample_ids")
    @classmethod
    def require_unique_sample_ids(cls, values: list[str]) -> list[str]:
        """Each source sample may be represented only once."""

        if len(values) != len(set(values)):
            raise ValueError("knowledge bundle sample IDs must be unique")
        return values

    @model_validator(mode="after")
    def validate_graph_integrity(self) -> "KnowledgeGraphBundle":
        """Reject duplicates, dangling references, and architecture leakage."""

        _validate_graph_integrity(
            architecture=self.architecture,
            nodes=self.nodes,
            edges=self.edges,
            evidence=self.evidence,
        )
        return self


class KnowledgeGraphSnapshot(DomainModel):
    """Stable JSON envelope for the independent knowledge graph repository."""

    format: Literal["chipchain_knowledge_graph"] = "chipchain_knowledge_graph"
    format_version: Literal[1] = 1
    architecture: Architecture
    sample_ids: list[Identifier] = Field(default_factory=list)
    nodes: list[KnowledgeNode] = Field(default_factory=list)
    edges: list[KnowledgeEdge] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_graph_integrity(self) -> "KnowledgeGraphSnapshot":
        """Revalidate every persisted graph invariant during loading."""

        if len(self.sample_ids) != len(set(self.sample_ids)):
            raise ValueError("knowledge snapshot sample IDs must be unique")
        _validate_graph_integrity(
            architecture=self.architecture,
            nodes=self.nodes,
            edges=self.edges,
            evidence=self.evidence,
        )
        return self


def _validate_graph_integrity(
    *,
    architecture: Architecture,
    nodes: list[KnowledgeNode],
    edges: list[KnowledgeEdge],
    evidence: list[Evidence],
) -> None:
    """Validate invariants shared by bundles and persisted snapshots."""

    node_by_id = {node.id: node for node in nodes}
    if len(node_by_id) != len(nodes):
        raise ValueError("knowledge node IDs must be unique")

    edge_ids = [edge.id for edge in edges]
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("knowledge edge IDs must be unique")

    evidence_ids = [item.id for item in evidence]
    if len(evidence_ids) != len(set(evidence_ids)):
        raise ValueError("knowledge evidence IDs must be unique")
    evidence_id_set = set(evidence_ids)

    for node in nodes:
        if node.architecture is not None and node.architecture is not architecture:
            raise ValueError(
                f"knowledge node {node.id!r} architecture does not match bundle"
            )
        missing = set(node.evidence_ids).difference(evidence_id_set)
        if missing:
            raise ValueError(
                f"knowledge node {node.id!r} references unknown evidence"
            )

    for edge in edges:
        source = node_by_id.get(edge.source_id)
        target = node_by_id.get(edge.target_id)
        if source is None or target is None:
            raise ValueError(
                f"knowledge edge {edge.id!r} references an unknown endpoint"
            )
        if edge.architecture is not architecture:
            raise ValueError(
                f"knowledge edge {edge.id!r} architecture does not match bundle"
            )
        for endpoint in (source, target):
            if (
                endpoint.architecture is not None
                and endpoint.architecture is not edge.architecture
            ):
                raise ValueError(
                    f"knowledge edge {edge.id!r} architecture does not match endpoint"
                )
        missing = set(edge.evidence_ids).difference(evidence_id_set)
        if missing:
            raise ValueError(
                f"knowledge edge {edge.id!r} references unknown evidence"
            )


def vulnerability_knowledge_entry_id(
    *,
    entry_kind: KnowledgeEntryKind,
    external_id: str,
    architecture: Architecture | None,
    title: str,
    summary: str,
    affected_components: list[str],
    references: list[str],
) -> str:
    """Build deterministic identity for a CVE, CWE, or CAPEC abstraction."""

    return _canonical_knowledge_id(
        "vulnerability-knowledge-entry",
        {
            "affected_components": sorted(affected_components),
            "architecture": architecture.value if architecture is not None else None,
            "entry_kind": entry_kind.value,
            "external_id": external_id,
            "references": sorted(references),
            "summary": summary,
            "title": title,
        },
    )


class VulnerabilityKnowledgeEntry(DomainModel):
    """Non-verdict CVE/CWE/CAPEC knowledge used only for local retrieval."""

    id: Identifier
    entry_kind: Literal[
        KnowledgeEntryKind.CVE,
        KnowledgeEntryKind.CWE,
        KnowledgeEntryKind.CAPEC,
    ]
    external_id: Identifier
    architecture: Architecture | None
    title: Identifier
    summary: Identifier
    affected_components: list[Identifier] = Field(default_factory=list)
    references: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("affected_components", "references")
    @classmethod
    def normalize_identifier_lists(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("knowledge entry identifier lists must be unique")
        return sorted(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_retrieval_metadata(value)

    @model_validator(mode="after")
    def validate_scope_and_identity(self) -> "VulnerabilityKnowledgeEntry":
        is_global = self.entry_kind in _GLOBAL_ENTRY_KINDS
        if is_global and self.architecture is not None:
            raise ValueError("CWE and CAPEC entries must be architecture-global")
        if not is_global and self.architecture is None:
            raise ValueError("CVE entries must declare an architecture")
        expected_id = vulnerability_knowledge_entry_id(
            entry_kind=self.entry_kind,
            external_id=self.external_id,
            architecture=self.architecture,
            title=self.title,
            summary=self.summary,
            affected_components=self.affected_components,
            references=self.references,
        )
        if self.id != expected_id:
            raise ValueError("VulnerabilityKnowledgeEntry ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        entry_kind: KnowledgeEntryKind | str,
        external_id: str,
        architecture: Architecture | str | None,
        title: str,
        summary: str,
        affected_components: list[str] | None = None,
        references: list[str] | None = None,
        metadata: Metadata | None = None,
    ) -> "VulnerabilityKnowledgeEntry":
        """Create a deterministic description without asserting vulnerability truth."""

        normalized_kind = KnowledgeEntryKind(entry_kind)
        if normalized_kind is KnowledgeEntryKind.HARDWARE:
            raise ValueError("hardware entries require HardwareKnowledgeEntry")
        normalized_architecture = (
            Architecture(architecture) if architecture is not None else None
        )
        normalized_external_id = external_id.strip()
        normalized_title = title.strip()
        normalized_summary = summary.strip()
        normalized_components = [
            item.strip() for item in (affected_components or [])
        ]
        normalized_references = [item.strip() for item in (references or [])]
        identity = vulnerability_knowledge_entry_id(
            entry_kind=normalized_kind,
            external_id=normalized_external_id,
            architecture=normalized_architecture,
            title=normalized_title,
            summary=normalized_summary,
            affected_components=normalized_components,
            references=normalized_references,
        )
        return cls(
            id=identity,
            entry_kind=normalized_kind,
            external_id=normalized_external_id,
            architecture=normalized_architecture,
            title=normalized_title,
            summary=normalized_summary,
            affected_components=normalized_components,
            references=normalized_references,
            metadata=metadata or {},
        )


def hardware_knowledge_entry_id(
    *,
    architecture: Architecture,
    component_id: str,
    title: str,
    summary: str,
    interface_ids: list[str],
    register_ids: list[str],
) -> str:
    """Build deterministic identity for one hardware knowledge abstraction."""

    return _canonical_knowledge_id(
        "hardware-knowledge-entry",
        {
            "architecture": architecture.value,
            "component_id": component_id,
            "interface_ids": sorted(interface_ids),
            "register_ids": sorted(register_ids),
            "summary": summary,
            "title": title,
        },
    )


class HardwareKnowledgeEntry(DomainModel):
    """Architecture-scoped hardware description without verification semantics."""

    id: Identifier
    entry_kind: Literal[KnowledgeEntryKind.HARDWARE] = KnowledgeEntryKind.HARDWARE
    architecture: Architecture
    component_id: Identifier
    title: Identifier
    summary: Identifier
    interface_ids: list[Identifier] = Field(default_factory=list)
    register_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("interface_ids", "register_ids")
    @classmethod
    def normalize_identifier_lists(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("hardware knowledge identifier lists must be unique")
        return sorted(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_retrieval_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "HardwareKnowledgeEntry":
        expected_id = hardware_knowledge_entry_id(
            architecture=self.architecture,
            component_id=self.component_id,
            title=self.title,
            summary=self.summary,
            interface_ids=self.interface_ids,
            register_ids=self.register_ids,
        )
        if self.id != expected_id:
            raise ValueError("HardwareKnowledgeEntry ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        architecture: Architecture | str,
        component_id: str,
        title: str,
        summary: str,
        interface_ids: list[str] | None = None,
        register_ids: list[str] | None = None,
        metadata: Metadata | None = None,
    ) -> "HardwareKnowledgeEntry":
        """Create a deterministic hardware description for local retrieval."""

        normalized_architecture = Architecture(architecture)
        normalized_component_id = component_id.strip()
        normalized_title = title.strip()
        normalized_summary = summary.strip()
        normalized_interfaces = [item.strip() for item in (interface_ids or [])]
        normalized_registers = [item.strip() for item in (register_ids or [])]
        identity = hardware_knowledge_entry_id(
            architecture=normalized_architecture,
            component_id=normalized_component_id,
            title=normalized_title,
            summary=normalized_summary,
            interface_ids=normalized_interfaces,
            register_ids=normalized_registers,
        )
        return cls(
            id=identity,
            architecture=normalized_architecture,
            component_id=normalized_component_id,
            title=normalized_title,
            summary=normalized_summary,
            interface_ids=normalized_interfaces,
            register_ids=normalized_registers,
            metadata=metadata or {},
        )


RetrievableKnowledgeEntry: TypeAlias = (
    VulnerabilityKnowledgeEntry | HardwareKnowledgeEntry
)


def knowledge_retrieval_query_id(
    *,
    architecture: Architecture,
    text: str,
    entry_kinds: list[KnowledgeEntryKind],
    component_ids: list[str],
    top_k: int,
) -> str:
    """Build deterministic identity for one local retrieval query."""

    return _canonical_knowledge_id(
        "knowledge-retrieval-query",
        {
            "architecture": architecture.value,
            "component_ids": sorted(component_ids),
            "entry_kinds": sorted(item.value for item in entry_kinds),
            "text": text,
            "top_k": top_k,
        },
    )


class KnowledgeRetrievalQuery(DomainModel):
    """Architecture-scoped deterministic query for local knowledge references."""

    id: Identifier
    architecture: Architecture
    text: Identifier
    entry_kinds: list[KnowledgeEntryKind] = Field(min_length=1)
    component_ids: list[Identifier] = Field(default_factory=list)
    top_k: int = Field(default=10, gt=0)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("entry_kinds")
    @classmethod
    def normalize_entry_kinds(
        cls, values: list[KnowledgeEntryKind]
    ) -> list[KnowledgeEntryKind]:
        if len(values) != len(set(values)):
            raise ValueError("retrieval entry kinds must be unique")
        return sorted(values, key=lambda item: item.value)

    @field_validator("component_ids")
    @classmethod
    def normalize_component_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("retrieval component IDs must be unique")
        return sorted(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_retrieval_metadata(value)

    @model_validator(mode="after")
    def validate_identity(self) -> "KnowledgeRetrievalQuery":
        expected_id = knowledge_retrieval_query_id(
            architecture=self.architecture,
            text=self.text,
            entry_kinds=self.entry_kinds,
            component_ids=self.component_ids,
            top_k=self.top_k,
        )
        if self.id != expected_id:
            raise ValueError("KnowledgeRetrievalQuery ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        architecture: Architecture | str,
        text: str,
        entry_kinds: list[KnowledgeEntryKind | str] | None = None,
        component_ids: list[str] | None = None,
        top_k: int = 10,
        metadata: Metadata | None = None,
    ) -> "KnowledgeRetrievalQuery":
        """Create a query whose identity excludes mutable metadata."""

        normalized_architecture = Architecture(architecture)
        normalized_text = text.strip()
        normalized_kinds = [
            KnowledgeEntryKind(item)
            for item in (
                entry_kinds
                if entry_kinds is not None
                else list(KnowledgeEntryKind)
            )
        ]
        normalized_components = [item.strip() for item in (component_ids or [])]
        identity = knowledge_retrieval_query_id(
            architecture=normalized_architecture,
            text=normalized_text,
            entry_kinds=normalized_kinds,
            component_ids=normalized_components,
            top_k=top_k,
        )
        return cls(
            id=identity,
            architecture=normalized_architecture,
            text=normalized_text,
            entry_kinds=normalized_kinds,
            component_ids=normalized_components,
            top_k=top_k,
            metadata=metadata or {},
        )


def knowledge_retrieval_hit_id(
    *,
    query_id: str,
    entry_id: str,
    matched_terms: list[str],
    relevance_score: float,
) -> str:
    """Build deterministic identity for one retrieval reference hit."""

    return _canonical_knowledge_id(
        "knowledge-retrieval-hit",
        {
            "entry_id": entry_id,
            "matched_terms": sorted(matched_terms),
            "query_id": query_id,
            "relevance_score": relevance_score,
        },
    )


class KnowledgeRetrievalHit(DomainModel):
    """Reference-only retrieval hit; it is not Evidence or a verdict."""

    id: Identifier
    query_id: Identifier
    entry_id: Identifier
    entry_kind: KnowledgeEntryKind
    architecture: Architecture | None
    matched_terms: list[Identifier] = Field(min_length=1)
    relevance_score: UnitInterval

    @field_validator("matched_terms")
    @classmethod
    def normalize_matched_terms(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("retrieval matched terms must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_scope_and_identity(self) -> "KnowledgeRetrievalHit":
        is_global = self.entry_kind in _GLOBAL_ENTRY_KINDS
        if is_global != (self.architecture is None):
            raise ValueError("retrieval hit architecture scope is inconsistent")
        expected_id = knowledge_retrieval_hit_id(
            query_id=self.query_id,
            entry_id=self.entry_id,
            matched_terms=self.matched_terms,
            relevance_score=self.relevance_score,
        )
        if self.id != expected_id:
            raise ValueError("KnowledgeRetrievalHit ID is not deterministic")
        return self


def knowledge_retrieval_result_id(
    *,
    query_id: str,
    hits: list[KnowledgeRetrievalHit],
    excluded_entry_ids: list[str],
) -> str:
    """Build deterministic identity for one ordered retrieval result."""

    return _canonical_knowledge_id(
        "knowledge-retrieval-result",
        {
            "excluded_entry_ids": sorted(excluded_entry_ids),
            "hit_ids": [hit.id for hit in hits],
            "query_id": query_id,
        },
    )


class KnowledgeRetrievalResult(DomainModel):
    """Deterministic reference set intended only for ReasoningContext input."""

    id: Identifier
    query: KnowledgeRetrievalQuery
    hits: list[KnowledgeRetrievalHit] = Field(default_factory=list)
    excluded_entry_ids: list[Identifier] = Field(default_factory=list)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("excluded_entry_ids")
    @classmethod
    def normalize_excluded_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("excluded knowledge entry IDs must be unique")
        return sorted(values)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_retrieval_metadata(value)

    @model_validator(mode="after")
    def validate_result(self) -> "KnowledgeRetrievalResult":
        hit_ids = [hit.id for hit in self.hits]
        entry_ids = [hit.entry_id for hit in self.hits]
        if len(hit_ids) != len(set(hit_ids)) or len(entry_ids) != len(set(entry_ids)):
            raise ValueError("retrieval hits must be unique")
        if len(self.hits) > self.query.top_k:
            raise ValueError("retrieval result exceeds query top_k")
        for hit in self.hits:
            if hit.query_id != self.query.id:
                raise ValueError("retrieval hit query identity mismatch")
            if (
                hit.architecture is not None
                and hit.architecture is not self.query.architecture
            ):
                raise ValueError("retrieval hit architecture mismatch")
        expected_id = knowledge_retrieval_result_id(
            query_id=self.query.id,
            hits=self.hits,
            excluded_entry_ids=self.excluded_entry_ids,
        )
        if self.id != expected_id:
            raise ValueError("KnowledgeRetrievalResult ID is not deterministic")
        return self

    @property
    def knowledge_entry_ids(self) -> list[str]:
        """Return detached references suitable for ``ReasoningContext`` input."""

        return [hit.entry_id for hit in self.hits]
