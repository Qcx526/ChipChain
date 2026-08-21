"""Public vulnerability knowledge graph API."""

from chipchain.knowledge.builder import VulnerabilityKnowledgeBuilder
from chipchain.knowledge.enums import KnowledgeNodeKind, KnowledgeRelationType
from chipchain.knowledge.errors import (
    DuplicateKnowledgeEdgeError,
    DuplicateKnowledgeEvidenceError,
    DuplicateKnowledgeNodeError,
    KnowledgeArchitectureMismatchError,
    KnowledgeEdgeNotFoundError,
    KnowledgeEvidenceNotFoundError,
    KnowledgeGraphError,
    KnowledgeNodeNotFoundError,
    KnowledgePersistenceError,
)
from chipchain.knowledge.match_keys import (
    address_match_key,
    component_match_key,
    hardware_resource_match_keys,
    interface_match_key,
    memory_map_region_match_key,
)
from chipchain.knowledge.models import (
    HardwareKnowledgeEntry,
    KnowledgeEdge,
    KnowledgeEntryKind,
    KnowledgeGraphBundle,
    KnowledgeGraphSnapshot,
    KnowledgeNode,
    KnowledgeRetrievalHit,
    KnowledgeRetrievalQuery,
    KnowledgeRetrievalResult,
    RetrievableKnowledgeEntry,
    VulnerabilityKnowledgeEntry,
    hardware_knowledge_entry_id,
    knowledge_retrieval_hit_id,
    knowledge_retrieval_query_id,
    knowledge_retrieval_result_id,
    vulnerability_knowledge_entry_id,
)
from chipchain.knowledge.networkx_repository import (
    NetworkXKnowledgeGraphRepository,
)
from chipchain.knowledge.repository import (
    InMemoryKnowledgeEntryRepository,
    KnowledgeEntryRepository,
    KnowledgeGraphRepository,
)
from chipchain.knowledge.retrieval import (
    DeterministicKnowledgeRetriever,
    KnowledgeRetrievalService,
)

__all__ = [
    "DuplicateKnowledgeEdgeError",
    "DuplicateKnowledgeEvidenceError",
    "DuplicateKnowledgeNodeError",
    "DeterministicKnowledgeRetriever",
    "HardwareKnowledgeEntry",
    "InMemoryKnowledgeEntryRepository",
    "KnowledgeArchitectureMismatchError",
    "KnowledgeEdge",
    "KnowledgeEdgeNotFoundError",
    "KnowledgeEntryKind",
    "KnowledgeEntryRepository",
    "KnowledgeEvidenceNotFoundError",
    "KnowledgeGraphBundle",
    "KnowledgeGraphError",
    "KnowledgeGraphRepository",
    "KnowledgeGraphSnapshot",
    "KnowledgeNode",
    "KnowledgeNodeKind",
    "KnowledgeNodeNotFoundError",
    "KnowledgePersistenceError",
    "KnowledgeRelationType",
    "KnowledgeRetrievalHit",
    "KnowledgeRetrievalQuery",
    "KnowledgeRetrievalResult",
    "KnowledgeRetrievalService",
    "NetworkXKnowledgeGraphRepository",
    "RetrievableKnowledgeEntry",
    "VulnerabilityKnowledgeBuilder",
    "VulnerabilityKnowledgeEntry",
    "address_match_key",
    "component_match_key",
    "hardware_resource_match_keys",
    "interface_match_key",
    "hardware_knowledge_entry_id",
    "knowledge_retrieval_hit_id",
    "knowledge_retrieval_query_id",
    "knowledge_retrieval_result_id",
    "memory_map_region_match_key",
    "vulnerability_knowledge_entry_id",
]
