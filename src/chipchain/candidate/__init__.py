"""Public exact entity-linking and cross-graph candidate API."""

from chipchain.candidate.capabilities import (
    CrossLayerSearchStrategy,
    require_supported_search_strategy,
    search_strategy_for_direction,
)
from chipchain.candidate.enums import EntityLinkMethod
from chipchain.candidate.errors import (
    CandidateArchitectureMismatchError,
    CandidateError,
    InvalidKnowledgeContextError,
    UnsupportedCrossLayerSearchError,
)
from chipchain.candidate.linking import ExactHardwareEntityLinker
from chipchain.candidate.models import (
    CrossGraphCandidate,
    EntityLink,
    EntityLinkResult,
    cross_graph_candidate_id,
    entity_link_id,
)
from chipchain.candidate.search import (
    ARM_CANDIDATE_LAYERS,
    ARM_CANDIDATE_RELATIONS,
    CrossGraphCandidateSearcher,
)

__all__ = [
    "ARM_CANDIDATE_LAYERS",
    "ARM_CANDIDATE_RELATIONS",
    "CandidateArchitectureMismatchError",
    "CandidateError",
    "CrossGraphCandidate",
    "CrossGraphCandidateSearcher",
    "CrossLayerSearchStrategy",
    "EntityLink",
    "EntityLinkMethod",
    "EntityLinkResult",
    "ExactHardwareEntityLinker",
    "InvalidKnowledgeContextError",
    "UnsupportedCrossLayerSearchError",
    "cross_graph_candidate_id",
    "entity_link_id",
    "require_supported_search_strategy",
    "search_strategy_for_direction",
]
