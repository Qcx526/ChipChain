"""Public exact entity-linking and cross-graph candidate API."""

from chipchain.candidate.enums import EntityLinkMethod
from chipchain.candidate.errors import (
    CandidateArchitectureMismatchError,
    CandidateError,
    InvalidKnowledgeContextError,
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
    "EntityLink",
    "EntityLinkMethod",
    "EntityLinkResult",
    "ExactHardwareEntityLinker",
    "InvalidKnowledgeContextError",
    "cross_graph_candidate_id",
    "entity_link_id",
]
