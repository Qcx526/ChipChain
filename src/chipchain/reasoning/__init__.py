"""Public Phase 7 context, retrieval, prompting, and provider API."""

from chipchain.reasoning.context import (
    CandidateContextAssembler,
    EvidenceResolver,
    InMemoryEvidenceResolver,
)
from chipchain.reasoning.documents import load_architecture_knowledge_documents
from chipchain.reasoning.enums import (
    ArchitectureKnowledgeScope,
    CandidateSemanticStatus,
    LLMAPIStyle,
)
from chipchain.reasoning.errors import (
    CandidateContextError,
    EvidenceResolutionError,
    LLMOutputValidationError,
    LLMProviderConfigurationError,
    LLMProviderResponseError,
    ReasoningError,
    RetrievalError,
)
from chipchain.reasoning.mock_provider import MockLLMProvider
from chipchain.reasoning.models import (
    ArchitectureKnowledgeDocument,
    CandidateContext,
    CandidateReasoningInput,
    CandidateReasoningResult,
    CandidateRetrievalQuery,
    CandidateSemanticAssessment,
    LLMProviderConfig,
    PromptRequest,
    RetrievalResult,
    RetrievedKnowledgeChunk,
)
from chipchain.reasoning.prompts import CandidatePromptBuilder
from chipchain.reasoning.provider import LLMProvider, OpenAICompatibleLLMProvider
from chipchain.reasoning.query import CandidateRetrievalQueryBuilder
from chipchain.reasoning.reasoning import CandidateReasoner
from chipchain.reasoning.retrieval import (
    KnowledgeRetriever,
    LocalLexicalKnowledgeRetriever,
)

__all__ = [
    "ArchitectureKnowledgeDocument",
    "ArchitectureKnowledgeScope",
    "CandidateContext",
    "CandidateContextAssembler",
    "CandidateContextError",
    "CandidatePromptBuilder",
    "CandidateReasoner",
    "CandidateReasoningInput",
    "CandidateReasoningResult",
    "CandidateRetrievalQuery",
    "CandidateRetrievalQueryBuilder",
    "CandidateSemanticAssessment",
    "CandidateSemanticStatus",
    "EvidenceResolutionError",
    "EvidenceResolver",
    "InMemoryEvidenceResolver",
    "KnowledgeRetriever",
    "LLMAPIStyle",
    "LLMOutputValidationError",
    "LLMProvider",
    "LLMProviderConfig",
    "LLMProviderConfigurationError",
    "LLMProviderResponseError",
    "LocalLexicalKnowledgeRetriever",
    "MockLLMProvider",
    "OpenAICompatibleLLMProvider",
    "PromptRequest",
    "ReasoningError",
    "RetrievalError",
    "RetrievalResult",
    "RetrievedKnowledgeChunk",
    "load_architecture_knowledge_documents",
]
