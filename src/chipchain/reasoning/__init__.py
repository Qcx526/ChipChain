"""Public semantic reasoning and non-verifying contract APIs."""

from chipchain.reasoning.context import (
    CandidateContextAssembler,
    EvidenceResolver,
    InMemoryEvidenceResolver,
)
from chipchain.reasoning.documents import load_architecture_knowledge_documents
from chipchain.reasoning.engine import ReasoningEngine
from chipchain.reasoning.evidence_loop import (
    EvidenceGuidedReasoningLoop,
    EvidenceLoopOutput,
)
from chipchain.reasoning.enums import (
    ArchitectureKnowledgeScope,
    CandidateSemanticStatus,
    EvidenceCategory,
    EvidencePriority,
    HypothesisSource,
    LLMAPIStyle,
    ReasoningAgentType,
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
from chipchain.reasoning.hypothesis import AttackHypothesis, attack_hypothesis_id
from chipchain.reasoning.chain_claim import (
    ModelAuthoredChainClaim,
    model_authored_chain_claim_id,
)
from chipchain.reasoning.evidence_request import EvidenceRequest, evidence_request_id
from chipchain.reasoning.feedback import (
    EvidenceFeedback,
    EvidenceFeedbackStatus,
    ObservationFeedbackRelation,
    ReasoningObservation,
    evidence_feedback_id,
    evidence_feedback_status,
    reasoning_observation_id,
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
    REASONING_PROVIDER_SCHEMA_NAME,
    StructuredPromptRequest,
    RetrievalResult,
    RetrievedKnowledgeChunk,
)
from chipchain.reasoning.prompts import CandidatePromptBuilder
from chipchain.reasoning.prompts import (
    RoleBasedReasoningPromptBuilder,
    reasoning_role_contract,
)
from chipchain.reasoning.provider import (
    LLMProvider,
    MockReasoningProvider,
    OpenAICompatibleLLMProvider,
    OpenAICompatibleReasoningProvider,
    ReasoningProvider,
    StructuredOutputProvider,
)
from chipchain.reasoning.query import CandidateRetrievalQueryBuilder
from chipchain.reasoning.reasoning import CandidateReasoner
from chipchain.reasoning.reasoning_result import (
    REASONING_RESULT_BOUNDARY,
    ReasoningResult,
    reasoning_result_id,
)
from chipchain.reasoning.reasoning_memory import (
    ReasoningMemory,
    reasoning_memory_id,
)
from chipchain.reasoning.parser import (
    ConstrainedReasoningOutputParser,
    ParsedReasoningContracts,
    reasoning_provider_output_json_schema,
)
from chipchain.reasoning.retrieval import (
    KnowledgeRetriever,
    LocalLexicalKnowledgeRetriever,
)

__all__ = [
    "ArchitectureKnowledgeDocument",
    "ArchitectureKnowledgeScope",
    "AttackHypothesis",
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
    "ConstrainedReasoningOutputParser",
    "EvidenceResolutionError",
    "EvidenceCategory",
    "EvidenceFeedback",
    "EvidenceFeedbackStatus",
    "EvidenceGuidedReasoningLoop",
    "EvidenceLoopOutput",
    "EvidencePriority",
    "EvidenceRequest",
    "EvidenceResolver",
    "InMemoryEvidenceResolver",
    "KnowledgeRetriever",
    "HypothesisSource",
    "LLMAPIStyle",
    "LLMOutputValidationError",
    "LLMProvider",
    "LLMProviderConfig",
    "LLMProviderConfigurationError",
    "LLMProviderResponseError",
    "LocalLexicalKnowledgeRetriever",
    "MockLLMProvider",
    "MockReasoningProvider",
    "ModelAuthoredChainClaim",
    "ObservationFeedbackRelation",
    "OpenAICompatibleLLMProvider",
    "OpenAICompatibleReasoningProvider",
    "PromptRequest",
    "StructuredOutputProvider",
    "StructuredPromptRequest",
    "ReasoningError",
    "ReasoningEngine",
    "ReasoningAgentType",
    "ReasoningProvider",
    "ReasoningMemory",
    "ReasoningObservation",
    "ReasoningResult",
    "REASONING_RESULT_BOUNDARY",
    "REASONING_PROVIDER_SCHEMA_NAME",
    "RetrievalError",
    "RetrievalResult",
    "RetrievedKnowledgeChunk",
    "RoleBasedReasoningPromptBuilder",
    "attack_hypothesis_id",
    "evidence_request_id",
    "evidence_feedback_id",
    "evidence_feedback_status",
    "load_architecture_knowledge_documents",
    "model_authored_chain_claim_id",
    "reasoning_result_id",
    "reasoning_memory_id",
    "reasoning_observation_id",
    "reasoning_role_contract",
    "reasoning_provider_output_json_schema",
    "ParsedReasoningContracts",
]
