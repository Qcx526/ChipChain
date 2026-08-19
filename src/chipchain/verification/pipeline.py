"""Top-level deterministic Phase 9A candidate verification pipeline."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from chipchain.candidate import CrossGraphCandidate
from chipchain.graph import GraphRepository
from chipchain.knowledge import KnowledgeGraphRepository
from chipchain.models import Evidence
from chipchain.reasoning import EvidenceResolver
from chipchain.reasoning.errors import EvidenceResolutionError
from chipchain.verification.architecture import ARMArchitectureRuleVerifier
from chipchain.verification.behavior import BehaviorEdgeVerifier
from chipchain.verification.conditions import ConditionVerifier
from chipchain.verification.entity_link import EntityLinkVerifier
from chipchain.verification.enums import (
    CandidateVerificationStatus,
    ConditionStatus,
    VerificationStatus,
)
from chipchain.verification.errors import VerificationInputError
from chipchain.verification.evidence import EvidenceCatalog
from chipchain.verification.knowledge import KnowledgeRelationVerifier
from chipchain.verification.models import (
    CandidateVerificationResult,
    VerificationRecord,
)
from chipchain.verification.root_cause import RootCauseLocalizer
from chipchain.verification.scoring import (
    VerificationScorer,
    load_verification_score_config,
)
from chipchain.verification.trigger_features import TriggerFeatureExtractor

if TYPE_CHECKING:
    from chipchain.multi_agent import MultiAgentReasoningResult

_DEFAULT_SCORE_CONFIG = (
    Path(__file__).resolve().parents[3] / "configs" / "verification_scoring_mvp.json"
)


class CandidateVerificationPipeline:
    """Verify referenced source facts without modifying them or trusting LLM output."""

    def __init__(self, *, score_config_path: str | Path = _DEFAULT_SCORE_CONFIG) -> None:
        self._behavior = BehaviorEdgeVerifier()
        self._entity_link = EntityLinkVerifier()
        self._knowledge = KnowledgeRelationVerifier()
        self._architecture = ARMArchitectureRuleVerifier()
        self._conditions = ConditionVerifier()
        self._features = TriggerFeatureExtractor()
        self._root_cause = RootCauseLocalizer()
        self._scorer = VerificationScorer(
            load_verification_score_config(score_config_path)
        )

    def verify(
        self,
        candidate: CrossGraphCandidate,
        behavior_repository: GraphRepository,
        knowledge_repository: KnowledgeGraphRepository,
        behavior_evidence_resolver: EvidenceResolver,
        *,
        multi_agent_result: "MultiAgentReasoningResult | None" = None,
    ) -> CandidateVerificationResult:
        """Produce an objective verification result and optional advisory text."""

        behavior_nodes = [
            behavior_repository.get_node(item)
            for item in candidate.behavior_path.node_ids
        ]
        behavior_edges = [
            behavior_repository.get_edge(item)
            for item in candidate.behavior_path.edge_ids
        ]
        behavior_node_by_id = {item.id: item for item in behavior_nodes}

        vulnerability = knowledge_repository.get_node(
            candidate.knowledge_vulnerability_id
        )
        knowledge_ids = sorted(
            {
                candidate.knowledge_anchor_node_id,
                *candidate.component_node_ids,
                *candidate.trigger_node_ids,
                *candidate.precondition_node_ids,
                *candidate.cwe_node_ids,
                *candidate.capec_node_ids,
                *candidate.behavior_node_ids,
                *candidate.interface_node_ids,
                *candidate.hardware_resource_node_ids,
                *candidate.security_mechanism_node_ids,
                *candidate.impact_node_ids,
                *candidate.root_cause_node_ids,
            }
        )
        knowledge_nodes = [knowledge_repository.get_node(item) for item in knowledge_ids]
        knowledge_node_by_id = {item.id: item for item in knowledge_nodes}
        knowledge_anchor = knowledge_node_by_id[candidate.knowledge_anchor_node_id]
        knowledge_edges = [
            knowledge_repository.get_edge(item) for item in candidate.knowledge_edge_ids
        ]

        behavior_evidence: list[Evidence] = []
        for evidence_id in sorted(
            {item for edge in behavior_edges for item in edge.evidence_ids}
        ):
            try:
                behavior_evidence.append(behavior_evidence_resolver.get(evidence_id))
            except EvidenceResolutionError:
                continue
        knowledge_evidence = [
            knowledge_repository.get_evidence(item)
            for item in candidate.knowledge_evidence_ids
        ]
        catalog = EvidenceCatalog([*behavior_evidence, *knowledge_evidence])

        behavior_records = [
            self._behavior.verify(
                edge,
                behavior_node_by_id[edge.source_id],
                behavior_node_by_id[edge.target_id],
                catalog,
            )
            for edge in behavior_edges
        ]
        entity_link_record = self._entity_link.verify(
            candidate.entity_link,
            behavior_node_by_id[candidate.entity_link.behavior_node_id],
            knowledge_anchor,
        )
        knowledge_records = [
            self._knowledge.verify(
                edge,
                vulnerability,
                knowledge_node_by_id[edge.target_id],
                catalog,
            )
            for edge in knowledge_edges
        ]
        architecture_records = self._architecture.verify(
            candidate,
            behavior_nodes,
            behavior_edges,
            [vulnerability, *knowledge_nodes],
        )

        behavior_names = {item.name for item in behavior_nodes}
        trigger_assessments = [
            self._conditions.verify(
                knowledge_node_by_id[item],
                catalog,
                behavior_records=behavior_records,
                behavior_entrypoint_names=behavior_names,
            )
            for item in candidate.trigger_node_ids
        ]
        precondition_assessments = [
            self._conditions.verify(knowledge_node_by_id[item], catalog)
            for item in candidate.precondition_node_ids
        ]
        features = self._features.extract(
            candidate_id=candidate.id,
            architecture=candidate.architecture,
            behavior_nodes=behavior_nodes,
            behavior_edges=behavior_edges,
            knowledge_nodes=knowledge_nodes,
            trigger_assessments=trigger_assessments,
            precondition_assessments=precondition_assessments,
        )
        score = self._scorer.score(
            behavior=behavior_records,
            entity_link=entity_link_record,
            knowledge=knowledge_records,
            triggers=trigger_assessments,
            preconditions=precondition_assessments,
            architecture=architecture_records,
        )
        root_cause_nodes = [
            knowledge_node_by_id[item] for item in candidate.root_cause_node_ids
        ]
        root_cause = self._root_cause.localize(
            candidate_id=candidate.id,
            architecture=candidate.architecture,
            behavior_nodes=behavior_nodes,
            behavior_edges=behavior_edges,
            behavior_records=behavior_records,
            knowledge_root_causes=root_cause_nodes,
            knowledge_anchor=knowledge_anchor,
            catalog=catalog,
        )

        required_evidence_ids = [
            item for edge in [*behavior_edges, *knowledge_edges] for item in edge.evidence_ids
        ]
        required_evidence_ids.extend(
            f"required:knowledge-edge:{edge.id}"
            for edge in knowledge_edges
            if not edge.evidence_ids
        )
        rejected_evidence_ids = [
            evidence_id
            for record in [*behavior_records, *knowledge_records]
            if record.status is VerificationStatus.REJECTED
            for evidence_id in record.evidence_ids
        ]
        inventory = catalog.inventory(
            required_evidence_ids,
            rejected_evidence_ids=rejected_evidence_ids,
        )
        advisory = self._advisory_steps(candidate, multi_agent_result)
        status = _candidate_status(
            behavior_records,
            entity_link_record,
            knowledge_records,
            architecture_records,
            trigger_assessments,
            precondition_assessments,
        )
        return CandidateVerificationResult(
            candidate_id=candidate.id,
            architecture=candidate.architecture,
            behavior_edge_verifications=behavior_records,
            entity_link_verification=entity_link_record,
            knowledge_edge_verifications=knowledge_records,
            architecture_rule_verifications=architecture_records,
            trigger_assessments=trigger_assessments,
            precondition_assessments=precondition_assessments,
            trigger_features=features,
            evidence_inventory=inventory,
            verification_score=score.verification_score,
            score_components=score.score_components,
            root_cause_localization=root_cause,
            verification_status=status,
            advisory_verification_steps=advisory,
            metadata={
                "phase": "9A",
                "dynamic_verification": False,
                "verified_attack_chain_created": False,
                "score_meaning": "evidence_support_not_attack_probability",
                "llm_objective_weight": 0.0,
            },
        )

    @staticmethod
    def _advisory_steps(
        candidate: CrossGraphCandidate,
        result: "MultiAgentReasoningResult | None",
    ) -> list[str]:
        if result is None:
            return []
        if result.candidate_id != candidate.id or result.architecture is not candidate.architecture:
            raise VerificationInputError("Multi-Agent advisory identity mismatch")
        return sorted(
            set(
                [
                    *result.evidence_analysis.recommended_evidence_collection_steps,
                    *result.security_reasoning.recommended_verification_steps,
                    *result.critic_review.required_revisions,
                ]
            )
        )


def _candidate_status(
    behavior: list[VerificationRecord],
    entity_link: VerificationRecord,
    knowledge: list[VerificationRecord],
    architecture: list[VerificationRecord],
    triggers,
    preconditions,
) -> CandidateVerificationStatus:
    objective = [*behavior, entity_link, *knowledge, *architecture]
    conditions = [*triggers, *preconditions]
    if any(item.status is VerificationStatus.REJECTED for item in objective) or any(
        item.status is ConditionStatus.UNSATISFIED for item in conditions
    ):
        return CandidateVerificationStatus.REJECTED
    if all(item.status is VerificationStatus.VERIFIED for item in objective) and all(
        item.status is ConditionStatus.SATISFIED for item in conditions
    ):
        return CandidateVerificationStatus.VERIFIED
    if any(item.status is VerificationStatus.VERIFIED for item in objective) or any(
        item.status is ConditionStatus.SATISFIED for item in conditions
    ):
        return CandidateVerificationStatus.PARTIALLY_VERIFIED
    return CandidateVerificationStatus.INSUFFICIENT_EVIDENCE
