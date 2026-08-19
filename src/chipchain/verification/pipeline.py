"""Top-level deterministic verification of typed CrossLayerInteraction objects."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from chipchain.candidate import CrossGraphCandidate
from chipchain.graph import GraphRepository
from chipchain.knowledge import KnowledgeGraphRepository, KnowledgeNode, KnowledgeNodeKind
from chipchain.models import (CrossLayerInteraction, Evidence, EvidenceType, Layer, RelationType)
from chipchain.reasoning import EvidenceResolver
from chipchain.verification.adapter import LegacyCandidateEvidenceContext, LegacyCandidateVerificationAdapter
from chipchain.verification.architecture import InteractionArchitectureRuleVerifier
from chipchain.verification.behavior import BehaviorEdgeVerifier
from chipchain.verification.conditions import ConditionVerifier
from chipchain.verification.entity_link import EntityLinkVerifier
from chipchain.verification.enums import (ConditionStatus, InteractionReferenceRole, InteractionSourceKind,
    InteractionVerificationStatus, RequiredFactCategory, VerificationCapabilityStatus,
    VerificationStatus, VerificationSubjectKind)
from chipchain.verification.errors import VerificationInputError
from chipchain.verification.evidence import EvidenceCatalog
from chipchain.verification.features import CrossLayerTriggerFeatureExtractor
from chipchain.verification.knowledge import KnowledgeRelationVerifier, VulnerabilityParticipantVerifier
from chipchain.verification.localization import InteractionLocationLocalizer
from chipchain.verification.models import (InteractionReferenceBinding, InteractionVerificationInput,
    InteractionVerificationResult, VerificationRecord, ConditionAssessment)
from chipchain.verification.requirements import build_interaction_requirements
from chipchain.verification.scoring import VerificationScorer, load_verification_score_config

if TYPE_CHECKING:
    from chipchain.multi_agent import MultiAgentReasoningResult

_DEFAULT_SCORE_CONFIG = Path(__file__).resolve().parents[3] / "configs" / "verification_scoring_mvp.json"


class InteractionVerificationPipeline:
    """Produce detached objective records; Agent output affects advisory text only."""

    def __init__(self, *, score_config_path: str | Path = _DEFAULT_SCORE_CONFIG) -> None:
        self._adapter = LegacyCandidateVerificationAdapter()
        self._behavior = BehaviorEdgeVerifier()
        self._entity = EntityLinkVerifier()
        self._knowledge = KnowledgeRelationVerifier()
        self._vulnerability = VulnerabilityParticipantVerifier()
        self._architecture = InteractionArchitectureRuleVerifier()
        self._conditions = ConditionVerifier()
        self._features = CrossLayerTriggerFeatureExtractor()
        self._localizer = InteractionLocationLocalizer()
        self._scorer = VerificationScorer(load_verification_score_config(score_config_path))

    def verify(self, interaction: CrossLayerInteraction, verification_input: InteractionVerificationInput,
               behavior_repository: GraphRepository | None = None,
               knowledge_repository: KnowledgeGraphRepository | None = None,
               behavior_evidence_resolver: EvidenceResolver | None = None, *,
               legacy_candidate: CrossGraphCandidate | None = None,
               interaction_evidence: Iterable[Evidence] = (),
               multi_agent_result: "MultiAgentReasoningResult | None" = None) -> InteractionVerificationResult:
        try: verification_input.validate_against(interaction)
        except ValueError as exc: raise VerificationInputError("verification input does not match interaction") from exc
        requirements = build_interaction_requirements(interaction.interaction_type)
        if requirements.capability_status is VerificationCapabilityStatus.NOT_IMPLEMENTED:
            if verification_input.legacy_candidate_id is not None or legacy_candidate is not None:
                raise VerificationInputError("Type III cannot use a legacy software-to-hardware Candidate")
            features = self._features.extract(interaction, verification_input.bindings, [], None)
            architecture_records = self._architecture.verify(
                interaction, verification_input.bindings, None
            )
            inventory = EvidenceCatalog(interaction_evidence).inventory([], required_fact_categories=requirements.required_facts)
            return InteractionVerificationResult(interaction_id=interaction.id, architecture=interaction.architecture,
                interaction_type=interaction.interaction_type, direction=interaction.direction,
                capability_status=VerificationCapabilityStatus.NOT_IMPLEMENTED,
                architecture_rule_verifications=architecture_records,
                trigger_features=features, evidence_inventory=inventory,
                verification_score=None, score_components={}, verification_status=None,
                metadata={"phase": "9A-R1", "objective_reverse_verification": "not_implemented",
                          "dynamic_verification": False, "verified_attack_chain_created": False})

        context = self._legacy_context(interaction, verification_input, legacy_candidate,
            behavior_repository, knowledge_repository, behavior_evidence_resolver)
        evidence = list(interaction_evidence)
        if context: evidence.extend(context.evidence)
        deduped = {item.id: item for item in evidence}
        catalog = EvidenceCatalog(deduped.values())
        behavior_records = self._verify_behavior(interaction, context, catalog)
        entity_records = self._verify_entity(interaction, context)
        knowledge_records = self._verify_knowledge(interaction, context, catalog)
        binding_records = self._verify_bindings(interaction, verification_input.bindings,
            context, catalog, behavior_records, entity_records)
        architecture_records = self._architecture.verify(interaction, verification_input.bindings, context)
        conditions = self._verify_conditions(interaction, verification_input, context, catalog)

        fact_statuses = _required_fact_statuses(interaction, verification_input.bindings,
            binding_records, behavior_records, entity_records, architecture_records, conditions, context)
        component_statuses = _score_components(interaction.interaction_type, fact_statuses)
        score = self._scorer.score(interaction.interaction_type, component_statuses)
        status = _interaction_status(
            requirements.required_facts,
            fact_statuses,
            requirements.capability_status,
        )
        required_evidence = _required_evidence_ids(verification_input.bindings, binding_records,
            behavior_records, entity_records, conditions)
        rejected_evidence = [e for record in [*binding_records, *behavior_records, *knowledge_records]
                             if record.status is VerificationStatus.REJECTED for e in record.evidence_ids]
        inventory = catalog.inventory(required_evidence,
            required_fact_categories=requirements.required_facts,
            supporting_evidence_ids=_supporting_evidence_ids(
                binding_records, conditions
            ),
            rejected_evidence_ids=rejected_evidence)
        features = self._features.extract(interaction, verification_input.bindings, conditions, context)
        locations = self._localizer.localize(interaction, verification_input.bindings,
            context, catalog, behavior_records)
        advisory = self._advisory_steps(verification_input, legacy_candidate, multi_agent_result)
        return InteractionVerificationResult(interaction_id=interaction.id, architecture=interaction.architecture,
            interaction_type=interaction.interaction_type, direction=interaction.direction,
            capability_status=requirements.capability_status,
            legacy_candidate_id=verification_input.legacy_candidate_id,
            binding_verifications=binding_records, behavior_edge_verifications=behavior_records,
            entity_link_verifications=entity_records, knowledge_edge_verifications=knowledge_records,
            architecture_rule_verifications=architecture_records, condition_assessments=conditions,
            trigger_features=features, evidence_inventory=inventory,
            verification_score=score.verification_score, score_components=score.score_components,
            location_findings=locations, verification_status=status,
            advisory_verification_steps=advisory,
            metadata={"phase": "9A-R1", "dynamic_verification": False,
                      "verified_attack_chain_created": False,
                      "score_meaning": "objective_evidence_support_not_probability",
                      "llm_objective_weight": 0.0})

    def _legacy_context(self, interaction, data, candidate, behavior, knowledge, resolver):
        if data.legacy_candidate_id is None:
            if candidate is not None: raise VerificationInputError("legacy Candidate was supplied without explicit input identity")
            return None
        if candidate is None or candidate.id != data.legacy_candidate_id:
            raise VerificationInputError("legacy Candidate identity mismatch")
        if behavior is None or knowledge is None or resolver is None:
            raise VerificationInputError("legacy Candidate verification requires repositories and Evidence resolver")
        return self._adapter.adapt(interaction, candidate, behavior, knowledge, resolver)

    def _verify_behavior(self, interaction, context, catalog):
        if context is None: return []
        nodes = {n.id: n for n in context.behavior_nodes}
        return [self._behavior.verify(interaction.id, e, nodes[e.source_id], nodes[e.target_id], catalog)
                for e in context.behavior_edges]

    def _verify_entity(self, interaction, context):
        if context is None: return []
        behavior = {n.id: n for n in context.behavior_nodes}
        knowledge = {n.id: n for n in context.knowledge_nodes}
        link = context.candidate.entity_link
        return [self._entity.verify(interaction.id, link, behavior[link.behavior_node_id], knowledge[link.knowledge_node_id])]

    def _verify_knowledge(self, interaction, context, catalog):
        if context is None: return []
        nodes = {n.id: n for n in context.knowledge_nodes}
        return [self._knowledge.verify(interaction.id, edge, nodes[edge.source_id], nodes[edge.target_id], catalog)
                for edge in context.knowledge_edges]

    def _verify_bindings(self, interaction, bindings, context, catalog, behavior_records, entity_records):
        behavior_by_id = {r.subject_id: r for r in behavior_records}
        entity_by_id = {r.subject_id: r for r in entity_records}
        behavior_nodes = {n.id: n for n in context.behavior_nodes} if context else {}
        knowledge_nodes = {n.id: n for n in context.knowledge_nodes} if context else {}
        records = []
        for binding in bindings:
            if binding.source_kind is InteractionSourceKind.KNOWLEDGE_NODE and binding.reference_role in {
                InteractionReferenceRole.INITIATING_VULNERABILITY, InteractionReferenceRole.TARGET_VULNERABILITY}:
                node = knowledge_nodes.get(binding.source_id)
                if node is not None:
                    records.append(self._vulnerability.verify(interaction.id, interaction.interaction_type,
                        interaction.architecture, binding, node, catalog)); continue
            source_record = None
            if binding.source_kind is InteractionSourceKind.BEHAVIOR_EDGE:
                source_record = behavior_by_id.get(binding.source_id)
            elif binding.source_kind is InteractionSourceKind.ENTITY_LINK:
                source_record = entity_by_id.get(binding.source_id)
            if source_record is not None:
                records.append(_binding_record(interaction, binding, source_record.status,
                    source_record.evidence_ids, ["explicit binding inherits verified source-fact status"],
                    supporting_evidence_ids=source_record.supporting_evidence_ids)); continue
            if binding.source_kind is InteractionSourceKind.BEHAVIOR_NODE:
                node = behavior_nodes.get(binding.source_id)
                status = VerificationStatus.UNKNOWN if node is None else (
                    VerificationStatus.UNKNOWN if node.architecture is interaction.architecture else VerificationStatus.REJECTED)
                records.append(_binding_record(interaction, binding, status, [], ["behavior node existence resolves a reference, not a behavior instance"])); continue
            if binding.source_kind is InteractionSourceKind.KNOWLEDGE_NODE:
                node = knowledge_nodes.get(binding.source_id)
                status = VerificationStatus.UNKNOWN if node is None else (
                    VerificationStatus.UNKNOWN if node.architecture in {None, interaction.architecture} else VerificationStatus.REJECTED)
                records.append(_binding_record(interaction, binding, status, [], ["knowledge node existence resolves a reference, not a security fact"])); continue
            if binding.source_kind is InteractionSourceKind.EVIDENCE:
                item = catalog.resolve(binding.source_id)
                status, messages, supporting = _evidence_binding_status(binding, item)
                records.append(_binding_record(
                    interaction, binding, status,
                    [binding.source_id] if item else [], messages,
                    supporting_evidence_ids=supporting,
                )); continue
            records.append(_binding_record(interaction, binding, VerificationStatus.UNKNOWN, [], ["binding source could not be resolved"]));
        return records

    def _verify_conditions(self, interaction, data, context, catalog):
        nodes = {n.id: n for n in context.knowledge_nodes} if context else {}
        results = []
        for binding in data.condition_bindings:
            node = nodes.get(binding.condition_node_id)
            if node is None:
                results.append(ConditionAssessment(interaction_id=interaction.id,
                    architecture=interaction.architecture,
                    condition_node_id=binding.condition_node_id,
                    condition_kind=binding.condition_kind,
                    applies_to_role=binding.applies_to_role, required=binding.required,
                    status=ConditionStatus.UNKNOWN,
                    rule_ids=["condition:explicit-binding-resolution:v1"],
                    messages=["explicit condition source could not be resolved"]))
            else:
                results.append(self._conditions.verify(interaction.id, interaction.architecture, binding, node, catalog))
        return results

    @staticmethod
    def _advisory_steps(data, candidate, result):
        if result is None: return []
        if candidate is None or result.candidate_id != candidate.id or result.architecture is not data.architecture:
            raise VerificationInputError("Multi-Agent advisory identity mismatch")
        return sorted(set([*result.evidence_analysis.recommended_evidence_collection_steps,
                           *result.security_reasoning.recommended_verification_steps,
                           *result.critic_review.required_revisions]))


def _binding_record(
    interaction, binding, status, evidence_ids, messages, *,
    supporting_evidence_ids=None,
):
    return VerificationRecord.create(interaction_id=interaction.id, architecture=interaction.architecture,
        subject_kind=VerificationSubjectKind.INTERACTION_PARTICIPANT,
        subject_id=f"{binding.reference_role.value}:{binding.interaction_reference_id}",
        status=status, verifier="phase9ar_explicit_binding_v1", evidence_ids=evidence_ids,
        supporting_evidence_ids=supporting_evidence_ids or [],
        rule_ids=["binding:explicit-role-source:v1"], messages=messages,
        metadata={"source_kind": binding.source_kind.value, "source_id": binding.source_id})


def _aggregate(statuses):
    if not statuses: return VerificationStatus.UNKNOWN
    if any(s is VerificationStatus.REJECTED for s in statuses): return VerificationStatus.REJECTED
    if all(s is VerificationStatus.VERIFIED for s in statuses): return VerificationStatus.VERIFIED
    return VerificationStatus.UNKNOWN


def _required_fact_statuses(interaction, bindings, binding_records, behavior, entity, architecture, conditions, context):
    by_subject = {r.subject_id: r.status for r in binding_records}
    def role(role):
        return [by_subject.get(f"{b.reference_role.value}:{b.interaction_reference_id}", VerificationStatus.UNKNOWN)
                for b in bindings if b.reference_role is role]
    mmio = [r.status for r in behavior if context and next((e for e in context.behavior_edges if e.id == r.subject_id), None)
            and next(e for e in context.behavior_edges if e.id == r.subject_id).relation in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}]
    transition = _aggregate([*([r.status for r in entity] if entity else [VerificationStatus.UNKNOWN]),
                             *(mmio if mmio else [VerificationStatus.UNKNOWN])])
    required_conditions = [c for c in conditions if c.required]
    cond = VerificationStatus.UNKNOWN if not required_conditions else (
        VerificationStatus.REJECTED if any(c.status is ConditionStatus.UNSATISFIED for c in required_conditions) else
        VerificationStatus.VERIFIED if all(c.status is ConditionStatus.SATISFIED for c in required_conditions) else VerificationStatus.UNKNOWN)
    return {
        RequiredFactCategory.INITIATING_VULNERABILITY_SUPPORT: _aggregate(role(InteractionReferenceRole.INITIATING_VULNERABILITY)),
        RequiredFactCategory.TRIGGER_BEHAVIOR_SUPPORT: _aggregate(role(InteractionReferenceRole.TRIGGER_BEHAVIOR)),
        RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT: transition,
        RequiredFactCategory.TARGET_VULNERABILITY_SUPPORT: _aggregate(role(InteractionReferenceRole.TARGET_VULNERABILITY)),
        RequiredFactCategory.ARCHITECTURE_RULES: _aggregate([r.status for r in architecture]),
        RequiredFactCategory.CONDITIONS: cond,
    }


def _score_components(interaction_type, facts):
    v = lambda category: [facts.get(category, VerificationStatus.UNKNOWN)]
    if interaction_type.value == "firmware_vulnerability_to_hardware":
        return {"initiating_vulnerability_support": v(RequiredFactCategory.INITIATING_VULNERABILITY_SUPPORT),
                "trigger_behavior_support": v(RequiredFactCategory.TRIGGER_BEHAVIOR_SUPPORT),
                "cross_layer_transition_support": v(RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT),
                "target_vulnerability_support": v(RequiredFactCategory.TARGET_VULNERABILITY_SUPPORT),
                "architecture_and_conditions": [facts[RequiredFactCategory.ARCHITECTURE_RULES], facts[RequiredFactCategory.CONDITIONS]]}
    return {"trigger_behavior_support": v(RequiredFactCategory.TRIGGER_BEHAVIOR_SUPPORT),
            "cross_layer_transition_support": v(RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT),
            "target_vulnerability_support": v(RequiredFactCategory.TARGET_VULNERABILITY_SUPPORT),
            "conditions": v(RequiredFactCategory.CONDITIONS),
            "architecture_rules": v(RequiredFactCategory.ARCHITECTURE_RULES)}


_SUBSTANTIVE_FACTS = {
    RequiredFactCategory.INITIATING_VULNERABILITY_SUPPORT,
    RequiredFactCategory.TRIGGER_BEHAVIOR_SUPPORT,
    RequiredFactCategory.CROSS_LAYER_TRANSITION_SUPPORT,
    RequiredFactCategory.TARGET_VULNERABILITY_SUPPORT,
    RequiredFactCategory.HARDWARE_FAULT_STATE_SUPPORT,
    RequiredFactCategory.PROPAGATION_MECHANISM_SUPPORT,
    RequiredFactCategory.AFFECTED_EXECUTION_SUPPORT,
}


def _interaction_status(required, facts, capability):
    statuses = [facts.get(item, VerificationStatus.UNKNOWN) for item in required]
    if any(s is VerificationStatus.REJECTED for s in statuses): return InteractionVerificationStatus.REJECTED
    if statuses and all(s is VerificationStatus.VERIFIED for s in statuses):
        return (
            InteractionVerificationStatus.VERIFIED
            if capability is VerificationCapabilityStatus.SUPPORTED
            else InteractionVerificationStatus.PARTIALLY_VERIFIED
        )
    substantive_statuses = [
        facts.get(item, VerificationStatus.UNKNOWN)
        for item in required
        if item in _SUBSTANTIVE_FACTS
    ]
    if any(s is VerificationStatus.VERIFIED for s in substantive_statuses):
        return InteractionVerificationStatus.PARTIALLY_VERIFIED
    return InteractionVerificationStatus.INSUFFICIENT_EVIDENCE


def _required_evidence_ids(bindings, binding_records, behavior, entity, conditions):
    required_subjects = {f"{b.reference_role.value}:{b.interaction_reference_id}" for b in bindings}
    ids = [e for r in binding_records if r.subject_id in required_subjects for e in r.evidence_ids]
    ids.extend(e for c in conditions if c.required for e in [*c.supporting_evidence_ids, *c.contradicting_evidence_ids])
    return sorted(set(ids))


def _supporting_evidence_ids(binding_records, conditions):
    ids = [
        evidence_id
        for record in binding_records
        for evidence_id in record.supporting_evidence_ids
    ]
    ids.extend(
        evidence_id
        for condition in conditions
        if condition.required
        for evidence_id in condition.supporting_evidence_ids
    )
    return sorted(set(ids))


def _evidence_binding_status(binding, evidence):
    if evidence is None:
        return VerificationStatus.UNKNOWN, ["explicit Evidence could not be resolved"], []
    metadata_reference = evidence.metadata.get("interaction_reference_id")
    metadata_role = evidence.metadata.get("reference_role")
    if metadata_reference is not None and metadata_reference != binding.interaction_reference_id:
        return VerificationStatus.REJECTED, ["Evidence interaction reference ID mismatch"], []
    if metadata_role is not None and metadata_role != binding.reference_role.value:
        return VerificationStatus.REJECTED, ["Evidence interaction reference role mismatch"], []
    if metadata_reference is None or metadata_role is None:
        return VerificationStatus.UNKNOWN, ["Evidence lacks structured interaction subject linkage"], []
    if evidence.type is EvidenceType.LLM_SEMANTIC or not evidence.verified:
        return VerificationStatus.UNKNOWN, ["subject-linked Evidence is not verified non-LLM Evidence"], []
    return VerificationStatus.VERIFIED, ["structured Evidence subject linkage matches binding"], [evidence.id]
