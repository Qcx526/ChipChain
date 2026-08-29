"""Offline public-knowledge projection and prompt-readiness materialization."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from chipchain.agents.base import ReasoningContext
from chipchain.corpus.models import PublicCveCorpus, PublicCveResearchSample
from chipchain.evaluation.ablation import PromptVisibilityAuditor
from chipchain.evaluation.experiment_models import (
    PHASE10D_PROVIDER_ROLE_ORDER,
    structured_prompt_request_sha256,
)
from chipchain.evaluation.public_knowledge_readiness_models import (
    PHASE10D_PUBLIC_KNOWLEDGE_LEAKAGE_AUDIT_CONTRACT,
    PHASE10D_PUBLIC_KNOWLEDGE_READINESS_CONTRACT,
    PHASE10D_STEP8B1A_FROZEN_COHORT_ID,
    PublicKnowledgeCaseReadiness,
    PublicKnowledgeLeakageAudit,
    PublicKnowledgeLeakageAuditStatus,
    PublicKnowledgePromptAssessment,
    PublicKnowledgeReadinessArtifact,
    public_knowledge_case_readiness_id,
    public_knowledge_leakage_audit_id,
    public_knowledge_prompt_assessment_id,
    public_knowledge_readiness_artifact_id,
)
from chipchain.evaluation.public_secondary_models import (
    PublicPromptReadinessResult,
    PublicSecondaryCohort,
)
from chipchain.knowledge.models import VulnerabilityKnowledgeEntry
from chipchain.reasoning.enums import (
    ReasoningAgentType,
    ReasoningPromptVisibility,
)
from chipchain.reasoning.knowledge_projection import (
    PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT,
    KnowledgeContentProjection,
)
from chipchain.reasoning.models import StructuredPromptRequest
from chipchain.reasoning.prompt_view import masked_chain_hidden_reference_ids
from chipchain.reasoning.prompts import RoleBasedReasoningPromptBuilder


PUBLIC_KNOWLEDGE_FORBIDDEN_PROMPT_FIELDS = frozenset(
    {
        "admission_blockers",
        "admission_status",
        "architecture_profile",
        "claim_binding_status",
        "cross_layer_classification",
        "evaluation_scope",
        "expected_attack_pattern_reference",
        "feasibility_status",
        "ground_truth_chains",
        "hardware_effect_summary",
        "hardware_trigger_signature_id",
        "metric_results",
        "objective_materialization",
        "precondition_summary",
        "related_cve_ids",
        "strict_hit",
        "trigger_summary",
        "triggerability",
        "underlying_issue_key",
    }
)
_PROJECTED_ENTRY_FIELDS = frozenset(
    {
        "affected_components",
        "architecture",
        "entry_id",
        "entry_kind",
        "external_id",
        "references",
        "summary",
        "title",
    }
)


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value))
    return set()


def _all_string_values(value: object) -> set[str]:
    if isinstance(value, dict):
        return set().union(
            *(_all_string_values(item) for item in value.values())
        )
    if isinstance(value, list):
        return set().union(*(_all_string_values(item) for item in value))
    return {value} if isinstance(value, str) else set()


class PublicKnowledgeLeakageAuditor:
    """Audit final provider-visible JSON without storing forbidden raw values."""

    @staticmethod
    def audit(
        prompt: StructuredPromptRequest,
        *,
        forbidden_exact_values: list[str],
    ) -> PublicKnowledgeLeakageAudit:
        if not isinstance(prompt, StructuredPromptRequest):
            raise TypeError("public knowledge audit requires StructuredPromptRequest")
        snapshot = StructuredPromptRequest.model_validate(
            prompt.model_dump(mode="json")
        )
        payload = json.loads(snapshot.user_prompt)
        if not isinstance(payload, dict):
            raise ValueError("public knowledge prompt payload must be an object")
        projected = payload.get("knowledge_reference_content")
        if not isinstance(projected, list) or not projected:
            raise ValueError("public knowledge prompt lacks projected content")
        if any(not isinstance(item, dict) for item in projected):
            raise ValueError("projected public knowledge entries must be objects")
        if payload.get("knowledge_content_projection_contract") != (
            PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT
        ):
            raise ValueError("public knowledge prompt projection contract mismatch")
        if not isinstance(
            payload.get("knowledge_content_projection_id"),
            str,
        ):
            raise ValueError("public knowledge prompt projection ID is missing")
        unexpected_projection_fields = {
            key
            for item in projected
            if isinstance(item, dict)
            for key in item
            if key not in _PROJECTED_ENTRY_FIELDS
        }
        keys = _all_keys(payload)
        detected_fields = sorted(
            PUBLIC_KNOWLEDGE_FORBIDDEN_PROMPT_FIELDS.intersection(keys)
            | unexpected_projection_fields
            | {
                item
                for item in PUBLIC_KNOWLEDGE_FORBIDDEN_PROMPT_FIELDS
                if item in snapshot.system_prompt
            }
        )
        visible_values = _all_string_values(payload)
        detected_value_hashes = sorted(
            {
                hashlib.sha256(item.encode("utf-8")).hexdigest()
                for item in forbidden_exact_values
                if item and item in visible_values
            }
        )
        status = (
            PublicKnowledgeLeakageAuditStatus.LEAK_DETECTED
            if detected_fields or detected_value_hashes
            else PublicKnowledgeLeakageAuditStatus.PASS
        )
        prompt_sha256 = structured_prompt_request_sha256(snapshot)
        identity = public_knowledge_leakage_audit_id(
            contract=PHASE10D_PUBLIC_KNOWLEDGE_LEAKAGE_AUDIT_CONTRACT,
            prompt_sha256=prompt_sha256,
            detected_forbidden_field_names=detected_fields,
            detected_forbidden_value_sha256s=detected_value_hashes,
            status=status,
        )
        return PublicKnowledgeLeakageAudit(
            id=identity,
            prompt_sha256=prompt_sha256,
            detected_forbidden_field_names=detected_fields,
            detected_forbidden_value_sha256s=detected_value_hashes,
            status=status,
        )


def _forbidden_exact_values(
    sample: PublicCveResearchSample,
    entry: VulnerabilityKnowledgeEntry,
) -> list[str]:
    allowed = {
        entry.id,
        entry.entry_kind.value,
        entry.external_id,
        entry.architecture.value if entry.architecture is not None else "",
        entry.title,
        entry.summary,
        *entry.affected_components,
        *entry.references,
    }
    candidates = {
        sample.architecture_profile.value,
        sample.cross_layer_classification.value,
        sample.underlying_issue_key,
        *sample.related_cve_ids,
        sample.trigger_summary,
        sample.precondition_summary,
        sample.hardware_effect_summary,
        sample.admission_status.value,
        *(item.value for item in sample.admission_blockers),
    }
    return sorted(item for item in candidates if item and item not in allowed)


def _assessment(
    *,
    cve_id: str,
    benchmark_case_id: str,
    context: ReasoningContext,
    entry: VulnerabilityKnowledgeEntry,
    projection: KnowledgeContentProjection,
    role: ReasoningAgentType,
    visibility: ReasoningPromptVisibility,
    prompt: StructuredPromptRequest,
    forbidden_exact_values: list[str],
) -> PublicKnowledgePromptAssessment:
    payload = json.loads(prompt.user_prompt)
    if (
        payload.get("knowledge_content_projection_contract")
        != projection.contract
        or payload.get("knowledge_content_projection_id") != projection.id
        or payload.get("knowledge_reference_content")
        != [item.model_dump(mode="json") for item in projection.entries]
    ):
        raise ValueError("public prompt projection provenance mismatch")
    visible_values = _all_string_values(payload)
    prompt_sha256 = structured_prompt_request_sha256(prompt)
    visibility_audit = None
    if visibility is ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT:
        visibility_audit = PromptVisibilityAuditor.audit(
            prompt,
            hidden_reference_ids=masked_chain_hidden_reference_ids(context),
        )
    leakage_audit = PublicKnowledgeLeakageAuditor.audit(
        prompt,
        forbidden_exact_values=forbidden_exact_values,
    )
    values = {
        "cve_id": cve_id,
        "benchmark_case_id": benchmark_case_id,
        "reasoning_context_id": context.id,
        "knowledge_entry_id": entry.id,
        "knowledge_projection_id": projection.id,
        "role": role,
        "visibility": visibility,
        "prompt_sha256": prompt_sha256,
        "visibility_audit": visibility_audit,
        "leakage_audit": leakage_audit,
        "cve_external_id_visible": entry.external_id in visible_values,
        "knowledge_entry_id_visible": entry.id in visible_values,
        "title_visible": entry.title in visible_values,
        "summary_visible": entry.summary in visible_values,
        "affected_components_visible": all(
            item in visible_values for item in entry.affected_components
        ),
        "public_references_visible": all(
            item in visible_values for item in entry.references
        ),
    }
    identity = public_knowledge_prompt_assessment_id(
        cve_id=cve_id,
        benchmark_case_id=benchmark_case_id,
        reasoning_context_id=context.id,
        knowledge_entry_id=entry.id,
        knowledge_projection_id=projection.id,
        role=role,
        visibility=visibility,
        prompt_sha256=prompt_sha256,
        visibility_audit_id=(
            visibility_audit.id if visibility_audit is not None else None
        ),
        leakage_audit_id=leakage_audit.id,
        cve_external_id_visible=values["cve_external_id_visible"],
        knowledge_entry_id_visible=values["knowledge_entry_id_visible"],
        title_visible=values["title_visible"],
        summary_visible=values["summary_visible"],
        affected_components_visible=values["affected_components_visible"],
        public_references_visible=values["public_references_visible"],
    )
    return PublicKnowledgePromptAssessment(id=identity, **values)


def materialize_public_knowledge_readiness(
    *,
    frozen_cohort: PublicSecondaryCohort,
    corpus: PublicCveCorpus,
) -> PublicKnowledgeReadinessArtifact:
    """Project exact local entries into FULL/MASKED prompts and audit them."""

    cohort = PublicSecondaryCohort.model_validate(
        frozen_cohort.model_dump(mode="json")
    )
    corpus_snapshot = PublicCveCorpus.model_validate(
        corpus.model_dump(mode="json")
    )
    if cohort.id != PHASE10D_STEP8B1A_FROZEN_COHORT_ID:
        raise ValueError("knowledge readiness requires frozen Step 8B-1A cohort")
    if cohort.source_corpus_id != corpus_snapshot.id:
        raise ValueError("knowledge readiness source corpus mismatch")
    entry_by_id = {item.id: item for item in corpus_snapshot.knowledge_entries}
    sample_by_cve = {item.cve_id: item for item in corpus_snapshot.records}
    builder = RoleBasedReasoningPromptBuilder()
    case_readiness: list[PublicKnowledgeCaseReadiness] = []

    for materialized in cohort.case_materializations:
        try:
            entry = entry_by_id[materialized.knowledge_entry_id]
            sample = sample_by_cve[materialized.cve_id]
        except KeyError as exc:
            raise ValueError("frozen public case lacks exact knowledge binding") from exc
        if sample.knowledge_entry_id != entry.id:
            raise ValueError("public case sample/knowledge binding mismatch")
        projection = KnowledgeContentProjection.create(
            materialized.reasoning_context,
            [entry],
        )
        forbidden_values = _forbidden_exact_values(sample, entry)
        assessments: list[PublicKnowledgePromptAssessment] = []
        for visibility in (
            ReasoningPromptVisibility.FULL_CONTEXT,
            ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
        ):
            for role in PHASE10D_PROVIDER_ROLE_ORDER:
                prompt = builder.build_with_knowledge_projection(
                    materialized.reasoning_context,
                    role=role,
                    visibility=visibility,
                    knowledge_projection=projection,
                )
                assessments.append(
                    _assessment(
                        cve_id=materialized.cve_id,
                        benchmark_case_id=materialized.benchmark_case_id,
                        context=materialized.reasoning_context,
                        entry=entry,
                        projection=projection,
                        role=role,
                        visibility=visibility,
                        prompt=prompt,
                        forbidden_exact_values=forbidden_values,
                    )
                )
        case_id = public_knowledge_case_readiness_id(
            cve_id=materialized.cve_id,
            benchmark_case_id=materialized.benchmark_case_id,
            documented_interaction_id=materialized.documented_interaction.id,
            reasoning_context_id=materialized.reasoning_context.id,
            knowledge_entry_id=entry.id,
            knowledge_projection_id=projection.id,
            prompt_assessment_ids=[item.id for item in assessments],
        )
        case_readiness.append(
            PublicKnowledgeCaseReadiness(
                id=case_id,
                cve_id=materialized.cve_id,
                benchmark_case_id=materialized.benchmark_case_id,
                documented_interaction_id=(
                    materialized.documented_interaction.id
                ),
                reasoning_context_id=materialized.reasoning_context.id,
                knowledge_entry_id=entry.id,
                knowledge_projection_id=projection.id,
                prompt_assessments=assessments,
            )
        )
    selected = sorted(item.cve_id for item in case_readiness)
    readiness = (
        PublicPromptReadinessResult.READY_FOR_PUBLIC_PROVIDER
        if all(
            assessment.content_complete
            for case in case_readiness
            for assessment in case.prompt_assessments
        )
        else PublicPromptReadinessResult.REFERENCE_CONTENT_INSUFFICIENT
    )
    identity = public_knowledge_readiness_artifact_id(
        contract=PHASE10D_PUBLIC_KNOWLEDGE_READINESS_CONTRACT,
        frozen_public_secondary_cohort_id=cohort.id,
        source_corpus_id=corpus_snapshot.id,
        knowledge_projection_contract=(
            PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT
        ),
        selected_cve_ids=selected,
        case_readiness_ids=[item.id for item in case_readiness],
        readiness_result=readiness,
    )
    artifact = PublicKnowledgeReadinessArtifact(
        id=identity,
        source_corpus_id=corpus_snapshot.id,
        selected_cve_ids=selected,
        case_readiness=case_readiness,
        readiness_result=readiness,
    )
    if artifact.readiness_result is not (
        PublicPromptReadinessResult.READY_FOR_PUBLIC_PROVIDER
    ):
        raise ValueError("public knowledge prompt readiness failed closed")
    return artifact


def serialize_public_knowledge_readiness(
    artifact: PublicKnowledgeReadinessArtifact,
) -> str:
    """Return stable UTF-8-ready JSON with one final newline."""

    snapshot = PublicKnowledgeReadinessArtifact.model_validate(
        artifact.model_dump(mode="json")
    )
    return snapshot.model_dump_json(indent=2, ensure_ascii=False) + "\n"


def load_public_knowledge_readiness(
    path: str | Path,
) -> PublicKnowledgeReadinessArtifact:
    """Load one local readiness artifact without resolving external content."""

    return PublicKnowledgeReadinessArtifact.model_validate_json(
        Path(path).read_text(encoding="utf-8")
    )


def write_public_knowledge_readiness(
    artifact: PublicKnowledgeReadinessArtifact,
    path: str | Path,
) -> None:
    """Write one deterministic readiness artifact without external state."""

    Path(path).write_text(
        serialize_public_knowledge_readiness(artifact),
        encoding="utf-8",
    )
