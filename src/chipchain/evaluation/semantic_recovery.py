"""Offline Phase 10D masked semantic/content recovery diagnostics."""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from pathlib import Path

from chipchain.agents.state import ReasoningSession
from chipchain.corpus.models import CrossLayerResearchClassification
from chipchain.corpus.source_models import (
    PUBLIC_CVE_SOURCE_CONTRACT,
    PublicCveSourceDocument,
    PublicCveSourceRecord,
)
from chipchain.evaluation.enums import (
    AblationConditionKind,
    BenchmarkCaseRunDisposition,
    ModelClaimBindingReason,
    ModelClaimBindingStatus,
)
from chipchain.evaluation.public_knowledge_execution_models import (
    PHASE10D_PUBLIC_CVE_CORPUS_ID,
    PHASE10D_PUBLIC_SECONDARY_CVE_IDS,
    PublicKnowledgeExecutionArchive,
    PublicKnowledgeExecutionCaseBinding,
)
from chipchain.evaluation.semantic_recovery_models import (
    InteractionTypeRecoveryStatus,
    MaskedSemanticRecoveryCaseDiagnostic,
    MaskedSemanticRecoveryDiagnosticArtifact,
    ParticipantGroundingDiagnostic,
    ReferenceContentCoverage,
    ReferenceCoverageScope,
    SemanticDiagnosticMode,
    SemanticDiagnosticTextSource,
    SemanticReferenceDigest,
    SemanticReferenceField,
)
from chipchain.models.cross_layer import (
    CrossLayerInteraction,
    CrossLayerInteractionType,
)
from chipchain.reasoning.chain_claim import ModelAuthoredChainClaim
from chipchain.reasoning.enums import ReasoningAgentType
from chipchain.reasoning.hypothesis import AttackHypothesis
from chipchain.reasoning.prompt_view import masked_chain_hidden_reference_ids
from chipchain.reasoning.reasoning_result import ReasoningResult


PHASE10D_STEP8B1D_ARCHIVE_SHA256 = (
    "5bf1f1268b90a8a7eaf17bb52846ae64f2edc752ec904b3db3125fc0efafdedd"
)
PHASE10D_STEP8B1D_ARCHIVE_ID = (
    "public-knowledge-execution-archive:"
    "f688bca23b0ef1f3d348c7e5c41ab2af8326d06c507e5090b1b15b0e9cf017d7"
)
PHASE10D_STEP8B1D_BINDING_ID = (
    "public-knowledge-execution-binding:"
    "bc4cc2613df0853cb80da4d5bb2c1c93b44299405cf5e28d22ea703ae0798415"
)
PHASE10D_STEP8B1D_EXPERIMENT_PLAN_ID = (
    "real-model-experiment-plan:"
    "70b5490561783d6048a63baa31b5737595c77646bc1248a1a8639c598ab525ba"
)
PHASE10D_STEP8B1D_MANIFEST_ID = (
    "benchmark-manifest:"
    "193ba6a515500cb9dac521c9db9fa3bbcc2d37ccf935c1b46e8878972fe94a5a"
)
PHASE10D_STEP8B1D_INPUT_SET_ID = (
    "real-experiment-input-set:"
    "a3e8110a16a97287999af9f0615ffb0c74e0066321e6bc1268226545f12dbaa5"
)

_REFERENCE_FIELDS = {
    SemanticReferenceField.TRIGGER_SUMMARY: "trigger_summary",
    SemanticReferenceField.PRECONDITION_SUMMARY: "precondition_summary",
    SemanticReferenceField.HARDWARE_EFFECT_SUMMARY: "hardware_effect_summary",
}
_CLAIM_REFERENCE_FIELDS = (
    "initiating_vulnerability_ids",
    "target_vulnerability_ids",
    "trigger_behavior_ids",
    "propagation_behavior_ids",
    "affected_execution_ids",
    "fault_state_ids",
    "hardware_resource_ids",
    "security_mechanism_ids",
)
_CLASSIFICATION_BY_TYPE = {
    CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE: (
        CrossLayerResearchClassification.TYPE_I_CANDIDATE
    ),
    CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE: (
        CrossLayerResearchClassification.TYPE_II_CANDIDATE
    ),
    CrossLayerInteractionType.HARDWARE_VULNERABILITY_TO_FIRMWARE: (
        CrossLayerResearchClassification.TYPE_III_CANDIDATE
    ),
}
_GENERIC_STOPWORDS = frozenset(
    {
        "a",
        "an",
        "and",
        "are",
        "as",
        "at",
        "be",
        "been",
        "by",
        "can",
        "could",
        "for",
        "from",
        "has",
        "have",
        "if",
        "in",
        "into",
        "is",
        "it",
        "its",
        "may",
        "of",
        "on",
        "or",
        "that",
        "the",
        "their",
        "then",
        "this",
        "through",
        "to",
        "under",
        "was",
        "were",
        "when",
        "where",
        "which",
        "with",
        "without",
        "would",
    }
)
_GENERIC_META_VOCABULARY = frozenset(
    {
        "affected",
        "available",
        "cve",
        "documented",
        "entry",
        "evidence",
        "hypothesis",
        "knowledge",
        "public",
        "reasoning",
        "reference",
        "report",
        "reports",
        "unverified",
    }
)
_TOKEN = re.compile(r"[a-z0-9]+(?:_[a-z0-9]+)*")
_CVE_TOKEN = re.compile(r"cve_[0-9]{4}_[0-9]{4,}")
_EVALUATOR_ONLY_FIELDS = frozenset(_REFERENCE_FIELDS.values())
_FROZEN_SOURCE_RECORD_SHA256_BY_CVE = {
    "CVE-2022-23960": (
        "5081d47d87b6012cf5ab507e2166139040790a06db660ee2346d08b308260efd"
    ),
    "CVE-2023-34320": (
        "980a723600d6288617bf924fcc9e6a95e89079c498d8890286c6bb01e43c5a42"
    ),
    "CVE-2023-52481": (
        "fc6ad81d8dace067181b9dab41cd6b989e8a00e7ffccad81033acd25ed17f241"
    ),
    "CVE-2024-26670": (
        "8e4e831d8f90876c75028bc0591ef51e9c6a898acb1260b751cc2c70d8200802"
    ),
    "CVE-2025-10263": (
        "1913e1bef673692572e76c233b3af6234d55eaf70c25a45cc2a8a9275a672826"
    ),
}


class MaskedSemanticRecoveryError(ValueError):
    """Fail-closed diagnostic provenance or isolation error."""


def semantic_tokens(text: str) -> frozenset[str]:
    """Apply the frozen generic v1 lexical normalization contract."""

    normalized = unicodedata.normalize("NFKC", text).lower()
    normalized = normalized.replace("-", "_")
    tokens = set(_TOKEN.findall(normalized))
    return frozenset(
        token
        for token in tokens
        if token not in _GENERIC_STOPWORDS
        and token not in _GENERIC_META_VOCABULARY
        and not _CVE_TOKEN.fullmatch(token)
    )


def semantic_token_set_sha256(tokens: frozenset[str] | set[str]) -> str:
    """Hash a canonical sorted token set without persisting duplicated arrays."""

    payload = json.dumps(
        sorted(tokens),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _source_record_sha256(record: PublicCveSourceRecord) -> str:
    payload = json.dumps(
        record.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_reference_content_coverage(
    *,
    reference_field: SemanticReferenceField,
    scope: ReferenceCoverageScope,
    reference_tokens: frozenset[str] | set[str],
    diagnostic_tokens: frozenset[str] | set[str],
) -> ReferenceContentCoverage:
    """Create exact set-intersection coverage with no score or threshold."""

    reference = frozenset(reference_tokens)
    matched = reference.intersection(diagnostic_tokens)
    return ReferenceContentCoverage.create(
        reference_field=reference_field,
        scope=scope,
        reference_token_count=len(reference),
        matched_token_count=len(matched),
        reference_token_set_sha256=semantic_token_set_sha256(reference),
        matched_token_set_sha256=semantic_token_set_sha256(matched),
    )


def interaction_type_recovery_status(
    *,
    expected: CrossLayerInteractionType,
    claim: ModelAuthoredChainClaim | None,
) -> InteractionTypeRecoveryStatus:
    """Compare only the exact typed claim, retaining missing as missing."""

    if claim is None:
        return InteractionTypeRecoveryStatus.CLAIM_MISSING
    if claim.interaction_type is expected:
        return InteractionTypeRecoveryStatus.MATCH
    return InteractionTypeRecoveryStatus.MISMATCH


def participant_grounding_diagnostic(
    *,
    binding_status: ModelClaimBindingStatus,
    binding_reasons: list[ModelClaimBindingReason],
    interaction: CrossLayerInteraction,
    claim: ModelAuthoredChainClaim | None,
    visible_knowledge_entry_id: str,
    hidden_reference_ids: list[str],
) -> ParticipantGroundingDiagnostic:
    """Explain existing exact-binder output without repairing any reference."""

    reasons = set(binding_reasons)
    if claim is None or binding_status is ModelClaimBindingStatus.MISSING:
        return ParticipantGroundingDiagnostic.CLAIM_MISSING
    if ModelClaimBindingReason.CLAIM_INTERACTION_TYPE_MISMATCH in reasons:
        return ParticipantGroundingDiagnostic.INTERACTION_TYPE_MISMATCH
    if ModelClaimBindingReason.CLAIM_TYPE_SHAPE_CONFLICT in reasons:
        return ParticipantGroundingDiagnostic.TYPE_SHAPE_CONFLICT
    if binding_status is ModelClaimBindingStatus.ALIGNED:
        return ParticipantGroundingDiagnostic.EXACT_REQUIRED_REFERENCES

    claim_references = {
        item
        for field_name in _CLAIM_REFERENCE_FIELDS
        for item in getattr(claim, field_name)
    }
    interaction_references = {
        item
        for field_name in _CLAIM_REFERENCE_FIELDS
        for item in getattr(interaction, field_name)
    }
    if (
        visible_knowledge_entry_id in claim_references
        and visible_knowledge_entry_id not in interaction_references
    ):
        return (
            ParticipantGroundingDiagnostic.VISIBLE_KNOWLEDGE_REFERENCE_SUBSTITUTION
        )
    if binding_status is ModelClaimBindingStatus.INCOMPLETE:
        return ParticipantGroundingDiagnostic.REQUIRED_REFERENCES_MISSING
    hidden = set(hidden_reference_ids)
    if binding_status is ModelClaimBindingStatus.MISMATCHED and (
        claim_references.intersection(hidden)
        or reasons.intersection(
            {
                ModelClaimBindingReason.CLAIM_INITIATING_VULNERABILITY_MISMATCH,
                ModelClaimBindingReason.CLAIM_TARGET_VULNERABILITY_MISMATCH,
                ModelClaimBindingReason.CLAIM_TRIGGER_BEHAVIOR_MISMATCH,
                ModelClaimBindingReason.CLAIM_AFFECTED_EXECUTION_MISMATCH,
                ModelClaimBindingReason.CLAIM_OPTIONAL_REFERENCE_MISMATCH,
            }
        )
    ):
        return ParticipantGroundingDiagnostic.HIDDEN_REFERENCE_MISMATCH
    return ParticipantGroundingDiagnostic.OTHER


def extract_attack_chain_diagnostic_text(
    session: ReasoningSession,
) -> tuple[AttackHypothesis, ReasoningResult | None, str]:
    """Select exact claim-carrying ATTACK_CHAIN text without any fallback."""

    sources = [
        item
        for item in session.hypotheses
        if item.model_authored_chain_claim is not None
    ]
    if len(sources) != 1:
        raise MaskedSemanticRecoveryError(
            "MASKED session requires one claim-carrying source hypothesis"
        )
    hypothesis = sources[0]
    claim = hypothesis.model_authored_chain_claim
    if claim is None or claim.author_role is not ReasoningAgentType.ATTACK_CHAIN:
        raise MaskedSemanticRecoveryError(
            "diagnostic source claim must be authored by ATTACK_CHAIN"
        )
    if not hypothesis.description.strip():
        raise MaskedSemanticRecoveryError(
            "ATTACK_CHAIN hypothesis description is required"
        )
    matching = [
        item
        for item in session.reasoning_results
        if item.hypothesis_id == hypothesis.id
    ]
    if len(matching) > 1:
        raise MaskedSemanticRecoveryError(
            "ATTACK_CHAIN hypothesis has multiple reasoning results"
        )
    result = matching[0] if matching else None
    if result is None:
        metadata = session.metadata
        if (
            session.workflow_contract != "phase9b2b_multi_agent_workflow_v1"
            or metadata.get("attack_chain_agent_scope") != "hypothesis_only"
            or metadata.get("execution_order")
            != ["code", "hardware", "vulnerability", "attack_chain"]
        ):
            raise MaskedSemanticRecoveryError(
                "missing ATTACK_CHAIN reasoning result lacks hypothesis-only provenance"
            )
        return hypothesis, None, hypothesis.description
    text = "\n".join((hypothesis.description, *result.reasoning_steps))
    return hypothesis, result, text


def _validate_frozen_archive(
    archive: PublicKnowledgeExecutionArchive,
    source_archive_sha256: str,
) -> None:
    binding = archive.public_knowledge_execution_binding
    execution = archive.real_model_execution_archive
    actual = (
        archive.id,
        source_archive_sha256,
        binding.id,
        execution.experiment_plan_id,
        execution.benchmark_manifest.id,
        execution.input_set.id,
        binding.source_corpus_id,
    )
    expected = (
        PHASE10D_STEP8B1D_ARCHIVE_ID,
        PHASE10D_STEP8B1D_ARCHIVE_SHA256,
        PHASE10D_STEP8B1D_BINDING_ID,
        PHASE10D_STEP8B1D_EXPERIMENT_PLAN_ID,
        PHASE10D_STEP8B1D_MANIFEST_ID,
        PHASE10D_STEP8B1D_INPUT_SET_ID,
        PHASE10D_PUBLIC_CVE_CORPUS_ID,
    )
    if actual != expected:
        raise MaskedSemanticRecoveryError(
            "semantic diagnostic source archive provenance mismatch"
        )


def _validate_source_projection_boundary(
    source: PublicCveSourceRecord,
    binding: PublicKnowledgeExecutionCaseBinding,
) -> str:
    entries = binding.knowledge_projection.entries
    if len(entries) != 1 or entries[0].external_id != source.cve_id:
        raise MaskedSemanticRecoveryError(
            "case source and visible knowledge projection mismatch"
        )
    projection_fields = set(entries[0].model_dump(mode="json"))
    if projection_fields.intersection(_EVALUATOR_ONLY_FIELDS):
        raise MaskedSemanticRecoveryError(
            "evaluator-only semantic fields leaked into knowledge projection"
        )
    return entries[0].summary


def _coverage_models(
    *,
    source: PublicCveSourceRecord,
    visible_summary: str,
    diagnostic_text: str,
) -> tuple[
    dict[SemanticReferenceField, SemanticReferenceDigest],
    dict[SemanticReferenceField, ReferenceContentCoverage],
    dict[SemanticReferenceField, ReferenceContentCoverage],
]:
    visible_tokens = semantic_tokens(visible_summary)
    diagnostic_tokens = semantic_tokens(diagnostic_text)
    digests: dict[SemanticReferenceField, SemanticReferenceDigest] = {}
    content: dict[SemanticReferenceField, ReferenceContentCoverage] = {}
    held_out: dict[SemanticReferenceField, ReferenceContentCoverage] = {}
    for field, source_field in _REFERENCE_FIELDS.items():
        reference_tokens = semantic_tokens(getattr(source, source_field))
        held_out_tokens = reference_tokens.difference(visible_tokens)
        digest = semantic_token_set_sha256(reference_tokens)
        digests[field] = SemanticReferenceDigest.create(
            reference_field=field,
            token_count=len(reference_tokens),
            token_set_sha256=digest,
        )
        content[field] = build_reference_content_coverage(
            reference_field=field,
            scope=ReferenceCoverageScope.CONTENT,
            reference_tokens=reference_tokens,
            diagnostic_tokens=diagnostic_tokens,
        )
        held_out[field] = build_reference_content_coverage(
            reference_field=field,
            scope=ReferenceCoverageScope.HELD_OUT,
            reference_tokens=held_out_tokens,
            diagnostic_tokens=diagnostic_tokens,
        )
    return digests, content, held_out


def materialize_masked_semantic_recovery_diagnostic(
    *,
    archive: PublicKnowledgeExecutionArchive,
    source_archive_sha256: str,
    public_source: PublicCveSourceDocument,
) -> MaskedSemanticRecoveryDiagnosticArtifact:
    """Build the frozen five-case retrospective diagnostic entirely offline."""

    archive_snapshot = PublicKnowledgeExecutionArchive.model_validate(
        archive.model_dump(mode="json")
    )
    source_snapshot = PublicCveSourceDocument.model_validate(
        public_source.model_dump(mode="json")
    )
    _validate_frozen_archive(archive_snapshot, source_archive_sha256)
    if source_snapshot.contract != PUBLIC_CVE_SOURCE_CONTRACT:
        raise MaskedSemanticRecoveryError("unsupported public source contract")

    source_by_cve = {item.cve_id: item for item in source_snapshot.records}
    binding = archive_snapshot.public_knowledge_execution_binding
    execution = archive_snapshot.real_model_execution_archive
    input_by_case = {
        item.benchmark_case_id: item for item in execution.input_set.case_inputs
    }
    session_by_key = {
        (item.condition_kind, item.benchmark_case_id): item
        for item in execution.reasoning_sessions
    }
    run_by_key = {
        (item.condition_kind, item.benchmark_case_id): item
        for item in execution.case_run_records_by_condition
    }
    case_diagnostics: list[MaskedSemanticRecoveryCaseDiagnostic] = []
    for case_binding in binding.case_bindings:
        source = source_by_cve.get(case_binding.cve_id)
        if source is None:
            raise MaskedSemanticRecoveryError(
                "frozen case has no authoritative public source record"
            )
        if _source_record_sha256(source) != _FROZEN_SOURCE_RECORD_SHA256_BY_CVE.get(
            source.cve_id
        ):
            raise MaskedSemanticRecoveryError(
                "authoritative evaluator source record differs from frozen bytes"
            )
        case_id = case_binding.benchmark_case_id
        case_input = input_by_case.get(case_id)
        session_binding = session_by_key.get(
            (AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL, case_id)
        )
        wrapped_run = run_by_key.get(
            (AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL, case_id)
        )
        if case_input is None or session_binding is None or wrapped_run is None:
            raise MaskedSemanticRecoveryError(
                "frozen case lacks isolated MASKED input/session/run"
            )
        context = case_input.reasoning_context
        interaction = context.cross_layer_interaction
        if interaction is None or context.id != case_binding.reasoning_context_id:
            raise MaskedSemanticRecoveryError(
                "frozen case lacks its bound documented interaction"
            )
        expected_classification = _CLASSIFICATION_BY_TYPE[interaction.interaction_type]
        if source.cross_layer_classification is not expected_classification:
            raise MaskedSemanticRecoveryError(
                "public source classification and typed interaction disagree"
            )
        visible_summary = _validate_source_projection_boundary(
            source, case_binding
        )

        session = session_binding.reasoning_session
        hypothesis, reasoning_result, diagnostic_text = (
            extract_attack_chain_diagnostic_text(session)
        )
        claim = hypothesis.model_authored_chain_claim
        run = wrapped_run.case_run_record
        if (
            run.disposition is not BenchmarkCaseRunDisposition.CANDIDATE
            or run.candidate_bundle is None
            or wrapped_run.reasoning_session_binding_id != session_binding.id
        ):
            raise MaskedSemanticRecoveryError(
                "MASKED diagnostic requires its exact candidate/session binding"
            )
        bundle = run.candidate_bundle
        candidate = bundle.candidate
        claim_binding = bundle.claim_binding
        feasibility = bundle.feasibility
        if (
            candidate.reasoning_session_id != session.session_id
            or candidate.reasoning_context_id != context.id
            or candidate.cross_layer_interaction_id != interaction.id
            or candidate.model_authored_chain_claim != claim
            or claim_binding.model_authored_chain_claim_id
            != (claim.id if claim is not None else None)
            or claim_binding.candidate_interaction_id != interaction.id
        ):
            raise MaskedSemanticRecoveryError(
                "MASKED candidate, claim, context, and interaction are crosswired"
            )

        digests, content, held_out = _coverage_models(
            source=source,
            visible_summary=visible_summary,
            diagnostic_text=diagnostic_text,
        )
        result_id = reasoning_result.id if reasoning_result is not None else None
        values: dict[str, object] = {
            "cve_id": source.cve_id,
            "benchmark_case_id": case_id,
            "reasoning_context_id": context.id,
            "masked_reasoning_session_id": session.session_id,
            "attack_chain_hypothesis_id": hypothesis.id,
            "model_authored_chain_claim_id": claim.id if claim is not None else None,
            "attack_chain_reasoning_result_id": result_id,
            "attack_chain_reasoning_steps_available": reasoning_result is not None,
            "diagnostic_text_source": (
                SemanticDiagnosticTextSource.ATTACK_CHAIN_HYPOTHESIS_AND_REASONING_STEPS
                if reasoning_result is not None
                else (
                    SemanticDiagnosticTextSource
                    .ATTACK_CHAIN_HYPOTHESIS_DESCRIPTION_ONLY
                )
            ),
            "knowledge_entry_id": case_binding.knowledge_entry_id,
            "expected_interaction_type": interaction.interaction_type,
            "claimed_interaction_type": (
                claim.interaction_type if claim is not None else None
            ),
            "interaction_type_recovery_status": interaction_type_recovery_status(
                expected=interaction.interaction_type,
                claim=claim,
            ),
            "exact_binding_assessment_id": claim_binding.id,
            "exact_binding_status": claim_binding.status,
            "exact_binding_reason_codes": claim_binding.reason_codes,
            "participant_grounding_diagnostic": participant_grounding_diagnostic(
                binding_status=claim_binding.status,
                binding_reasons=claim_binding.reason_codes,
                interaction=interaction,
                claim=claim,
                visible_knowledge_entry_id=case_binding.knowledge_entry_id,
                hidden_reference_ids=masked_chain_hidden_reference_ids(context),
            ),
            "trigger_reference_digest": digests[
                SemanticReferenceField.TRIGGER_SUMMARY
            ],
            "precondition_reference_digest": digests[
                SemanticReferenceField.PRECONDITION_SUMMARY
            ],
            "hardware_effect_reference_digest": digests[
                SemanticReferenceField.HARDWARE_EFFECT_SUMMARY
            ],
            "trigger_content_coverage": content[
                SemanticReferenceField.TRIGGER_SUMMARY
            ],
            "precondition_content_coverage": content[
                SemanticReferenceField.PRECONDITION_SUMMARY
            ],
            "hardware_effect_content_coverage": content[
                SemanticReferenceField.HARDWARE_EFFECT_SUMMARY
            ],
            "trigger_held_out_coverage": held_out[
                SemanticReferenceField.TRIGGER_SUMMARY
            ],
            "precondition_held_out_coverage": held_out[
                SemanticReferenceField.PRECONDITION_SUMMARY
            ],
            "hardware_effect_held_out_coverage": held_out[
                SemanticReferenceField.HARDWARE_EFFECT_SUMMARY
            ],
            "objective_feasibility_status": feasibility.status,
            "objective_feasibility_assessment_id": feasibility.id,
        }
        case_diagnostics.append(
            MaskedSemanticRecoveryCaseDiagnostic.create(**values)
        )

    if {item.cve_id for item in case_diagnostics} != set(
        PHASE10D_PUBLIC_SECONDARY_CVE_IDS
    ):
        raise MaskedSemanticRecoveryError(
            "semantic diagnostic must contain the frozen five-CVE cohort"
        )
    return MaskedSemanticRecoveryDiagnosticArtifact.create(
        diagnostic_mode=SemanticDiagnosticMode.RETROSPECTIVE_DIAGNOSTIC,
        prospective_metric_eligible=False,
        source_archive_id=archive_snapshot.id,
        source_archive_sha256=source_archive_sha256,
        experiment_plan_id=execution.experiment_plan_id,
        benchmark_manifest_id=execution.benchmark_manifest.id,
        public_knowledge_binding_id=binding.id,
        source_corpus_id=binding.source_corpus_id,
        case_diagnostics=case_diagnostics,
    )


def build_masked_semantic_recovery_diagnostic_from_files(
    *,
    source_archive_path: str | Path,
    public_source_path: str | Path,
) -> MaskedSemanticRecoveryDiagnosticArtifact:
    """Read each immutable local input once, validate, and materialize it."""

    archive_bytes = Path(source_archive_path).read_bytes()
    source_bytes = Path(public_source_path).read_bytes()
    archive_sha256 = hashlib.sha256(archive_bytes).hexdigest()
    archive = PublicKnowledgeExecutionArchive.model_validate_json(archive_bytes)
    source = PublicCveSourceDocument.model_validate_json(source_bytes)
    return materialize_masked_semantic_recovery_diagnostic(
        archive=archive,
        source_archive_sha256=archive_sha256,
        public_source=source,
    )


def serialize_masked_semantic_recovery_diagnostic(
    artifact: MaskedSemanticRecoveryDiagnosticArtifact,
) -> bytes:
    """Produce canonical, reviewable deterministic artifact bytes."""

    snapshot = MaskedSemanticRecoveryDiagnosticArtifact.model_validate(
        artifact.model_dump(mode="json")
    )
    return (
        json.dumps(
            snapshot.model_dump(mode="json"),
            ensure_ascii=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def write_masked_semantic_recovery_diagnostic(
    artifact: MaskedSemanticRecoveryDiagnosticArtifact,
    path: str | Path,
) -> None:
    """Write deterministic diagnostic bytes without transport side effects."""

    Path(path).write_bytes(serialize_masked_semantic_recovery_diagnostic(artifact))
