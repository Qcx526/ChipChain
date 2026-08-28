"""Pure offline materialization for public-documented SECONDARY cases."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from chipchain.agents.base import ReasoningContext
from chipchain.corpus import (
    ArmArchitectureProfile,
    CrossLayerResearchClassification,
    PublicCveCorpus,
    PublicCveSourceDocument,
    PublicCveSourceRecord,
    build_public_cve_corpus,
)
from chipchain.evaluation.ablation import PromptVisibilityAuditor
from chipchain.evaluation.enums import (
    BenchmarkCaseLabel,
    BenchmarkSourceKind,
    EvaluationScope,
)
from chipchain.evaluation.experiment_models import (
    PHASE10D_PROVIDER_ROLE_ORDER,
    structured_prompt_request_sha256,
)
from chipchain.evaluation.models import (
    BenchmarkArtifactReference,
    BenchmarkManifest,
    EvaluationBenchmarkCase,
    GroundTruthChain,
)
from chipchain.evaluation.public_secondary_models import (
    PUBLIC_SECONDARY_BENCHMARK_VERSION,
    PublicPromptContentAssessment,
    PublicSecondaryCaseMaterialization,
    PublicSecondaryCohort,
    PublicSecondarySelectionDocument,
)
from chipchain.models import Architecture
from chipchain.models.cross_layer import (
    CrossLayerInteraction,
    CrossLayerInteractionType,
)
from chipchain.models.enums import Layer
from chipchain.reasoning.enums import ReasoningPromptVisibility
from chipchain.reasoning.prompt_view import masked_chain_hidden_reference_ids
from chipchain.reasoning.prompts import RoleBasedReasoningPromptBuilder


_INTERACTION_TYPE_BY_CLASSIFICATION = {
    CrossLayerResearchClassification.TYPE_I_CANDIDATE: (
        CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
    ),
    CrossLayerResearchClassification.TYPE_II_CANDIDATE: (
        CrossLayerInteractionType.FIRMWARE_BEHAVIOR_TO_HARDWARE
    ),
}
_SOURCE_RECORD_REFERENCE = (
    "data/public_cve/source/arm_cross_layer_seed_v1.source.json"
)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def public_cve_source_record_sha256(record: PublicCveSourceRecord) -> str:
    """Hash the canonical validated JSON for exactly one source record."""

    snapshot = PublicCveSourceRecord.model_validate(
        record.model_dump(mode="json")
    )
    return hashlib.sha256(
        _canonical_json_bytes(snapshot.model_dump(mode="json"))
    ).hexdigest()


def public_cve_source_artifact_id(cve_id: str) -> str:
    """Derive a path-neutral source-record artifact identity from CVE ID."""

    digest = hashlib.sha256(
        _canonical_json_bytes(
            {
                "contract": "public_cve_source_record_artifact_v1",
                "cve_id": cve_id.strip(),
            }
        )
    ).hexdigest()
    return f"public-cve-source-record:{digest}"


def public_documented_participant_id(cve_id: str, semantic_role: str) -> str:
    """Return an opaque collision-safe participant reference."""

    digest = hashlib.sha256(
        _canonical_json_bytes(
            {
                "contract": "public_documented_participant_v1",
                "cve_id": cve_id.strip(),
                "semantic_role": semantic_role.strip(),
            }
        )
    ).hexdigest()
    return f"public-documented-participant:{digest}"


def _documented_interaction(
    record: PublicCveSourceRecord,
    *,
    source_layer: Layer,
) -> CrossLayerInteraction:
    try:
        interaction_type = _INTERACTION_TYPE_BY_CLASSIFICATION[
            record.cross_layer_classification
        ]
    except KeyError as exc:
        raise ValueError(
            "selected public CVE lacks a supported Type I/II classification"
        ) from exc
    values: dict[str, list[str]] = {
        "target_vulnerability_ids": [
            public_documented_participant_id(record.cve_id, "target")
        ],
        "trigger_behavior_ids": [
            public_documented_participant_id(record.cve_id, "trigger")
        ],
    }
    if (
        interaction_type
        is CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
    ):
        values["initiating_vulnerability_ids"] = [
            public_documented_participant_id(record.cve_id, "initiating")
        ]
    return CrossLayerInteraction.create(
        architecture=Architecture.ARM,
        interaction_type=interaction_type,
        source_layer=source_layer,
        target_layer=Layer.HARDWARE,
        metadata={},
        **values,
    )


def _prompt_assessments(
    *,
    record: PublicCveSourceRecord,
    context: ReasoningContext,
    knowledge_entry_id: str,
) -> list[PublicPromptContentAssessment]:
    builder = RoleBasedReasoningPromptBuilder()
    hidden = masked_chain_hidden_reference_ids(context)
    descriptive_values = (
        record.summary,
        record.trigger_summary,
        record.precondition_summary,
        record.hardware_effect_summary,
    )
    assessments: list[PublicPromptContentAssessment] = []
    for visibility in (
        ReasoningPromptVisibility.FULL_CONTEXT,
        ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
    ):
        for role in PHASE10D_PROVIDER_ROLE_ORDER:
            prompt = builder.build(
                context,
                role=role,
                visibility=visibility,
            )
            prompt_sha256 = structured_prompt_request_sha256(prompt)
            serialized_payload = prompt.system_prompt + "\n" + prompt.user_prompt
            audit = None
            if visibility is ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT:
                audit = PromptVisibilityAuditor.audit(
                    prompt,
                    hidden_reference_ids=hidden,
                )
            assessments.append(
                PublicPromptContentAssessment.create(
                    cve_id=record.cve_id,
                    reasoning_context_id=context.id,
                    role=role,
                    visibility=visibility,
                    prompt_sha256=prompt_sha256,
                    visibility_audit=audit,
                    cve_id_visible=record.cve_id in serialized_payload,
                    affected_components_visible=all(
                        item in serialized_payload
                        for item in record.affected_components
                    ),
                    knowledge_entry_reference_visible=(
                        knowledge_entry_id in serialized_payload
                    ),
                    public_source_references_visible=all(
                        item in serialized_payload
                        for item in record.source_references
                    ),
                    descriptive_public_content_visible=any(
                        item in serialized_payload for item in descriptive_values
                    ),
                )
            )
    return assessments


def materialize_public_secondary_cohort(
    *,
    source: PublicCveSourceDocument,
    corpus: PublicCveCorpus,
    selection: PublicSecondarySelectionDocument,
) -> PublicSecondaryCohort:
    """Build cases and hash-only prompt audits from local validated inputs."""

    source_snapshot = PublicCveSourceDocument.model_validate(
        source.model_dump(mode="json")
    )
    corpus_snapshot = PublicCveCorpus.model_validate(
        corpus.model_dump(mode="json")
    )
    selection_snapshot = PublicSecondarySelectionDocument.model_validate(
        selection.model_dump(mode="json")
    )
    if build_public_cve_corpus(source_snapshot) != corpus_snapshot:
        raise ValueError(
            "public secondary materialization requires the exact generated corpus"
        )
    source_by_cve = {item.cve_id: item for item in source_snapshot.records}
    sample_by_cve = {item.cve_id: item for item in corpus_snapshot.records}
    entry_by_external_id = {
        item.external_id: item for item in corpus_snapshot.knowledge_entries
    }

    benchmark_cases: list[EvaluationBenchmarkCase] = []
    materialized_cases: list[PublicSecondaryCaseMaterialization] = []
    for selected in selection_snapshot.records:
        try:
            source_record = source_by_cve[selected.cve_id]
            sample = sample_by_cve[selected.cve_id]
            entry = entry_by_external_id[selected.cve_id]
        except KeyError as exc:
            raise ValueError(
                "selected public CVE is absent from source/corpus"
            ) from exc
        if source_record.architecture_profile is not ArmArchitectureProfile.A_PROFILE:
            raise ValueError("public secondary cohort is limited to ARM A-profile")
        if sample.knowledge_entry_id != entry.id:
            raise ValueError("public secondary knowledge binding mismatch")

        interaction = _documented_interaction(
            source_record,
            source_layer=selected.software_source_layer,
        )
        source_hash = public_cve_source_record_sha256(source_record)
        artifact = BenchmarkArtifactReference(
            artifact_id=public_cve_source_artifact_id(source_record.cve_id),
            architecture=Architecture.ARM,
            artifact_type="public_cve_source_record",
            artifact_sha256=source_hash,
            artifact_reference=(
                f"{_SOURCE_RECORD_REFERENCE}#record={source_record.cve_id}"
            ),
        )
        truth = GroundTruthChain.create(
            cross_layer_interaction=interaction,
            hardware_trigger_signature_id=None,
            expected_attack_pattern_reference=None,
            source_reference_ids=source_record.source_references,
            metadata={
                "metric_scope": "secondary_only",
                "truth_basis": "public_documentation",
            },
        )
        benchmark_case = EvaluationBenchmarkCase.create(
            benchmark_version=PUBLIC_SECONDARY_BENCHMARK_VERSION,
            architecture=Architecture.ARM,
            source_kind=BenchmarkSourceKind.PUBLIC_DOCUMENTED,
            label=BenchmarkCaseLabel.POSITIVE_FEASIBLE,
            artifact=artifact,
            ground_truth_chains=[truth],
            source_reference_ids=source_record.source_references,
            evaluation_scope=EvaluationScope.SECONDARY_ONLY,
            metadata={},
        )
        context = ReasoningContext.create(
            architecture=Architecture.ARM,
            subject_id=source_record.cve_id,
            affected_components=source_record.affected_components,
            knowledge_entry_ids=[entry.id],
            cross_layer_interaction=interaction,
            runtime_observations=[],
            dynamic_trigger_fact_reference=None,
            attack_pattern_reference=None,
            metadata={},
        )
        assessments = _prompt_assessments(
            record=source_record,
            context=context,
            knowledge_entry_id=entry.id,
        )
        benchmark_cases.append(benchmark_case)
        materialized_cases.append(
            PublicSecondaryCaseMaterialization.create(
                cve_id=source_record.cve_id,
                source_record_sha256=source_hash,
                benchmark_case_id=benchmark_case.id,
                documented_interaction=interaction,
                reasoning_context=context,
                knowledge_entry_id=entry.id,
                prompt_assessments=assessments,
            )
        )

    manifest = BenchmarkManifest.create(
        benchmark_version=PUBLIC_SECONDARY_BENCHMARK_VERSION,
        architecture_scope=[Architecture.ARM],
        cases=benchmark_cases,
        metadata={},
    )
    return PublicSecondaryCohort.create(
        cohort_name=selection_snapshot.cohort_name,
        source_corpus_id=corpus_snapshot.id,
        benchmark_manifest=manifest,
        case_materializations=materialized_cases,
    )


def serialize_public_secondary_cohort(cohort: PublicSecondaryCohort) -> str:
    """Return deterministic UTF-8-ready JSON with one final newline."""

    snapshot = PublicSecondaryCohort.model_validate(
        cohort.model_dump(mode="json")
    )
    return snapshot.model_dump_json(indent=2, ensure_ascii=False) + "\n"


def load_public_secondary_selection(
    path: str | Path,
) -> PublicSecondarySelectionDocument:
    """Load one local selection document without external resolution."""

    return PublicSecondarySelectionDocument.model_validate_json(
        Path(path).read_text(encoding="utf-8")
    )


def load_public_secondary_cohort(path: str | Path) -> PublicSecondaryCohort:
    """Load and validate one generated public cohort artifact."""

    return PublicSecondaryCohort.model_validate_json(
        Path(path).read_text(encoding="utf-8")
    )


def write_public_secondary_cohort(
    cohort: PublicSecondaryCohort,
    path: str | Path,
) -> None:
    """Write one deterministic generated cohort without external state."""

    Path(path).write_text(
        serialize_public_secondary_cohort(cohort),
        encoding="utf-8",
    )
