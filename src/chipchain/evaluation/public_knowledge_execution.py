"""Offline construction and fail-closed preflight for public execution."""

from __future__ import annotations

from chipchain.corpus.models import PublicCveCorpus
from chipchain.evaluation.ablation import PromptVisibilityAuditor
from chipchain.evaluation.enums import PromptVisibilityAuditStatus
from chipchain.evaluation.execution_models import RealExperimentInputSet
from chipchain.evaluation.experiment_models import (
    RealModelExperimentPlan,
    structured_prompt_request_sha256,
)
from chipchain.evaluation.models import BenchmarkManifest
from chipchain.evaluation.public_knowledge_execution_models import (
    PHASE10D_PUBLIC_CVE_CORPUS_ID,
    PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_BINDING_CONTRACT,
    PHASE10D_STEP8B1A_FROZEN_COHORT_ID,
    PHASE10D_STEP8B1B_FROZEN_READINESS_ID,
    PublicKnowledgeExecutionBinding,
    PublicKnowledgeExecutionCaseBinding,
    PublicKnowledgeExpectedPromptRecord,
    public_knowledge_execution_binding_id,
    public_knowledge_execution_case_binding_id,
)
from chipchain.evaluation.public_knowledge_readiness import (
    PublicKnowledgeLeakageAuditor,
)
from chipchain.evaluation.public_knowledge_readiness_models import (
    PublicKnowledgeLeakageAuditStatus,
    PublicKnowledgeReadinessArtifact,
)
from chipchain.evaluation.public_secondary_models import (
    PublicPromptReadinessResult,
    PublicSecondaryCohort,
)
from chipchain.reasoning.enums import ReasoningPromptVisibility
from chipchain.reasoning.knowledge_projection import (
    PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT,
    KnowledgeContentProjection,
)
from chipchain.reasoning.prompt_view import masked_chain_hidden_reference_ids
from chipchain.reasoning.prompts import RoleBasedReasoningPromptBuilder


class PublicKnowledgeExecutionPreflightError(ValueError):
    """Fail-closed local public-execution coherence error."""


def materialize_public_knowledge_execution_binding(
    *,
    experiment_plan: RealModelExperimentPlan,
    frozen_cohort: PublicSecondaryCohort,
    readiness_artifact: PublicKnowledgeReadinessArtifact,
    corpus: PublicCveCorpus,
    input_set: RealExperimentInputSet,
) -> PublicKnowledgeExecutionBinding:
    """Reconstruct exact local projections and bind all forty frozen hashes."""

    plan = RealModelExperimentPlan.model_validate(
        experiment_plan.model_dump(mode="json")
    )
    cohort = PublicSecondaryCohort.model_validate(
        frozen_cohort.model_dump(mode="json")
    )
    readiness = PublicKnowledgeReadinessArtifact.model_validate(
        readiness_artifact.model_dump(mode="json")
    )
    corpus_snapshot = PublicCveCorpus.model_validate(corpus.model_dump(mode="json"))
    inputs = RealExperimentInputSet.model_validate(input_set.model_dump(mode="json"))
    if cohort.id != PHASE10D_STEP8B1A_FROZEN_COHORT_ID:
        raise PublicKnowledgeExecutionPreflightError(
            "public execution requires frozen Step 8B-1A cohort"
        )
    if readiness.id != PHASE10D_STEP8B1B_FROZEN_READINESS_ID:
        raise PublicKnowledgeExecutionPreflightError(
            "public execution requires frozen Step 8B-1B readiness"
        )
    if readiness.readiness_result is not (
        PublicPromptReadinessResult.READY_FOR_PUBLIC_PROVIDER
    ):
        raise PublicKnowledgeExecutionPreflightError(
            "public knowledge readiness is not READY_FOR_PUBLIC_PROVIDER"
        )
    if corpus_snapshot.id != PHASE10D_PUBLIC_CVE_CORPUS_ID:
        raise PublicKnowledgeExecutionPreflightError(
            "public execution requires frozen generated corpus"
        )
    if (
        cohort.source_corpus_id,
        readiness.source_corpus_id,
    ) != (corpus_snapshot.id, corpus_snapshot.id):
        raise PublicKnowledgeExecutionPreflightError(
            "public execution corpus provenance mismatch"
        )
    if (
        plan.benchmark_manifest_id != cohort.benchmark_manifest.id
        or set(plan.case_ids)
        != {item.id for item in cohort.benchmark_manifest.cases}
    ):
        raise PublicKnowledgeExecutionPreflightError(
            "public execution plan does not bind frozen manifest"
        )
    if inputs.experiment_plan_id != plan.id or {
        item.benchmark_case_id for item in inputs.case_inputs
    } != set(plan.case_ids):
        raise PublicKnowledgeExecutionPreflightError(
            "public execution input set does not bind plan cohort"
        )
    if inputs.metadata:
        raise PublicKnowledgeExecutionPreflightError(
            "public execution input-set metadata must be empty"
        )

    input_by_case = {item.benchmark_case_id: item for item in inputs.case_inputs}
    readiness_by_cve = {item.cve_id: item for item in readiness.case_readiness}
    entry_by_id = {item.id: item for item in corpus_snapshot.knowledge_entries}
    case_bindings: list[PublicKnowledgeExecutionCaseBinding] = []
    for materialized in cohort.case_materializations:
        case_input = input_by_case[materialized.benchmark_case_id]
        if (
            case_input.reasoning_context != materialized.reasoning_context
            or case_input.triggerability is not None
            or case_input.objective_materialization is not None
            or case_input.metadata
        ):
            raise PublicKnowledgeExecutionPreflightError(
                "public execution case input differs from frozen candidate context"
            )
        try:
            entry = entry_by_id[materialized.knowledge_entry_id]
            ready = readiness_by_cve[materialized.cve_id]
        except KeyError as exc:
            raise PublicKnowledgeExecutionPreflightError(
                "public execution case lacks exact local knowledge source"
            ) from exc
        projection = KnowledgeContentProjection.create(
            case_input.reasoning_context,
            [entry],
        )
        if projection.id != ready.knowledge_projection_id:
            raise PublicKnowledgeExecutionPreflightError(
                "reconstructed public projection differs from frozen readiness"
            )
        records = [
            PublicKnowledgeExpectedPromptRecord.create(
                visibility=item.visibility,
                role=item.role,
                expected_prompt_sha256=item.prompt_sha256,
                expected_visibility_audit_id=(
                    item.visibility_audit.id
                    if item.visibility_audit is not None
                    else None
                ),
                expected_leakage_audit_id=item.leakage_audit.id,
            )
            for item in ready.prompt_assessments
        ]
        values = {
            "cve_id": materialized.cve_id,
            "benchmark_case_id": materialized.benchmark_case_id,
            "reasoning_context_id": case_input.reasoning_context.id,
            "knowledge_entry_id": entry.id,
            "knowledge_projection_id": projection.id,
            "expected_prompt_record_ids": [item.id for item in records],
        }
        case_bindings.append(
            PublicKnowledgeExecutionCaseBinding(
                id=public_knowledge_execution_case_binding_id(**values),
                cve_id=materialized.cve_id,
                benchmark_case_id=materialized.benchmark_case_id,
                reasoning_context_id=case_input.reasoning_context.id,
                knowledge_entry_id=entry.id,
                knowledge_projection=projection,
                expected_prompt_records=records,
            )
        )
    identity_values = {
        "contract": PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_BINDING_CONTRACT,
        "experiment_plan_id": plan.id,
        "benchmark_manifest_id": cohort.benchmark_manifest.id,
        "real_experiment_input_set_id": inputs.id,
        "public_secondary_cohort_id": cohort.id,
        "public_knowledge_readiness_artifact_id": readiness.id,
        "source_corpus_id": corpus_snapshot.id,
        "knowledge_projection_contract": (
            PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT
        ),
        "case_binding_ids": [item.id for item in case_bindings],
    }
    return PublicKnowledgeExecutionBinding(
        id=public_knowledge_execution_binding_id(**identity_values),
        experiment_plan_id=plan.id,
        benchmark_manifest_id=cohort.benchmark_manifest.id,
        real_experiment_input_set_id=inputs.id,
        public_secondary_cohort_id=cohort.id,
        public_knowledge_readiness_artifact=readiness,
        source_corpus_id=corpus_snapshot.id,
        case_bindings=case_bindings,
    )


class PublicKnowledgeRealExecutionPreflight:
    """Rebuild and audit every public prompt without constructing a provider."""

    @staticmethod
    def validate(
        *,
        experiment_plan: RealModelExperimentPlan,
        manifest: BenchmarkManifest,
        input_set: RealExperimentInputSet,
        binding: PublicKnowledgeExecutionBinding,
    ) -> PublicKnowledgeExecutionBinding:
        plan = RealModelExperimentPlan.model_validate(
            experiment_plan.model_dump(mode="json")
        )
        manifest_snapshot = BenchmarkManifest.model_validate(
            manifest.model_dump(mode="json")
        )
        inputs = RealExperimentInputSet.model_validate(
            input_set.model_dump(mode="json")
        )
        bound = PublicKnowledgeExecutionBinding.model_validate(
            binding.model_dump(mode="json")
        )
        if (
            bound.experiment_plan_id,
            bound.benchmark_manifest_id,
            bound.real_experiment_input_set_id,
        ) != (plan.id, manifest_snapshot.id, inputs.id):
            raise PublicKnowledgeExecutionPreflightError(
                "public execution plan/manifest/input binding mismatch"
            )
        if set(plan.case_ids) != {
            item.id for item in manifest_snapshot.cases
        } or set(plan.case_ids) != {
            item.benchmark_case_id for item in bound.case_bindings
        }:
            raise PublicKnowledgeExecutionPreflightError(
                "public execution case cohort mismatch"
            )
        input_by_case = {
            item.benchmark_case_id: item for item in inputs.case_inputs
        }
        builder = RoleBasedReasoningPromptBuilder()
        prompt_count = 0
        for case_binding in bound.case_bindings:
            case_input = input_by_case[case_binding.benchmark_case_id]
            if (
                case_input.reasoning_context.id
                != case_binding.reasoning_context_id
                or case_input.reasoning_context
                != next(
                    item.reasoning_context
                    for item in inputs.case_inputs
                    if item.benchmark_case_id == case_binding.benchmark_case_id
                )
            ):
                raise PublicKnowledgeExecutionPreflightError(
                    "public execution reasoning context mismatch"
                )
            for expected in case_binding.expected_prompt_records:
                prompt = builder.build_with_knowledge_projection(
                    case_input.reasoning_context,
                    role=expected.role,
                    visibility=expected.visibility,
                    knowledge_projection=case_binding.knowledge_projection,
                )
                leakage = PublicKnowledgeLeakageAuditor.audit(
                    prompt,
                    forbidden_exact_values=[],
                )
                if (
                    leakage.status is not PublicKnowledgeLeakageAuditStatus.PASS
                    or leakage.id != expected.expected_leakage_audit_id
                ):
                    raise PublicKnowledgeExecutionPreflightError(
                        "public prompt structured leakage audit failed"
                    )
                if (
                    structured_prompt_request_sha256(prompt)
                    != expected.expected_prompt_sha256
                ):
                    raise PublicKnowledgeExecutionPreflightError(
                        "public projected prompt hash differs from frozen readiness"
                    )
                if expected.visibility is (
                    ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
                ):
                    visibility_audit = PromptVisibilityAuditor.audit(
                        prompt,
                        hidden_reference_ids=masked_chain_hidden_reference_ids(
                            case_input.reasoning_context
                        ),
                    )
                    if (
                        visibility_audit.status
                        is not PromptVisibilityAuditStatus.PASS
                        or visibility_audit.id
                        != expected.expected_visibility_audit_id
                    ):
                        raise PublicKnowledgeExecutionPreflightError(
                            "public MASKED prompt visibility audit failed"
                        )
                prompt_count += 1
        if prompt_count != 40:
            raise PublicKnowledgeExecutionPreflightError(
                "public execution preflight requires exactly 40 prompts"
            )
        return bound
