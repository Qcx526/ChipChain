"""Offline public-documented SECONDARY cohort contracts."""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.agents.base import ReasoningContext
from chipchain.evaluation.ablation_models import PromptVisibilityAudit
from chipchain.evaluation.enums import (
    BenchmarkCaseLabel,
    BenchmarkSourceKind,
    EvaluationScope,
    PromptVisibilityAuditStatus,
)
from chipchain.evaluation.experiment_models import PHASE10D_PROVIDER_ROLE_ORDER
from chipchain.evaluation.models import BenchmarkManifest
from chipchain.models.common import DomainModel, Identifier
from chipchain.models.cross_layer import (
    CrossLayerInteraction,
    CrossLayerInteractionType,
)
from chipchain.models.enums import Layer
from chipchain.reasoning.enums import (
    ReasoningAgentType,
    ReasoningPromptVisibility,
)


PUBLIC_SECONDARY_SELECTION_CONTRACT = (
    "phase10d_public_secondary_selection_v1"
)
PUBLIC_SECONDARY_COHORT_CONTRACT = (
    "phase10d_public_documented_secondary_cohort_v1"
)
PUBLIC_SECONDARY_BENCHMARK_VERSION = (
    "phase10d_public_documented_arm_secondary_v1"
)

_CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SOFTWARE_SOURCE_LAYERS = frozenset({Layer.DRIVER, Layer.INTERFACE})
_PROMPT_VISIBILITIES = (
    ReasoningPromptVisibility.FULL_CONTEXT,
    ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
)


def _canonical_hash(prefix: str, payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(encoded).hexdigest()}"


class PublicSecondarySelectionRecord(DomainModel):
    """One human evaluation choice with no duplicated CVE facts."""

    cve_id: Identifier
    software_source_layer: Layer

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, value: str) -> str:
        if not _CVE_ID.fullmatch(value):
            raise ValueError("public secondary selection requires a canonical CVE ID")
        return value

    @field_validator("software_source_layer")
    @classmethod
    def validate_source_layer(cls, value: Layer) -> Layer:
        if value not in _SOFTWARE_SOURCE_LAYERS:
            raise ValueError(
                "public secondary source layer must be interface or driver"
            )
        return value


class PublicSecondarySelectionDocument(DomainModel):
    """Human-maintained selection only; all technical facts remain elsewhere."""

    contract: Literal[PUBLIC_SECONDARY_SELECTION_CONTRACT] = (
        PUBLIC_SECONDARY_SELECTION_CONTRACT
    )
    cohort_name: Identifier
    records: list[PublicSecondarySelectionRecord] = Field(min_length=1)

    @field_validator("records")
    @classmethod
    def normalize_records(
        cls, values: list[PublicSecondarySelectionRecord]
    ) -> list[PublicSecondarySelectionRecord]:
        if len(values) != len({item.cve_id for item in values}):
            raise ValueError("public secondary selection CVE IDs must be unique")
        return sorted(values, key=lambda item: item.cve_id)


class PublicPromptReadinessResult(str, Enum):
    """Closed gate for later public-provider execution preparation."""

    READY_FOR_PUBLIC_PROVIDER = "ready_for_public_provider"
    REFERENCE_CONTENT_INSUFFICIENT = "reference_content_insufficient"


def public_prompt_content_assessment_id(
    *,
    cve_id: str,
    reasoning_context_id: str,
    role: ReasoningAgentType,
    visibility: ReasoningPromptVisibility,
    prompt_sha256: str,
    visibility_audit_id: str | None,
    cve_id_visible: bool,
    affected_components_visible: bool,
    knowledge_entry_reference_visible: bool,
    public_source_references_visible: bool,
    descriptive_public_content_visible: bool,
) -> str:
    """Bind one readiness observation to exact provider-visible prompt bytes."""

    return _canonical_hash(
        "public-prompt-content-assessment",
        {
            "affected_components_visible": affected_components_visible,
            "cve_id": cve_id,
            "cve_id_visible": cve_id_visible,
            "descriptive_public_content_visible": (
                descriptive_public_content_visible
            ),
            "knowledge_entry_reference_visible": (
                knowledge_entry_reference_visible
            ),
            "prompt_sha256": prompt_sha256,
            "public_source_references_visible": (
                public_source_references_visible
            ),
            "reasoning_context_id": reasoning_context_id,
            "role": role.value,
            "visibility": visibility.value,
            "visibility_audit_id": visibility_audit_id,
        },
    )


class PublicPromptContentAssessment(DomainModel):
    """Hash-only observation of content in one serialized prompt payload."""

    id: Identifier
    cve_id: Identifier
    reasoning_context_id: Identifier
    role: ReasoningAgentType
    visibility: ReasoningPromptVisibility
    prompt_sha256: Identifier
    visibility_audit: PromptVisibilityAudit | None = None
    cve_id_visible: bool
    affected_components_visible: bool
    knowledge_entry_reference_visible: bool
    public_source_references_visible: bool
    descriptive_public_content_visible: bool

    @field_validator("prompt_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("public prompt hash must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def validate_audit_and_identity(self) -> "PublicPromptContentAssessment":
        audit_id: str | None = None
        if self.visibility is ReasoningPromptVisibility.FULL_CONTEXT:
            if self.visibility_audit is not None:
                raise ValueError("FULL public prompt must not carry a MASKED audit")
        else:
            if self.visibility_audit is None:
                raise ValueError("MASKED public prompt requires its exact audit")
            if (
                self.visibility_audit.prompt_sha256 != self.prompt_sha256
                or self.visibility_audit.status
                is not PromptVisibilityAuditStatus.PASS
                or self.visibility_audit.leaked_reference_ids
                or self.visibility_audit.metadata
            ):
                raise ValueError("MASKED public prompt audit must pass exactly")
            audit_id = self.visibility_audit.id
        expected = public_prompt_content_assessment_id(
            cve_id=self.cve_id,
            reasoning_context_id=self.reasoning_context_id,
            role=self.role,
            visibility=self.visibility,
            prompt_sha256=self.prompt_sha256,
            visibility_audit_id=audit_id,
            cve_id_visible=self.cve_id_visible,
            affected_components_visible=self.affected_components_visible,
            knowledge_entry_reference_visible=(
                self.knowledge_entry_reference_visible
            ),
            public_source_references_visible=(
                self.public_source_references_visible
            ),
            descriptive_public_content_visible=(
                self.descriptive_public_content_visible
            ),
        )
        if self.id != expected:
            raise ValueError("PublicPromptContentAssessment ID is not deterministic")
        return self

    @property
    def public_content_complete(self) -> bool:
        """Apply the provider-readiness gate to one exact prompt payload."""

        return all(
            (
                self.cve_id_visible,
                self.affected_components_visible,
                self.knowledge_entry_reference_visible,
                self.descriptive_public_content_visible,
            )
        )

    @classmethod
    def create(
        cls,
        *,
        cve_id: str,
        reasoning_context_id: str,
        role: ReasoningAgentType | str,
        visibility: ReasoningPromptVisibility | str,
        prompt_sha256: str,
        visibility_audit: PromptVisibilityAudit | None,
        cve_id_visible: bool,
        affected_components_visible: bool,
        knowledge_entry_reference_visible: bool,
        public_source_references_visible: bool,
        descriptive_public_content_visible: bool,
    ) -> "PublicPromptContentAssessment":
        normalized_role = ReasoningAgentType(role)
        normalized_visibility = ReasoningPromptVisibility(visibility)
        audit = (
            PromptVisibilityAudit.model_validate(
                visibility_audit.model_dump(mode="json")
            )
            if visibility_audit is not None
            else None
        )
        identity = public_prompt_content_assessment_id(
            cve_id=cve_id,
            reasoning_context_id=reasoning_context_id,
            role=normalized_role,
            visibility=normalized_visibility,
            prompt_sha256=prompt_sha256,
            visibility_audit_id=audit.id if audit is not None else None,
            cve_id_visible=cve_id_visible,
            affected_components_visible=affected_components_visible,
            knowledge_entry_reference_visible=(
                knowledge_entry_reference_visible
            ),
            public_source_references_visible=(
                public_source_references_visible
            ),
            descriptive_public_content_visible=(
                descriptive_public_content_visible
            ),
        )
        return cls(
            id=identity,
            cve_id=cve_id,
            reasoning_context_id=reasoning_context_id,
            role=normalized_role,
            visibility=normalized_visibility,
            prompt_sha256=prompt_sha256,
            visibility_audit=audit,
            cve_id_visible=cve_id_visible,
            affected_components_visible=affected_components_visible,
            knowledge_entry_reference_visible=(
                knowledge_entry_reference_visible
            ),
            public_source_references_visible=(
                public_source_references_visible
            ),
            descriptive_public_content_visible=(
                descriptive_public_content_visible
            ),
        )


def public_secondary_case_materialization_id(
    *,
    cve_id: str,
    source_record_sha256: str,
    benchmark_case_id: str,
    documented_interaction_id: str,
    reasoning_context_id: str,
    knowledge_entry_id: str,
    prompt_assessment_ids: list[str],
) -> str:
    """Build one order-independent public case materialization identity."""

    return _canonical_hash(
        "public-secondary-case-materialization",
        {
            "benchmark_case_id": benchmark_case_id,
            "cve_id": cve_id,
            "documented_interaction_id": documented_interaction_id,
            "knowledge_entry_id": knowledge_entry_id,
            "prompt_assessment_ids": sorted(prompt_assessment_ids),
            "reasoning_context_id": reasoning_context_id,
            "source_record_sha256": source_record_sha256,
        },
    )


class PublicSecondaryCaseMaterialization(DomainModel):
    """One public source-to-context mapping without objective evidence."""

    id: Identifier
    cve_id: Identifier
    source_record_sha256: Identifier
    benchmark_case_id: Identifier
    documented_interaction: CrossLayerInteraction
    reasoning_context: ReasoningContext
    knowledge_entry_id: Identifier
    prompt_assessments: list[PublicPromptContentAssessment]

    @field_validator("cve_id")
    @classmethod
    def validate_cve_id(cls, value: str) -> str:
        if not _CVE_ID.fullmatch(value):
            raise ValueError("public case materialization requires canonical CVE ID")
        return value

    @field_validator("source_record_sha256")
    @classmethod
    def validate_source_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("source record hash must be lowercase SHA-256")
        return value

    @field_validator("prompt_assessments")
    @classmethod
    def normalize_assessments(
        cls, values: list[PublicPromptContentAssessment]
    ) -> list[PublicPromptContentAssessment]:
        keys = {(item.visibility, item.role) for item in values}
        expected = {
            (visibility, role)
            for visibility in _PROMPT_VISIBILITIES
            for role in PHASE10D_PROVIDER_ROLE_ORDER
        }
        if len(values) != len(expected) or keys != expected:
            raise ValueError(
                "public case requires FULL and MASKED assessment for four roles"
            )
        return sorted(
            values,
            key=lambda item: (
                _PROMPT_VISIBILITIES.index(item.visibility),
                PHASE10D_PROVIDER_ROLE_ORDER.index(item.role),
            ),
        )

    @model_validator(mode="after")
    def validate_bindings_and_identity(
        self,
    ) -> "PublicSecondaryCaseMaterialization":
        interaction = self.documented_interaction
        context = self.reasoning_context
        if interaction.metadata or interaction.evidence_ids:
            raise ValueError("public documented interaction must contain no evidence")
        if any(
            (
                interaction.propagation_behavior_ids,
                interaction.affected_execution_ids,
                interaction.fault_state_ids,
                interaction.hardware_resource_ids,
                interaction.security_mechanism_ids,
                interaction.referenced_architectures,
            )
        ):
            raise ValueError("public documented interaction must remain minimal")
        if len(interaction.target_vulnerability_ids) != 1 or len(
            interaction.trigger_behavior_ids
        ) != 1:
            raise ValueError("public documented interaction participants are inexact")
        if (
            interaction.interaction_type
            is CrossLayerInteractionType.FIRMWARE_VULNERABILITY_TO_HARDWARE
        ) != (len(interaction.initiating_vulnerability_ids) == 1):
            raise ValueError("public Type I initiating participant is inexact")
        if (
            context.subject_id != self.cve_id
            or context.cross_layer_interaction != interaction
            or context.knowledge_entry_ids != [self.knowledge_entry_id]
        ):
            raise ValueError("public reasoning context binding mismatch")
        if any(
            (
                context.observed_fact_ids,
                context.available_evidence_ids,
                context.runtime_observations,
            )
        ) or any(
            value is not None
            for value in (
                context.dynamic_trigger_fact_reference,
                context.attack_pattern_reference,
                context.knowledge_retrieval_result,
            )
        ):
            raise ValueError("public reasoning context must not invent evidence")
        if context.metadata:
            raise ValueError("public reasoning context metadata must be empty")
        if any(
            item.cve_id != self.cve_id
            or item.reasoning_context_id != context.id
            for item in self.prompt_assessments
        ):
            raise ValueError("public prompt assessment case binding mismatch")
        expected = public_secondary_case_materialization_id(
            cve_id=self.cve_id,
            source_record_sha256=self.source_record_sha256,
            benchmark_case_id=self.benchmark_case_id,
            documented_interaction_id=interaction.id,
            reasoning_context_id=context.id,
            knowledge_entry_id=self.knowledge_entry_id,
            prompt_assessment_ids=[item.id for item in self.prompt_assessments],
        )
        if self.id != expected:
            raise ValueError(
                "PublicSecondaryCaseMaterialization ID is not deterministic"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        cve_id: str,
        source_record_sha256: str,
        benchmark_case_id: str,
        documented_interaction: CrossLayerInteraction,
        reasoning_context: ReasoningContext,
        knowledge_entry_id: str,
        prompt_assessments: list[PublicPromptContentAssessment],
    ) -> "PublicSecondaryCaseMaterialization":
        interaction = CrossLayerInteraction.model_validate(
            documented_interaction.model_dump(mode="json")
        )
        context = ReasoningContext.model_validate(
            reasoning_context.model_dump(mode="json")
        )
        assessments = [
            PublicPromptContentAssessment.model_validate(
                item.model_dump(mode="json")
            )
            for item in prompt_assessments
        ]
        identity = public_secondary_case_materialization_id(
            cve_id=cve_id,
            source_record_sha256=source_record_sha256,
            benchmark_case_id=benchmark_case_id,
            documented_interaction_id=interaction.id,
            reasoning_context_id=context.id,
            knowledge_entry_id=knowledge_entry_id,
            prompt_assessment_ids=[item.id for item in assessments],
        )
        return cls(
            id=identity,
            cve_id=cve_id,
            source_record_sha256=source_record_sha256,
            benchmark_case_id=benchmark_case_id,
            documented_interaction=interaction,
            reasoning_context=context,
            knowledge_entry_id=knowledge_entry_id,
            prompt_assessments=assessments,
        )


def public_secondary_cohort_id(
    *,
    contract: str,
    cohort_name: str,
    source_corpus_id: str,
    selected_cve_ids: list[str],
    benchmark_manifest_id: str,
    case_materialization_ids: list[str],
    readiness_result: PublicPromptReadinessResult,
) -> str:
    """Build identity for one offline public SECONDARY cohort snapshot."""

    return _canonical_hash(
        "public-secondary-cohort",
        {
            "benchmark_manifest_id": benchmark_manifest_id,
            "case_materialization_ids": sorted(case_materialization_ids),
            "cohort_name": cohort_name,
            "contract": contract,
            "readiness_result": readiness_result.value,
            "selected_cve_ids": sorted(selected_cve_ids),
            "source_corpus_id": source_corpus_id,
        },
    )


class PublicSecondaryCohort(DomainModel):
    """Deterministic hash-only prompt-readiness artifact for public cases."""

    id: Identifier
    contract: Literal[PUBLIC_SECONDARY_COHORT_CONTRACT] = (
        PUBLIC_SECONDARY_COHORT_CONTRACT
    )
    cohort_name: Identifier
    source_corpus_id: Identifier
    selected_cve_ids: list[Identifier] = Field(min_length=1)
    benchmark_manifest: BenchmarkManifest
    case_materializations: list[PublicSecondaryCaseMaterialization] = Field(
        min_length=1
    )
    readiness_result: PublicPromptReadinessResult

    @field_validator("selected_cve_ids")
    @classmethod
    def normalize_cve_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("public secondary selected CVE IDs must be unique")
        if any(not _CVE_ID.fullmatch(item) for item in values):
            raise ValueError("public secondary cohort contains invalid CVE ID")
        return sorted(values)

    @field_validator("case_materializations")
    @classmethod
    def normalize_cases(
        cls, values: list[PublicSecondaryCaseMaterialization]
    ) -> list[PublicSecondaryCaseMaterialization]:
        if len(values) != len({item.cve_id for item in values}) or len(
            values
        ) != len({item.benchmark_case_id for item in values}):
            raise ValueError("public secondary case bindings must be one-to-one")
        return sorted(values, key=lambda item: item.cve_id)

    @model_validator(mode="after")
    def validate_cohort_and_identity(self) -> "PublicSecondaryCohort":
        materialization_by_case = {
            item.benchmark_case_id: item for item in self.case_materializations
        }
        manifest_case_ids = {item.id for item in self.benchmark_manifest.cases}
        if self.selected_cve_ids != [
            item.cve_id for item in self.case_materializations
        ] or manifest_case_ids != set(materialization_by_case):
            raise ValueError("public secondary cohort selection binding mismatch")
        for case in self.benchmark_manifest.cases:
            materialized = materialization_by_case[case.id]
            if (
                case.source_kind is not BenchmarkSourceKind.PUBLIC_DOCUMENTED
                or case.evaluation_scope is not EvaluationScope.SECONDARY_ONLY
                or case.label is not BenchmarkCaseLabel.POSITIVE_FEASIBLE
                or len(case.ground_truth_chains) != 1
                or case.metadata
                or case.artifact.artifact_type != "public_cve_source_record"
                or case.artifact.artifact_sha256
                != materialized.source_record_sha256
                or not case.artifact.artifact_reference.endswith(
                    f"#record={materialized.cve_id}"
                )
            ):
                raise ValueError("public cohort benchmark case semantics are invalid")
            truth = case.ground_truth_chains[0]
            if (
                truth.cross_layer_interaction
                != materialized.documented_interaction
                or truth.hardware_trigger_signature_id is not None
                or truth.expected_attack_pattern_reference is not None
                or truth.source_reference_ids != case.source_reference_ids
                or truth.metadata
                != {
                    "metric_scope": "secondary_only",
                    "truth_basis": "public_documentation",
                }
            ):
                raise ValueError("public cohort Ground Truth semantics are invalid")
        derived_readiness = (
            PublicPromptReadinessResult.READY_FOR_PUBLIC_PROVIDER
            if all(
                assessment.public_content_complete
                for item in self.case_materializations
                for assessment in item.prompt_assessments
            )
            else PublicPromptReadinessResult.REFERENCE_CONTENT_INSUFFICIENT
        )
        if self.readiness_result is not derived_readiness:
            raise ValueError("public prompt readiness result is not derived")
        expected = public_secondary_cohort_id(
            contract=self.contract,
            cohort_name=self.cohort_name,
            source_corpus_id=self.source_corpus_id,
            selected_cve_ids=self.selected_cve_ids,
            benchmark_manifest_id=self.benchmark_manifest.id,
            case_materialization_ids=[
                item.id for item in self.case_materializations
            ],
            readiness_result=self.readiness_result,
        )
        if self.id != expected:
            raise ValueError("PublicSecondaryCohort ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        cohort_name: str,
        source_corpus_id: str,
        benchmark_manifest: BenchmarkManifest,
        case_materializations: list[PublicSecondaryCaseMaterialization],
    ) -> "PublicSecondaryCohort":
        manifest = BenchmarkManifest.model_validate(
            benchmark_manifest.model_dump(mode="json")
        )
        if manifest.metadata:
            raise ValueError("public secondary manifest metadata must be empty")
        materializations = [
            PublicSecondaryCaseMaterialization.model_validate(
                item.model_dump(mode="json")
            )
            for item in case_materializations
        ]
        selected = sorted(item.cve_id for item in materializations)
        readiness = (
            PublicPromptReadinessResult.READY_FOR_PUBLIC_PROVIDER
            if all(
                assessment.public_content_complete
                for item in materializations
                for assessment in item.prompt_assessments
            )
            else PublicPromptReadinessResult.REFERENCE_CONTENT_INSUFFICIENT
        )
        identity = public_secondary_cohort_id(
            contract=PUBLIC_SECONDARY_COHORT_CONTRACT,
            cohort_name=cohort_name,
            source_corpus_id=source_corpus_id,
            selected_cve_ids=selected,
            benchmark_manifest_id=manifest.id,
            case_materialization_ids=[item.id for item in materializations],
            readiness_result=readiness,
        )
        return cls(
            id=identity,
            cohort_name=cohort_name,
            source_corpus_id=source_corpus_id,
            selected_cve_ids=selected,
            benchmark_manifest=manifest,
            case_materializations=materializations,
            readiness_result=readiness,
        )
