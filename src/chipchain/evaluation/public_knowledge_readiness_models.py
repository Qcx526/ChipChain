"""Offline public-knowledge prompt-readiness artifact contracts."""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.evaluation.ablation_models import PromptVisibilityAudit
from chipchain.evaluation.enums import PromptVisibilityAuditStatus
from chipchain.evaluation.experiment_models import PHASE10D_PROVIDER_ROLE_ORDER
from chipchain.evaluation.public_secondary_models import (
    PublicPromptReadinessResult,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.reasoning.enums import (
    ReasoningAgentType,
    ReasoningPromptVisibility,
)
from chipchain.reasoning.knowledge_projection import (
    PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT,
)


PHASE10D_PUBLIC_KNOWLEDGE_LEAKAGE_AUDIT_CONTRACT = (
    "phase10d_public_knowledge_leakage_audit_v1"
)
PHASE10D_PUBLIC_KNOWLEDGE_READINESS_CONTRACT = (
    "phase10d_public_knowledge_readiness_v1"
)
PHASE10D_STEP8B1A_FROZEN_COHORT_ID = (
    "public-secondary-cohort:"
    "9587452d6c9ae26debb73c7511dfd417c8cb7f0d383084d432a3ad91da8800b5"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
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


class PublicKnowledgeLeakageAuditStatus(str, Enum):
    """Closed result for structured public-knowledge leakage checks."""

    PASS = "pass"
    LEAK_DETECTED = "leak_detected"


def public_knowledge_leakage_audit_id(
    *,
    contract: str,
    prompt_sha256: str,
    detected_forbidden_field_names: list[str],
    detected_forbidden_value_sha256s: list[str],
    status: PublicKnowledgeLeakageAuditStatus,
) -> str:
    return _canonical_hash(
        "public-knowledge-leakage-audit",
        {
            "contract": contract,
            "detected_forbidden_field_names": sorted(
                detected_forbidden_field_names
            ),
            "detected_forbidden_value_sha256s": sorted(
                detected_forbidden_value_sha256s
            ),
            "prompt_sha256": prompt_sha256,
            "status": status.value,
        },
    )


class PublicKnowledgeLeakageAudit(DomainModel):
    """Hash-only audit of forbidden structured labels and exact values."""

    id: Identifier
    contract: Literal[
        PHASE10D_PUBLIC_KNOWLEDGE_LEAKAGE_AUDIT_CONTRACT
    ] = PHASE10D_PUBLIC_KNOWLEDGE_LEAKAGE_AUDIT_CONTRACT
    prompt_sha256: Identifier
    detected_forbidden_field_names: list[Identifier] = Field(
        default_factory=list
    )
    detected_forbidden_value_sha256s: list[Identifier] = Field(
        default_factory=list
    )
    status: PublicKnowledgeLeakageAuditStatus

    @field_validator("prompt_sha256")
    @classmethod
    def validate_prompt_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("leakage audit prompt hash must be SHA-256")
        return value

    @field_validator(
        "detected_forbidden_field_names",
        "detected_forbidden_value_sha256s",
    )
    @classmethod
    def normalize_detections(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("leakage audit detections must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_status_and_identity(self) -> "PublicKnowledgeLeakageAudit":
        if any(
            not _SHA256.fullmatch(value)
            for value in self.detected_forbidden_value_sha256s
        ):
            raise ValueError("forbidden-value detections must be hash-only")
        expected_status = (
            PublicKnowledgeLeakageAuditStatus.LEAK_DETECTED
            if self.detected_forbidden_field_names
            or self.detected_forbidden_value_sha256s
            else PublicKnowledgeLeakageAuditStatus.PASS
        )
        if self.status is not expected_status:
            raise ValueError("public knowledge leakage status is not derived")
        expected = public_knowledge_leakage_audit_id(
            contract=self.contract,
            prompt_sha256=self.prompt_sha256,
            detected_forbidden_field_names=(
                self.detected_forbidden_field_names
            ),
            detected_forbidden_value_sha256s=(
                self.detected_forbidden_value_sha256s
            ),
            status=self.status,
        )
        if self.id != expected:
            raise ValueError("PublicKnowledgeLeakageAudit ID is not deterministic")
        return self


def public_knowledge_prompt_assessment_id(
    *,
    cve_id: str,
    benchmark_case_id: str,
    reasoning_context_id: str,
    knowledge_entry_id: str,
    knowledge_projection_id: str,
    role: ReasoningAgentType,
    visibility: ReasoningPromptVisibility,
    prompt_sha256: str,
    visibility_audit_id: str | None,
    leakage_audit_id: str,
    cve_external_id_visible: bool,
    knowledge_entry_id_visible: bool,
    title_visible: bool,
    summary_visible: bool,
    affected_components_visible: bool,
    public_references_visible: bool,
) -> str:
    return _canonical_hash(
        "public-knowledge-prompt-assessment",
        {
            "affected_components_visible": affected_components_visible,
            "benchmark_case_id": benchmark_case_id,
            "cve_external_id_visible": cve_external_id_visible,
            "cve_id": cve_id,
            "knowledge_entry_id": knowledge_entry_id,
            "knowledge_entry_id_visible": knowledge_entry_id_visible,
            "knowledge_projection_id": knowledge_projection_id,
            "leakage_audit_id": leakage_audit_id,
            "prompt_sha256": prompt_sha256,
            "public_references_visible": public_references_visible,
            "reasoning_context_id": reasoning_context_id,
            "role": role.value,
            "summary_visible": summary_visible,
            "title_visible": title_visible,
            "visibility": visibility.value,
            "visibility_audit_id": visibility_audit_id,
        },
    )


class PublicKnowledgePromptAssessment(DomainModel):
    """Visibility and leakage facts for one exact projected prompt."""

    id: Identifier
    cve_id: Identifier
    benchmark_case_id: Identifier
    reasoning_context_id: Identifier
    knowledge_entry_id: Identifier
    knowledge_projection_id: Identifier
    role: ReasoningAgentType
    visibility: ReasoningPromptVisibility
    prompt_sha256: Identifier
    visibility_audit: PromptVisibilityAudit | None = None
    leakage_audit: PublicKnowledgeLeakageAudit
    cve_external_id_visible: bool
    knowledge_entry_id_visible: bool
    title_visible: bool
    summary_visible: bool
    affected_components_visible: bool
    public_references_visible: bool

    @field_validator("prompt_sha256")
    @classmethod
    def validate_prompt_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("public knowledge prompt hash must be SHA-256")
        return value

    @model_validator(mode="after")
    def validate_audits_and_identity(
        self,
    ) -> "PublicKnowledgePromptAssessment":
        visibility_audit_id: str | None = None
        if self.visibility is ReasoningPromptVisibility.FULL_CONTEXT:
            if self.visibility_audit is not None:
                raise ValueError("FULL projected prompt must not carry MASKED audit")
        else:
            audit = self.visibility_audit
            if (
                audit is None
                or audit.prompt_sha256 != self.prompt_sha256
                or audit.status is not PromptVisibilityAuditStatus.PASS
                or audit.leaked_reference_ids
                or audit.metadata
            ):
                raise ValueError("MASKED projected prompt audit must pass exactly")
            visibility_audit_id = audit.id
        if (
            self.leakage_audit.prompt_sha256 != self.prompt_sha256
            or self.leakage_audit.status
            is not PublicKnowledgeLeakageAuditStatus.PASS
        ):
            raise ValueError("public knowledge leakage audit must pass exactly")
        expected = public_knowledge_prompt_assessment_id(
            cve_id=self.cve_id,
            benchmark_case_id=self.benchmark_case_id,
            reasoning_context_id=self.reasoning_context_id,
            knowledge_entry_id=self.knowledge_entry_id,
            knowledge_projection_id=self.knowledge_projection_id,
            role=self.role,
            visibility=self.visibility,
            prompt_sha256=self.prompt_sha256,
            visibility_audit_id=visibility_audit_id,
            leakage_audit_id=self.leakage_audit.id,
            cve_external_id_visible=self.cve_external_id_visible,
            knowledge_entry_id_visible=self.knowledge_entry_id_visible,
            title_visible=self.title_visible,
            summary_visible=self.summary_visible,
            affected_components_visible=self.affected_components_visible,
            public_references_visible=self.public_references_visible,
        )
        if self.id != expected:
            raise ValueError(
                "PublicKnowledgePromptAssessment ID is not deterministic"
            )
        return self

    @property
    def content_complete(self) -> bool:
        """Return whether every required neutral entry field is visible."""

        return all(
            (
                self.cve_external_id_visible,
                self.knowledge_entry_id_visible,
                self.title_visible,
                self.summary_visible,
                self.affected_components_visible,
                self.public_references_visible,
            )
        )


def public_knowledge_case_readiness_id(
    *,
    cve_id: str,
    benchmark_case_id: str,
    documented_interaction_id: str,
    reasoning_context_id: str,
    knowledge_entry_id: str,
    knowledge_projection_id: str,
    prompt_assessment_ids: list[str],
) -> str:
    return _canonical_hash(
        "public-knowledge-case-readiness",
        {
            "benchmark_case_id": benchmark_case_id,
            "cve_id": cve_id,
            "documented_interaction_id": documented_interaction_id,
            "knowledge_entry_id": knowledge_entry_id,
            "knowledge_projection_id": knowledge_projection_id,
            "prompt_assessment_ids": sorted(prompt_assessment_ids),
            "reasoning_context_id": reasoning_context_id,
        },
    )


class PublicKnowledgeCaseReadiness(DomainModel):
    """One frozen public case with its projected prompt provenance."""

    id: Identifier
    cve_id: Identifier
    benchmark_case_id: Identifier
    documented_interaction_id: Identifier
    reasoning_context_id: Identifier
    knowledge_entry_id: Identifier
    knowledge_projection_id: Identifier
    prompt_assessments: list[PublicKnowledgePromptAssessment]

    @field_validator("prompt_assessments")
    @classmethod
    def normalize_assessments(
        cls,
        values: list[PublicKnowledgePromptAssessment],
    ) -> list[PublicKnowledgePromptAssessment]:
        expected = {
            (visibility, role)
            for visibility in _PROMPT_VISIBILITIES
            for role in PHASE10D_PROVIDER_ROLE_ORDER
        }
        if len(values) != len(expected) or {
            (item.visibility, item.role) for item in values
        } != expected:
            raise ValueError(
                "public knowledge case requires FULL/MASKED four-role prompts"
            )
        return sorted(
            values,
            key=lambda item: (
                _PROMPT_VISIBILITIES.index(item.visibility),
                PHASE10D_PROVIDER_ROLE_ORDER.index(item.role),
            ),
        )

    @model_validator(mode="after")
    def validate_bindings_and_identity(self) -> "PublicKnowledgeCaseReadiness":
        if any(
            (
                item.cve_id,
                item.benchmark_case_id,
                item.reasoning_context_id,
                item.knowledge_entry_id,
                item.knowledge_projection_id,
            )
            != (
                self.cve_id,
                self.benchmark_case_id,
                self.reasoning_context_id,
                self.knowledge_entry_id,
                self.knowledge_projection_id,
            )
            for item in self.prompt_assessments
        ):
            raise ValueError("public knowledge prompt case binding mismatch")
        expected = public_knowledge_case_readiness_id(
            cve_id=self.cve_id,
            benchmark_case_id=self.benchmark_case_id,
            documented_interaction_id=self.documented_interaction_id,
            reasoning_context_id=self.reasoning_context_id,
            knowledge_entry_id=self.knowledge_entry_id,
            knowledge_projection_id=self.knowledge_projection_id,
            prompt_assessment_ids=[item.id for item in self.prompt_assessments],
        )
        if self.id != expected:
            raise ValueError("PublicKnowledgeCaseReadiness ID is not deterministic")
        return self


def public_knowledge_readiness_artifact_id(
    *,
    contract: str,
    frozen_public_secondary_cohort_id: str,
    source_corpus_id: str,
    knowledge_projection_contract: str,
    selected_cve_ids: list[str],
    case_readiness_ids: list[str],
    readiness_result: PublicPromptReadinessResult,
) -> str:
    return _canonical_hash(
        "public-knowledge-readiness-artifact",
        {
            "case_readiness_ids": sorted(case_readiness_ids),
            "contract": contract,
            "frozen_public_secondary_cohort_id": (
                frozen_public_secondary_cohort_id
            ),
            "knowledge_projection_contract": knowledge_projection_contract,
            "readiness_result": readiness_result.value,
            "selected_cve_ids": sorted(selected_cve_ids),
            "source_corpus_id": source_corpus_id,
        },
    )


class PublicKnowledgeReadinessArtifact(DomainModel):
    """Hash-only readiness result for the frozen public SECONDARY cohort."""

    id: Identifier
    contract: Literal[PHASE10D_PUBLIC_KNOWLEDGE_READINESS_CONTRACT] = (
        PHASE10D_PUBLIC_KNOWLEDGE_READINESS_CONTRACT
    )
    frozen_public_secondary_cohort_id: Literal[
        PHASE10D_STEP8B1A_FROZEN_COHORT_ID
    ] = PHASE10D_STEP8B1A_FROZEN_COHORT_ID
    source_corpus_id: Identifier
    knowledge_projection_contract: Literal[
        PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT
    ] = PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT
    selected_cve_ids: list[Identifier] = Field(min_length=1)
    case_readiness: list[PublicKnowledgeCaseReadiness] = Field(min_length=1)
    readiness_result: PublicPromptReadinessResult

    @field_validator("selected_cve_ids")
    @classmethod
    def normalize_cve_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("public knowledge readiness CVEs must be unique")
        return sorted(values)

    @field_validator("case_readiness")
    @classmethod
    def normalize_cases(
        cls,
        values: list[PublicKnowledgeCaseReadiness],
    ) -> list[PublicKnowledgeCaseReadiness]:
        if len(values) != len({item.cve_id for item in values}) or len(
            values
        ) != len({item.benchmark_case_id for item in values}):
            raise ValueError("public knowledge readiness cases must be unique")
        return sorted(values, key=lambda item: item.cve_id)

    @model_validator(mode="after")
    def validate_readiness_and_identity(
        self,
    ) -> "PublicKnowledgeReadinessArtifact":
        if self.selected_cve_ids != [
            item.cve_id for item in self.case_readiness
        ]:
            raise ValueError("public knowledge readiness selection mismatch")
        derived = (
            PublicPromptReadinessResult.READY_FOR_PUBLIC_PROVIDER
            if all(
                assessment.content_complete
                for case in self.case_readiness
                for assessment in case.prompt_assessments
            )
            else PublicPromptReadinessResult.REFERENCE_CONTENT_INSUFFICIENT
        )
        if self.readiness_result is not derived:
            raise ValueError("public knowledge readiness result is not derived")
        expected = public_knowledge_readiness_artifact_id(
            contract=self.contract,
            frozen_public_secondary_cohort_id=(
                self.frozen_public_secondary_cohort_id
            ),
            source_corpus_id=self.source_corpus_id,
            knowledge_projection_contract=self.knowledge_projection_contract,
            selected_cve_ids=self.selected_cve_ids,
            case_readiness_ids=[item.id for item in self.case_readiness],
            readiness_result=self.readiness_result,
        )
        if self.id != expected:
            raise ValueError(
                "PublicKnowledgeReadinessArtifact ID is not deterministic"
            )
        return self
