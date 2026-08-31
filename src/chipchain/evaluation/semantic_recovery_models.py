"""Deterministic Phase 10D masked semantic-recovery diagnostic contracts."""

from __future__ import annotations

import re
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.evaluation.enums import (
    ChainFeasibilityStatus,
    ModelClaimBindingReason,
    ModelClaimBindingStatus,
)
from chipchain.evaluation.models import _canonical_hash
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.cross_layer import CrossLayerInteractionType


PHASE10D_MASKED_SEMANTIC_RECOVERY_DIAGNOSTIC_CONTRACT = (
    "phase10d_masked_semantic_recovery_diagnostic_v1"
)
PHASE10D_SEMANTIC_TOKENIZATION_CONTRACT = (
    "phase10d_semantic_tokenization_v1"
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FROZEN_PUBLIC_CVE_COHORT = frozenset(
    {
        "CVE-2022-23960",
        "CVE-2023-34320",
        "CVE-2023-52481",
        "CVE-2024-26670",
        "CVE-2025-10263",
    }
)


class SemanticDiagnosticMode(str, Enum):
    """Whether a diagnostic contract predates the model execution it reads."""

    RETROSPECTIVE_DIAGNOSTIC = "retrospective_diagnostic"
    PROSPECTIVE_DIAGNOSTIC = "prospective_diagnostic"


class SemanticDiagnosticTextSource(str, Enum):
    """Closed model-authored text sources allowed by the diagnostic."""

    ATTACK_CHAIN_HYPOTHESIS_DESCRIPTION_ONLY = (
        "attack_chain_hypothesis_description_only"
    )
    ATTACK_CHAIN_HYPOTHESIS_AND_REASONING_STEPS = (
        "attack_chain_hypothesis_and_reasoning_steps"
    )


class InteractionTypeRecoveryStatus(str, Enum):
    """Exact claim-type comparison without alternate-type repair."""

    MATCH = "match"
    MISMATCH = "mismatch"
    CLAIM_MISSING = "claim_missing"


class ParticipantGroundingDiagnostic(str, Enum):
    """Descriptive claim/binder grounding categories, never verdicts."""

    EXACT_REQUIRED_REFERENCES = "exact_required_references"
    REQUIRED_REFERENCES_MISSING = "required_references_missing"
    VISIBLE_KNOWLEDGE_REFERENCE_SUBSTITUTION = (
        "visible_knowledge_reference_substitution"
    )
    HIDDEN_REFERENCE_MISMATCH = "hidden_reference_mismatch"
    TYPE_SHAPE_CONFLICT = "type_shape_conflict"
    INTERACTION_TYPE_MISMATCH = "interaction_type_mismatch"
    CLAIM_MISSING = "claim_missing"
    OTHER = "other"


class SemanticReferenceField(str, Enum):
    """Evaluator-only public-source fields used as lexical references."""

    TRIGGER_SUMMARY = "trigger_summary"
    PRECONDITION_SUMMARY = "precondition_summary"
    HARDWARE_EFFECT_SUMMARY = "hardware_effect_summary"


class ReferenceCoverageScope(str, Enum):
    """The complete reference or its provider-hidden remainder."""

    CONTENT = "content"
    HELD_OUT = "held_out"


def semantic_reference_digest_id(
    *,
    reference_field: SemanticReferenceField,
    token_count: int,
    token_set_sha256: str,
) -> str:
    return _canonical_hash(
        "semantic-reference-digest",
        {
            "reference_field": SemanticReferenceField(reference_field).value,
            "token_count": token_count,
            "token_set_sha256": token_set_sha256,
        },
    )


class SemanticReferenceDigest(DomainModel):
    """Hash/count commitment to one normalized evaluator reference field."""

    id: Identifier
    reference_field: SemanticReferenceField
    token_count: int = Field(ge=0)
    token_set_sha256: Identifier

    @field_validator("token_set_sha256")
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("semantic reference digest must be SHA-256")
        return value

    @model_validator(mode="after")
    def validate_identity(self) -> "SemanticReferenceDigest":
        expected = semantic_reference_digest_id(
            reference_field=self.reference_field,
            token_count=self.token_count,
            token_set_sha256=self.token_set_sha256,
        )
        if self.id != expected:
            raise ValueError("semantic reference digest ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        reference_field: SemanticReferenceField,
        token_count: int,
        token_set_sha256: str,
    ) -> "SemanticReferenceDigest":
        values = {
            "reference_field": SemanticReferenceField(reference_field),
            "token_count": token_count,
            "token_set_sha256": token_set_sha256,
        }
        return cls(id=semantic_reference_digest_id(**values), **values)


def reference_content_coverage_id(
    *,
    reference_field: SemanticReferenceField,
    scope: ReferenceCoverageScope,
    reference_token_count: int,
    matched_token_count: int,
    numerator: int,
    denominator: int,
    defined: bool,
    reference_token_set_sha256: str,
    matched_token_set_sha256: str,
) -> str:
    return _canonical_hash(
        "reference-content-coverage",
        {
            "defined": defined,
            "denominator": denominator,
            "matched_token_count": matched_token_count,
            "matched_token_set_sha256": matched_token_set_sha256,
            "numerator": numerator,
            "reference_field": SemanticReferenceField(reference_field).value,
            "reference_token_count": reference_token_count,
            "reference_token_set_sha256": reference_token_set_sha256,
            "scope": ReferenceCoverageScope(scope).value,
        },
    )


class ReferenceContentCoverage(DomainModel):
    """Exact rational lexical coverage with no threshold or success flag."""

    id: Identifier
    reference_field: SemanticReferenceField
    scope: ReferenceCoverageScope
    reference_token_count: int = Field(ge=0)
    matched_token_count: int = Field(ge=0)
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    defined: bool
    reference_token_set_sha256: Identifier
    matched_token_set_sha256: Identifier

    @field_validator(
        "reference_token_set_sha256", "matched_token_set_sha256"
    )
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("coverage token-set digest must be SHA-256")
        return value

    @model_validator(mode="after")
    def validate_fraction_and_identity(self) -> "ReferenceContentCoverage":
        if (
            self.reference_token_count != self.denominator
            or self.matched_token_count != self.numerator
            or self.matched_token_count > self.reference_token_count
        ):
            raise ValueError("coverage counts and exact fraction are inconsistent")
        if self.defined != (self.denominator > 0):
            raise ValueError("coverage defined flag must reflect its denominator")
        expected = reference_content_coverage_id(
            reference_field=self.reference_field,
            scope=self.scope,
            reference_token_count=self.reference_token_count,
            matched_token_count=self.matched_token_count,
            numerator=self.numerator,
            denominator=self.denominator,
            defined=self.defined,
            reference_token_set_sha256=self.reference_token_set_sha256,
            matched_token_set_sha256=self.matched_token_set_sha256,
        )
        if self.id != expected:
            raise ValueError("reference content coverage ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        reference_field: SemanticReferenceField,
        scope: ReferenceCoverageScope,
        reference_token_count: int,
        matched_token_count: int,
        reference_token_set_sha256: str,
        matched_token_set_sha256: str,
    ) -> "ReferenceContentCoverage":
        values = {
            "reference_field": SemanticReferenceField(reference_field),
            "scope": ReferenceCoverageScope(scope),
            "reference_token_count": reference_token_count,
            "matched_token_count": matched_token_count,
            "numerator": matched_token_count,
            "denominator": reference_token_count,
            "defined": reference_token_count > 0,
            "reference_token_set_sha256": reference_token_set_sha256,
            "matched_token_set_sha256": matched_token_set_sha256,
        }
        return cls(id=reference_content_coverage_id(**values), **values)


def masked_semantic_recovery_case_diagnostic_id(**values: object) -> str:
    payload = {
        key: (
            value.value
            if isinstance(value, Enum)
            else [item.value if isinstance(item, Enum) else item for item in value]
            if isinstance(value, list)
            else value.id
            if isinstance(value, DomainModel)
            else value
        )
        for key, value in values.items()
    }
    return _canonical_hash("masked-semantic-recovery-case", payload)


class MaskedSemanticRecoveryCaseDiagnostic(DomainModel):
    """One isolated MASKED case's three-axis descriptive diagnostic."""

    id: Identifier
    cve_id: Identifier
    benchmark_case_id: Identifier
    reasoning_context_id: Identifier
    masked_reasoning_session_id: Identifier
    attack_chain_hypothesis_id: Identifier
    model_authored_chain_claim_id: Identifier | None = None
    attack_chain_reasoning_result_id: Identifier | None = None
    attack_chain_reasoning_steps_available: bool
    diagnostic_text_source: SemanticDiagnosticTextSource
    knowledge_entry_id: Identifier
    expected_interaction_type: CrossLayerInteractionType
    claimed_interaction_type: CrossLayerInteractionType | None = None
    interaction_type_recovery_status: InteractionTypeRecoveryStatus
    exact_binding_assessment_id: Identifier
    exact_binding_status: ModelClaimBindingStatus
    exact_binding_reason_codes: list[ModelClaimBindingReason] = Field(min_length=1)
    participant_grounding_diagnostic: ParticipantGroundingDiagnostic
    trigger_reference_digest: SemanticReferenceDigest
    precondition_reference_digest: SemanticReferenceDigest
    hardware_effect_reference_digest: SemanticReferenceDigest
    trigger_content_coverage: ReferenceContentCoverage
    precondition_content_coverage: ReferenceContentCoverage
    hardware_effect_content_coverage: ReferenceContentCoverage
    trigger_held_out_coverage: ReferenceContentCoverage
    precondition_held_out_coverage: ReferenceContentCoverage
    hardware_effect_held_out_coverage: ReferenceContentCoverage
    objective_feasibility_status: ChainFeasibilityStatus
    objective_feasibility_assessment_id: Identifier

    @field_validator("exact_binding_reason_codes")
    @classmethod
    def normalize_binding_reasons(
        cls, values: list[ModelClaimBindingReason]
    ) -> list[ModelClaimBindingReason]:
        if len(values) != len(set(values)):
            raise ValueError("diagnostic binding reasons must be unique")
        return sorted(values, key=lambda item: item.value)

    def _identity_values(self) -> dict[str, object]:
        return {
            key: value
            for key, value in self.__dict__.items()
            if key != "id"
        }

    @model_validator(mode="after")
    def validate_semantics_and_identity(
        self,
    ) -> "MaskedSemanticRecoveryCaseDiagnostic":
        result_available = self.attack_chain_reasoning_result_id is not None
        if result_available != self.attack_chain_reasoning_steps_available:
            raise ValueError("ATTACK_CHAIN reasoning-result provenance is inconsistent")
        expected_source = (
            SemanticDiagnosticTextSource.ATTACK_CHAIN_HYPOTHESIS_AND_REASONING_STEPS
            if result_available
            else SemanticDiagnosticTextSource.ATTACK_CHAIN_HYPOTHESIS_DESCRIPTION_ONLY
        )
        if self.diagnostic_text_source is not expected_source:
            raise ValueError("diagnostic text source disagrees with result provenance")
        if self.model_authored_chain_claim_id is None:
            expected_type_status = InteractionTypeRecoveryStatus.CLAIM_MISSING
            if self.claimed_interaction_type is not None:
                raise ValueError("missing claim cannot retain a claimed type")
        else:
            if self.claimed_interaction_type is None:
                raise ValueError("model claim requires its claimed interaction type")
            expected_type_status = (
                InteractionTypeRecoveryStatus.MATCH
                if self.claimed_interaction_type is self.expected_interaction_type
                else InteractionTypeRecoveryStatus.MISMATCH
            )
        if self.interaction_type_recovery_status is not expected_type_status:
            raise ValueError("interaction-type recovery status is not exact")
        expected_fields = (
            (
                self.trigger_reference_digest,
                self.trigger_content_coverage,
                self.trigger_held_out_coverage,
                SemanticReferenceField.TRIGGER_SUMMARY,
            ),
            (
                self.precondition_reference_digest,
                self.precondition_content_coverage,
                self.precondition_held_out_coverage,
                SemanticReferenceField.PRECONDITION_SUMMARY,
            ),
            (
                self.hardware_effect_reference_digest,
                self.hardware_effect_content_coverage,
                self.hardware_effect_held_out_coverage,
                SemanticReferenceField.HARDWARE_EFFECT_SUMMARY,
            ),
        )
        for digest, content, held_out, field in expected_fields:
            if (
                digest.reference_field is not field
                or content.reference_field is not field
                or content.scope is not ReferenceCoverageScope.CONTENT
                or held_out.reference_field is not field
                or held_out.scope is not ReferenceCoverageScope.HELD_OUT
                or digest.token_count != content.reference_token_count
                or digest.token_set_sha256 != content.reference_token_set_sha256
            ):
                raise ValueError("semantic reference and coverage fields are misbound")
        expected_id = masked_semantic_recovery_case_diagnostic_id(
            **self._identity_values()
        )
        if self.id != expected_id:
            raise ValueError("masked semantic-recovery case ID is not deterministic")
        return self

    @classmethod
    def create(cls, **values: object) -> "MaskedSemanticRecoveryCaseDiagnostic":
        return cls(
            id=masked_semantic_recovery_case_diagnostic_id(**values),
            **values,
        )


def masked_semantic_recovery_diagnostic_artifact_id(
    *,
    contract: str,
    diagnostic_mode: SemanticDiagnosticMode,
    prospective_metric_eligible: bool,
    source_archive_id: str,
    source_archive_sha256: str,
    experiment_plan_id: str,
    benchmark_manifest_id: str,
    public_knowledge_binding_id: str,
    source_corpus_id: str,
    tokenization_contract: str,
    case_diagnostic_ids: list[str],
) -> str:
    return _canonical_hash(
        "masked-semantic-recovery-diagnostic",
        {
            "benchmark_manifest_id": benchmark_manifest_id,
            "case_diagnostic_ids": sorted(case_diagnostic_ids),
            "contract": contract,
            "diagnostic_mode": SemanticDiagnosticMode(diagnostic_mode).value,
            "experiment_plan_id": experiment_plan_id,
            "prospective_metric_eligible": prospective_metric_eligible,
            "public_knowledge_binding_id": public_knowledge_binding_id,
            "source_archive_id": source_archive_id,
            "source_archive_sha256": source_archive_sha256,
            "source_corpus_id": source_corpus_id,
            "tokenization_contract": tokenization_contract,
        },
    )


class MaskedSemanticRecoveryDiagnosticArtifact(DomainModel):
    """Five-case offline diagnostic; not a metric, verdict, or benchmark rate."""

    id: Identifier
    contract: Literal[
        PHASE10D_MASKED_SEMANTIC_RECOVERY_DIAGNOSTIC_CONTRACT
    ] = PHASE10D_MASKED_SEMANTIC_RECOVERY_DIAGNOSTIC_CONTRACT
    diagnostic_mode: SemanticDiagnosticMode
    prospective_metric_eligible: bool
    source_archive_id: Identifier
    source_archive_sha256: Identifier
    experiment_plan_id: Identifier
    benchmark_manifest_id: Identifier
    public_knowledge_binding_id: Identifier
    source_corpus_id: Identifier
    tokenization_contract: Literal[
        PHASE10D_SEMANTIC_TOKENIZATION_CONTRACT
    ] = PHASE10D_SEMANTIC_TOKENIZATION_CONTRACT
    case_diagnostics: list[MaskedSemanticRecoveryCaseDiagnostic]
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("source_archive_sha256")
    @classmethod
    def validate_source_sha256(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("source archive digest must be SHA-256")
        return value

    @field_validator("case_diagnostics")
    @classmethod
    def normalize_cases(
        cls, values: list[MaskedSemanticRecoveryCaseDiagnostic]
    ) -> list[MaskedSemanticRecoveryCaseDiagnostic]:
        if len(values) != 5:
            raise ValueError("masked semantic recovery requires exactly five cases")
        if len(values) != len({item.id for item in values}) or len(values) != len(
            {item.cve_id for item in values}
        ):
            raise ValueError("masked semantic-recovery cases must be unique")
        if {item.cve_id for item in values} != _FROZEN_PUBLIC_CVE_COHORT:
            raise ValueError(
                "masked semantic recovery requires the frozen five-CVE cohort"
            )
        return sorted(values, key=lambda item: item.cve_id)

    @field_validator("metadata")
    @classmethod
    def require_empty_metadata(cls, value: Metadata) -> Metadata:
        if value:
            raise ValueError("semantic diagnostic metadata must remain empty")
        return value

    @model_validator(mode="after")
    def validate_mode_and_identity(
        self,
    ) -> "MaskedSemanticRecoveryDiagnosticArtifact":
        if (
            self.diagnostic_mode
            is SemanticDiagnosticMode.RETROSPECTIVE_DIAGNOSTIC
            and self.prospective_metric_eligible
        ):
            raise ValueError("retrospective diagnostic cannot be metric-eligible")
        expected = masked_semantic_recovery_diagnostic_artifact_id(
            contract=self.contract,
            diagnostic_mode=self.diagnostic_mode,
            prospective_metric_eligible=self.prospective_metric_eligible,
            source_archive_id=self.source_archive_id,
            source_archive_sha256=self.source_archive_sha256,
            experiment_plan_id=self.experiment_plan_id,
            benchmark_manifest_id=self.benchmark_manifest_id,
            public_knowledge_binding_id=self.public_knowledge_binding_id,
            source_corpus_id=self.source_corpus_id,
            tokenization_contract=self.tokenization_contract,
            case_diagnostic_ids=[item.id for item in self.case_diagnostics],
        )
        if self.id != expected:
            raise ValueError(
                "masked semantic-recovery artifact ID is not deterministic"
            )
        return self

    @classmethod
    def create(
        cls,
        *,
        diagnostic_mode: SemanticDiagnosticMode,
        prospective_metric_eligible: bool,
        source_archive_id: str,
        source_archive_sha256: str,
        experiment_plan_id: str,
        benchmark_manifest_id: str,
        public_knowledge_binding_id: str,
        source_corpus_id: str,
        case_diagnostics: list[MaskedSemanticRecoveryCaseDiagnostic],
    ) -> "MaskedSemanticRecoveryDiagnosticArtifact":
        values = {
            "contract": PHASE10D_MASKED_SEMANTIC_RECOVERY_DIAGNOSTIC_CONTRACT,
            "diagnostic_mode": SemanticDiagnosticMode(diagnostic_mode),
            "prospective_metric_eligible": prospective_metric_eligible,
            "source_archive_id": source_archive_id,
            "source_archive_sha256": source_archive_sha256,
            "experiment_plan_id": experiment_plan_id,
            "benchmark_manifest_id": benchmark_manifest_id,
            "public_knowledge_binding_id": public_knowledge_binding_id,
            "source_corpus_id": source_corpus_id,
            "tokenization_contract": PHASE10D_SEMANTIC_TOKENIZATION_CONTRACT,
            "case_diagnostic_ids": [item.id for item in case_diagnostics],
        }
        return cls(
            id=masked_semantic_recovery_diagnostic_artifact_id(**values),
            case_diagnostics=case_diagnostics,
            metadata={},
            **{
                key: value
                for key, value in values.items()
                if key != "case_diagnostic_ids"
            },
        )
