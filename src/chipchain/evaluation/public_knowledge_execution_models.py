"""Phase 10D public-knowledge execution binding and wrapper contracts."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import Field, SkipValidation, field_validator, model_validator

from chipchain.evaluation.enums import AblationConditionKind
from chipchain.evaluation.execution_models import RealModelExecutionArchive
from chipchain.evaluation.models import _canonical_hash
from chipchain.evaluation.public_knowledge_readiness_models import (
    PublicKnowledgeLeakageAudit,
    PublicKnowledgeLeakageAuditStatus,
    PublicKnowledgeReadinessArtifact,
)
from chipchain.models.common import DomainModel, Identifier
from chipchain.reasoning.enums import (
    ReasoningAgentType,
    ReasoningPromptVisibility,
)
from chipchain.reasoning.knowledge_projection import (
    PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT,
    KnowledgeContentProjection,
)


PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_BINDING_CONTRACT = (
    "phase10d_public_knowledge_execution_binding_v1"
)
PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_ARCHIVE_CONTRACT = (
    "phase10d_public_knowledge_execution_archive_v1"
)
PHASE10D_STEP8B1A_FROZEN_COHORT_ID = (
    "public-secondary-cohort:"
    "9587452d6c9ae26debb73c7511dfd417c8cb7f0d383084d432a3ad91da8800b5"
)
PHASE10D_STEP8B1B_FROZEN_READINESS_ID = (
    "public-knowledge-readiness-artifact:"
    "4a0f6ba0db963ba42130667e17ccc407fe093677fd5a019742dc70a279768e26"
)
PHASE10D_PUBLIC_CVE_CORPUS_ID = (
    "public-cve-corpus:"
    "778765c51a0d9b939eb37b390367a3d0cd02720942c8746c19eb0a1c38930e49"
)
PHASE10D_PUBLIC_SECONDARY_CVE_IDS = (
    "CVE-2022-23960",
    "CVE-2023-34320",
    "CVE-2023-52481",
    "CVE-2024-26670",
    "CVE-2025-10263",
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_VISIBILITIES = (
    ReasoningPromptVisibility.FULL_CONTEXT,
    ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT,
)
_ROLES = (
    ReasoningAgentType.CODE,
    ReasoningAgentType.HARDWARE,
    ReasoningAgentType.VULNERABILITY,
    ReasoningAgentType.ATTACK_CHAIN,
)


def public_knowledge_expected_prompt_record_id(
    *,
    visibility: ReasoningPromptVisibility,
    role: ReasoningAgentType,
    expected_prompt_sha256: str,
    expected_visibility_audit_id: str | None,
    expected_leakage_audit_id: str,
) -> str:
    """Bind one exact frozen projected-prompt provenance record."""

    return _canonical_hash(
        "public-knowledge-expected-prompt",
        {
            "expected_leakage_audit_id": expected_leakage_audit_id,
            "expected_prompt_sha256": expected_prompt_sha256,
            "expected_visibility_audit_id": expected_visibility_audit_id,
            "role": ReasoningAgentType(role).value,
            "visibility": ReasoningPromptVisibility(visibility).value,
        },
    )


class PublicKnowledgeExpectedPromptRecord(DomainModel):
    """Expected hash and PASS-audit provenance for one case/visibility/role."""

    id: Identifier
    visibility: ReasoningPromptVisibility
    role: ReasoningAgentType
    expected_prompt_sha256: Identifier
    expected_visibility_audit_id: Identifier | None = None
    expected_leakage_audit_id: Identifier

    @field_validator("expected_prompt_sha256")
    @classmethod
    def validate_hash(cls, value: str) -> str:
        if not _SHA256.fullmatch(value):
            raise ValueError("expected public prompt hash must be SHA-256")
        return value

    @model_validator(mode="after")
    def validate_shape_and_identity(self) -> "PublicKnowledgeExpectedPromptRecord":
        if (
            self.visibility is ReasoningPromptVisibility.FULL_CONTEXT
            and self.expected_visibility_audit_id is not None
        ):
            raise ValueError("FULL public prompt cannot bind a MASKED audit")
        if (
            self.visibility is ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT
            and self.expected_visibility_audit_id is None
        ):
            raise ValueError("MASKED public prompt requires visibility audit")
        expected = public_knowledge_expected_prompt_record_id(
            visibility=self.visibility,
            role=self.role,
            expected_prompt_sha256=self.expected_prompt_sha256,
            expected_visibility_audit_id=self.expected_visibility_audit_id,
            expected_leakage_audit_id=self.expected_leakage_audit_id,
        )
        if self.id != expected:
            raise ValueError("public expected-prompt record ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        visibility: ReasoningPromptVisibility,
        role: ReasoningAgentType,
        expected_prompt_sha256: str,
        expected_visibility_audit_id: str | None,
        expected_leakage_audit_id: str,
    ) -> "PublicKnowledgeExpectedPromptRecord":
        values = {
            "visibility": ReasoningPromptVisibility(visibility),
            "role": ReasoningAgentType(role),
            "expected_prompt_sha256": expected_prompt_sha256,
            "expected_visibility_audit_id": expected_visibility_audit_id,
            "expected_leakage_audit_id": expected_leakage_audit_id,
        }
        return cls(
            id=public_knowledge_expected_prompt_record_id(**values),
            **values,
        )


def public_knowledge_execution_case_binding_id(
    *,
    cve_id: str,
    benchmark_case_id: str,
    reasoning_context_id: str,
    knowledge_entry_id: str,
    knowledge_projection_id: str,
    expected_prompt_record_ids: list[str],
) -> str:
    return _canonical_hash(
        "public-knowledge-execution-case-binding",
        {
            "benchmark_case_id": benchmark_case_id,
            "cve_id": cve_id,
            "expected_prompt_record_ids": sorted(expected_prompt_record_ids),
            "knowledge_entry_id": knowledge_entry_id,
            "knowledge_projection_id": knowledge_projection_id,
            "reasoning_context_id": reasoning_context_id,
        },
    )


class PublicKnowledgeExecutionCaseBinding(DomainModel):
    """Exact public entry/projection/prompt binding for one frozen case."""

    id: Identifier
    cve_id: Identifier
    benchmark_case_id: Identifier
    reasoning_context_id: Identifier
    knowledge_entry_id: Identifier
    knowledge_projection: KnowledgeContentProjection
    expected_prompt_records: list[PublicKnowledgeExpectedPromptRecord]

    @field_validator("knowledge_projection")
    @classmethod
    def snapshot_projection(
        cls, value: KnowledgeContentProjection
    ) -> KnowledgeContentProjection:
        return KnowledgeContentProjection.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("expected_prompt_records")
    @classmethod
    def normalize_records(
        cls, values: list[PublicKnowledgeExpectedPromptRecord]
    ) -> list[PublicKnowledgeExpectedPromptRecord]:
        expected_keys = {
            (visibility, role)
            for visibility in _VISIBILITIES
            for role in _ROLES
        }
        actual_keys = {(item.visibility, item.role) for item in values}
        if len(values) != 8 or actual_keys != expected_keys:
            raise ValueError("public case requires exactly eight prompt records")
        if len(values) != len({item.id for item in values}):
            raise ValueError("public prompt record IDs must be unique")
        return sorted(
            values,
            key=lambda item: (
                _VISIBILITIES.index(item.visibility),
                _ROLES.index(item.role),
            ),
        )

    @model_validator(mode="after")
    def validate_binding_and_identity(self) -> "PublicKnowledgeExecutionCaseBinding":
        if (
            self.knowledge_projection.reasoning_context_id
            != self.reasoning_context_id
            or [item.entry_id for item in self.knowledge_projection.entries]
            != [self.knowledge_entry_id]
        ):
            raise ValueError("public execution projection binding mismatch")
        expected = public_knowledge_execution_case_binding_id(
            cve_id=self.cve_id,
            benchmark_case_id=self.benchmark_case_id,
            reasoning_context_id=self.reasoning_context_id,
            knowledge_entry_id=self.knowledge_entry_id,
            knowledge_projection_id=self.knowledge_projection.id,
            expected_prompt_record_ids=[
                item.id for item in self.expected_prompt_records
            ],
        )
        if self.id != expected:
            raise ValueError("public execution case binding ID is not deterministic")
        return self

    def expected_record(
        self,
        visibility: ReasoningPromptVisibility,
        role: ReasoningAgentType,
    ) -> PublicKnowledgeExpectedPromptRecord:
        """Resolve one closed visibility/role record without fallback."""

        key = (ReasoningPromptVisibility(visibility), ReasoningAgentType(role))
        return next(
            item
            for item in self.expected_prompt_records
            if (item.visibility, item.role) == key
        )


def public_knowledge_execution_binding_id(
    *,
    contract: str,
    experiment_plan_id: str,
    benchmark_manifest_id: str,
    real_experiment_input_set_id: str,
    public_secondary_cohort_id: str,
    public_knowledge_readiness_artifact_id: str,
    source_corpus_id: str,
    knowledge_projection_contract: str,
    case_binding_ids: list[str],
) -> str:
    return _canonical_hash(
        "public-knowledge-execution-binding",
        {
            "benchmark_manifest_id": benchmark_manifest_id,
            "case_binding_ids": sorted(case_binding_ids),
            "contract": contract,
            "experiment_plan_id": experiment_plan_id,
            "knowledge_projection_contract": knowledge_projection_contract,
            "public_knowledge_readiness_artifact_id": (
                public_knowledge_readiness_artifact_id
            ),
            "public_secondary_cohort_id": public_secondary_cohort_id,
            "real_experiment_input_set_id": real_experiment_input_set_id,
            "source_corpus_id": source_corpus_id,
        },
    )


class PublicKnowledgeExecutionBinding(DomainModel):
    """Detached binding around frozen plan/input/readiness contracts."""

    id: Identifier
    contract: Literal[
        PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_BINDING_CONTRACT
    ] = PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_BINDING_CONTRACT
    experiment_plan_id: Identifier
    benchmark_manifest_id: Identifier
    real_experiment_input_set_id: Identifier
    public_secondary_cohort_id: Literal[
        PHASE10D_STEP8B1A_FROZEN_COHORT_ID
    ] = PHASE10D_STEP8B1A_FROZEN_COHORT_ID
    public_knowledge_readiness_artifact: PublicKnowledgeReadinessArtifact
    source_corpus_id: Literal[PHASE10D_PUBLIC_CVE_CORPUS_ID] = (
        PHASE10D_PUBLIC_CVE_CORPUS_ID
    )
    knowledge_projection_contract: Literal[
        PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT
    ] = PHASE10D_PUBLIC_KNOWLEDGE_CONTENT_PROJECTION_CONTRACT
    case_bindings: list[PublicKnowledgeExecutionCaseBinding]

    @field_validator("public_knowledge_readiness_artifact")
    @classmethod
    def snapshot_readiness(
        cls, value: PublicKnowledgeReadinessArtifact
    ) -> PublicKnowledgeReadinessArtifact:
        return PublicKnowledgeReadinessArtifact.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("case_bindings")
    @classmethod
    def normalize_cases(
        cls, values: list[PublicKnowledgeExecutionCaseBinding]
    ) -> list[PublicKnowledgeExecutionCaseBinding]:
        if len(values) != 5:
            raise ValueError("public execution binding requires exactly five cases")
        if len(values) != len({item.cve_id for item in values}) or len(
            values
        ) != len({item.benchmark_case_id for item in values}):
            raise ValueError("public execution case bindings must be unique")
        if {item.cve_id for item in values} != set(
            PHASE10D_PUBLIC_SECONDARY_CVE_IDS
        ):
            raise ValueError("public execution binding has wrong frozen CVE cohort")
        return sorted(values, key=lambda item: item.cve_id)

    @model_validator(mode="after")
    def validate_readiness_and_identity(self) -> "PublicKnowledgeExecutionBinding":
        readiness = self.public_knowledge_readiness_artifact
        if readiness.id != PHASE10D_STEP8B1B_FROZEN_READINESS_ID:
            raise ValueError("public execution requires frozen Step 8B-1B readiness")
        if (
            readiness.source_corpus_id != self.source_corpus_id
            or readiness.knowledge_projection_contract
            != self.knowledge_projection_contract
        ):
            raise ValueError("public execution readiness source mismatch")
        readiness_by_cve = {item.cve_id: item for item in readiness.case_readiness}
        for bound in self.case_bindings:
            ready = readiness_by_cve.get(bound.cve_id)
            if ready is None or (
                bound.benchmark_case_id,
                bound.reasoning_context_id,
                bound.knowledge_entry_id,
                bound.knowledge_projection.id,
            ) != (
                ready.benchmark_case_id,
                ready.reasoning_context_id,
                ready.knowledge_entry_id,
                ready.knowledge_projection_id,
            ):
                raise ValueError("public execution case/readiness binding mismatch")
            ready_by_key = {
                (item.visibility, item.role): item
                for item in ready.prompt_assessments
            }
            for record in bound.expected_prompt_records:
                assessment = ready_by_key[(record.visibility, record.role)]
                if (
                    record.expected_prompt_sha256,
                    record.expected_visibility_audit_id,
                    record.expected_leakage_audit_id,
                ) != (
                    assessment.prompt_sha256,
                    (
                        assessment.visibility_audit.id
                        if assessment.visibility_audit is not None
                        else None
                    ),
                    assessment.leakage_audit.id,
                ):
                    raise ValueError("public expected prompt differs from readiness")
        expected = public_knowledge_execution_binding_id(
            contract=self.contract,
            experiment_plan_id=self.experiment_plan_id,
            benchmark_manifest_id=self.benchmark_manifest_id,
            real_experiment_input_set_id=self.real_experiment_input_set_id,
            public_secondary_cohort_id=self.public_secondary_cohort_id,
            public_knowledge_readiness_artifact_id=readiness.id,
            source_corpus_id=self.source_corpus_id,
            knowledge_projection_contract=self.knowledge_projection_contract,
            case_binding_ids=[item.id for item in self.case_bindings],
        )
        if self.id != expected:
            raise ValueError("PublicKnowledgeExecutionBinding ID is not deterministic")
        return self

    def case_binding(
        self, benchmark_case_id: str
    ) -> PublicKnowledgeExecutionCaseBinding:
        """Resolve one exact benchmark case binding without fallback."""

        return next(
            item
            for item in self.case_bindings
            if item.benchmark_case_id == benchmark_case_id
        )

    def expected_prompt_hashes_for_archive(self) -> dict[str, str]:
        """Return the closed 40-key hash map used only for archive validation."""

        result: dict[str, str] = {}
        condition_by_visibility = {
            ReasoningPromptVisibility.FULL_CONTEXT: (
                AblationConditionKind.FULL_CONTEXT_MODEL
            ),
            ReasoningPromptVisibility.MASKED_CHAIN_CONTEXT: (
                AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL
            ),
        }
        for case in self.case_bindings:
            for record in case.expected_prompt_records:
                condition = condition_by_visibility[record.visibility]
                key = "|".join(
                    (condition.value, case.benchmark_case_id, record.role.value)
                )
                result[key] = record.expected_prompt_sha256
        if len(result) != 40:
            raise ValueError("public execution binding must expose 40 prompt hashes")
        return result


def public_knowledge_execution_archive_id(
    *,
    contract: str,
    public_knowledge_execution_binding_id: str,
    real_model_execution_archive_id: str,
    transport_leakage_audit_ids: list[str],
) -> str:
    return _canonical_hash(
        "public-knowledge-execution-archive",
        {
            "contract": contract,
            "public_knowledge_execution_binding_id": (
                public_knowledge_execution_binding_id
            ),
            "real_model_execution_archive_id": real_model_execution_archive_id,
            "transport_leakage_audit_ids": sorted(transport_leakage_audit_ids),
        },
    )


class PublicKnowledgeExecutionArchive(DomainModel):
    """Public binding plus the unchanged hash-only Step 2 execution archive."""

    id: Identifier
    contract: Literal[
        PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_ARCHIVE_CONTRACT
    ] = PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_ARCHIVE_CONTRACT
    public_knowledge_execution_binding: PublicKnowledgeExecutionBinding
    real_model_execution_archive: SkipValidation[RealModelExecutionArchive]
    transport_leakage_audits: list[PublicKnowledgeLeakageAudit] = Field(
        default_factory=list
    )

    @model_validator(mode="before")
    @classmethod
    def validate_nested_archive_with_binding(cls, value: Any) -> Any:
        if not isinstance(value, dict):
            return value
        copied = dict(value)
        binding = PublicKnowledgeExecutionBinding.model_validate(
            copied.get("public_knowledge_execution_binding")
        )
        archive_value = copied.get("real_model_execution_archive")
        if not isinstance(archive_value, RealModelExecutionArchive):
            archive_value = RealModelExecutionArchive.model_validate(
                archive_value,
                context={
                    "public_knowledge_execution_binding": binding
                },
            )
        copied["public_knowledge_execution_binding"] = binding
        copied["real_model_execution_archive"] = archive_value
        return copied

    @field_validator("transport_leakage_audits")
    @classmethod
    def normalize_leakage_audits(
        cls, values: list[PublicKnowledgeLeakageAudit]
    ) -> list[PublicKnowledgeLeakageAudit]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("transport leakage audit IDs must be unique")
        if any(
            item.status is not PublicKnowledgeLeakageAuditStatus.PASS
            for item in values
        ):
            raise ValueError("transport public knowledge leakage audit must pass")
        return sorted(values, key=lambda item: item.prompt_sha256)

    @model_validator(mode="after")
    def validate_cross_bindings_and_identity(self) -> "PublicKnowledgeExecutionArchive":
        binding = self.public_knowledge_execution_binding
        archive = self.real_model_execution_archive
        if archive.experiment_plan_id != binding.experiment_plan_id:
            raise ValueError("public archive experiment plan mismatch")
        if archive.benchmark_manifest.id != binding.benchmark_manifest_id:
            raise ValueError("public archive manifest mismatch")
        if archive.input_set.id != binding.real_experiment_input_set_id:
            raise ValueError("public archive input set mismatch")
        input_contexts = {
            item.benchmark_case_id: item.reasoning_context.id
            for item in archive.input_set.case_inputs
        }
        if input_contexts != {
            item.benchmark_case_id: item.reasoning_context_id
            for item in binding.case_bindings
        }:
            raise ValueError("public archive reasoning context mismatch")

        expected_hashes = binding.expected_prompt_hashes_for_archive()
        reached_hashes: list[str] = []
        for condition in archive.experiment_artifact.condition_records:
            if condition.condition_kind not in {
                AblationConditionKind.FULL_CONTEXT_MODEL,
                AblationConditionKind.MASKED_CHAIN_CONTEXT_MODEL,
            }:
                continue
            for invocation in condition.invocation_records:
                if invocation.prompt_sha256 is None:
                    continue
                key = "|".join(
                    (
                        condition.condition_kind.value,
                        invocation.invocation_key.benchmark_case_id,
                        invocation.invocation_key.role.value,
                    )
                )
                if invocation.prompt_sha256 != expected_hashes.get(key):
                    raise ValueError("public archive prompt hash mismatch")
                reached_hashes.append(invocation.prompt_sha256)
        audit_hashes = [item.prompt_sha256 for item in self.transport_leakage_audits]
        if sorted(audit_hashes) != sorted(reached_hashes):
            raise ValueError("public archive transport leakage accounting mismatch")
        expected = public_knowledge_execution_archive_id(
            contract=self.contract,
            public_knowledge_execution_binding_id=binding.id,
            real_model_execution_archive_id=archive.id,
            transport_leakage_audit_ids=[
                item.id for item in self.transport_leakage_audits
            ],
        )
        if self.id != expected:
            raise ValueError("PublicKnowledgeExecutionArchive ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        binding: PublicKnowledgeExecutionBinding,
        archive: RealModelExecutionArchive,
        transport_leakage_audits: list[PublicKnowledgeLeakageAudit],
    ) -> "PublicKnowledgeExecutionArchive":
        binding_snapshot = PublicKnowledgeExecutionBinding.model_validate(
            binding.model_dump(mode="json")
        )
        audit_snapshots = [
            PublicKnowledgeLeakageAudit.model_validate(item.model_dump(mode="json"))
            for item in transport_leakage_audits
        ]
        values = {
            "contract": PHASE10D_PUBLIC_KNOWLEDGE_EXECUTION_ARCHIVE_CONTRACT,
            "public_knowledge_execution_binding": binding_snapshot,
            "real_model_execution_archive": archive,
            "transport_leakage_audits": audit_snapshots,
        }
        return cls(
            id=public_knowledge_execution_archive_id(
                contract=values["contract"],
                public_knowledge_execution_binding_id=binding_snapshot.id,
                real_model_execution_archive_id=archive.id,
                transport_leakage_audit_ids=[item.id for item in audit_snapshots],
            ),
            **values,
        )
