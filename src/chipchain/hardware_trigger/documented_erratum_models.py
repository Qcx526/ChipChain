"""Authoritative documented-hardware-erratum contracts for Phase 10D.

These models preserve what a vendor errata notice documents.  They are not
runtime observations, experimental proofs, triggerability results, or
verification outcomes.
"""

from __future__ import annotations

import hashlib
import json
from datetime import date
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier
from chipchain.models.enums import Architecture


PHASE10D_DOCUMENTED_ERRATUM_SOURCE_CONTRACT = (
    "phase10d_documented_erratum_source_v1"
)
PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT = (
    "phase10d_documented_hardware_erratum_v1"
)

_EXPECTED_CVE_ID = "CVE-2023-34320"
_EXPECTED_ERRATUM_ID = "1508412"
_EXPECTED_PUBLIC_SOURCE_ARTIFACT = (
    "public-cve-source:arm_cross_layer_seed_v1.source.json"
)
_EXPECTED_PUBLIC_SOURCE_FILE_SHA256 = (
    "32a1f9782a2c966123f7f7bc141adb2d82a7ee8452705e06b1d4835e00f0e848"
)
_EXPECTED_PUBLIC_SOURCE_RECORD_SHA256 = (
    "980a723600d6288617bf924fcc9e6a95e89079c498d8890286c6bb01e43c5a42"
)
_EXPECTED_PUBLIC_CORPUS_ID = (
    "public-cve-corpus:"
    "778765c51a0d9b939eb37b390367a3d0"
    "cd02720942c8746c19eb0a1c38930e49"
)


class AuthoritativeErratumSourceKind(str, Enum):
    """Closed source kind for authoritative documented errata."""

    VENDOR_ERRATA_NOTICE = "vendor_errata_notice"


class AuthoritativeSourceAccessStatus(str, Enum):
    """Access status observed when the concise facts were curated."""

    PUBLICLY_ACCESSIBLE_AT_CURATION = "publicly_accessible_at_curation"


class CpuRevisionDisposition(str, Enum):
    """A revision disposition explicitly stated by the vendor notice."""

    AFFECTED = "affected"
    FIXED = "fixed"


class DocumentedSemanticEventKind(str, Enum):
    """Minimal semantic event vocabulary needed by erratum 1508412."""

    MEMORY_LOAD = "memory_load"
    STORE_EXCLUSIVE = "store_exclusive"
    SYSTEM_REGISTER_READ = "system_register_read"


class DocumentedMemoryType(str, Enum):
    """Memory types explicitly distinguished by the documented cases."""

    DEVICE = "device"
    NORMAL_NON_CACHEABLE = "normal_non_cacheable"


class DocumentedOperationApplicability(str, Enum):
    """Known execution-state applicability without broadening the source."""

    ARM_A_PROFILE = "arm_a_profile"
    PRIVILEGED_AARCH64 = "privileged_aarch64"


class DocumentedProgramRelation(str, Enum):
    """Qualitative program relation stated by the vendor notice."""

    CLOSE_PROXIMITY = "close_proximity"


class DocumentedRelationPrecision(str, Enum):
    """Whether a documented proximity relation includes an exact bound."""

    QUALITATIVE_ONLY = "qualitative_only"
    QUANTITATIVE_BOUND_AVAILABLE = "quantitative_bound_available"


class AdditionalTimingConditionPrecision(str, Enum):
    """Precision of the additional conditions governing possible failure."""

    UNSPECIFIED_BY_PUBLIC_SOURCE = "unspecified_by_public_source"


class DocumentedHardwareEffectKind(str, Enum):
    """Hardware effect documented by the authoritative source."""

    CORE_DEADLOCK = "core_deadlock"


class DocumentedEffectModality(str, Enum):
    """Modal force of a documented hardware effect."""

    POSSIBLE = "possible"


class DocumentedMitigationKind(str, Enum):
    """Concise source-derived mitigation categories, not implementations."""

    PAR_EL1_DMB_SY_ORDERING = "par_el1_dmb_sy_ordering"
    EXCLUSIVE_RELATED_FIRMWARE_OR_HARDWARE = (
        "exclusive_related_firmware_or_hardware"
    )
    CASE_B_EL0_DEVICE_ACCESS_RESTRICTION = (
        "case_b_el0_device_access_restriction"
    )


class DocumentedMitigationSemantics(str, Enum):
    """Separate documentation from an observed mitigation state."""

    DOCUMENTED_MITIGATION = "documented_mitigation"


class DocumentedErratumObjectiveUse(str, Enum):
    """Non-verdict boundary for later objective-observation work."""

    SEMANTIC_PATTERN_REFERENCE_ONLY = "semantic_pattern_reference_only"


class AuthoritativeErratumSource(DomainModel):
    """Stable identity of the authoritative Arm errata notice section."""

    vendor: Literal["Arm"]
    document_id: Literal["SDEN-1152370"]
    document_version: Literal["11.0"]
    issue_date: date
    erratum_id: Literal["1508412"]
    section_title: Literal[
        "NC/Device Load and Store Exclusive or PAR-Read collision can cause deadlock"
    ]
    source_locator: Identifier
    source_kind: Literal[
        AuthoritativeErratumSourceKind.VENDOR_ERRATA_NOTICE
    ]
    source_access_status: Literal[
        AuthoritativeSourceAccessStatus.PUBLICLY_ACCESSIBLE_AT_CURATION
    ]

    @field_validator("source_locator")
    @classmethod
    def validate_stable_logical_locator(cls, value: str) -> str:
        lowered = value.lower()
        if value != "arm-document:SDEN-1152370:11.0:erratum-1508412":
            raise ValueError("source locator must use the frozen logical identity")
        if any(marker in value for marker in ("?", "#")) or any(
            marker in lowered
            for marker in ("token=", "signature=", "access_key=", "secret=")
        ):
            raise ValueError("source locator must not contain transient access data")
        return value

    @field_validator("issue_date")
    @classmethod
    def validate_issue_date(cls, value: date) -> date:
        if value != date(2020, 9, 1):
            raise ValueError("issue date must match Arm SDEN-1152370 version 11.0")
        return value


class CpuRevisionRecord(DomainModel):
    """One explicitly documented Cortex-A77 revision disposition."""

    processor: Literal["Cortex-A77"]
    revision: Literal["r0p0", "r1p0", "r1p1"]
    disposition: CpuRevisionDisposition

    @model_validator(mode="after")
    def validate_revision_disposition(self) -> "CpuRevisionRecord":
        expected = {
            "r0p0": CpuRevisionDisposition.AFFECTED,
            "r1p0": CpuRevisionDisposition.AFFECTED,
            "r1p1": CpuRevisionDisposition.FIXED,
        }
        if self.disposition is not expected[self.revision]:
            raise ValueError("CPU revision disposition contradicts the Arm notice")
        return self


class DocumentedSemanticEvent(DomainModel):
    """One documented semantic operation, not a runtime event."""

    kind: DocumentedSemanticEventKind
    memory_types: list[DocumentedMemoryType] = Field(default_factory=list)
    system_register: Literal["PAR_EL1"] | None = None
    applicability: DocumentedOperationApplicability

    @field_validator("memory_types")
    @classmethod
    def normalize_memory_types(
        cls, values: list[DocumentedMemoryType]
    ) -> list[DocumentedMemoryType]:
        if len(values) != len(set(values)):
            raise ValueError("documented memory types must be unique")
        return sorted(values, key=lambda item: item.value)

    @model_validator(mode="after")
    def validate_event_shape(self) -> "DocumentedSemanticEvent":
        if self.kind is DocumentedSemanticEventKind.MEMORY_LOAD:
            if not self.memory_types or self.system_register is not None:
                raise ValueError("memory load requires only documented memory types")
            if self.applicability is not DocumentedOperationApplicability.ARM_A_PROFILE:
                raise ValueError("memory-load applicability must remain A-profile")
        elif self.kind is DocumentedSemanticEventKind.STORE_EXCLUSIVE:
            if self.memory_types or self.system_register is not None:
                raise ValueError("store exclusive has no memory-type/register payload")
            if self.applicability is not DocumentedOperationApplicability.ARM_A_PROFILE:
                raise ValueError("store-exclusive applicability must remain A-profile")
        else:
            if self.memory_types or self.system_register != "PAR_EL1":
                raise ValueError("system-register read must identify only PAR_EL1")
            if self.applicability is not (
                DocumentedOperationApplicability.PRIVILEGED_AARCH64
            ):
                raise ValueError("PAR_EL1 read requires privileged AArch64")
        return self


class DocumentedEventPosition(DomainModel):
    """One ordered position containing one or more documented alternatives."""

    alternatives: list[DocumentedSemanticEvent] = Field(min_length=1)

    @field_validator("alternatives")
    @classmethod
    def normalize_alternatives(
        cls, values: list[DocumentedSemanticEvent]
    ) -> list[DocumentedSemanticEvent]:
        keys = [item.model_dump_json() for item in values]
        if len(keys) != len(set(keys)):
            raise ValueError("documented event alternatives must be unique")
        return sorted(values, key=lambda item: item.kind.value)


class DocumentedProgramOrderCase(DomainModel):
    """One exact ordered semantic pattern documented for the erratum."""

    case_id: Literal["case_a", "case_b"]
    event_1: DocumentedEventPosition
    event_2: DocumentedEventPosition
    relation: Literal[DocumentedProgramRelation.CLOSE_PROXIMITY]
    relation_precision: Literal[
        DocumentedRelationPrecision.QUALITATIVE_ONLY
    ]
    quantitative_bound: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_exact_case(self) -> "DocumentedProgramOrderCase":
        if self.quantitative_bound is not None:
            raise ValueError("the public source defines no quantitative bound")
        first = self.event_1.alternatives
        second = self.event_2.alternatives
        operation_alternatives = {
            DocumentedSemanticEventKind.STORE_EXCLUSIVE,
            DocumentedSemanticEventKind.SYSTEM_REGISTER_READ,
        }
        if self.case_id == "case_a":
            if {item.kind for item in first} != operation_alternatives:
                raise ValueError("Case A event 1 alternatives are exact")
            if len(second) != 1 or second[0].kind is not (
                DocumentedSemanticEventKind.MEMORY_LOAD
            ):
                raise ValueError("Case A event 2 must be the documented load")
            if set(second[0].memory_types) != {
                DocumentedMemoryType.DEVICE,
                DocumentedMemoryType.NORMAL_NON_CACHEABLE,
            }:
                raise ValueError("Case A load requires Device and Normal-NC")
        else:
            if len(first) != 1 or first[0].kind is not (
                DocumentedSemanticEventKind.MEMORY_LOAD
            ):
                raise ValueError("Case B event 1 must be the documented load")
            if first[0].memory_types != [DocumentedMemoryType.DEVICE]:
                raise ValueError("Case B load permits Device memory only")
            if {item.kind for item in second} != operation_alternatives:
                raise ValueError("Case B event 2 alternatives are exact")
        return self


class DocumentedHardwareEffect(DomainModel):
    """Vendor-documented possible effect; never a runtime observation."""

    kind: Literal[DocumentedHardwareEffectKind.CORE_DEADLOCK]
    modality: Literal[DocumentedEffectModality.POSSIBLE]


class DocumentedMitigation(DomainModel):
    """One documentation-only mitigation category."""

    kind: DocumentedMitigationKind
    semantics: Literal[
        DocumentedMitigationSemantics.DOCUMENTED_MITIGATION
    ]


class DocumentedSourcePrecision(DomainModel):
    """Explicit limits of the public source's semantic precision."""

    program_order_defined: Literal[True]
    quantitative_proximity_bound_defined: Literal[False]
    additional_timing_conditions_fully_defined: Literal[False]
    unique_machine_code_sequence_defined: Literal[False]
    effective_memory_type_resolution_defined: Literal[False]
    runtime_environment_defined: Literal[False]
    hardware_failure_observation_present: Literal[False]


class _DocumentedErratumSemanticBody(DomainModel):
    """Shared, strict semantic body for curated and generated contracts."""

    curation_basis: Literal["authoritative_vendor_documentation"]
    architecture: Literal[Architecture.ARM]
    architecture_profile: Literal["a_profile"]
    processor: Literal["Cortex-A77"]
    cve_id: Literal["CVE-2023-34320"]
    configurations: Literal["all_configurations"]
    authoritative_source: AuthoritativeErratumSource
    revision_records: list[CpuRevisionRecord] = Field(min_length=3, max_length=3)
    program_order_cases: list[DocumentedProgramOrderCase] = Field(
        min_length=2, max_length=2
    )
    additional_timing_condition_precision: Literal[
        AdditionalTimingConditionPrecision.UNSPECIFIED_BY_PUBLIC_SOURCE
    ]
    documented_effect: DocumentedHardwareEffect
    documented_mitigations: list[DocumentedMitigation] = Field(
        min_length=3, max_length=3
    )
    source_precision: DocumentedSourcePrecision
    objective_use: Literal[
        DocumentedErratumObjectiveUse.SEMANTIC_PATTERN_REFERENCE_ONLY
    ]
    public_source_artifact: Literal[_EXPECTED_PUBLIC_SOURCE_ARTIFACT]
    public_source_file_sha256: Identifier
    public_source_record_sha256: Identifier
    public_corpus_id: Identifier

    @field_validator("revision_records")
    @classmethod
    def normalize_revisions(
        cls, values: list[CpuRevisionRecord]
    ) -> list[CpuRevisionRecord]:
        revisions = [item.revision for item in values]
        if len(revisions) != len(set(revisions)):
            raise ValueError("CPU revision records must be unique")
        if set(revisions) != {"r0p0", "r1p0", "r1p1"}:
            raise ValueError("the exact documented revision set is required")
        return sorted(values, key=lambda item: item.revision)

    @field_validator("program_order_cases")
    @classmethod
    def normalize_cases(
        cls, values: list[DocumentedProgramOrderCase]
    ) -> list[DocumentedProgramOrderCase]:
        case_ids = [item.case_id for item in values]
        if len(case_ids) != len(set(case_ids)):
            raise ValueError("documented cases must be unique")
        if set(case_ids) != {"case_a", "case_b"}:
            raise ValueError("Case A and Case B are both required")
        return sorted(values, key=lambda item: item.case_id)

    @field_validator("documented_mitigations")
    @classmethod
    def normalize_mitigations(
        cls, values: list[DocumentedMitigation]
    ) -> list[DocumentedMitigation]:
        kinds = [item.kind for item in values]
        if len(kinds) != len(set(kinds)):
            raise ValueError("documented mitigation categories must be unique")
        if set(kinds) != set(DocumentedMitigationKind):
            raise ValueError("all and only the documented mitigation categories are required")
        return sorted(values, key=lambda item: item.kind.value)

    @field_validator(
        "public_source_file_sha256", "public_source_record_sha256"
    )
    @classmethod
    def validate_sha256(cls, value: str) -> str:
        if len(value) != 64 or any(
            character not in "0123456789abcdef" for character in value
        ):
            raise ValueError("source provenance hashes must be lowercase SHA-256")
        return value

    @model_validator(mode="after")
    def validate_identity_bindings(self) -> "_DocumentedErratumSemanticBody":
        if self.cve_id != _EXPECTED_CVE_ID:
            raise ValueError("documented erratum is bound to CVE-2023-34320")
        if self.authoritative_source.erratum_id != _EXPECTED_ERRATUM_ID:
            raise ValueError("documented erratum identity mismatch")
        if self.public_source_file_sha256 != _EXPECTED_PUBLIC_SOURCE_FILE_SHA256:
            raise ValueError("frozen public-source file SHA-256 changed")
        if self.public_source_record_sha256 != (
            _EXPECTED_PUBLIC_SOURCE_RECORD_SHA256
        ):
            raise ValueError("frozen public-source record SHA-256 changed")
        if self.public_corpus_id != _EXPECTED_PUBLIC_CORPUS_ID:
            raise ValueError("frozen public corpus identity changed")
        return self


class DocumentedErratumSourceDocument(_DocumentedErratumSemanticBody):
    """Human-reviewed offline source for the generated erratum contract."""

    contract: Literal[PHASE10D_DOCUMENTED_ERRATUM_SOURCE_CONTRACT] = (
        PHASE10D_DOCUMENTED_ERRATUM_SOURCE_CONTRACT
    )


def documented_hardware_erratum_id(payload: dict[str, object]) -> str:
    """Return the deterministic semantic identity for one generated contract."""

    canonical = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"documented-hardware-erratum:{hashlib.sha256(canonical).hexdigest()}"


class DocumentedHardwareErratumContract(_DocumentedErratumSemanticBody):
    """Frozen authoritative semantics, separate from objective observation."""

    id: Identifier
    contract: Literal[PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT] = (
        PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT
    )

    @classmethod
    def create(cls, **values: object) -> "DocumentedHardwareErratumContract":
        """Create the strict contract and bind every semantic field into its ID."""

        payload = {
            "contract": PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT,
            **values,
        }
        snapshot = _DocumentedErratumSemanticBody.model_validate(values)
        normalized = snapshot.model_dump(mode="json")
        normalized["contract"] = PHASE10D_DOCUMENTED_HARDWARE_ERRATUM_CONTRACT
        return cls(id=documented_hardware_erratum_id(normalized), **payload)

    @model_validator(mode="after")
    def validate_deterministic_id(self) -> "DocumentedHardwareErratumContract":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != documented_hardware_erratum_id(payload):
            raise ValueError("documented erratum ID does not match semantic content")
        return self
