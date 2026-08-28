"""Human-authoritative public-CVE source contracts without derived IDs."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.corpus.models import (
    ArmArchitectureProfile,
    BenchmarkAdmissionBlocker,
    BenchmarkAdmissionStatus,
    CrossLayerResearchClassification,
    _validate_public_cve_research_facts,
    _validate_safe_text,
)
from chipchain.models import Architecture
from chipchain.models.common import DomainModel, Identifier


PUBLIC_CVE_SOURCE_CONTRACT = "chipchain_public_cve_source_v1"


class PublicCveSourceRecord(DomainModel):
    """Curator-maintained research facts with no generated identity fields."""

    cve_id: Identifier
    architecture: Literal[Architecture.ARM]
    architecture_profile: ArmArchitectureProfile
    title: Identifier
    summary: Identifier
    affected_components: list[Identifier] = Field(min_length=1)
    cross_layer_classification: CrossLayerResearchClassification
    underlying_issue_key: Identifier
    related_cve_ids: list[Identifier] = Field(default_factory=list)
    trigger_summary: Identifier
    precondition_summary: Identifier
    hardware_effect_summary: Identifier
    source_references: list[Identifier] = Field(min_length=1)
    admission_status: BenchmarkAdmissionStatus
    admission_blockers: list[BenchmarkAdmissionBlocker] = Field(min_length=1)

    @field_validator("affected_components", "related_cve_ids", "source_references")
    @classmethod
    def normalize_text_lists(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("public CVE source lists must be unique")
        return sorted(_validate_safe_text(value) for value in values)

    @field_validator("admission_blockers")
    @classmethod
    def normalize_blockers(
        cls, values: list[BenchmarkAdmissionBlocker]
    ) -> list[BenchmarkAdmissionBlocker]:
        if len(values) != len(set(values)):
            raise ValueError("public CVE source blockers must be unique")
        return sorted(values, key=lambda item: item.value)

    @field_validator(
        "title",
        "summary",
        "trigger_summary",
        "precondition_summary",
        "hardware_effect_summary",
    )
    @classmethod
    def reject_raw_or_host_text(cls, value: str) -> str:
        return _validate_safe_text(value)

    @model_validator(mode="after")
    def validate_research_facts(self) -> "PublicCveSourceRecord":
        _validate_public_cve_research_facts(
            cve_id=self.cve_id,
            architecture_profile=self.architecture_profile,
            cross_layer_classification=self.cross_layer_classification,
            underlying_issue_key=self.underlying_issue_key,
            related_cve_ids=self.related_cve_ids,
            admission_status=self.admission_status,
            admission_blockers=self.admission_blockers,
        )
        return self


class PublicCveSourceDocument(DomainModel):
    """Single human-maintained source for one generated corpus snapshot."""

    contract: Literal[PUBLIC_CVE_SOURCE_CONTRACT] = PUBLIC_CVE_SOURCE_CONTRACT
    corpus_name: Identifier
    records: list[PublicCveSourceRecord] = Field(min_length=1)

    @field_validator("corpus_name")
    @classmethod
    def validate_corpus_name(cls, value: str) -> str:
        return _validate_safe_text(value)

    @field_validator("records")
    @classmethod
    def normalize_records(
        cls, values: list[PublicCveSourceRecord]
    ) -> list[PublicCveSourceRecord]:
        return sorted(values, key=lambda item: item.cve_id)

    @model_validator(mode="after")
    def validate_unique_records_and_relations(self) -> "PublicCveSourceDocument":
        record_by_cve = {item.cve_id: item for item in self.records}
        if len(record_by_cve) != len(self.records):
            raise ValueError("public CVE source records must have unique CVE IDs")
        for record in self.records:
            for related_cve_id in record.related_cve_ids:
                related = record_by_cve.get(related_cve_id)
                if related is not None and record.cve_id not in (
                    related.related_cve_ids
                ):
                    raise ValueError(
                        "in-source related CVE links must be reciprocal"
                    )
        return self
