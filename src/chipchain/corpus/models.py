"""Typed public-CVE research intake and benchmark-admission staging."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.knowledge import KnowledgeEntryKind, VulnerabilityKnowledgeEntry
from chipchain.models import Architecture
from chipchain.models.common import DomainModel, Identifier, Metadata


PUBLIC_CVE_CORPUS_CONTRACT = "chipchain_public_cve_corpus_v1"
_CVE_ID = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$")
_ISSUE_KEY = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_FORBIDDEN_TEXT_FRAGMENTS = (
    "<!doctype",
    "<html",
    "owned_synthetic",
)
_LOCAL_PATH_PATTERNS = (
    re.compile(r"(?:^|[\s(\"'=])/(?!/)[^\s]+"),
    re.compile(r"(?:^|[\s(\"'=])~/[^\s]+"),
    re.compile(r"(?:^|[\s(\"'=])[a-z]:[\\/][^\s]+", re.IGNORECASE),
    re.compile(r"(?:^|[\s(\"'=])\\+[^\s]+"),
    re.compile(r"\bfile:/+[^\s]+", re.IGNORECASE),
)
_FORBIDDEN_METADATA_KEYS = frozenset(
    {
        "attackchain",
        "downloadedhtml",
        "evidence",
        "exploitcode",
        "filepath",
        "hostpath",
        "notrealvulnerability",
        "owned",
        "payload",
        "poc",
        "pocpayload",
        "rawhtml",
        "synthetic",
        "verificationrecord",
        "verificationstatus",
        "vulnerabilityverdict",
    }
)


class ArmArchitectureProfile(str, Enum):
    """ARM execution profiles distinguished by the intake contract."""

    A_PROFILE = "a_profile"
    M_PROFILE = "m_profile"


class CrossLayerResearchClassification(str, Enum):
    """Non-verdict research classification for future admission work."""

    TYPE_I_CANDIDATE = "type_i_candidate"
    TYPE_II_CANDIDATE = "type_ii_candidate"
    TYPE_III_CANDIDATE = "type_iii_candidate"
    CROSS_LAYER_RELATED = "cross_layer_related"
    OUT_OF_CURRENT_ARCH_SCOPE = "out_of_current_arch_scope"


class BenchmarkAdmissionStatus(str, Enum):
    """Staging disposition; it is not an evaluation result or verdict."""

    NEXT_OBJECTIVE_CANDIDATE = "next_objective_candidate"
    SECONDARY_ONLY = "secondary_only"
    BLOCKED_CURRENT_VERIFIER = "blocked_current_verifier"
    OUT_OF_CURRENT_ARCH_SCOPE = "out_of_current_arch_scope"


class BenchmarkAdmissionBlocker(str, Enum):
    """Closed reasons that currently prevent objective benchmark admission."""

    NEEDS_A64_SUPPORT = "needs_a64_support"
    NEEDS_TYPE_I_ORACLE = "needs_type_i_oracle"
    NEEDS_STATEFUL_PRECONDITION_MODEL = (
        "needs_stateful_precondition_model"
    )
    NEEDS_SPECULATION_MODEL = "needs_speculation_model"
    NEEDS_BRANCH_HISTORY_MODEL = "needs_branch_history_model"
    NEEDS_CONCURRENCY_MODEL = "needs_concurrency_model"
    TARGET_HARDWARE_VULNERABILITY_UNCLEAR = (
        "target_hardware_vulnerability_unclear"
    )
    M_PROFILE_OUT_OF_CURRENT_SCOPE = "m_profile_out_of_current_scope"


def _canonical_corpus_id(prefix: str, payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(serialized).hexdigest()}"


def _normalized_metadata_key(value: object) -> str:
    return "".join(
        character
        for character in str(value).lower()
        if character.isalnum()
    )


def _validate_safe_text(value: str) -> str:
    lowered = value.lower()
    if any(fragment in lowered for fragment in _FORBIDDEN_TEXT_FRAGMENTS):
        raise ValueError("public CVE corpus contains forbidden raw or host text")
    if any(pattern.search(value) for pattern in _LOCAL_PATH_PATTERNS):
        raise ValueError("public CVE corpus contains a host path")
    return value


def _validate_corpus_metadata(metadata: Metadata) -> Metadata:
    def visit(value: object) -> None:
        if isinstance(value, dict):
            for key, nested in value.items():
                if _normalized_metadata_key(key) in _FORBIDDEN_METADATA_KEYS:
                    raise ValueError(
                        "public CVE metadata contains forbidden execution state"
                    )
                visit(nested)
        elif isinstance(value, list):
            for nested in value:
                visit(nested)
        elif isinstance(value, str):
            _validate_safe_text(value)

    visit(metadata)
    return metadata


def _validate_public_cve_research_facts(
    *,
    cve_id: str,
    architecture_profile: ArmArchitectureProfile,
    cross_layer_classification: CrossLayerResearchClassification,
    underlying_issue_key: str,
    related_cve_ids: list[str],
    admission_status: BenchmarkAdmissionStatus,
    admission_blockers: list[BenchmarkAdmissionBlocker],
) -> None:
    """Apply shared source/generated research-scope invariants."""

    if not _CVE_ID.fullmatch(cve_id):
        raise ValueError("public CVE ID must use canonical CVE syntax")
    if not _ISSUE_KEY.fullmatch(underlying_issue_key):
        raise ValueError("underlying issue key must be a lowercase slug")
    if any(not _CVE_ID.fullmatch(item) for item in related_cve_ids):
        raise ValueError("related CVE IDs must use canonical CVE syntax")
    if cve_id in related_cve_ids:
        raise ValueError("a public CVE cannot relate to itself")

    out_of_scope = (
        cross_layer_classification
        is CrossLayerResearchClassification.OUT_OF_CURRENT_ARCH_SCOPE
    )
    if architecture_profile is ArmArchitectureProfile.M_PROFILE:
        if not out_of_scope or admission_status is not (
            BenchmarkAdmissionStatus.OUT_OF_CURRENT_ARCH_SCOPE
        ):
            raise ValueError(
                "M-profile research cannot enter current objective admission"
            )
        if BenchmarkAdmissionBlocker.M_PROFILE_OUT_OF_CURRENT_SCOPE not in (
            admission_blockers
        ):
            raise ValueError("M-profile research requires its scope blocker")
    if out_of_scope != (
        admission_status is BenchmarkAdmissionStatus.OUT_OF_CURRENT_ARCH_SCOPE
    ):
        raise ValueError("out-of-scope classification and admission must align")
    if (
        cross_layer_classification
        is CrossLayerResearchClassification.CROSS_LAYER_RELATED
        and admission_status
        is BenchmarkAdmissionStatus.NEXT_OBJECTIVE_CANDIDATE
    ):
        raise ValueError(
            "cross-layer-related research cannot become an objective candidate"
        )
    if (
        BenchmarkAdmissionBlocker.TARGET_HARDWARE_VULNERABILITY_UNCLEAR
        in admission_blockers
        and cross_layer_classification
        in {
            CrossLayerResearchClassification.TYPE_I_CANDIDATE,
            CrossLayerResearchClassification.TYPE_II_CANDIDATE,
            CrossLayerResearchClassification.TYPE_III_CANDIDATE,
        }
    ):
        raise ValueError(
            "unclear target hardware cannot receive a strict type candidate"
        )


def public_cve_research_sample_id(
    *,
    cve_id: str,
    architecture: Architecture,
    architecture_profile: ArmArchitectureProfile,
    title: str,
    summary: str,
    affected_components: list[str],
    cross_layer_classification: CrossLayerResearchClassification,
    underlying_issue_key: str,
    related_cve_ids: list[str],
    trigger_summary: str,
    precondition_summary: str,
    hardware_effect_summary: str,
    source_references: list[str],
    admission_status: BenchmarkAdmissionStatus,
    admission_blockers: list[BenchmarkAdmissionBlocker],
    knowledge_entry_id: str,
) -> str:
    """Build identity from stable curated facts, excluding metadata."""

    return _canonical_corpus_id(
        "public-cve-research-sample",
        {
            "admission_blockers": sorted(
                blocker.value for blocker in admission_blockers
            ),
            "admission_status": admission_status.value,
            "affected_components": sorted(affected_components),
            "architecture": architecture.value,
            "architecture_profile": architecture_profile.value,
            "cross_layer_classification": cross_layer_classification.value,
            "cve_id": cve_id,
            "hardware_effect_summary": hardware_effect_summary,
            "knowledge_entry_id": knowledge_entry_id,
            "precondition_summary": precondition_summary,
            "related_cve_ids": sorted(related_cve_ids),
            "source_references": sorted(source_references),
            "summary": summary,
            "title": title,
            "trigger_summary": trigger_summary,
            "underlying_issue_key": underlying_issue_key,
        },
    )


class PublicCveResearchSample(DomainModel):
    """One public-source research record, not an admitted benchmark case."""

    id: Identifier
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
    knowledge_entry_id: Identifier
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("affected_components", "related_cve_ids", "source_references")
    @classmethod
    def normalize_text_lists(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("public CVE identifier lists must be unique")
        return sorted(_validate_safe_text(value) for value in values)

    @field_validator("admission_blockers")
    @classmethod
    def normalize_blockers(
        cls, values: list[BenchmarkAdmissionBlocker]
    ) -> list[BenchmarkAdmissionBlocker]:
        if len(values) != len(set(values)):
            raise ValueError("public CVE admission blockers must be unique")
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

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_corpus_metadata(value)

    @model_validator(mode="after")
    def validate_scope_relations_and_identity(self) -> "PublicCveResearchSample":
        _validate_public_cve_research_facts(
            cve_id=self.cve_id,
            architecture_profile=self.architecture_profile,
            cross_layer_classification=self.cross_layer_classification,
            underlying_issue_key=self.underlying_issue_key,
            related_cve_ids=self.related_cve_ids,
            admission_status=self.admission_status,
            admission_blockers=self.admission_blockers,
        )

        expected_id = public_cve_research_sample_id(
            cve_id=self.cve_id,
            architecture=self.architecture,
            architecture_profile=self.architecture_profile,
            title=self.title,
            summary=self.summary,
            affected_components=self.affected_components,
            cross_layer_classification=self.cross_layer_classification,
            underlying_issue_key=self.underlying_issue_key,
            related_cve_ids=self.related_cve_ids,
            trigger_summary=self.trigger_summary,
            precondition_summary=self.precondition_summary,
            hardware_effect_summary=self.hardware_effect_summary,
            source_references=self.source_references,
            admission_status=self.admission_status,
            admission_blockers=self.admission_blockers,
            knowledge_entry_id=self.knowledge_entry_id,
        )
        if self.id != expected_id:
            raise ValueError("PublicCveResearchSample ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        cve_id: str,
        architecture: Architecture | str,
        architecture_profile: ArmArchitectureProfile | str,
        title: str,
        summary: str,
        affected_components: list[str],
        cross_layer_classification: CrossLayerResearchClassification | str,
        underlying_issue_key: str,
        related_cve_ids: list[str] | None,
        trigger_summary: str,
        precondition_summary: str,
        hardware_effect_summary: str,
        source_references: list[str],
        admission_status: BenchmarkAdmissionStatus | str,
        admission_blockers: list[BenchmarkAdmissionBlocker | str],
        knowledge_entry_id: str,
        metadata: Metadata | None = None,
    ) -> "PublicCveResearchSample":
        """Create a deterministic staging record without producing a verdict."""

        normalized_architecture = Architecture(architecture)
        normalized_profile = ArmArchitectureProfile(architecture_profile)
        normalized_classification = CrossLayerResearchClassification(
            cross_layer_classification
        )
        normalized_status = BenchmarkAdmissionStatus(admission_status)
        normalized_blockers = [
            BenchmarkAdmissionBlocker(item) for item in admission_blockers
        ]
        values = {
            "cve_id": cve_id.strip(),
            "architecture": normalized_architecture,
            "architecture_profile": normalized_profile,
            "title": title.strip(),
            "summary": summary.strip(),
            "affected_components": [item.strip() for item in affected_components],
            "cross_layer_classification": normalized_classification,
            "underlying_issue_key": underlying_issue_key.strip(),
            "related_cve_ids": [
                item.strip() for item in (related_cve_ids or [])
            ],
            "trigger_summary": trigger_summary.strip(),
            "precondition_summary": precondition_summary.strip(),
            "hardware_effect_summary": hardware_effect_summary.strip(),
            "source_references": [item.strip() for item in source_references],
            "admission_status": normalized_status,
            "admission_blockers": normalized_blockers,
            "knowledge_entry_id": knowledge_entry_id.strip(),
        }
        identity = public_cve_research_sample_id(**values)
        return cls(id=identity, **values, metadata=metadata or {})


class PublicCveCorpusSummary(DomainModel):
    """Deterministic CVE-record and independent-issue intake counts."""

    total_cve_records: int = Field(ge=0)
    unique_underlying_issues: int = Field(ge=0)
    classification_counts: dict[CrossLayerResearchClassification, int]
    admission_counts: dict[BenchmarkAdmissionStatus, int]

    @model_validator(mode="after")
    def validate_complete_counts(self) -> "PublicCveCorpusSummary":
        if set(self.classification_counts) != set(
            CrossLayerResearchClassification
        ):
            raise ValueError("classification counts must cover the closed enum")
        if set(self.admission_counts) != set(BenchmarkAdmissionStatus):
            raise ValueError("admission counts must cover the closed enum")
        if any(value < 0 for value in self.classification_counts.values()):
            raise ValueError("classification counts cannot be negative")
        if any(value < 0 for value in self.admission_counts.values()):
            raise ValueError("admission counts cannot be negative")
        if sum(self.classification_counts.values()) != self.total_cve_records:
            raise ValueError("classification counts must cover every CVE record")
        if sum(self.admission_counts.values()) != self.total_cve_records:
            raise ValueError("admission counts must cover every CVE record")
        if self.unique_underlying_issues > self.total_cve_records:
            raise ValueError("underlying issue count cannot exceed CVE records")
        return self


def summarize_public_cve_samples(
    records: list[PublicCveResearchSample],
) -> PublicCveCorpusSummary:
    """Count records separately from curator-declared issue keys."""

    snapshots = [
        PublicCveResearchSample.model_validate(item.model_dump(mode="json"))
        for item in records
    ]
    classification_counts = Counter(
        item.cross_layer_classification for item in snapshots
    )
    admission_counts = Counter(item.admission_status for item in snapshots)
    return PublicCveCorpusSummary(
        total_cve_records=len(snapshots),
        unique_underlying_issues=len(
            {item.underlying_issue_key for item in snapshots}
        ),
        classification_counts={
            key: classification_counts[key]
            for key in CrossLayerResearchClassification
        },
        admission_counts={
            key: admission_counts[key]
            for key in BenchmarkAdmissionStatus
        },
    )


def public_cve_corpus_id(
    *,
    contract: str,
    record_ids: list[str],
    knowledge_entry_ids: list[str],
) -> str:
    """Build an order-independent identity for one curated corpus snapshot."""

    return _canonical_corpus_id(
        "public-cve-corpus",
        {
            "contract": contract,
            "knowledge_entry_ids": sorted(knowledge_entry_ids),
            "record_ids": sorted(record_ids),
        },
    )


class PublicCveCorpus(DomainModel):
    """Validated public research corpus isolated from benchmark execution."""

    id: Identifier
    contract: Literal[PUBLIC_CVE_CORPUS_CONTRACT] = PUBLIC_CVE_CORPUS_CONTRACT
    records: list[PublicCveResearchSample] = Field(min_length=1)
    knowledge_entries: list[VulnerabilityKnowledgeEntry] = Field(min_length=1)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("records")
    @classmethod
    def normalize_records(
        cls, values: list[PublicCveResearchSample]
    ) -> list[PublicCveResearchSample]:
        return sorted(values, key=lambda item: item.cve_id)

    @field_validator("knowledge_entries")
    @classmethod
    def normalize_knowledge_entries(
        cls, values: list[VulnerabilityKnowledgeEntry]
    ) -> list[VulnerabilityKnowledgeEntry]:
        return sorted(values, key=lambda item: item.external_id)

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: Metadata) -> Metadata:
        return _validate_corpus_metadata(value)

    @model_validator(mode="after")
    def validate_bindings_relations_and_identity(self) -> "PublicCveCorpus":
        cve_ids = [item.cve_id for item in self.records]
        record_ids = [item.id for item in self.records]
        knowledge_ids = [item.id for item in self.knowledge_entries]
        if len(cve_ids) != len(set(cve_ids)):
            raise ValueError("public CVE records must have unique CVE IDs")
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("public CVE record IDs must be unique")
        if len(knowledge_ids) != len(set(knowledge_ids)):
            raise ValueError("public CVE knowledge entry IDs must be unique")
        if len(self.records) != len(self.knowledge_entries):
            raise ValueError("public CVE corpus requires one knowledge entry per record")

        entry_by_id = {item.id: item for item in self.knowledge_entries}
        record_by_cve = {item.cve_id: item for item in self.records}
        for entry in self.knowledge_entries:
            _validate_corpus_metadata(entry.metadata)
            for value in (
                entry.title,
                entry.summary,
                *entry.affected_components,
                *entry.references,
            ):
                _validate_safe_text(value)
        for record in self.records:
            entry = entry_by_id.get(record.knowledge_entry_id)
            if entry is None:
                raise ValueError("public CVE record references unknown knowledge entry")
            if (
                entry.entry_kind is not KnowledgeEntryKind.CVE
                or entry.external_id != record.cve_id
                or entry.architecture is not record.architecture
                or entry.affected_components != record.affected_components
                or entry.references != record.source_references
            ):
                raise ValueError("public CVE knowledge entry binding mismatch")
            for related_cve_id in record.related_cve_ids:
                related = record_by_cve.get(related_cve_id)
                if related is not None and record.cve_id not in (
                    related.related_cve_ids
                ):
                    raise ValueError("in-corpus related CVE links must be reciprocal")

        expected_id = public_cve_corpus_id(
            contract=self.contract,
            record_ids=record_ids,
            knowledge_entry_ids=knowledge_ids,
        )
        if self.id != expected_id:
            raise ValueError("PublicCveCorpus ID is not deterministic")
        return self

    @property
    def summary(self) -> PublicCveCorpusSummary:
        """Return detached intake and admission counts."""

        return summarize_public_cve_samples(self.records)

    @classmethod
    def create(
        cls,
        *,
        records: list[PublicCveResearchSample],
        knowledge_entries: list[VulnerabilityKnowledgeEntry],
        metadata: Metadata | None = None,
    ) -> "PublicCveCorpus":
        """Create a detached corpus snapshot from curated typed inputs."""

        record_snapshots = [
            PublicCveResearchSample.model_validate(item.model_dump(mode="json"))
            for item in records
        ]
        entry_snapshots = [
            VulnerabilityKnowledgeEntry.model_validate(
                item.model_dump(mode="json")
            )
            for item in knowledge_entries
        ]
        identity = public_cve_corpus_id(
            contract=PUBLIC_CVE_CORPUS_CONTRACT,
            record_ids=[item.id for item in record_snapshots],
            knowledge_entry_ids=[item.id for item in entry_snapshots],
        )
        return cls(
            id=identity,
            records=record_snapshots,
            knowledge_entries=entry_snapshots,
            metadata=metadata or {},
        )
