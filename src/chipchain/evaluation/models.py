"""Immutable-identity Phase 10A benchmark and Ground Truth contracts."""

from __future__ import annotations

import hashlib
import json
import re

from pydantic import Field, field_validator, model_validator

from chipchain.evaluation.enums import (
    BenchmarkCaseLabel,
    BenchmarkSourceKind,
    EvaluationScope,
)
from chipchain.models.common import DomainModel, Identifier, Metadata
from chipchain.models.cross_layer import CrossLayerInteraction
from chipchain.models.enums import Architecture


_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_ABSOLUTE_PATH = re.compile(r"^[A-Za-z]:[\\/]")


def _canonical_hash(prefix: str, payload: object) -> str:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(serialized).hexdigest()}"


def _canonical_sha256(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("artifact SHA-256 must be lowercase hexadecimal")
    candidate = value.strip()
    if not _SHA256.fullmatch(candidate):
        raise ValueError("artifact SHA-256 must be 64 lowercase hexadecimal digits")
    return candidate


def _path_neutral_reference(value: object) -> str:
    if not isinstance(value, str) or not (candidate := value.strip()):
        raise ValueError("artifact reference must be non-empty text")
    if (
        candidate.startswith(("/", "\\", "~"))
        or _WINDOWS_ABSOLUTE_PATH.match(candidate)
        or candidate.lower().startswith("file:")
        or "\\" in candidate
        or ".." in candidate.split("/")
    ):
        raise ValueError("artifact reference must not be a host absolute path")
    return candidate


class BenchmarkArtifactReference(DomainModel):
    """Path-neutral reference to immutable benchmark artifact bytes."""

    artifact_id: Identifier
    architecture: Architecture
    artifact_type: Identifier
    artifact_sha256: Identifier
    artifact_reference: Identifier

    @field_validator("artifact_sha256", mode="before")
    @classmethod
    def validate_sha256(cls, value: object) -> str:
        return _canonical_sha256(value)

    @field_validator("artifact_reference", mode="before")
    @classmethod
    def validate_reference(cls, value: object) -> str:
        return _path_neutral_reference(value)

    @model_validator(mode="after")
    def validate_architecture_scope(self) -> "BenchmarkArtifactReference":
        if self.architecture is not Architecture.ARM:
            raise ValueError("Phase 10A benchmark artifacts support ARM only")
        return self


def ground_truth_chain_id(
    *,
    architecture: Architecture,
    cross_layer_interaction_id: str,
    hardware_trigger_signature_id: str | None,
    expected_attack_pattern_reference: str | None,
    source_reference_ids: list[str],
) -> str:
    """Build identity from typed chain truth and stable provenance references."""

    return _canonical_hash(
        "ground-truth-chain",
        {
            "architecture": Architecture(architecture).value,
            "cross_layer_interaction_id": cross_layer_interaction_id,
            "expected_attack_pattern_reference": expected_attack_pattern_reference,
            "hardware_trigger_signature_id": hardware_trigger_signature_id,
            "source_reference_ids": sorted(source_reference_ids),
        },
    )


class GroundTruthChain(DomainModel):
    """Typed feasible-chain Ground Truth; deliberately not an AttackChain."""

    id: Identifier
    architecture: Architecture
    cross_layer_interaction: CrossLayerInteraction
    hardware_trigger_signature_id: Identifier | None = None
    expected_attack_pattern_reference: Identifier | None = None
    source_reference_ids: list[Identifier] = Field(min_length=1)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("source_reference_ids")
    @classmethod
    def normalize_source_references(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("Ground Truth source reference IDs must be unique")
        return sorted(values)

    @model_validator(mode="after")
    def validate_semantics_and_identity(self) -> "GroundTruthChain":
        if self.architecture is not Architecture.ARM:
            raise ValueError("Phase 10A Ground Truth supports ARM only")
        if self.cross_layer_interaction.architecture is not self.architecture:
            raise ValueError("Ground Truth interaction architecture mismatch")
        if self.cross_layer_interaction.metadata:
            raise ValueError("Ground Truth interaction metadata must be empty")
        expected_id = ground_truth_chain_id(
            architecture=self.architecture,
            cross_layer_interaction_id=self.cross_layer_interaction.id,
            hardware_trigger_signature_id=self.hardware_trigger_signature_id,
            expected_attack_pattern_reference=self.expected_attack_pattern_reference,
            source_reference_ids=self.source_reference_ids,
        )
        if self.id != expected_id:
            raise ValueError("GroundTruthChain ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        cross_layer_interaction: CrossLayerInteraction,
        hardware_trigger_signature_id: str | None = None,
        expected_attack_pattern_reference: str | None = None,
        source_reference_ids: list[str],
        metadata: Metadata | None = None,
    ) -> "GroundTruthChain":
        """Create a detached typed Ground Truth chain with empty interaction metadata."""

        if not isinstance(cross_layer_interaction, CrossLayerInteraction):
            raise TypeError("Ground Truth requires a CrossLayerInteraction")
        interaction_values = cross_layer_interaction.model_dump(mode="json")
        interaction_values["metadata"] = {}
        interaction = CrossLayerInteraction.model_validate(interaction_values)
        references = sorted(item.strip() for item in source_reference_ids)
        signature_id = (
            hardware_trigger_signature_id.strip()
            if hardware_trigger_signature_id is not None
            else None
        )
        attack_reference = (
            expected_attack_pattern_reference.strip()
            if expected_attack_pattern_reference is not None
            else None
        )
        identity = ground_truth_chain_id(
            architecture=interaction.architecture,
            cross_layer_interaction_id=interaction.id,
            hardware_trigger_signature_id=signature_id,
            expected_attack_pattern_reference=attack_reference,
            source_reference_ids=references,
        )
        return cls(
            id=identity,
            architecture=interaction.architecture,
            cross_layer_interaction=interaction,
            hardware_trigger_signature_id=signature_id,
            expected_attack_pattern_reference=attack_reference,
            source_reference_ids=references,
            metadata=metadata or {},
        )


def benchmark_case_id(
    *,
    benchmark_version: str,
    architecture: Architecture,
    source_kind: BenchmarkSourceKind,
    label: BenchmarkCaseLabel,
    artifact: BenchmarkArtifactReference,
    ground_truth_chain_ids: list[str],
    source_reference_ids: list[str],
    evaluation_scope: EvaluationScope,
) -> str:
    """Build one case identity from predeclared truth and scope semantics."""

    return _canonical_hash(
        "evaluation-benchmark-case",
        {
            "architecture": Architecture(architecture).value,
            "artifact": artifact.model_dump(mode="json"),
            "benchmark_version": benchmark_version,
            "evaluation_scope": EvaluationScope(evaluation_scope).value,
            "ground_truth_chain_ids": sorted(ground_truth_chain_ids),
            "label": BenchmarkCaseLabel(label).value,
            "source_kind": BenchmarkSourceKind(source_kind).value,
            "source_reference_ids": sorted(source_reference_ids),
        },
    )


class EvaluationBenchmarkCase(DomainModel):
    """One predeclared positive or negative Phase 10A benchmark case."""

    id: Identifier
    benchmark_version: Identifier
    architecture: Architecture
    source_kind: BenchmarkSourceKind
    label: BenchmarkCaseLabel
    artifact: BenchmarkArtifactReference
    ground_truth_chains: list[GroundTruthChain] = Field(default_factory=list)
    source_reference_ids: list[Identifier] = Field(default_factory=list)
    evaluation_scope: EvaluationScope
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("source_reference_ids")
    @classmethod
    def normalize_source_references(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("benchmark source reference IDs must be unique")
        return sorted(values)

    @field_validator("ground_truth_chains")
    @classmethod
    def normalize_ground_truth(
        cls, values: list[GroundTruthChain]
    ) -> list[GroundTruthChain]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("Ground Truth chain IDs must be unique within a case")
        return sorted(values, key=lambda item: item.id)

    @model_validator(mode="after")
    def validate_case_semantics_and_identity(self) -> "EvaluationBenchmarkCase":
        if self.architecture is not Architecture.ARM:
            raise ValueError("Phase 10A benchmark cases support ARM only")
        if self.artifact.architecture is not self.architecture:
            raise ValueError("benchmark artifact architecture mismatch")
        if any(
            item.architecture is not self.architecture
            for item in self.ground_truth_chains
        ):
            raise ValueError("Ground Truth chain architecture mismatch")
        if (
            self.source_kind
            in {
                BenchmarkSourceKind.PUBLIC_BENCHMARK,
                BenchmarkSourceKind.PUBLIC_DOCUMENTED,
            }
            and not self.source_reference_ids
        ):
            raise ValueError("public benchmark sources require stable references")
        if (
            self.label is BenchmarkCaseLabel.POSITIVE_FEASIBLE
            and not self.ground_truth_chains
        ):
            raise ValueError("positive feasible cases require Ground Truth chains")
        if (
            self.label is BenchmarkCaseLabel.NEGATIVE_CONTROL
            and self.ground_truth_chains
        ):
            raise ValueError("negative control cases require zero feasible chains")
        expected_id = benchmark_case_id(
            benchmark_version=self.benchmark_version,
            architecture=self.architecture,
            source_kind=self.source_kind,
            label=self.label,
            artifact=self.artifact,
            ground_truth_chain_ids=[item.id for item in self.ground_truth_chains],
            source_reference_ids=self.source_reference_ids,
            evaluation_scope=self.evaluation_scope,
        )
        if self.id != expected_id:
            raise ValueError("EvaluationBenchmarkCase ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        benchmark_version: str,
        architecture: Architecture | str,
        source_kind: BenchmarkSourceKind | str,
        label: BenchmarkCaseLabel | str,
        artifact: BenchmarkArtifactReference,
        ground_truth_chains: list[GroundTruthChain] | None = None,
        source_reference_ids: list[str] | None = None,
        evaluation_scope: EvaluationScope | str,
        metadata: Metadata | None = None,
    ) -> "EvaluationBenchmarkCase":
        """Create a detached case whose truth and metric scope are predeclared."""

        if not isinstance(artifact, BenchmarkArtifactReference):
            raise TypeError("benchmark case requires BenchmarkArtifactReference")
        detached_artifact = BenchmarkArtifactReference.model_validate(
            artifact.model_dump(mode="json")
        )
        chains = [
            GroundTruthChain.model_validate(item.model_dump(mode="json"))
            for item in (ground_truth_chains or [])
        ]
        source_references = sorted(
            item.strip() for item in (source_reference_ids or [])
        )
        normalized_architecture = Architecture(architecture)
        normalized_source_kind = BenchmarkSourceKind(source_kind)
        normalized_label = BenchmarkCaseLabel(label)
        scope = EvaluationScope(evaluation_scope)
        version = benchmark_version.strip()
        identity = benchmark_case_id(
            benchmark_version=version,
            architecture=normalized_architecture,
            source_kind=normalized_source_kind,
            label=normalized_label,
            artifact=detached_artifact,
            ground_truth_chain_ids=[item.id for item in chains],
            source_reference_ids=source_references,
            evaluation_scope=scope,
        )
        return cls(
            id=identity,
            benchmark_version=version,
            architecture=normalized_architecture,
            source_kind=normalized_source_kind,
            label=normalized_label,
            artifact=detached_artifact,
            ground_truth_chains=chains,
            source_reference_ids=source_references,
            evaluation_scope=scope,
            metadata=metadata or {},
        )


def benchmark_manifest_id(
    *,
    benchmark_version: str,
    architecture_scope: list[Architecture],
    case_ids: list[str],
) -> str:
    """Build identity for one fixed, versioned benchmark case set."""

    return _canonical_hash(
        "benchmark-manifest",
        {
            "architecture_scope": sorted(
                Architecture(item).value for item in architecture_scope
            ),
            "benchmark_version": benchmark_version,
            "case_ids": sorted(case_ids),
        },
    )


class BenchmarkManifest(DomainModel):
    """Versioned ARM-first benchmark manifest with deterministic ordering."""

    id: Identifier
    benchmark_version: Identifier
    architecture_scope: list[Architecture] = Field(min_length=1)
    cases: list[EvaluationBenchmarkCase] = Field(min_length=1)
    metadata: Metadata = Field(default_factory=dict)

    @field_validator("architecture_scope")
    @classmethod
    def normalize_architecture_scope(
        cls, values: list[Architecture]
    ) -> list[Architecture]:
        if len(values) != len(set(values)):
            raise ValueError("manifest architecture scope must be unique")
        normalized = sorted(values, key=lambda item: item.value)
        if normalized != [Architecture.ARM]:
            raise ValueError("Phase 10A benchmark manifest is ARM-only")
        return normalized

    @field_validator("cases")
    @classmethod
    def normalize_cases(
        cls, values: list[EvaluationBenchmarkCase]
    ) -> list[EvaluationBenchmarkCase]:
        if len(values) != len({item.id for item in values}):
            raise ValueError("benchmark manifest case IDs must be unique")
        chain_ids = [
            chain.id
            for case in values
            for chain in case.ground_truth_chains
        ]
        if len(chain_ids) != len(set(chain_ids)):
            raise ValueError("benchmark manifest Ground Truth chain IDs must be unique")
        return sorted(values, key=lambda item: item.id)

    @model_validator(mode="after")
    def validate_manifest_semantics_and_identity(self) -> "BenchmarkManifest":
        scope = set(self.architecture_scope)
        if any(item.architecture not in scope for item in self.cases):
            raise ValueError("benchmark case architecture is outside manifest scope")
        if any(
            item.benchmark_version != self.benchmark_version
            for item in self.cases
        ):
            raise ValueError("benchmark case version mismatch")
        expected_id = benchmark_manifest_id(
            benchmark_version=self.benchmark_version,
            architecture_scope=self.architecture_scope,
            case_ids=[item.id for item in self.cases],
        )
        if self.id != expected_id:
            raise ValueError("BenchmarkManifest ID is not deterministic")
        return self

    @classmethod
    def create(
        cls,
        *,
        benchmark_version: str,
        architecture_scope: list[Architecture | str],
        cases: list[EvaluationBenchmarkCase],
        metadata: Metadata | None = None,
    ) -> "BenchmarkManifest":
        """Create a detached manifest; input ordering cannot affect identity."""

        version = benchmark_version.strip()
        architectures = [Architecture(item) for item in architecture_scope]
        detached_cases = [
            EvaluationBenchmarkCase.model_validate(item.model_dump(mode="json"))
            for item in cases
        ]
        identity = benchmark_manifest_id(
            benchmark_version=version,
            architecture_scope=architectures,
            case_ids=[item.id for item in detached_cases],
        )
        return cls(
            id=identity,
            benchmark_version=version,
            architecture_scope=architectures,
            cases=detached_cases,
            metadata=metadata or {},
        )
