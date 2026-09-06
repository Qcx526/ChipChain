"""Pure source-bound runtime evidence extraction for 2D4-A requirements."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Literal

from pydantic import Field, field_validator, model_validator

from chipchain.models.common import DomainModel, Identifier
from chipchain.runtime.enums import RuntimeEventKind
from chipchain.runtime.models import RuntimeObservation, RuntimeTrace
from chipchain.verification.candidate_runtime_evidence_models import (
    CandidateRuntimeEvidenceGap,
    CandidateRuntimeEvidenceKind,
    CandidateRuntimeEvidenceProjection,
    CandidateRuntimeInstructionEvidence,
    CandidateRuntimeOrderEvidence,
    CandidateRuntimeRequirementEvidenceBinding,
    CandidateRuntimeTraceIncompatibility,
    CandidateRuntimeTraceIncompatibilityReason,
    candidate_runtime_acquisition_gap_reason,
)
from chipchain.verification.cross_layer_requirement_models import (
    StaticCandidateVerificationRequirement,
    StaticCrossLayerEvidenceRequirementKind,
)
from chipchain.verification.cross_layer_requirements import (
    StaticCrossLayerVerificationRequirementMaterialization,
)


PHASE10D_CANDIDATE_RUNTIME_EVIDENCE_MATERIALIZATION_CONTRACT = (
    "phase10d_candidate_runtime_evidence_materialization_v1"
)

_SUPPORTED_REQUIREMENT_KINDS = {
    StaticCrossLayerEvidenceRequirementKind.RUNTIME_EXECUTION_TRACE_REQUIRED,
    StaticCrossLayerEvidenceRequirementKind.PATH_FEASIBILITY_EVIDENCE_REQUIRED,
}


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def candidate_runtime_evidence_materialization_id(payload: object) -> str:
    """Return one deterministic authoritative B1 materialization ID."""

    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"candidate-runtime-evidence-materialization:{digest}"


@dataclass(frozen=True)
class _ResolvedSubject:
    position_candidate_id: str
    fused_fact_node_id: str
    instruction_address: str


def _candidate_source(requirements: StaticCrossLayerVerificationRequirementMaterialization):
    return (
        requirements.source_cross_layer_candidate_materialization_snapshot
        .source_candidate_materialization_snapshot
    )


def _resolve_requirement_subjects(
    requirements: StaticCrossLayerVerificationRequirementMaterialization,
    requirement: StaticCandidateVerificationRequirement,
) -> list[_ResolvedSubject]:
    candidate_source = _candidate_source(requirements)
    candidate = next(
        (
            item
            for item in candidate_source.projection.case_candidates
            if item.id == requirement.source_case_candidate_id
        ),
        None,
    )
    if candidate is None:
        raise ValueError("runtime requirement references an absent candidate")
    positions = {
        item.id: item
        for item in candidate.position_candidates
        if item.id in requirement.subject_position_candidate_ids
    }
    if set(positions) != set(requirement.subject_position_candidate_ids):
        raise ValueError("runtime requirement references a foreign position")

    fused = candidate_source.source_fused_graph_materialization_snapshot
    fused_nodes = {item.id: item for item in fused.projection.nodes}
    semantic_facts = {
        item.id: item
        for item in (
            fused.source_semantic_graph_materialization
            .source_inventory_snapshot.facts
        )
    }
    resolved = []
    for position in positions.values():
        if position.source_fused_fact_node_id not in (
            requirement.subject_fused_fact_node_ids
        ):
            raise ValueError("runtime requirement position/fact linkage mismatch")
        fused_fact = fused_nodes.get(position.source_fused_fact_node_id)
        if fused_fact is None or fused_fact.instruction_address is None:
            raise ValueError("runtime requirement fused fact is absent")
        if len(position.source_semantic_fact_ids) != 1:
            raise ValueError("runtime requirement needs one semantic fact source")
        semantic_fact = semantic_facts.get(position.source_semantic_fact_ids[0])
        if semantic_fact is None:
            raise ValueError("runtime requirement semantic fact is absent")
        if position.source_semantic_fact_ids[0] not in (
            fused_fact.semantic_source_fact_ids
        ):
            raise ValueError("fused fact semantic provenance mismatch")
        addresses = {
            position.instruction_address,
            fused_fact.instruction_address,
            semantic_fact.instruction_address,
        }
        if len(addresses) != 1:
            raise ValueError("runtime requirement instruction address mismatch")
        resolved.append(
            _ResolvedSubject(
                position_candidate_id=position.id,
                fused_fact_node_id=position.source_fused_fact_node_id,
                instruction_address=semantic_fact.instruction_address,
            )
        )
    if {item.fused_fact_node_id for item in resolved} != set(
        requirement.subject_fused_fact_node_ids
    ):
        raise ValueError("runtime requirement subject fact set is incomplete")
    return sorted(resolved, key=lambda item: item.position_candidate_id)


def _trace_common(trace: RuntimeTrace) -> dict[str, object]:
    return {
        "source_runtime_trace_id": trace.manifest.id,
        "source_runtime_manifest_id": trace.manifest.id,
        "source_runtime_backend_manifest_id": trace.backend_manifest.id,
        "source_runtime_backend_kind": trace.backend_manifest.backend_kind,
        "source_runtime_run_mode": trace.manifest.run_mode,
    }


def _incompatibility_reasons(
    requirements: StaticCrossLayerVerificationRequirementMaterialization,
    trace: RuntimeTrace,
) -> list[CandidateRuntimeTraceIncompatibilityReason]:
    projection = requirements.projection
    reasons = []
    if trace.manifest.architecture is not projection.architecture:
        reasons.append(
            CandidateRuntimeTraceIncompatibilityReason.ARCHITECTURE_MISMATCH
        )
    if trace.manifest.artifact_id != projection.artifact_id:
        reasons.append(
            CandidateRuntimeTraceIncompatibilityReason.ARTIFACT_ID_MISMATCH
        )
    if trace.manifest.artifact_sha256 != projection.artifact_sha256:
        reasons.append(
            CandidateRuntimeTraceIncompatibilityReason.ARTIFACT_SHA256_MISMATCH
        )
    return reasons


def _instruction_observations(
    trace: RuntimeTrace, address: str
) -> list[RuntimeObservation]:
    return [
        item
        for item in trace.observations
        if item.event_kind is RuntimeEventKind.INSTRUCTION_EXEC
        and item.pc is not None
        and item.pc.value == address
    ]


def _binding_values(
    requirements: StaticCrossLayerVerificationRequirementMaterialization,
    requirement: StaticCandidateVerificationRequirement,
    evidence_id: str,
) -> dict[str, object]:
    return {
        "source_requirement_materialization_id": requirements.id,
        "source_requirement_projection_id": requirements.projection.id,
        "source_requirement_id": requirement.id,
        "source_requirement_kind": requirement.evidence_requirement_kind,
        "source_case_candidate_id": requirement.source_case_candidate_id,
        "source_runtime_evidence_id": evidence_id,
    }


def _project_candidate_runtime_evidence(
    requirements: StaticCrossLayerVerificationRequirementMaterialization,
    runtime_traces: list[RuntimeTrace],
) -> CandidateRuntimeEvidenceProjection:
    requirement_projection = requirements.projection
    compatible = []
    incompatible = []
    for trace in runtime_traces:
        reasons = _incompatibility_reasons(requirements, trace)
        if not reasons:
            compatible.append(trace)
            continue
        incompatible.append(
            CandidateRuntimeTraceIncompatibility.create(
                **_trace_common(trace),
                observed_architecture=trace.manifest.architecture,
                observed_artifact_id=trace.manifest.artifact_id,
                observed_artifact_sha256=trace.manifest.artifact_sha256,
                reasons=reasons,
            )
        )

    candidate_requirements = requirement_projection.candidate_requirements
    supported = [
        item
        for item in candidate_requirements
        if item.evidence_requirement_kind in _SUPPORTED_REQUIREMENT_KINDS
    ]
    subjects_by_requirement = {
        item.id: _resolve_requirement_subjects(requirements, item)
        for item in supported
    }
    fact_sources: dict[str, dict[str, object]] = {}
    for subjects in subjects_by_requirement.values():
        for subject in subjects:
            entry = fact_sources.setdefault(
                subject.fused_fact_node_id,
                {
                    "address": subject.instruction_address,
                    "positions": set(),
                },
            )
            if entry["address"] != subject.instruction_address:
                raise ValueError("one fused fact has conflicting instruction addresses")
            positions = entry["positions"]
            if not isinstance(positions, set):
                raise TypeError("internal runtime subject positions are invalid")
            positions.add(subject.position_candidate_id)

    facts_by_address: dict[str, list[str]] = {}
    for fact_id, values in fact_sources.items():
        address = values["address"]
        if not isinstance(address, str):
            raise TypeError("internal runtime subject address is invalid")
        facts_by_address.setdefault(address, []).append(fact_id)

    artifact_common = {
        "architecture": requirement_projection.architecture,
        "artifact_id": requirement_projection.artifact_id,
        "artifact_sha256": requirement_projection.artifact_sha256,
        "instruction_set": requirement_projection.instruction_set,
    }
    instruction_evidence = []
    for trace in compatible:
        for observation in trace.observations:
            if (
                observation.event_kind is not RuntimeEventKind.INSTRUCTION_EXEC
                or observation.pc is None
            ):
                continue
            fact_ids = sorted(facts_by_address.get(observation.pc.value, []))
            if not fact_ids:
                continue
            position_ids = sorted(
                {
                    position_id
                    for fact_id in fact_ids
                    for position_id in fact_sources[fact_id]["positions"]
                }
            )
            instruction_evidence.append(
                CandidateRuntimeInstructionEvidence.create(
                    **artifact_common,
                    **_trace_common(trace),
                    source_position_candidate_ids=position_ids,
                    source_fused_fact_node_ids=fact_ids,
                    expected_instruction_address=observation.pc,
                    source_runtime_observation_id=observation.id,
                    observation_sequence_index=observation.sequence_index,
                    observation_vcpu_index=observation.vcpu_index,
                    observed_pc=observation.pc,
                )
            )

    requirement_evidence_bindings = []
    for evidence in instruction_evidence:
        evidence_facts = set(evidence.source_fused_fact_node_ids)
        for requirement in supported:
            requirement_facts = {
                item.fused_fact_node_id
                for item in subjects_by_requirement[requirement.id]
            }
            if evidence_facts.intersection(requirement_facts):
                requirement_evidence_bindings.append(
                    CandidateRuntimeRequirementEvidenceBinding.create(
                        **_binding_values(requirements, requirement, evidence.id)
                    )
                )

    candidate_source = _candidate_source(requirements)
    candidates = {
        item.id: item for item in candidate_source.projection.case_candidates
    }
    order_evidence_by_id: dict[str, CandidateRuntimeOrderEvidence] = {}
    path_requirements = [
        item
        for item in supported
        if item.evidence_requirement_kind
        is StaticCrossLayerEvidenceRequirementKind
        .PATH_FEASIBILITY_EVIDENCE_REQUIRED
    ]
    for requirement in path_requirements:
        candidate = candidates[requirement.source_case_candidate_id]
        witnesses = {
            item.id: item for item in candidate.order_witnesses
        }
        subjects = {
            item.position_candidate_id: item
            for item in subjects_by_requirement[requirement.id]
        }
        for witness_id in requirement.subject_order_witness_ids:
            witness = witnesses.get(witness_id)
            if witness is None:
                raise ValueError("path requirement references an absent witness")
            source = subjects.get(witness.source_position_candidate_id)
            target = subjects.get(witness.target_position_candidate_id)
            if source is None or target is None:
                raise ValueError("path witness endpoint is outside requirement subjects")
            for trace in compatible:
                source_observations = _instruction_observations(
                    trace, source.instruction_address
                )
                target_observations = _instruction_observations(
                    trace, target.instruction_address
                )
                for source_observation in source_observations:
                    for target_observation in target_observations:
                        if (
                            source_observation.vcpu_index
                            != target_observation.vcpu_index
                            or source_observation.sequence_index
                            >= target_observation.sequence_index
                        ):
                            continue
                        evidence = CandidateRuntimeOrderEvidence.create(
                            **artifact_common,
                            **_trace_common(trace),
                            source_static_order_witness_id=witness.id,
                            source_position_candidate_id=source.position_candidate_id,
                            target_position_candidate_id=target.position_candidate_id,
                            source_fused_fact_node_id=source.fused_fact_node_id,
                            target_fused_fact_node_id=target.fused_fact_node_id,
                            expected_source_instruction_address=(
                                source.instruction_address
                            ),
                            expected_target_instruction_address=(
                                target.instruction_address
                            ),
                            source_runtime_observation_id=source_observation.id,
                            target_runtime_observation_id=target_observation.id,
                            source_sequence_index=(
                                source_observation.sequence_index
                            ),
                            target_sequence_index=(
                                target_observation.sequence_index
                            ),
                            vcpu_index=source_observation.vcpu_index,
                        )
                        retained = order_evidence_by_id.get(evidence.id)
                        if retained is None:
                            order_evidence_by_id[evidence.id] = (
                                CandidateRuntimeOrderEvidence.model_validate(
                                    evidence.model_dump(mode="json")
                                )
                            )
                        elif retained != evidence:
                            raise ValueError("runtime order evidence ID collision")
                        requirement_evidence_bindings.append(
                            CandidateRuntimeRequirementEvidenceBinding.create(
                                **_binding_values(
                                    requirements, requirement, evidence.id
                                )
                            )
                        )

    order_evidence = list(order_evidence_by_id.values())
    catalog = {item.id: item for item in [*instruction_evidence, *order_evidence]}
    kinds_by_requirement: dict[str, set[CandidateRuntimeEvidenceKind]] = {}
    for binding in requirement_evidence_bindings:
        kinds_by_requirement.setdefault(binding.source_requirement_id, set()).add(
            catalog[binding.source_runtime_evidence_id].evidence_kind
        )
    evidence_gaps = []
    for requirement in candidate_requirements:
        reason = candidate_runtime_acquisition_gap_reason(
            requirement.evidence_requirement_kind,
            has_compatible_trace=bool(compatible),
            evidence_kinds=kinds_by_requirement.get(requirement.id, set()),
        )
        if reason is None:
            continue
        evidence_gaps.append(
            CandidateRuntimeEvidenceGap.create(
                source_requirement_materialization_id=requirements.id,
                source_requirement_projection_id=requirement_projection.id,
                source_requirement_id=requirement.id,
                source_requirement_kind=requirement.evidence_requirement_kind,
                source_case_candidate_id=requirement.source_case_candidate_id,
                reason=reason,
            )
        )

    return CandidateRuntimeEvidenceProjection.create(
        **artifact_common,
        source_requirement_materialization_id=requirements.id,
        source_requirement_projection_id=requirement_projection.id,
        source_runtime_trace_ids=[item.manifest.id for item in runtime_traces],
        compatible_runtime_trace_ids=[item.manifest.id for item in compatible],
        incompatible_runtime_sources=incompatible,
        instruction_evidence=instruction_evidence,
        order_evidence=order_evidence,
        requirement_evidence_bindings=requirement_evidence_bindings,
        evidence_gaps=evidence_gaps,
        out_of_scope_requirement_ids=[
            item.id for item in requirement_projection.binding_requirements
        ],
    )


class _CandidateRuntimeEvidenceMaterializationBody(DomainModel):
    contract: Literal[
        "phase10d_candidate_runtime_evidence_materialization_v1"
    ]
    source_requirement_materialization_id: Identifier
    source_requirement_materialization_snapshot: (
        StaticCrossLayerVerificationRequirementMaterialization
    )
    source_runtime_trace_snapshots: list[RuntimeTrace] = Field(default_factory=list)
    projection: CandidateRuntimeEvidenceProjection

    @field_validator("source_requirement_materialization_snapshot")
    @classmethod
    def detach_requirements(
        cls, value: StaticCrossLayerVerificationRequirementMaterialization
    ) -> StaticCrossLayerVerificationRequirementMaterialization:
        return StaticCrossLayerVerificationRequirementMaterialization.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("source_runtime_trace_snapshots")
    @classmethod
    def detach_traces(cls, values: list[RuntimeTrace]) -> list[RuntimeTrace]:
        detached = [
            RuntimeTrace.model_validate(item.model_dump(mode="json"))
            for item in values
        ]
        trace_ids = [item.manifest.id for item in detached]
        if len(trace_ids) != len(set(trace_ids)):
            raise ValueError("runtime trace IDs must be unique")
        return sorted(detached, key=lambda item: item.manifest.id)

    @field_validator("projection")
    @classmethod
    def detach_projection(
        cls, value: CandidateRuntimeEvidenceProjection
    ) -> CandidateRuntimeEvidenceProjection:
        return CandidateRuntimeEvidenceProjection.model_validate(
            value.model_dump(mode="json")
        )

    @model_validator(mode="after")
    def validate_source_reprojection(
        self,
    ) -> "_CandidateRuntimeEvidenceMaterializationBody":
        if (
            self.source_requirement_materialization_id
            != self.source_requirement_materialization_snapshot.id
        ):
            raise ValueError("candidate runtime requirement source ID mismatch")
        expected = _project_candidate_runtime_evidence(
            self.source_requirement_materialization_snapshot,
            self.source_runtime_trace_snapshots,
        )
        if self.projection != expected:
            raise ValueError(
                "runtime evidence projection differs from deterministic source reprojection"
            )
        return self


class CandidateRuntimeEvidenceMaterialization(
    _CandidateRuntimeEvidenceMaterializationBody
):
    """Detached authoritative requirement/trace sources plus B1 projection."""

    id: Identifier

    @classmethod
    def create(
        cls,
        *,
        requirement_materialization: (
            StaticCrossLayerVerificationRequirementMaterialization
        ),
        runtime_traces: list[RuntimeTrace],
    ) -> "CandidateRuntimeEvidenceMaterialization":
        requirements = StaticCrossLayerVerificationRequirementMaterialization.model_validate(
            requirement_materialization.model_dump(mode="json")
        )
        traces = [
            RuntimeTrace.model_validate(item.model_dump(mode="json"))
            for item in runtime_traces
        ]
        trace_ids = [item.manifest.id for item in traces]
        if len(trace_ids) != len(set(trace_ids)):
            raise ValueError("runtime trace IDs must be unique")
        traces.sort(key=lambda item: item.manifest.id)
        body = _CandidateRuntimeEvidenceMaterializationBody.model_validate(
            {
                "contract": (
                    PHASE10D_CANDIDATE_RUNTIME_EVIDENCE_MATERIALIZATION_CONTRACT
                ),
                "source_requirement_materialization_id": requirements.id,
                "source_requirement_materialization_snapshot": requirements,
                "source_runtime_trace_snapshots": traces,
                "projection": _project_candidate_runtime_evidence(
                    requirements, traces
                ),
            }
        )
        payload = body.model_dump(mode="json")
        return cls(
            id=candidate_runtime_evidence_materialization_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_id(self) -> "CandidateRuntimeEvidenceMaterialization":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != candidate_runtime_evidence_materialization_id(payload):
            raise ValueError("candidate runtime evidence materialization ID mismatch")
        return self


def bind_candidate_runtime_evidence(
    requirement_materialization: (
        StaticCrossLayerVerificationRequirementMaterialization
    ),
    runtime_traces: list[RuntimeTrace],
) -> CandidateRuntimeEvidenceMaterialization:
    """Extract exact runtime observations from two detached logical inputs."""

    return CandidateRuntimeEvidenceMaterialization.create(
        requirement_materialization=requirement_materialization,
        runtime_traces=runtime_traces,
    )
