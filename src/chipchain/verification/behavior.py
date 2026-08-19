"""Strict static verification of supported BehaviorEdge relations."""

from __future__ import annotations

from chipchain.models import (
    BehaviorEdge,
    BehaviorNode,
    Evidence,
    EvidenceType,
    NodeKind,
    RelationType,
)
from chipchain.verification.enums import VerificationStatus, VerificationSubjectKind
from chipchain.verification.evidence import EvidenceCatalog
from chipchain.verification.models import VerificationRecord

_FUNCTION_KINDS = {NodeKind.FUNCTION, NodeKind.DRIVER_FUNCTION}
_HARDWARE_KINDS = {NodeKind.REGISTER, NodeKind.HARDWARE_RESOURCE}


class BehaviorEdgeVerifier:
    """Verify only CALLS and MMIO contracts with their own structured evidence."""

    verifier_name = "phase9a_behavior_static_v1"

    def verify(
        self,
        edge: BehaviorEdge,
        source: BehaviorNode,
        target: BehaviorNode,
        catalog: EvidenceCatalog,
    ) -> VerificationRecord:
        """Return VERIFIED, REJECTED, or UNKNOWN without mutating source facts."""

        if edge.architecture is not source.architecture or edge.architecture is not target.architecture:
            return self._record(edge, VerificationStatus.REJECTED, [], ["architecture mismatch"])
        if edge.source_id != source.id or edge.target_id != target.id:
            return self._record(edge, VerificationStatus.REJECTED, [], ["endpoint mismatch"])
        if edge.relation is RelationType.CALLS:
            return self._verify_calls(edge, source, target, catalog)
        if edge.relation in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}:
            return self._verify_mmio(edge, source, target, catalog)
        return self._record(
            edge,
            VerificationStatus.UNKNOWN,
            [],
            ["relation has no Phase 9A evidence contract"],
        )

    def _verify_calls(
        self,
        edge: BehaviorEdge,
        source: BehaviorNode,
        target: BehaviorNode,
        catalog: EvidenceCatalog,
    ) -> VerificationRecord:
        if source.kind not in _FUNCTION_KINDS or target.kind not in _FUNCTION_KINDS:
            return self._record(edge, VerificationStatus.REJECTED, [], ["CALLS endpoints must be functions"])
        if "observation" not in edge.metadata or source.address is None or target.address is None:
            return self._record(edge, VerificationStatus.UNKNOWN, [], ["CALLS comparison fields are incomplete"])
        if edge.metadata.get("observation") != "call_xref":
            return self._record(edge, VerificationStatus.REJECTED, [], ["CALLS edge observation mismatch"])
        return self._evaluate_evidence(
            edge,
            catalog,
            lambda evidence: self._calls_evidence_conflicts(evidence, source, target),
            required_fields=("caller_address", "callee_address", "resolved", "observation"),
        )

    @staticmethod
    def _calls_evidence_conflicts(
        evidence: Evidence, source: BehaviorNode, target: BehaviorNode
    ) -> list[str]:
        metadata = evidence.metadata
        conflicts: list[str] = []
        if metadata.get("observation") != "call_xref":
            conflicts.append("Evidence observation is not call_xref")
        if metadata.get("resolved") is not True:
            conflicts.append("CALLS Evidence is explicitly unresolved")
        if metadata.get("caller_address") != source.address:
            conflicts.append("CALLS caller address mismatch")
        if metadata.get("callee_address") != target.address:
            conflicts.append("CALLS callee address mismatch")
        return conflicts

    def _verify_mmio(
        self,
        edge: BehaviorEdge,
        source: BehaviorNode,
        target: BehaviorNode,
        catalog: EvidenceCatalog,
    ) -> VerificationRecord:
        if source.kind not in _FUNCTION_KINDS or target.kind not in _HARDWARE_KINDS:
            return self._record(edge, VerificationStatus.REJECTED, [], ["MMIO endpoints must be function to hardware"])
        required_edge_fields = ("observation", "resolved_target_address", "memory_map_id", "memory_map_region", "instruction_address")
        if any(field not in edge.metadata for field in required_edge_fields):
            return self._record(edge, VerificationStatus.UNKNOWN, [], ["MMIO edge contract fields are incomplete"])
        if (
            target.metadata.get("memory_map_id") is None
            or target.metadata.get("memory_map_region") is None
            or (
                target.address is None
                and (
                    target.metadata.get("region_start") is None
                    or target.metadata.get("region_end") is None
                )
            )
        ):
            return self._record(edge, VerificationStatus.UNKNOWN, [], ["MMIO hardware comparison fields are incomplete"])
        if edge.metadata.get("observation") != edge.relation.value:
            return self._record(edge, VerificationStatus.REJECTED, [], ["MMIO edge relation/observation mismatch"])
        if edge.metadata.get("resolved_target_address") != target.address:
            region_start = target.metadata.get("region_start")
            region_end = target.metadata.get("region_end")
            resolved = edge.metadata.get("resolved_target_address")
            if not _address_in_range(resolved, region_start, region_end):
                return self._record(edge, VerificationStatus.REJECTED, [], ["MMIO target address mismatch"])
        if edge.metadata.get("memory_map_id") != target.metadata.get("memory_map_id"):
            return self._record(edge, VerificationStatus.REJECTED, [], ["MMIO memory_map_id mismatch"])
        if edge.metadata.get("memory_map_region") != target.metadata.get("memory_map_region"):
            return self._record(edge, VerificationStatus.REJECTED, [], ["MMIO memory_map_region mismatch"])
        return self._evaluate_evidence(
            edge,
            catalog,
            lambda evidence: self._mmio_evidence_conflicts(evidence, edge, target),
            required_fields=("observation", "resolved_target_address", "memory_map_id", "memory_map_region", "resolved"),
        )

    @staticmethod
    def _mmio_evidence_conflicts(
        evidence: Evidence, edge: BehaviorEdge, target: BehaviorNode
    ) -> list[str]:
        metadata = evidence.metadata
        conflicts: list[str] = []
        expected = {
            "observation": edge.relation.value,
            "memory_map_id": target.metadata.get("memory_map_id"),
            "memory_map_region": target.metadata.get("memory_map_region"),
        }
        for field, value in expected.items():
            if metadata.get(field) != value:
                conflicts.append(f"MMIO Evidence {field} mismatch")
        if metadata.get("resolved") is not True:
            conflicts.append("MMIO Evidence is explicitly unresolved")
        resolved = metadata.get("resolved_target_address")
        if resolved != target.address and not _address_in_range(
            resolved, target.metadata.get("region_start"), target.metadata.get("region_end")
        ):
            conflicts.append("MMIO Evidence target address mismatch")
        if evidence.address != edge.metadata.get("instruction_address"):
            conflicts.append("MMIO instruction/Evidence address mismatch")
        return conflicts

    def _evaluate_evidence(
        self,
        edge: BehaviorEdge,
        catalog: EvidenceCatalog,
        conflict_finder,
        *,
        required_fields: tuple[str, ...],
    ) -> VerificationRecord:
        if not edge.evidence_ids:
            return self._record(edge, VerificationStatus.UNKNOWN, [], ["Evidence is missing"])
        usable: list[str] = []
        resolved_ids: list[str] = []
        messages: list[str] = []
        for evidence_id in edge.evidence_ids:
            evidence = catalog.resolve(evidence_id)
            if evidence is None:
                messages.append(f"Evidence {evidence_id} is unresolved")
                continue
            resolved_ids.append(evidence_id)
            if evidence.type is EvidenceType.LLM_SEMANTIC or not evidence.verified:
                messages.append(f"Evidence {evidence_id} is not verified non-LLM evidence")
                continue
            if evidence.type is not EvidenceType.STATIC_ANALYSIS:
                messages.append(f"Evidence {evidence_id} is not static analysis")
                continue
            missing = [field for field in required_fields if field not in evidence.metadata]
            if missing:
                messages.append(f"Evidence {evidence_id} lacks required contract fields")
                continue
            conflicts = conflict_finder(evidence)
            if conflicts:
                return self._record(edge, VerificationStatus.REJECTED, resolved_ids, conflicts)
            usable.append(evidence_id)
        status = VerificationStatus.VERIFIED if usable else VerificationStatus.UNKNOWN
        if usable:
            messages.append("verified static Evidence matches the referenced edge")
        return self._record(edge, status, resolved_ids, messages)

    def _record(
        self,
        edge: BehaviorEdge,
        status: VerificationStatus,
        evidence_ids: list[str],
        messages: list[str],
    ) -> VerificationRecord:
        return VerificationRecord.create(
            architecture=edge.architecture,
            subject_kind=VerificationSubjectKind.BEHAVIOR_EDGE,
            subject_id=edge.id,
            status=status,
            verifier=self.verifier_name,
            evidence_ids=evidence_ids,
            rule_ids=[f"behavior:{edge.relation.value}:static-v1"],
            messages=messages,
        )


def _address_in_range(value: object, start: object, end: object) -> bool:
    try:
        return int(str(start), 16) <= int(str(value), 16) <= int(str(end), 16)
    except (TypeError, ValueError):
        return False
