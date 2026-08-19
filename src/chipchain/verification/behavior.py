"""Strict static verification of CALLS and MMIO behavior observations."""

from chipchain.models import BehaviorEdge, BehaviorNode, Evidence, EvidenceType, NodeKind, RelationType
from chipchain.verification.enums import VerificationStatus, VerificationSubjectKind
from chipchain.verification.evidence import EvidenceCatalog
from chipchain.verification.models import VerificationRecord

_FUNCTION_KINDS = {NodeKind.FUNCTION, NodeKind.DRIVER_FUNCTION}
_HARDWARE_KINDS = {NodeKind.REGISTER, NodeKind.HARDWARE_RESOURCE}


class BehaviorEdgeVerifier:
    verifier_name = "phase9ar_behavior_static_v1"

    def verify(self, interaction_id: str, edge: BehaviorEdge, source: BehaviorNode,
               target: BehaviorNode, catalog: EvidenceCatalog) -> VerificationRecord:
        if edge.architecture is not source.architecture or edge.architecture is not target.architecture:
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["architecture mismatch"])
        if edge.source_id != source.id or edge.target_id != target.id:
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["endpoint mismatch"])
        if edge.relation is RelationType.CALLS:
            return self._verify_calls(interaction_id, edge, source, target, catalog)
        if edge.relation in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}:
            return self._verify_mmio(interaction_id, edge, source, target, catalog)
        return self._record(interaction_id, edge, VerificationStatus.UNKNOWN, [],
                            ["relation has no Phase 9A-R evidence contract"])

    def _verify_calls(self, interaction_id: str, edge: BehaviorEdge, source: BehaviorNode,
                      target: BehaviorNode, catalog: EvidenceCatalog) -> VerificationRecord:
        if source.kind not in _FUNCTION_KINDS or target.kind not in _FUNCTION_KINDS:
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["CALLS endpoints must be functions"])
        if "observation" not in edge.metadata or source.address is None or target.address is None:
            return self._record(interaction_id, edge, VerificationStatus.UNKNOWN, [], ["CALLS comparison fields are incomplete"])
        if edge.metadata.get("observation") != "call_xref":
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["CALLS edge observation mismatch"])
        return self._evaluate(interaction_id, edge, catalog,
            lambda e: _calls_conflicts(e, source, target),
            ("caller_address", "callee_address", "resolved", "observation"))

    def _verify_mmio(self, interaction_id: str, edge: BehaviorEdge, source: BehaviorNode,
                     target: BehaviorNode, catalog: EvidenceCatalog) -> VerificationRecord:
        if source.kind not in _FUNCTION_KINDS or target.kind not in _HARDWARE_KINDS:
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["MMIO endpoints must be function to hardware"])
        fields = ("observation", "resolved_target_address", "memory_map_id", "memory_map_region", "instruction_address")
        if any(field not in edge.metadata for field in fields):
            return self._record(interaction_id, edge, VerificationStatus.UNKNOWN, [], ["MMIO edge contract fields are incomplete"])
        if target.metadata.get("memory_map_id") is None or target.metadata.get("memory_map_region") is None:
            return self._record(interaction_id, edge, VerificationStatus.UNKNOWN, [], ["MMIO hardware comparison fields are incomplete"])
        if edge.metadata.get("observation") != edge.relation.value:
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["MMIO edge relation/observation mismatch"])
        resolved = edge.metadata.get("resolved_target_address")
        if resolved != target.address and not _address_in_range(resolved, target.metadata.get("region_start"), target.metadata.get("region_end")):
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["MMIO target address mismatch"])
        if edge.metadata.get("memory_map_id") != target.metadata.get("memory_map_id"):
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["MMIO memory_map_id mismatch"])
        if edge.metadata.get("memory_map_region") != target.metadata.get("memory_map_region"):
            return self._record(interaction_id, edge, VerificationStatus.REJECTED, [], ["MMIO memory_map_region mismatch"])
        return self._evaluate(interaction_id, edge, catalog,
            lambda e: _mmio_conflicts(e, edge, target),
            ("observation", "resolved_target_address", "memory_map_id", "memory_map_region", "resolved"))

    def _evaluate(self, interaction_id: str, edge: BehaviorEdge, catalog: EvidenceCatalog,
                  conflict_finder, required_fields: tuple[str, ...]) -> VerificationRecord:
        if not edge.evidence_ids:
            return self._record(interaction_id, edge, VerificationStatus.UNKNOWN, [], ["Evidence is missing"])
        resolved: list[str] = []
        usable: list[str] = []
        messages: list[str] = []
        for evidence_id in edge.evidence_ids:
            evidence = catalog.resolve(evidence_id)
            if evidence is None:
                messages.append(f"Evidence {evidence_id} is unresolved")
                continue
            resolved.append(evidence_id)
            if evidence.type is EvidenceType.LLM_SEMANTIC or not evidence.verified:
                messages.append(f"Evidence {evidence_id} is not verified non-LLM evidence")
                continue
            if evidence.type is not EvidenceType.STATIC_ANALYSIS:
                messages.append(f"Evidence {evidence_id} is not static analysis")
                continue
            if any(field not in evidence.metadata for field in required_fields):
                messages.append(f"Evidence {evidence_id} lacks required contract fields")
                continue
            conflicts = conflict_finder(evidence)
            if conflicts:
                return self._record(interaction_id, edge, VerificationStatus.REJECTED, resolved, conflicts)
            usable.append(evidence_id)
        if usable:
            messages.append("verified static Evidence matches the referenced edge")
        return self._record(interaction_id, edge,
                            VerificationStatus.VERIFIED if usable else VerificationStatus.UNKNOWN,
                            resolved, messages, supporting_evidence_ids=usable)

    def _record(self, interaction_id: str, edge: BehaviorEdge, status: VerificationStatus,
                evidence_ids: list[str], messages: list[str], *,
                supporting_evidence_ids: list[str] | None = None) -> VerificationRecord:
        return VerificationRecord.create(interaction_id=interaction_id, architecture=edge.architecture,
            subject_kind=VerificationSubjectKind.BEHAVIOR_EDGE, subject_id=edge.id, status=status,
            verifier=self.verifier_name, evidence_ids=evidence_ids,
            supporting_evidence_ids=supporting_evidence_ids or [],
            rule_ids=[f"behavior:{edge.relation.value}:static-v1"], messages=messages)


def _calls_conflicts(evidence: Evidence, source: BehaviorNode, target: BehaviorNode) -> list[str]:
    conflicts = []
    if evidence.metadata.get("observation") != "call_xref": conflicts.append("Evidence observation is not call_xref")
    if evidence.metadata.get("resolved") is not True: conflicts.append("CALLS Evidence is explicitly unresolved")
    if evidence.metadata.get("caller_address") != source.address: conflicts.append("CALLS caller address mismatch")
    if evidence.metadata.get("callee_address") != target.address: conflicts.append("CALLS callee address mismatch")
    return conflicts


def _mmio_conflicts(evidence: Evidence, edge: BehaviorEdge, target: BehaviorNode) -> list[str]:
    conflicts = []
    for field, value in (("observation", edge.relation.value), ("memory_map_id", target.metadata.get("memory_map_id")),
                         ("memory_map_region", target.metadata.get("memory_map_region"))):
        if evidence.metadata.get(field) != value: conflicts.append(f"MMIO Evidence {field} mismatch")
    if evidence.metadata.get("resolved") is not True: conflicts.append("MMIO Evidence is explicitly unresolved")
    resolved = evidence.metadata.get("resolved_target_address")
    if resolved != target.address and not _address_in_range(resolved, target.metadata.get("region_start"), target.metadata.get("region_end")):
        conflicts.append("MMIO Evidence target address mismatch")
    if evidence.address != edge.metadata.get("instruction_address"):
        conflicts.append("MMIO instruction/Evidence address mismatch")
    return conflicts


def _address_in_range(value: object, start: object, end: object) -> bool:
    try: return int(str(start), 16) <= int(str(value), 16) <= int(str(end), 16)
    except (TypeError, ValueError): return False
