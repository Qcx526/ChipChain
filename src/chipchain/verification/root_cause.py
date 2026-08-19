"""Non-LLM binary sink localization with explicit address namespaces."""

from __future__ import annotations

from chipchain.knowledge import KnowledgeNode
from chipchain.models import Architecture, BehaviorEdge, BehaviorNode, Evidence, EvidenceType, RelationType
from chipchain.verification.enums import RootCauseLocalizationStatus, VerificationStatus
from chipchain.verification.evidence import EvidenceCatalog
from chipchain.verification.models import (
    HardwareAddress,
    ProgramAddress,
    RootCauseLocalizationResult,
    VerificationRecord,
)


class RootCauseLocalizer:
    """Locate verified MMIO program sinks and compare, never copy, KG hints."""

    method = "verified_mmio_sink_plus_checked_kg_hint_v1"

    def localize(
        self,
        *,
        candidate_id: str,
        architecture: Architecture,
        behavior_nodes: list[BehaviorNode],
        behavior_edges: list[BehaviorEdge],
        behavior_records: list[VerificationRecord],
        knowledge_root_causes: list[KnowledgeNode],
        knowledge_anchor: KnowledgeNode,
        catalog: EvidenceCatalog,
    ) -> RootCauseLocalizationResult:
        node_by_id = {item.id: item for item in behavior_nodes}
        record_by_id = {item.subject_id: item for item in behavior_records}
        observations: list[tuple[int, BehaviorEdge, Evidence]] = []
        for edge in behavior_edges:
            if edge.relation not in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}:
                continue
            record = record_by_id.get(edge.id)
            if record is None or record.status is not VerificationStatus.VERIFIED:
                continue
            for evidence_id in edge.evidence_ids:
                evidence = catalog.resolve(evidence_id)
                if (
                    evidence is not None
                    and evidence.verified
                    and evidence.type is not EvidenceType.LLM_SEMANTIC
                    and evidence.address is not None
                ):
                    observations.append((int(evidence.address, 16), edge, evidence))
        observations.sort(key=lambda item: (item[0], item[1].id, item[2].id))
        if not observations:
            return RootCauseLocalizationResult(
                candidate_id=candidate_id,
                architecture=architecture,
                localization_method=self.method,
                localization_status=RootCauseLocalizationStatus.INSUFFICIENT_EVIDENCE,
                knowledge_root_cause_node_ids=[item.id for item in knowledge_root_causes],
                reason_codes=["no_verified_mmio_sink"],
                metadata={"root_cause_verified": False},
            )

        _, sink_edge, sink_evidence = observations[0]
        function = node_by_id[sink_edge.source_id]
        hardware = node_by_id[sink_edge.target_id]
        contradictions: list[str] = []
        reason_codes = ["verified_mmio_sink_instruction_extracted"]
        supporting_knowledge: list[str] = []
        for hint in knowledge_root_causes:
            metadata = hint.metadata
            expected_function = metadata.get("function")
            if isinstance(expected_function, str) and expected_function not in {function.id, function.name}:
                contradictions.append(f"{hint.id}:function_mismatch")
            binary_address = metadata.get("binary_address")
            if isinstance(binary_address, str) and function.address is not None:
                if _canonical_hex(binary_address) != _canonical_hex(function.address):
                    contradictions.append(f"{hint.id}:binary_address_mismatch")
            instruction = metadata.get("instruction")
            if isinstance(instruction, str) and sink_evidence.instruction is not None and instruction != sink_evidence.instruction:
                contradictions.append(f"{hint.id}:instruction_mismatch")
            mmio_address = metadata.get("mmio_address")
            if isinstance(mmio_address, str) and hardware.address is not None:
                if _canonical_hex(mmio_address) != _canonical_hex(hardware.address):
                    contradictions.append(f"{hint.id}:mmio_address_mismatch")
            resource = metadata.get("hardware_resource")
            valid_resources = {knowledge_anchor.id, *knowledge_anchor.external_ids}
            if isinstance(resource, str) and resource not in valid_resources:
                contradictions.append(f"{hint.id}:hardware_resource_mismatch")
            for evidence_id in hint.evidence_ids:
                evidence = catalog.resolve(evidence_id)
                if evidence is not None and evidence.verified and evidence.type is not EvidenceType.LLM_SEMANTIC:
                    supporting_knowledge.append(evidence_id)
                    if hardware.address is not None and evidence.address == hardware.address:
                        reason_codes.append("knowledge_evidence_address_is_hardware_namespace")

        source_file = sink_evidence.metadata.get("source_file")
        source_line = sink_evidence.metadata.get("source_line")
        if not isinstance(source_file, str):
            source_file = None
        if not isinstance(source_line, int) or source_line < 1:
            source_line = None
        status = (
            RootCauseLocalizationStatus.CONTRADICTORY_CONTEXT
            if contradictions
            else RootCauseLocalizationStatus.LOCALIZED_CANDIDATE
        )
        return RootCauseLocalizationResult(
            candidate_id=candidate_id,
            architecture=architecture,
            function_id=function.id,
            function_name=function.name,
            candidate_binary_addresses=(
                [ProgramAddress(value=function.address)] if function.address is not None else []
            ),
            candidate_instruction_addresses=[ProgramAddress(value=sink_evidence.address)],
            source_file=source_file,
            source_line=source_line,
            hardware_address=(
                HardwareAddress(value=hardware.address) if hardware.address is not None else None
            ),
            knowledge_root_cause_node_ids=[item.id for item in knowledge_root_causes],
            supporting_behavior_evidence_ids=[sink_evidence.id],
            supporting_knowledge_evidence_ids=supporting_knowledge,
            localization_method=self.method,
            localization_status=status,
            reason_codes=reason_codes,
            contradictions=contradictions,
            metadata={
                "root_cause_verified": False,
                "source_line_error_available": source_line is not None,
                "llm_used": False,
            },
        )


def _canonical_hex(value: str) -> str:
    try:
        return hex(int(value, 16))
    except ValueError:
        return value
