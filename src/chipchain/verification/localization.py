"""Role-aware localization; MMIO sites are trigger points, not root causes."""

from chipchain.models import CrossLayerInteraction, CrossLayerLocationRole, RelationType
from chipchain.verification.adapter import LegacyCandidateEvidenceContext
from chipchain.verification.enums import InteractionSourceKind, LocationFindingStatus, VerificationStatus
from chipchain.verification.evidence import EvidenceCatalog
from chipchain.verification.models import (CrossLayerLocationFinding, HardwareAddress,
    InteractionReferenceBinding, ProgramAddress, VerificationRecord)


class InteractionLocationLocalizer:
    def localize(self, interaction: CrossLayerInteraction, bindings: list[InteractionReferenceBinding],
                 context: LegacyCandidateEvidenceContext | None, catalog: EvidenceCatalog,
                 behavior_records: list[VerificationRecord]) -> list[CrossLayerLocationFinding]:
        if context is None: return []
        bound_edges = {b.source_id for b in bindings if b.reference_role.value == "trigger_behavior" and b.source_kind is InteractionSourceKind.BEHAVIOR_EDGE}
        records = {r.subject_id: r for r in behavior_records}
        nodes = {n.id: n for n in context.behavior_nodes}
        findings = []
        for edge in context.behavior_edges:
            if edge.id not in bound_edges or edge.relation not in {RelationType.MMIO_READ, RelationType.MMIO_WRITE}: continue
            record = records.get(edge.id)
            if record is None or record.status is not VerificationStatus.VERIFIED: continue
            source, target = nodes[edge.source_id], nodes[edge.target_id]
            evidence = next(
                (
                    item
                    for evidence_id in record.supporting_evidence_ids
                    if (item := catalog.resolve(evidence_id)) is not None
                ),
                None,
            )
            if evidence is None:
                continue
            instruction = evidence.address if evidence else edge.metadata.get("instruction_address")
            source_file = evidence.metadata.get("source_file") if evidence else None
            source_line = evidence.metadata.get("source_line") if evidence else None
            findings.append(CrossLayerLocationFinding(interaction_id=interaction.id,
                architecture=interaction.architecture, role=CrossLayerLocationRole.CROSS_LAYER_TRIGGER_POINT,
                status=LocationFindingStatus.LOCALIZED_CANDIDATE, source_kind=InteractionSourceKind.BEHAVIOR_EDGE,
                source_id=edge.id, function_id=source.id, function_name=source.name,
                program_address=ProgramAddress(value=source.address) if source.address else None,
                instruction_address=ProgramAddress(value=instruction) if isinstance(instruction, str) else None,
                hardware_address=HardwareAddress(value=target.address) if target.address else None,
                source_file=source_file if isinstance(source_file, str) else None,
                source_line=source_line if isinstance(source_line, int) and source_line > 0 else None,
                supporting_evidence_ids=record.supporting_evidence_ids,
                rule_ids=["localization:verified-mmio-trigger-point:v1"],
                reason_codes=["verified_mmio_is_cross_layer_trigger_point"],
                metadata={"initiating_root_cause": False, "llm_used": False}))
        return findings
