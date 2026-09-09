"""Single-source processor fragments with strict referential integrity."""

from typing import Annotated, Literal, Self, TypeAlias, TypeVar

from pydantic import Field, field_validator, model_validator

from chipchain.core import (
    Architecture, ArtifactProvenance, HardwareTargetIdentity, Identifier,
    ImmutableFirmwareArtifact, ProcessorFuzzArtifact,
)
from chipchain.behavior.processor.base import _IdentifiedModel
from chipchain.behavior.processor.enums import (
    BehaviorFactNature, BehaviorRelationKind, BehaviorSourceKind,
)
from chipchain.behavior.processor.events import (
    ControlTransferBehavior, MemoryAccessBehavior, ProcessorEvent, RegisterAccessBehavior,
)
from chipchain.behavior.processor.instructions import InstructionBehavior
from chipchain.behavior.processor.relations import BehaviorRelation
from chipchain.behavior.processor.state import MemoryStateFact, PrivilegeStateFact, RegisterStateFact


class BehaviorSourceContext(_IdentifiedModel):
    """One declared provenance/target context, not a fact derivation nature.

    Runtime vocabulary requires an explicit observation-artifact declaration,
    not simply relabeling static firmware bytes. No runtime adapter exists here.
    """

    _namespace = "v2-processor-source-context-v1"
    source_kind: BehaviorSourceKind
    artifact: ArtifactProvenance
    hardware_target: HardwareTargetIdentity
    producer_profile_id: Identifier
    firmware: ImmutableFirmwareArtifact | None = None
    processor_fuzz: ProcessorFuzzArtifact | None = None

    @property
    def architecture(self) -> Architecture:
        """Return the sole declared target architecture."""

        return self.hardware_target.architecture

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        """Check explicit target and exact optional origin bindings."""

        k = BehaviorSourceKind
        if self.artifact.architecture != self.architecture:
            raise ValueError("source artifact must declare the target architecture")
        if (self.processor_fuzz is not None) != (self.source_kind == k.PROCESSORFUZZ_SI):
            raise ValueError("ProcessorFuzz binding required exactly for processorfuzz_si")
        if self.processor_fuzz is not None:
            if self.firmware is not None:
                raise ValueError("ProcessorFuzz source cannot silently bind client firmware")
            if self.processor_fuzz.hardware_target != self.hardware_target:
                raise ValueError("ProcessorFuzz hardware target mismatch")
            if self.processor_fuzz.provenance != self.artifact:
                raise ValueError("ProcessorFuzz source provenance mismatch")
        if self.source_kind in {k.FIRMWARE_ARTIFACT, k.STATIC_ANALYSIS_ARTIFACT} and self.firmware is None:
            raise ValueError("firmware-derived source requires exact firmware binding")
        if self.firmware is not None:
            if self.firmware.hardware_target != self.hardware_target:
                raise ValueError("source firmware hardware target mismatch")
            fw = self.firmware.provenance
            if self.artifact.artifact_id == fw.artifact_id and self.artifact != fw:
                raise ValueError("source artifact ID conflicts with firmware provenance")
            if self.source_kind == k.FIRMWARE_ARTIFACT and self.artifact != fw:
                raise ValueError("static decode must bind the exact firmware provenance")
            if self.source_kind == k.RUNTIME_OBSERVATION_ARTIFACT and self.artifact.artifact_id == fw.artifact_id:
                raise ValueError("runtime observation artifact must be distinct from firmware bytes")
        return self


BehaviorElement: TypeAlias = Annotated[
    InstructionBehavior | RegisterAccessBehavior | MemoryAccessBehavior
    | ControlTransferBehavior | ProcessorEvent | RegisterStateFact
    | PrivilegeStateFact | MemoryStateFact,
    Field(discriminator="kind"),
]

_RecordT = TypeVar("_RecordT", bound=_IdentifiedModel)


class ProcessorBehaviorFragment(_IdentifiedModel):
    """Single-source facts with individual natures, not a vulnerability result."""

    _namespace = "v2-processor-behavior-fragment-v1"
    contract: Literal["v2_processor_behavior_fragment_v1"] = "v2_processor_behavior_fragment_v1"
    source: BehaviorSourceContext
    elements: tuple[BehaviorElement, ...] = ()
    relations: tuple[BehaviorRelation, ...] = ()

    @field_validator("elements", "relations")
    @classmethod
    def canonicalize_set(cls, records: tuple[_RecordT, ...]) -> tuple[_RecordT, ...]:
        """Reject duplicates before sorting unordered collections by derived ID."""

        ids = [record.id for record in records]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate behavior element/relation ID")
        return tuple(sorted(records, key=lambda record: record.id))

    @model_validator(mode="after")
    def validate_integrity(self) -> Self:
        """Reject mixed provenance, dangling/wrong references and contradictory order."""

        elements = {element.id: element for element in self.elements}
        instructions = {key: item for key, item in elements.items() if isinstance(item, InstructionBehavior)}
        ordinals = [instruction.source_ordinal for instruction in instructions.values()]
        if len(ordinals) != len(set(ordinals)):
            raise ValueError("duplicate instruction source ordinal")
        k, n = BehaviorSourceKind, BehaviorFactNature
        compatible_natures = {
            k.DECLARED_ARTIFACT: {n.SOURCE_DECLARED},
            k.PROCESSORFUZZ_SI: {n.SOURCE_DECLARED},
            k.FIRMWARE_ARTIFACT: {n.STATIC_DECODED, n.STATIC_INFERRED},
            k.STATIC_ANALYSIS_ARTIFACT: {n.STATIC_DECODED, n.STATIC_INFERRED},
            k.RUNTIME_OBSERVATION_ARTIFACT: {n.RUNTIME_OBSERVED},
            k.SYNTHETIC_FIXTURE: {n.SYNTHETIC_FIXTURE},
        }
        for record in (*self.elements, *self.relations):
            if record.source_context_id != self.source.id:
                raise ValueError("behavior source context mismatch")
            if record.architecture != self.source.architecture:
                raise ValueError("behavior architecture mismatch")
            if record.nature not in compatible_natures[self.source.source_kind]:
                raise ValueError("behavior nature incompatible with source kind")
        occurrence_ordinals = [
            item.occurrence_ordinal for item in self.elements
            if isinstance(item, ProcessorEvent) and item.occurrence_ordinal is not None
        ]
        if len(occurrence_ordinals) != len(set(occurrence_ordinals)):
            raise ValueError("duplicate source-local occurrence ordinal")
        slots: set[tuple] = set()
        for item in self.elements:
            if isinstance(item, (RegisterAccessBehavior, MemoryAccessBehavior, ControlTransferBehavior, ProcessorEvent)):
                if item.instruction_id is not None and item.instruction_id not in instructions:
                    raise ValueError("invalid instruction reference")
                slot = (item.kind, item.instruction_id, item.effect_index)
                if isinstance(item, ProcessorEvent):
                    slot += (item.occurrence_ordinal,)
            elif isinstance(item, (RegisterStateFact, PrivilegeStateFact, MemoryStateFact)):
                slot = (item.kind, item.fact_index)
            else:
                continue
            if slot in slots:
                raise ValueError("duplicate behavior fact/effect slot")
            slots.add(slot)
        for relation in self.relations:
            if relation.source_id not in elements or relation.target_id not in elements:
                raise ValueError("relation endpoint missing from fragment")
            if relation.relation in {BehaviorRelationKind.SOURCE_SEQUENCE, BehaviorRelationKind.STATIC_CFG_SUCCESSOR}:
                if relation.source_id not in instructions or relation.target_id not in instructions:
                    raise ValueError("source sequence/CFG endpoints must be instructions")
            if relation.relation == BehaviorRelationKind.SOURCE_SEQUENCE:
                if instructions[relation.source_id].source_ordinal >= instructions[relation.target_id].source_ordinal:
                    raise ValueError("source sequence contradicts declared ordinals")
            if relation.relation == BehaviorRelationKind.RUNTIME_PRECEDES:
                for endpoint_id in (relation.source_id, relation.target_id):
                    endpoint = elements[endpoint_id]
                    if (
                        not isinstance(endpoint, ProcessorEvent)
                        or endpoint.occurrence_ordinal is None
                        or endpoint.nature not in {n.RUNTIME_OBSERVED, n.SYNTHETIC_FIXTURE}
                    ):
                        raise ValueError("runtime_precedes endpoints must be dynamic ProcessorEvent occurrences")
        self._reject_runtime_order_cycles()
        return self

    def _reject_runtime_order_cycles(self) -> None:
        # Structural strict-order consistency only; not reachability analysis.
        successors: dict[str, list[str]] = {}
        incoming: dict[str, int] = {}
        for edge in self.relations:
            if edge.relation == BehaviorRelationKind.RUNTIME_PRECEDES:
                successors.setdefault(edge.source_id, []).append(edge.target_id)
                incoming.setdefault(edge.source_id, 0)
                incoming[edge.target_id] = incoming.get(edge.target_id, 0) + 1
        ready = [key for key, degree in incoming.items() if degree == 0]
        visited = 0
        while ready:
            key = ready.pop()
            visited += 1
            for target in successors.get(key, ()):
                incoming[target] -= 1
                if incoming[target] == 0:
                    ready.append(target)
        if visited != len(incoming):
            raise ValueError("runtime_precedes contains contradictory cyclic order")
