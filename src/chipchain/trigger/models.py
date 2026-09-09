"""Single-source Hardware Trigger IR; consistency checks only, not a matcher."""

from typing import Literal, Self, TypeVar

from pydantic import field_validator, model_validator

from chipchain.core import (
    Architecture, ArtifactProvenance, HardwareTargetIdentity, Identifier, ProcessorFuzzArtifact,
)
from chipchain.trigger.base import _TriggerModel
from chipchain.trigger.enums import TriggerSourceKind
from chipchain.trigger.relations import TriggerOrderRequirement
from chipchain.trigger.requirements import StateTriggerRequirement, StepTriggerRequirement


class TriggerSourceContext(_TriggerModel):
    """Declared hardware provenance only; no fact nature or applicability verdict."""

    _namespace = "v2-trigger-source-context-v1"
    source_kind: Literal[TriggerSourceKind.PROCESSORFUZZ_ARTIFACT, TriggerSourceKind.SYNTHETIC_FIXTURE]
    artifact: ArtifactProvenance
    hardware_target: HardwareTargetIdentity
    producer_profile_id: Identifier
    processor_fuzz: ProcessorFuzzArtifact | None = None

    @property
    def architecture(self) -> Architecture:
        """Return the sole declared hardware target architecture."""

        return self.hardware_target.architecture

    @model_validator(mode="after")
    def validate_source(self) -> Self:
        """Require exact architecture, producer and optional ProcessorFuzz binding."""

        if self.artifact.architecture != self.architecture:
            raise ValueError("source artifact must declare the target architecture")
        if self.artifact.producer_profile_id != self.producer_profile_id:
            raise ValueError("source producer profile mismatch")
        required = self.source_kind == TriggerSourceKind.PROCESSORFUZZ_ARTIFACT
        if (self.processor_fuzz is not None) != required:
            raise ValueError("ProcessorFuzz binding required exactly for processorfuzz_artifact")
        if self.processor_fuzz is not None:
            if self.processor_fuzz.provenance != self.artifact:
                raise ValueError("ProcessorFuzz source provenance mismatch")
            if self.processor_fuzz.hardware_target != self.hardware_target:
                raise ValueError("ProcessorFuzz hardware target mismatch")
        return self


_RecordT = TypeVar("_RecordT", bound=_TriggerModel)


class HardwareTriggerSpec(_TriggerModel):
    """Unordered requirement sets plus explicit order, not a proven hardware trigger.

    Empty collections declare no requirements; they do not report satisfaction.
    Slots identify local nodes and never implicitly establish execution order.
    """

    _namespace = "v2-hardware-trigger-spec-v1"
    contract: Literal["v2_hardware_trigger_spec_v1"] = "v2_hardware_trigger_spec_v1"
    source: TriggerSourceContext
    preconditions: tuple[StateTriggerRequirement, ...] = ()
    steps: tuple[StepTriggerRequirement, ...] = ()
    order_requirements: tuple[TriggerOrderRequirement, ...] = ()

    @field_validator("preconditions", "steps", "order_requirements")
    @classmethod
    def canonicalize_set(cls, records: tuple[_RecordT, ...]) -> tuple[_RecordT, ...]:
        """Reject duplicate IDs before sorting; never silently deduplicate/renumber."""

        ids = [record.id for record in records]
        if len(ids) != len(set(ids)):
            raise ValueError("duplicate requirement/order ID")
        return tuple(sorted(records, key=lambda record: record.id))

    @model_validator(mode="after")
    def validate_integrity(self) -> Self:
        """Check ownership, local slots, step references and precedence acyclicity."""

        requirements = (*self.preconditions, *self.steps)
        slots = [item.requirement_slot for item in requirements]
        if len(slots) != len(set(slots)):
            raise ValueError("duplicate requirement_slot across spec")
        for item in (*requirements, *self.order_requirements):
            if item.source_context_id != self.source.id:
                raise ValueError("trigger source context mismatch")
            if item.architecture != self.source.architecture:
                raise ValueError("trigger architecture mismatch")

        successors: dict[str, set[str]] = {step.id: set() for step in self.steps}
        indegree = dict.fromkeys(successors, 0)
        for edge in self.order_requirements:
            if edge.before_id not in successors or edge.after_id not in successors:
                raise ValueError("order endpoints must be steps in this spec")
            if edge.after_id not in successors[edge.before_id]:
                successors[edge.before_id].add(edge.after_id)
                indegree[edge.after_id] += 1
        ready = [key for key, count in indegree.items() if count == 0]
        visited = 0
        while ready:
            key = ready.pop()
            visited += 1
            for successor in successors[key]:
                indegree[successor] -= 1
                if indegree[successor] == 0:
                    ready.append(successor)
        if visited != len(successors):
            raise ValueError("cyclic required precedence")
        return self
