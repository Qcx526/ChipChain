"""Debug acquisition/control declarations, without probe or hardware access."""

from enum import Enum
from typing import Self

from pydantic import field_validator, model_validator

from chipchain.core.artifacts import ImmutableFirmwareArtifact
from chipchain.core.identity import deterministic_id
from chipchain.core.models import DomainModel, Identifier


class DebugObservationMode(str, Enum):
    """Vocabulary only; no mode is implemented by this contract layer."""

    PASSIVE_READ = "passive_read"
    NON_HALTING_TRACE = "non_halting_trace"
    HARDWARE_BREAKPOINT_HALT = "hardware_breakpoint_halt"
    MANUAL_HALT = "manual_halt"
    SINGLE_STEP = "single_step"
    SOFTWARE_BREAKPOINT = "software_breakpoint"
    STATE_WRITE = "state_write"
    RESET = "reset"
    RESET_HALT = "reset_halt"


class ExecutionPerturbation(str, Enum):
    """Declared effects; none_observed is not proof of non-interference."""

    UNKNOWN = "unknown"
    NONE_OBSERVED = "none_observed"
    HALT_INDUCED = "halt_induced"
    STEP_INDUCED = "step_induced"
    PROGRAM_BYTES_MAY_BE_MODIFIED = "program_bytes_may_be_modified"
    STATE_INJECTION = "state_injection"
    RESET_INDUCED = "reset_induced"


class DebugProvenance(DomainModel):
    """One declared debug mode and its effects relative to original firmware.

    A software breakpoint references the original image but cannot turn its
    patched observation into unchanged-image evidence. This is not a trace.
    """

    firmware: ImmutableFirmwareArtifact
    producer_profile_id: Identifier
    observation_mode: DebugObservationMode
    perturbations: tuple[ExecutionPerturbation, ...]

    @field_validator("perturbations")
    @classmethod
    def canonicalize_perturbations(
        cls, values: tuple[ExecutionPerturbation, ...],
    ) -> tuple[ExecutionPerturbation, ...]:
        """Treat effects as a nonempty set; reject duplicates, canonicalize order."""

        if not values or len(set(values)) != len(values):
            raise ValueError("perturbations must be nonempty and unique")
        return tuple(sorted(values, key=lambda value: value.value))

    @model_validator(mode="after")
    def validate_effects(self) -> Self:
        """Reject understated known effects; do not manufacture observed facts."""

        effects = set(self.perturbations)
        p = ExecutionPerturbation
        m = DebugObservationMode
        if len(effects) > 1 and effects & {p.UNKNOWN, p.NONE_OBSERVED}:
            raise ValueError("unknown/none_observed cannot accompany declared effects")
        required = {
            m.HARDWARE_BREAKPOINT_HALT: {p.HALT_INDUCED},
            m.MANUAL_HALT: {p.HALT_INDUCED},
            m.SINGLE_STEP: {p.STEP_INDUCED},
            m.SOFTWARE_BREAKPOINT: {p.PROGRAM_BYTES_MAY_BE_MODIFIED},
            m.STATE_WRITE: {p.STATE_INJECTION},
            m.RESET: {p.RESET_INDUCED},
            m.RESET_HALT: {p.RESET_INDUCED, p.HALT_INDUCED},
        }.get(self.observation_mode, set())
        if not required <= effects:
            raise ValueError("debug mode requires its known perturbation declarations")
        if self.observation_mode in {m.PASSIVE_READ, m.NON_HALTING_TRACE}:
            if effects not in ({p.UNKNOWN}, {p.NONE_OBSERVED}):
                raise ValueError("passive/non-halting mode cannot describe active control")
        return self

    @property
    def id(self) -> str:
        """Identify provenance with order-independent perturbation declarations."""

        return deterministic_id("v2-debug-provenance-v1", self.model_dump(mode="json"))
