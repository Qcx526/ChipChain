"""Debug vocabulary is provenance, not a functioning probe or natural timing proof."""

import pytest
from pydantic import TypeAdapter, ValidationError

from chipchain.core import DebugObservationMode, DebugProvenance, ExecutionPerturbation


@pytest.mark.parametrize("mode,effects", [
    ("passive_read", ["none_observed"]),
    ("non_halting_trace", ["unknown"]),
    ("hardware_breakpoint_halt", ["halt_induced"]),
    ("manual_halt", ["halt_induced"]),
    ("single_step", ["step_induced"]),
    ("software_breakpoint", ["program_bytes_may_be_modified"]),
    ("state_write", ["state_injection"]),
    ("reset", ["reset_induced"]),
    ("reset_halt", ["reset_induced", "halt_induced"]),
])
def test_explicit_mode_effect_vocabulary(firmware, mode, effects) -> None:
    record = DebugProvenance(
        firmware=firmware, producer_profile_id="synthetic-debug-v1",
        observation_mode=mode, perturbations=effects,
    )
    assert record.observation_mode.value == mode
    assert {p.value for p in record.perturbations} == set(effects)
    assert DebugProvenance.model_validate_json(record.model_dump_json()).id == record.id
    assert not hasattr(record, "read_register") and not hasattr(record, "write_register")


@pytest.mark.parametrize("mode,effects", [
    ("hardware_breakpoint_halt", ["none_observed"]),
    ("hardware_breakpoint_halt", ["unknown"]),
    ("single_step", ["none_observed"]),
    ("single_step", ["halt_induced"]),
    ("software_breakpoint", ["none_observed"]),
    ("software_breakpoint", ["halt_induced"]),
    ("state_write", ["none_observed"]),
    ("reset_halt", ["halt_induced"]),
    ("passive_read", ["state_injection"]),
    ("non_halting_trace", ["halt_induced"]),
    ("manual_halt", ["halt_induced", "none_observed"]),
    ("manual_halt", ["halt_induced", "unknown"]),
    ("manual_halt", ["halt_induced", "halt_induced"]),
    ("passive_read", []),
    ("passive_read", ["undisturbed"]),
    ("real_jtag_backend", ["unknown"]),
])
def test_contradictory_or_missing_debug_effects_fail_closed(firmware, mode, effects) -> None:
    with pytest.raises(ValidationError):
        DebugProvenance(firmware=firmware, producer_profile_id="synthetic-debug-v1",
                        observation_mode=mode, perturbations=effects)


def test_effect_order_not_identity_bearing_and_caller_list_detached(firmware) -> None:
    effects = ["step_induced", "halt_induced"]
    first = DebugProvenance(firmware=firmware, producer_profile_id="synthetic-debug-v1",
                            observation_mode="single_step", perturbations=effects)
    second = DebugProvenance.model_validate({**first.model_dump(), "perturbations": list(reversed(effects))})
    assert first.id == second.id
    effects.clear()
    assert len(first.perturbations) == 2
    only_step = DebugProvenance.model_validate({**first.model_dump(), "perturbations": ["step_induced"]})
    assert first.id != only_step.id


def test_halt_step_and_software_patch_are_not_passive(firmware) -> None:
    mode = DebugObservationMode
    assert mode.HARDWARE_BREAKPOINT_HALT != mode.PASSIVE_READ
    assert mode.SINGLE_STEP != mode.NON_HALTING_TRACE
    assert mode.STATE_WRITE != mode.PASSIVE_READ
    software = DebugProvenance(
        firmware=firmware, producer_profile_id="synthetic-debug-v1",
        observation_mode=mode.SOFTWARE_BREAKPOINT,
        perturbations=(ExecutionPerturbation.PROGRAM_BYTES_MAY_BE_MODIFIED,),
    )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        DebugProvenance.model_validate({**software.model_dump(), "unchanged_program_bytes": True})
    assert "none_observed" in TypeAdapter(ExecutionPerturbation).json_schema()["enum"]
    assert "passive_read" in TypeAdapter(DebugObservationMode).json_schema()["enum"]
