"""Offline Phase 9C Step 4 triggerability aggregation tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.hardware_trigger import (
    ArmMemoryPrecondition,
    ArmPrivilegeMode,
    ArmRegisterPrecondition,
    HardwareTriggerPreconditions,
    HardwareTriggerSignature,
    InvalidTriggerabilityInputError,
    RuntimeFirmwareTriggerMatchResult,
    RuntimeFirmwareTriggerMatcher,
    RuntimeFirmwareTriggerOccurrence,
    RuntimeInstructionOccurrence,
    RuntimeTriggerExecutionTrace,
    StaticFirmwareTriggerMatch,
    StaticFirmwareTriggerMatchResult,
    TriggerabilityAggregationResult,
    TriggerabilityAggregator,
    TriggerabilityBindingError,
    TriggerabilityStatus,
    runtime_trigger_match_result_sha256,
    static_trigger_result_sha256,
)
from chipchain.models import Architecture
from chipchain.runtime.qemu import QemuTriggerRawTraceParser


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "phase9c" / "arm_a32_trigger_runtime"
RAW = (
    ROOT
    / "tests"
    / "fixtures"
    / "qemu_trigger_raw"
    / "valid_arm_a32_trigger_trace.jsonl"
)
TRUTH = json.loads((FIXTURE / "ground_truth.json").read_text("utf-8"))
BASE_SIGNATURE = HardwareTriggerSignature.model_validate_json(
    (FIXTURE / "hardware_trigger_signature.json").read_text("utf-8")
)


def _signature(
    preconditions: HardwareTriggerPreconditions | None = None,
    *,
    hardware_vulnerability_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> HardwareTriggerSignature:
    return HardwareTriggerSignature.create(
        architecture=BASE_SIGNATURE.architecture,
        execution_mode=BASE_SIGNATURE.execution_mode,
        hardware_vulnerability_id=(
            hardware_vulnerability_id
            or BASE_SIGNATURE.hardware_vulnerability_id
        ),
        instruction_sequence=list(BASE_SIGNATURE.instruction_sequence),
        preconditions=preconditions or HardwareTriggerPreconditions(),
        expected_effect=BASE_SIGNATURE.expected_effect,
        proof=BASE_SIGNATURE.proof,
        metadata=metadata or BASE_SIGNATURE.metadata,
    )


def _static_result(
    signature: HardwareTriggerSignature,
    *,
    match_count: int = 2,
    artifact_id: str = str(TRUTH["artifact_id"]),
    artifact_sha256: str = str(TRUTH["artifact_sha256"]),
    words: list[str] | None = None,
    diagnostics: list[str] | None = None,
) -> StaticFirmwareTriggerMatchResult:
    matches: list[StaticFirmwareTriggerMatch] = []
    for item in TRUTH["static_occurrences"][:match_count]:
        instruction_words = words or list(signature.instruction_sequence)
        matches.append(
            StaticFirmwareTriggerMatch.create(
                artifact_id=artifact_id,
                artifact_sha256=artifact_sha256,
                signature_id=signature.id,
                hardware_vulnerability_id=signature.hardware_vulnerability_id,
                architecture=signature.architecture,
                execution_mode=signature.execution_mode,
                function_address=item["function_address"],
                function_name=item["function"],
                instruction_locations=[
                    {
                        "instruction_address": address,
                        "instruction_word": word,
                        "basic_block_address": item["function_address"],
                    }
                    for address, word in zip(
                        item["instruction_addresses"],
                        instruction_words,
                        strict=True,
                    )
                ],
                basic_block_path=[item["function_address"]],
                metadata={"fixture": True},
            )
        )
    return StaticFirmwareTriggerMatchResult(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        signature_id=signature.id,
        hardware_vulnerability_id=signature.hardware_vulnerability_id,
        architecture=signature.architecture,
        execution_mode=signature.execution_mode,
        matches=matches,
        diagnostics=diagnostics or ["owned_synthetic_static_fixture"],
    )


def _runtime_trace(
    static: StaticFirmwareTriggerMatchResult,
    *,
    observed: bool = True,
) -> RuntimeTriggerExecutionTrace:
    parsed = QemuTriggerRawTraceParser().parse(RAW)
    instructions = (
        [
            RuntimeInstructionOccurrence.create(
                sequence_index=item.sequence_index,
                pc=f"0x{int(item.pc.value, 16):08x}",
                instruction_size=item.instruction_size,
                instruction_bytes=item.instruction_bytes,
            )
            for item in parsed.events
        ]
        if observed
        else []
    )
    return RuntimeTriggerExecutionTrace.create(
        raw_trace_id=parsed.id,
        raw_trace_sha256=parsed.raw_trace_sha256,
        run_id=parsed.header.run_id,
        scenario_id="owned-phase9c-trigger-runtime-scenario",
        artifact_id=static.artifact_id,
        artifact_sha256=static.artifact_sha256,
        architecture=static.architecture,
        execution_mode=static.execution_mode,
        instructions=instructions,
        metadata={"fixture": True},
    )


def _runtime_result(
    static: StaticFirmwareTriggerMatchResult,
    *,
    observed: bool = True,
) -> RuntimeFirmwareTriggerMatchResult:
    return RuntimeFirmwareTriggerMatcher().match(
        static, _runtime_trace(static, observed=observed)
    )


def _case(
    *,
    preconditions: HardwareTriggerPreconditions | None = None,
    match_count: int = 2,
    observed: bool = True,
) -> tuple[
    HardwareTriggerSignature,
    StaticFirmwareTriggerMatchResult,
    RuntimeFirmwareTriggerMatchResult,
    TriggerabilityAggregationResult,
]:
    signature = _signature(preconditions)
    static = _static_result(signature, match_count=match_count)
    runtime = _runtime_result(static, observed=observed)
    result = TriggerabilityAggregator().aggregate(signature, static, runtime)
    return signature, static, runtime, result


def _runtime_copy(
    source: RuntimeFirmwareTriggerMatchResult,
    **changes: object,
) -> RuntimeFirmwareTriggerMatchResult:
    values = source.model_dump(mode="json")
    values.update(changes)
    return RuntimeFirmwareTriggerMatchResult.model_validate(values)


def _occurrence_with_sequence(
    runtime: RuntimeFirmwareTriggerMatchResult,
    static_match: StaticFirmwareTriggerMatch,
    *,
    pcs: list[str] | None = None,
    words: list[str] | None = None,
    metadata: dict[str, object] | None = None,
) -> RuntimeFirmwareTriggerOccurrence:
    expected_pcs = [item.instruction_address for item in static_match.instruction_locations]
    expected_words = [item.instruction_word for item in static_match.instruction_locations]
    selected_pcs = pcs or expected_pcs
    selected_words = words or expected_words
    matching_occurrence = next(
        (
            item
            for item in runtime.occurrences
            if item.static_match_id == static_match.id
        ),
        None,
    )
    sequence_indexes = (
        [item.sequence_index for item in matching_occurrence.instructions]
        if matching_occurrence is not None
        else list(range(len(selected_pcs)))
    )
    instructions = [
        RuntimeInstructionOccurrence.create(
            sequence_index=sequence_index,
            pc=pc,
            instruction_size=4,
            instruction_bytes=int(word, 16).to_bytes(4, "little").hex(),
        )
        for sequence_index, (pc, word) in zip(
            sequence_indexes,
            zip(selected_pcs, selected_words, strict=True),
            strict=True,
        )
    ]
    return RuntimeFirmwareTriggerOccurrence.create(
        trace_id=runtime.trace_id,
        raw_trace_sha256=runtime.raw_trace_sha256,
        artifact_id=runtime.artifact_id,
        artifact_sha256=runtime.artifact_sha256,
        static_match_id=static_match.id,
        signature_id=runtime.signature_id,
        hardware_vulnerability_id=runtime.hardware_vulnerability_id,
        architecture=runtime.architecture,
        execution_mode=runtime.execution_mode,
        instructions=instructions,
        metadata=metadata or {},
    )


def test_owned_synthetic_empty_p_end_to_end_is_triggerable() -> None:
    """Triggerable only under the owned synthetic declared trigger contract."""

    _, static, runtime, result = _case()

    assert len(static.matches) == 2
    assert len(runtime.occurrences) == 1
    assert result.status is TriggerabilityStatus.TRIGGERABLE
    assert result.declared_preconditions_present is False
    assert result.static_match_ids == sorted(item.id for item in static.matches)
    assert result.runtime_occurrence_ids == [runtime.occurrences[0].id]


def test_one_of_multiple_static_matches_is_enough_when_runtime_executes_it() -> None:
    _, static, runtime, result = _case(match_count=2)

    assert len(static.matches) == 2
    assert {item.static_match_id for item in runtime.occurrences} == {
        static.matches[0].id
    }
    assert result.status is TriggerabilityStatus.TRIGGERABLE


def test_static_match_without_runtime_occurrence_is_scenario_specific() -> None:
    _, _, runtime, result = _case(observed=False)

    assert runtime.occurrences == []
    assert result.status is TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME


def test_zero_static_and_zero_runtime_is_no_static_trigger_match() -> None:
    _, static, runtime, result = _case(match_count=0)

    assert static.matches == []
    assert runtime.static_match_ids == []
    assert runtime.occurrences == []
    assert result.status is TriggerabilityStatus.NO_STATIC_TRIGGER_MATCH


@pytest.mark.parametrize(
    "preconditions",
    [
        HardwareTriggerPreconditions(privilege_mode=ArmPrivilegeMode.SUPERVISOR),
        HardwareTriggerPreconditions(
            register_preconditions=[
                ArmRegisterPrecondition(register="r0", value="0x00000001")
            ]
        ),
        HardwareTriggerPreconditions(
            memory_preconditions=[
                ArmMemoryPrecondition(
                    address="0x00001000", access_size=4, value="0x00000001"
                )
            ]
        ),
        HardwareTriggerPreconditions(
            privilege_mode=ArmPrivilegeMode.SUPERVISOR,
            register_preconditions=[
                ArmRegisterPrecondition(register="r1", value="0x00000002")
            ],
            memory_preconditions=[
                ArmMemoryPrecondition(
                    address="0x00001004", access_size=4, value="0x00000003"
                )
            ],
        ),
    ],
    ids=("privilege", "register", "memory", "multiple"),
)
def test_any_declared_p_is_insufficient_without_step3b(
    preconditions: HardwareTriggerPreconditions,
) -> None:
    _, _, runtime, result = _case(preconditions=preconditions)

    assert runtime.occurrences
    assert result.declared_preconditions_present is True
    assert (
        result.status
        is TriggerabilityStatus.INSUFFICIENT_PRECONDITION_EVIDENCE
    )


def test_absence_of_declared_p_is_never_inferred_from_metadata() -> None:
    signature = _signature(
        metadata={
            "privilege_mode": "supervisor",
            "register_precondition": "r0=1",
            "memory_precondition": "0x1000=1",
        }
    )
    static = _static_result(signature)
    runtime = _runtime_result(static)

    result = TriggerabilityAggregator().aggregate(signature, static, runtime)

    assert signature.preconditions == HardwareTriggerPreconditions()
    assert result.status is TriggerabilityStatus.TRIGGERABLE


@pytest.mark.parametrize("mismatch", ["signature_id", "hardware_vulnerability_id"])
def test_signature_static_identity_mismatch_fails_closed(mismatch: str) -> None:
    signature = _signature()
    static = _static_result(signature)
    runtime = _runtime_result(static)
    replacement = (
        _signature(
            HardwareTriggerPreconditions(privilege_mode=ArmPrivilegeMode.USER)
        )
        if mismatch == "signature_id"
        else _signature(hardware_vulnerability_id="different-hardware-contract")
    )

    with pytest.raises(TriggerabilityBindingError, match="signature.*static"):
        TriggerabilityAggregator().aggregate(replacement, static, runtime)


@pytest.mark.parametrize(
    ("field", "value"),
    [("artifact_id", "different-artifact"), ("artifact_sha256", "f" * 64)],
)
def test_static_runtime_artifact_mismatch_fails_closed(
    field: str, value: str
) -> None:
    signature = _signature()
    static = _static_result(signature)
    runtime = _runtime_result(static, observed=False)
    changed = _runtime_copy(runtime, **{field: value})

    with pytest.raises(TriggerabilityBindingError, match="static and runtime"):
        TriggerabilityAggregator().aggregate(signature, static, changed)


def test_runtime_static_semantic_hash_mismatch_fails_closed() -> None:
    signature, static, runtime, _ = _case()
    changed = _runtime_copy(runtime, static_result_sha256="f" * 64)

    with pytest.raises(TriggerabilityBindingError, match="semantic hash"):
        TriggerabilityAggregator().aggregate(signature, static, changed)


def test_runtime_static_match_id_set_must_be_exact() -> None:
    signature, static, runtime, _ = _case()
    changed = _runtime_copy(
        runtime,
        static_match_ids=[*runtime.static_match_ids, "unknown-static-match"],
    )

    with pytest.raises(TriggerabilityBindingError, match="exact static set"):
        TriggerabilityAggregator().aggregate(signature, static, changed)


def test_static_words_must_equal_signature_sequence_even_when_model_is_valid() -> None:
    signature = _signature()
    changed_words = list(signature.instruction_sequence)
    changed_words[1] = "0xe2801002"
    static = _static_result(signature, match_count=1, words=changed_words)
    runtime = _runtime_result(static, observed=False)

    with pytest.raises(TriggerabilityBindingError, match="static trigger words"):
        TriggerabilityAggregator().aggregate(signature, static, runtime)


@pytest.mark.parametrize("change", ["pc", "word"])
def test_runtime_occurrence_must_equal_referenced_static_sequence(change: str) -> None:
    signature = _signature()
    static = _static_result(signature)
    runtime = _runtime_result(static)
    pcs = [item.instruction_address for item in static.matches[0].instruction_locations]
    words = [item.instruction_word for item in static.matches[0].instruction_locations]
    if change == "pc":
        pcs[1] = "0x4020002c"
    else:
        words[1] = "0xe2801002"
    occurrence = _occurrence_with_sequence(
        runtime, static.matches[0], pcs=pcs, words=words
    )
    changed = _runtime_copy(runtime, occurrences=[occurrence.model_dump(mode="json")])

    with pytest.raises(TriggerabilityBindingError, match="PC/word sequence"):
        TriggerabilityAggregator().aggregate(signature, static, changed)


def test_detached_revalidation_rejects_tampered_inputs() -> None:
    signature, static, runtime, _ = _case()
    static.matches[0].instruction_locations[0].__dict__["instruction_word"] = (
        "0xe3a00002"
    )

    with pytest.raises(InvalidTriggerabilityInputError, match="revalidation"):
        TriggerabilityAggregator().aggregate(signature, static, runtime)


def test_runtime_semantic_hash_excludes_diagnostics_and_occurrence_metadata() -> None:
    _, static, runtime, _ = _case()
    changed_diagnostics = _runtime_copy(
        runtime, diagnostics=["different diagnostic wording"]
    )
    changed_metadata_occurrence = _occurrence_with_sequence(
        runtime, static.matches[0], metadata={"different": "wording"}
    )
    changed_metadata = _runtime_copy(
        runtime,
        occurrences=[changed_metadata_occurrence.model_dump(mode="json")],
    )

    expected = runtime_trigger_match_result_sha256(runtime)
    assert runtime_trigger_match_result_sha256(changed_diagnostics) == expected
    assert runtime_trigger_match_result_sha256(changed_metadata) == expected


def test_runtime_semantic_hash_changes_with_semantic_occurrence_input() -> None:
    _, static, runtime, _ = _case()
    words = [item.instruction_word for item in static.matches[0].instruction_locations]
    words[1] = "0xe2801002"
    changed_occurrence = _occurrence_with_sequence(
        runtime, static.matches[0], words=words
    )
    changed = _runtime_copy(
        runtime, occurrences=[changed_occurrence.model_dump(mode="json")]
    )

    assert runtime_trigger_match_result_sha256(changed) != (
        runtime_trigger_match_result_sha256(runtime)
    )


def test_static_diagnostics_do_not_change_static_or_aggregation_identity() -> None:
    signature, static, runtime, result = _case()
    changed_static = _static_result(
        signature, diagnostics=["different static diagnostics"]
    )
    assert static_trigger_result_sha256(changed_static) == (
        static_trigger_result_sha256(static)
    )
    changed_runtime = _runtime_copy(
        runtime,
        static_result_sha256=static_trigger_result_sha256(changed_static),
    )
    changed_result = TriggerabilityAggregator().aggregate(
        signature, changed_static, changed_runtime
    )
    assert changed_result.id == result.id


def test_aggregation_metadata_does_not_change_identity() -> None:
    _, _, _, result = _case()
    values = result.model_dump(mode="json", exclude={"id", "status", "metadata"})

    changed = TriggerabilityAggregationResult.create(
        **values, metadata={"display_only": "different wording"}
    )

    assert changed.id == result.id
    assert changed.status is result.status


def test_result_roundtrip_repeated_aggregation_and_caller_isolation() -> None:
    signature, static, runtime, first = _case()
    second = TriggerabilityAggregator().aggregate(signature, static, runtime)
    restored = TriggerabilityAggregationResult.model_validate_json(
        first.model_dump_json()
    )

    assert second == first == restored
    assert second.model_dump_json() == first.model_dump_json()
    static.matches.clear()
    runtime.occurrences.clear()
    signature.metadata["caller_mutation"] = True
    assert first.static_match_ids
    assert first.runtime_occurrence_ids
    assert "caller_mutation" not in first.metadata


def test_tampered_aggregation_id_or_caller_selected_status_is_rejected() -> None:
    _, _, _, result = _case()
    values = result.model_dump(mode="json")
    values["id"] = "triggerability-aggregation:" + "0" * 64
    with pytest.raises(ValidationError, match="not deterministic"):
        TriggerabilityAggregationResult.model_validate(values)

    values = result.model_dump(mode="json")
    values["status"] = TriggerabilityStatus.NOT_OBSERVED_IN_RUNTIME.value
    with pytest.raises(ValidationError, match="not derived"):
        TriggerabilityAggregationResult.model_validate(values)


def test_result_has_no_verification_chain_score_or_vulnerability_verdict() -> None:
    _, _, _, result = _case()
    serialized = result.model_dump(mode="json")
    forbidden_keys = {
        "verified",
        "confidence",
        "score",
        "attack_chain",
        "chain_status",
        "vulnerability_status",
        "interaction_status",
        "verification_record",
    }

    assert forbidden_keys.isdisjoint(serialized)
    assert "AttackChain" not in result.model_dump_json()
    assert "VerificationRecord" not in result.model_dump_json()
    assert {item.value for item in TriggerabilityStatus} == {
        "triggerable",
        "insufficient_precondition_evidence",
        "not_observed_in_runtime",
        "no_static_trigger_match",
    }
    assert "not_triggerable" not in {item.value for item in TriggerabilityStatus}
