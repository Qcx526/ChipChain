"""Offline Phase 9C Step 1 hardware-trigger signature contract tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

import chipchain.hardware_trigger as hardware_trigger_api
from chipchain.hardware_trigger import (
    ArmExecutionMode,
    ArmMemoryPrecondition,
    ArmPrivilegeMode,
    ArmRegisterPrecondition,
    HardwareFailureEffect,
    HardwareFailureEffectKind,
    HardwareTriggerPreconditions,
    HardwareTriggerProof,
    HardwareTriggerProofKind,
    HardwareTriggerSignature,
)
from chipchain.models import Architecture, VulnerabilitySample


FIXTURE_PATH = (
    Path(__file__).parent
    / "fixtures"
    / "phase9c"
    / "arm_a32_hardware_trigger_signature.json"
)
VULNERABILITY_FIXTURE_PATH = (
    Path(__file__).parent / "fixtures" / "valid_arm_vulnerability.json"
)


def _preconditions() -> HardwareTriggerPreconditions:
    return HardwareTriggerPreconditions(
        privilege_mode=ArmPrivilegeMode.SUPERVISOR,
        register_preconditions=[
            ArmRegisterPrecondition(register="r1", value="0x00000002"),
            ArmRegisterPrecondition(register="r0", value="0x00000001"),
        ],
        memory_preconditions=[
            ArmMemoryPrecondition(
                address="0x00001000",
                access_size=4,
                value="0x12345678",
            )
        ],
    )


def _effect(
    *,
    observed_value: str = "0x00000004",
) -> HardwareFailureEffect:
    return HardwareFailureEffect(
        kind=HardwareFailureEffectKind.REGISTER_MISMATCH,
        register="r2",
        expected_value="0x00000003",
        observed_value=observed_value,
    )


def _proof(
    *,
    description: str = "Owned synthetic differential mismatch",
    reference_ids: list[str] | None = None,
) -> HardwareTriggerProof:
    return HardwareTriggerProof(
        kind=HardwareTriggerProofKind.GOLDEN_MODEL_MISMATCH,
        description=description,
        reference_ids=reference_ids
        or [
            "owned-hardware-diff-run:case-002",
            "owned-hardware-diff-run:case-001",
        ],
    )


def _signature(
    *,
    architecture: Architecture = Architecture.ARM,
    execution_mode: ArmExecutionMode | str = ArmExecutionMode.A32,
    instruction_sequence: list[str] | None = None,
    preconditions: HardwareTriggerPreconditions | None = None,
    expected_effect: HardwareFailureEffect | None = None,
    proof: HardwareTriggerProof | None = None,
    metadata: dict[str, object] | None = None,
) -> HardwareTriggerSignature:
    return HardwareTriggerSignature.create(
        architecture=architecture,
        execution_mode=execution_mode,
        hardware_vulnerability_id=(
            "synthetic-owned-arm-a32-hardware-trigger-test"
        ),
        instruction_sequence=instruction_sequence
        if instruction_sequence is not None
        else ["0xe3a00001", "0xe2801001", "0xe1a02001"],
        preconditions=preconditions or _preconditions(),
        expected_effect=expected_effect or _effect(),
        proof=proof or _proof(),
        metadata=metadata
        or {"fixture": True, "synthetic": True, "owned": True},
    )


def test_valid_arm_a32_signature_construction() -> None:
    signature = _signature()

    assert signature.architecture is Architecture.ARM
    assert signature.execution_mode is ArmExecutionMode.A32
    assert signature.id.startswith("hardware-trigger-signature:")
    assert len(signature.id.removeprefix("hardware-trigger-signature:")) == 64
    assert signature.preconditions.privilege_mode is ArmPrivilegeMode.SUPERVISOR


def test_non_arm_architecture_is_rejected() -> None:
    with pytest.raises((ValidationError, ValueError), match="support ARM only"):
        _signature(architecture=Architecture.RISC_V)


def test_non_a32_execution_mode_is_rejected() -> None:
    with pytest.raises(ValueError):
        _signature(execution_mode="thumb_t32")


def test_instruction_sequence_must_be_non_empty() -> None:
    with pytest.raises((ValidationError, ValueError), match="non-empty"):
        _signature(instruction_sequence=[])


def test_uppercase_instruction_digits_are_canonicalized() -> None:
    signature = _signature(
        instruction_sequence=["0xE3A00001", "0xE2801001", "0xE1A02001"]
    )

    assert signature.instruction_sequence == [
        "0xe3a00001",
        "0xe2801001",
        "0xe1a02001",
    ]


@pytest.mark.parametrize(
    "word",
    ["e3a00001", "0xzzzzzzzz", "0xe3a0000", 0xE3A00001],
)
def test_malformed_or_ambiguous_instruction_word_is_rejected(
    word: object,
) -> None:
    with pytest.raises((ValidationError, ValueError), match="instruction word"):
        _signature(instruction_sequence=[word])  # type: ignore[list-item]


def test_instruction_word_wider_than_32_bits_is_rejected() -> None:
    with pytest.raises(ValueError, match="exactly 8"):
        _signature(instruction_sequence=["0x1e3a00001"])


def test_exact_instruction_order_is_preserved() -> None:
    words = ["0xe1a02001", "0xe3a00001", "0xe2801001"]

    assert _signature(instruction_sequence=words).instruction_sequence == words


def test_changing_instruction_word_changes_signature_id() -> None:
    first = _signature()
    second = _signature(
        instruction_sequence=["0xe3a00002", "0xe2801001", "0xe1a02001"]
    )

    assert first.id != second.id


def test_changing_instruction_order_changes_signature_id() -> None:
    first = _signature()
    second = _signature(
        instruction_sequence=["0xe2801001", "0xe3a00001", "0xe1a02001"]
    )

    assert first.id != second.id


def test_metadata_changes_do_not_change_semantic_id() -> None:
    first = _signature(metadata={"fixture": True, "note": "first"})
    second = _signature(metadata={"fixture": True, "note": "second"})

    assert first.id == second.id
    assert first.metadata != second.metadata


def test_proof_wording_and_reference_order_do_not_change_semantic_id() -> None:
    first = _signature(
        proof=_proof(
            description="First owned proof wording",
            reference_ids=["owned:second", "owned:first"],
        )
    )
    second = _signature(
        proof=_proof(
            description="Reworded owned proof",
            reference_ids=["owned:first", "owned:second"],
        )
    )

    assert first.id == second.id
    assert first.proof.reference_ids == second.proof.reference_ids


def test_changing_true_precondition_changes_signature_id() -> None:
    changed = _preconditions().model_copy(deep=True)
    changed.register_preconditions[0] = ArmRegisterPrecondition(
        register="r0",
        value="0x00000005",
    )

    assert _signature().id != _signature(preconditions=changed).id


def test_changing_expected_failure_semantics_changes_signature_id() -> None:
    assert _signature().id != _signature(
        expected_effect=_effect(observed_value="0x00000005")
    ).id


@pytest.mark.parametrize("register", ["r0", "r7", "r15"])
def test_canonical_arm_register_names_are_valid(register: str) -> None:
    value = ArmRegisterPrecondition(register=register, value="0xFFFFFFFF")

    assert value.register == register
    assert value.value == "0xffffffff"
    assert value.model_dump(mode="json")["register"] == register


@pytest.mark.parametrize("register", ["sp", "lr", "pc", "R0", "r16", "x0"])
def test_register_aliases_and_invalid_names_are_rejected(register: str) -> None:
    with pytest.raises(ValidationError, match="canonical spelling"):
        ArmRegisterPrecondition(register=register, value="0x00000000")


@pytest.mark.parametrize(
    "value",
    ["0x100000000", "0xfffffffff", "0x0000000g", "0x1", 1],
)
def test_register_value_must_be_explicit_uint32_hex(value: object) -> None:
    with pytest.raises(ValidationError, match="register value"):
        ArmRegisterPrecondition(register="r0", value=value)  # type: ignore[arg-type]


def test_duplicate_register_preconditions_are_rejected() -> None:
    with pytest.raises(ValidationError, match="unique registers"):
        HardwareTriggerPreconditions(
            register_preconditions=[
                {"register": "r0", "value": "0x00000000"},
                {"register": "r0", "value": "0xffffffff"},
            ]
        )


def test_register_preconditions_are_stored_in_canonical_order() -> None:
    preconditions = HardwareTriggerPreconditions(
        register_preconditions=[
            {"register": "r10", "value": "0x0000000a"},
            {"register": "r2", "value": "0x00000002"},
            {"register": "r1", "value": "0x00000001"},
        ]
    )

    assert [item.register for item in preconditions.register_preconditions] == [
        "r1",
        "r2",
        "r10",
    ]


@pytest.mark.parametrize("mode", list(ArmPrivilegeMode))
def test_all_declared_a32_privilege_modes_are_valid(
    mode: ArmPrivilegeMode,
) -> None:
    assert HardwareTriggerPreconditions(privilege_mode=mode).privilege_mode is mode


def test_invalid_privilege_mode_is_rejected() -> None:
    with pytest.raises(ValidationError):
        HardwareTriggerPreconditions(privilege_mode="kernel")


def test_empty_precondition_container_is_valid() -> None:
    value = HardwareTriggerPreconditions()

    assert value.privilege_mode is None
    assert value.register_preconditions == []
    assert value.memory_preconditions == []


@pytest.mark.parametrize(
    ("access_size", "value", "canonical"),
    [(1, "0xFF", "0xff"), (2, "0x1234", "0x1234"), (4, "0x89ABCDEF", "0x89abcdef")],
)
def test_valid_exact_memory_preconditions(
    access_size: int,
    value: str,
    canonical: str,
) -> None:
    precondition = ArmMemoryPrecondition(
        address="0xFFFF0000",
        access_size=access_size,
        value=value,
    )

    assert precondition.address == "0xffff0000"
    assert precondition.value == canonical


@pytest.mark.parametrize(
    ("access_size", "value"),
    [(1, "0x0100"), (2, "0x010000"), (4, "0x100000000")],
)
def test_memory_value_overflow_is_rejected(
    access_size: int,
    value: str,
) -> None:
    with pytest.raises(ValidationError, match="memory value"):
        ArmMemoryPrecondition(
            address="0x00001000",
            access_size=access_size,
            value=value,
        )


@pytest.mark.parametrize("access_size", [0, 3, 8])
def test_unsupported_memory_access_size_is_rejected(access_size: int) -> None:
    with pytest.raises(ValidationError):
        ArmMemoryPrecondition(
            address="0x00001000",
            access_size=access_size,
            value="0x00",
        )


def test_duplicate_memory_binding_is_rejected() -> None:
    with pytest.raises(ValidationError, match="unique address/access-size"):
        HardwareTriggerPreconditions(
            memory_preconditions=[
                {
                    "address": "0x00001000",
                    "access_size": 4,
                    "value": "0x00000000",
                },
                {
                    "address": "0x00001000",
                    "access_size": 4,
                    "value": "0xffffffff",
                },
            ]
        )


@pytest.mark.parametrize(
    "missing_field",
    ["register", "expected_value", "observed_value"],
)
def test_register_mismatch_requires_all_typed_fields(
    missing_field: str,
) -> None:
    payload = {
        "kind": "register_mismatch",
        "register": "r2",
        "expected_value": "0x00000003",
        "observed_value": "0x00000004",
    }
    payload.pop(missing_field)

    with pytest.raises(ValidationError, match="requires register"):
        HardwareFailureEffect.model_validate(payload)


def test_register_mismatch_rejects_equal_values() -> None:
    with pytest.raises(ValidationError, match="must differ"):
        HardwareFailureEffect(
            kind="register_mismatch",
            register="r2",
            expected_value="0x00000003",
            observed_value="0x00000003",
        )


def test_register_mismatch_rejects_assertion_fields() -> None:
    with pytest.raises(ValidationError, match="must not contain assertion"):
        HardwareFailureEffect(
            kind="register_mismatch",
            register="r2",
            expected_value="0x00000003",
            observed_value="0x00000004",
            assertion_id="synthetic-assertion",
        )


def test_assertion_violation_requires_identity_or_description() -> None:
    with pytest.raises(ValidationError, match="requires assertion"):
        HardwareFailureEffect(kind="assertion_violation")


def test_assertion_violation_is_not_coerced_to_register_mismatch() -> None:
    effect = HardwareFailureEffect(
        kind="assertion_violation",
        assertion_id="owned-rtl-assertion:assert-17",
    )

    assert effect.kind is HardwareFailureEffectKind.ASSERTION_VIOLATION
    assert effect.register is None


def test_assertion_violation_rejects_register_fields() -> None:
    with pytest.raises(ValidationError, match="must not contain register"):
        HardwareFailureEffect(
            kind="assertion_violation",
            assertion_id="owned-assertion",
            register="r0",
            expected_value="0x00000000",
            observed_value="0x00000001",
        )


@pytest.mark.parametrize(
    "kind",
    [
        HardwareTriggerProofKind.GOLDEN_MODEL_MISMATCH,
        HardwareTriggerProofKind.ASSERTION_VIOLATION,
    ],
)
def test_supported_proof_kinds_validate(kind: HardwareTriggerProofKind) -> None:
    assert HardwareTriggerProof(
        kind=kind,
        description="Owned proof record",
        reference_ids=["owned-proof:001"],
    ).kind is kind


def test_invalid_proof_kind_is_rejected() -> None:
    with pytest.raises(ValidationError):
        HardwareTriggerProof(
            kind="firmware_execution",
            description="Invalid proof category",
            reference_ids=["owned-proof:001"],
        )


def test_proof_references_must_be_non_empty() -> None:
    with pytest.raises(ValidationError):
        HardwareTriggerProof(
            kind="golden_model_mismatch",
            description="Owned proof record",
            reference_ids=[],
        )


def test_duplicate_proof_references_are_rejected() -> None:
    with pytest.raises(ValidationError, match="must be unique"):
        HardwareTriggerProof(
            kind="golden_model_mismatch",
            description="Owned proof record",
            reference_ids=["owned-proof:001", "owned-proof:001"],
        )


def test_tampered_deserialized_signature_id_is_rejected() -> None:
    payload = _signature().model_dump(mode="json")
    payload["instruction_sequence"][0] = "0xe3a00002"

    with pytest.raises(ValidationError, match="ID is not deterministic"):
        HardwareTriggerSignature.model_validate(payload)


def test_owned_synthetic_fixture_loads_with_explicit_boundary() -> None:
    signature = HardwareTriggerSignature.model_validate_json(
        FIXTURE_PATH.read_text(encoding="utf-8")
    )

    assert signature.hardware_vulnerability_id.startswith("synthetic-owned-")
    assert signature.metadata["fixture"] is True
    assert signature.metadata["synthetic"] is True
    assert signature.metadata["owned"] is True
    assert signature.metadata["real_hardware_vulnerability"] is False
    assert "no real ARM hardware vulnerability" in signature.proof.description


def test_fixture_json_round_trip_preserves_model_and_id() -> None:
    first = HardwareTriggerSignature.model_validate_json(
        FIXTURE_PATH.read_text(encoding="utf-8")
    )
    second = HardwareTriggerSignature.model_validate_json(
        first.model_dump_json()
    )

    assert second == first
    assert second.id == first.id


@pytest.mark.parametrize(
    "target",
    ["signature", "preconditions", "effect", "proof"],
)
def test_unknown_fields_fail_closed(target: str) -> None:
    payload = _signature().model_dump(mode="json")
    container = {
        "signature": payload,
        "preconditions": payload["preconditions"],
        "effect": payload["expected_effect"],
        "proof": payload["proof"],
    }[target]
    container["unexpected_field"] = "not-allowed"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        HardwareTriggerSignature.model_validate(payload)


def test_existing_vulnerability_sample_contract_is_unchanged() -> None:
    sample = VulnerabilitySample.model_validate_json(
        VULNERABILITY_FIXTURE_PATH.read_text(encoding="utf-8")
    )
    schema_fields = VulnerabilitySample.model_fields

    assert sample.triggers
    assert sample.preconditions
    assert "hardware_trigger_signature" not in schema_fields
    assert "hardware_trigger_signatures" not in schema_fields


def test_public_api_contains_contracts_but_no_future_result_or_matcher() -> None:
    assert set(hardware_trigger_api.__all__) == {
        "ArmExecutionMode",
        "ArmMemoryPrecondition",
        "ArmPrivilegeMode",
        "ArmRegisterPrecondition",
        "HardwareFailureEffect",
        "HardwareFailureEffectKind",
        "HardwareTriggerPreconditions",
        "HardwareTriggerProof",
        "HardwareTriggerProofKind",
        "HardwareTriggerSignature",
        "hardware_trigger_signature_id",
    }
    serialized = json.dumps(_signature().model_dump(mode="json")).lower()
    for forbidden in (
        "firmware_id",
        "function_id",
        "instruction_address",
        "reachability",
        "runtime_trace",
        "triggerability_status",
        "verificationrecord",
        "attackchain",
        "score",
        "confidence",
    ):
        assert forbidden not in serialized
