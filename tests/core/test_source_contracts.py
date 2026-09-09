"""Exact V2 source/target bindings without interpreting synthetic artifact bytes."""

import copy

import pytest
from pydantic import ValidationError

from chipchain.core import (
    Architecture, ArtifactProvenance, DebugProvenance, DomainModel,
    ExternalInputArtifact, ExternalInputEndpoint, ExternalInputTransport,
    GDBFuzzArtifact, HardwareTargetIdentity, ImmutableFirmwareArtifact,
    InputDeliveryProvenance, InputSynchronizationMode, ProcessorFuzzArtifact,
    deterministic_id,
)


def source(**changes: object) -> ArtifactProvenance:
    return ArtifactProvenance.model_validate({
        "artifact_id": "synthetic-source", "artifact_sha256": "c" * 64,
        "architecture": "riscv", "source_kind": "synthetic",
        "producer_profile_id": "synthetic-tool-v1", **changes,
    })


@pytest.mark.parametrize("architecture", ["riscv", "arm"])
def test_target_deterministic_vocabulary_and_labels(architecture: str) -> None:
    payload = {
        "target_id": "synthetic-board", "architecture": architecture,
        "hardware_model": "Synthetic CPU Model", "hardware_revision": "r1 p0",
    }
    target = HardwareTargetIdentity.model_validate(payload)
    reordered = HardwareTargetIdentity.model_validate(dict(reversed(list(payload.items()))))
    assert target.id == reordered.id
    assert target.hardware_model == "Synthetic CPU Model"
    assert target.hardware_revision == "r1 p0"
    assert target.architecture.value == architecture
    assert target.id == deterministic_id("v2-hardware-target-v1", target.model_dump(mode="json"))
    unknown = HardwareTargetIdentity.model_validate({**payload, "hardware_revision": None})
    assert unknown.hardware_revision is None and unknown.id != target.id


@pytest.mark.parametrize("field", ["hardware_model", "hardware_revision"])
@pytest.mark.parametrize("value", ["", " ", " leading", "trailing ", "line\nbreak", 12])
def test_invalid_hardware_labels_fail_closed(target, field, value) -> None:
    with pytest.raises(ValidationError):
        HardwareTargetIdentity.model_validate({**target.model_dump(), field: value})


@pytest.mark.parametrize("field,value", [
    ("target_id", "synthetic-other"), ("architecture", "arm"),
    ("hardware_model", "Other Model"), ("hardware_revision", "rev 2"),
    ("instruction_set_profile_id", "other-profile"),
])
def test_target_identity_bears_every_field(target, field, value) -> None:
    changed = HardwareTargetIdentity.model_validate({**target.model_dump(), field: value})
    assert changed.id != target.id


def test_firmware_declared_exact_sha_and_copy_binding(firmware) -> None:
    assert firmware.provenance.artifact_sha256 == "ab" * 32
    assert firmware.provenance.architecture == Architecture.RISC_V
    payload = firmware.model_dump(mode="json")
    payload["provenance"]["source_kind"] = "synthetic-offline-copy"
    copied = ImmutableFirmwareArtifact.model_validate(payload)
    copied.require_same_target(firmware)
    # Declaration identity includes provenance; artifact byte identity does not.
    assert copied.id != firmware.id
    assert copied.provenance.artifact_id == firmware.provenance.artifact_id
    assert copied.provenance.artifact_sha256 == firmware.provenance.artifact_sha256


@pytest.mark.parametrize("architecture", [None, "arm"])
def test_firmware_architecture_is_explicit_and_matches_target(firmware, architecture) -> None:
    data = firmware.model_dump(mode="json")
    data["provenance"]["architecture"] = architecture
    with pytest.raises(ValidationError, match="architecture"):
        ImmutableFirmwareArtifact.model_validate(data)


@pytest.mark.parametrize("path,value", [
    (("provenance", "artifact_id"), "synthetic-other-image"),
    (("provenance", "artifact_sha256"), "d" * 64),
    (("hardware_target", "target_id"), "synthetic-other-board"),
    (("hardware_target", "hardware_revision"), "rev 2"),
    (("instruction_set_profile_id",), "other-profile"),
])
def test_exact_binding_rejects_different_target(firmware, delivery, path, value) -> None:
    payload = firmware.model_dump(mode="json")
    cursor = payload
    for key in path[:-1]:
        cursor = cursor[key]
    cursor[path[-1]] = value
    different = ImmutableFirmwareArtifact.model_validate(payload)
    assert different.id != firmware.id
    campaign = GDBFuzzArtifact(provenance=source(), firmware=firmware)
    testcase = ExternalInputArtifact(provenance=source(), firmware=firmware, delivery=delivery)
    for require in (firmware.require_same_target, campaign.require_firmware, testcase.require_firmware):
        with pytest.raises(ValueError, match="exact firmware target binding mismatch"):
            require(different)


def test_exact_binding_rejects_different_architecture(firmware) -> None:
    payload = firmware.model_dump(mode="json")
    payload["provenance"]["architecture"] = "arm"
    payload["hardware_target"]["architecture"] = "arm"
    other = ImmutableFirmwareArtifact.model_validate(payload)
    with pytest.raises(ValueError, match="binding mismatch"):
        firmware.require_same_target(other)


def test_processorfuzz_target_is_retained_not_equated_with_client(target) -> None:
    implementation = HardwareTargetIdentity.model_validate({
        **target.model_dump(), "target_id": "synthetic-processorfuzz-implementation",
    })
    si = ProcessorFuzzArtifact(provenance=source(), hardware_target=implementation)
    assert si.hardware_target == implementation
    assert si.hardware_target.id != target.id
    assert si.hardware_target.architecture == target.architecture
    assert set(type(si).model_fields) == {"provenance", "hardware_target"}
    with pytest.raises(ValidationError):
        ProcessorFuzzArtifact(provenance=source())


@pytest.mark.parametrize("kind", ["processor", "gdb"])
@pytest.mark.parametrize("changes", [
    {"architecture": "arm"}, {"architecture": None}, {"producer_profile_id": None},
])
def test_tool_sources_require_architecture_and_producer(target, firmware, kind, changes) -> None:
    with pytest.raises(ValidationError):
        if kind == "processor":
            ProcessorFuzzArtifact(provenance=source(**changes), hardware_target=target)
        else:
            GDBFuzzArtifact(provenance=source(**changes), firmware=firmware)


def test_gdbfuzz_exact_binding_is_one_nested_snapshot(firmware) -> None:
    campaign = GDBFuzzArtifact(provenance=source(), firmware=firmware)
    campaign.require_firmware(firmware)
    assert campaign.firmware is not firmware
    assert campaign.firmware.provenance.artifact_id == "synthetic-firmware"
    assert campaign.firmware.provenance.artifact_sha256 == "ab" * 32
    # A second, contradictory flattened binding is never silently accepted.
    for field in ("firmware_artifact_id", "firmware_sha256", "architecture", "target_id"):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            GDBFuzzArtifact.model_validate({**campaign.model_dump(), field: "contradiction"})


@pytest.mark.parametrize("transport", list(ExternalInputTransport))
def test_endpoint_transport_vocabulary(target, transport) -> None:
    endpoint = ExternalInputEndpoint(
        endpoint_id="synthetic-endpoint", hardware_target=target, transport=transport,
        declared_transport_id="synthetic-other-bus" if transport == ExternalInputTransport.OTHER_DECLARED else None,
    )
    assert ExternalInputEndpoint.model_validate_json(endpoint.model_dump_json()).id == endpoint.id
    assert endpoint.application_protocol_profile_id is None


@pytest.mark.parametrize("transport,declared", [
    ("unknown", None), ("other_declared", None), ("serial_uart", "other"),
])
def test_endpoint_rejects_unknown_or_ambiguous_transport(target, transport, declared) -> None:
    with pytest.raises(ValidationError):
        ExternalInputEndpoint(
            endpoint_id="synthetic", hardware_target=target, transport=transport,
            declared_transport_id=declared,
        )


def test_delivery_separates_tool_transport_protocol_and_unknowns(delivery) -> None:
    assert delivery.synchronization_mode == InputSynchronizationMode.UNKNOWN
    assert delivery.reset_profile_id is None and delivery.framing_profile_id is None
    assert delivery.endpoint.transport == ExternalInputTransport.SERIAL_UART
    declared = InputDeliveryProvenance.model_validate({
        **delivery.model_dump(), "producer_tool": "gdbfuzz",
        "host_adapter_profile_id": "synthetic-serial-example-profile",
        "framing_profile_id": "synthetic-length-prefixed",
        "synchronization_mode": "target_ready_marker",
    })
    assert declared.endpoint == delivery.endpoint
    assert declared.id != delivery.id
    assert set(type(declared).model_fields).isdisjoint({"consumed", "executed", "firmware_modified"})


@pytest.mark.parametrize("mode,profile", [("declared_profile", None), ("unknown", "profile"), ("bogus", None)])
def test_delivery_synchronization_fail_closed(delivery, mode, profile) -> None:
    with pytest.raises(ValidationError):
        InputDeliveryProvenance.model_validate({
            **delivery.model_dump(), "synchronization_mode": mode,
            "synchronization_profile_id": profile,
        })


@pytest.mark.parametrize("length", [None, 0, 128])
def test_input_artifact_binds_bytes_delivery_and_firmware(firmware, delivery, length) -> None:
    testcase = ExternalInputArtifact(
        provenance=source(architecture=None), firmware=firmware, delivery=delivery, byte_length=length,
    )
    testcase.require_firmware(firmware)
    assert testcase.delivery.endpoint.hardware_target == testcase.firmware.hardware_target
    assert testcase.byte_length == length


@pytest.mark.parametrize("length", [-1, True, 1.5, "2"])
def test_input_length_is_strict_nonnegative(firmware, delivery, length) -> None:
    with pytest.raises(ValidationError):
        ExternalInputArtifact(provenance=source(), firmware=firmware, delivery=delivery, byte_length=length)


@pytest.mark.parametrize("field,value", [("target_id", "other-client"), ("hardware_revision", "rev 2")])
def test_input_endpoint_exact_target_mismatch(firmware, delivery, field, value) -> None:
    data = delivery.model_dump(mode="json")
    data["endpoint"]["hardware_target"][field] = value
    other = InputDeliveryProvenance.model_validate(data)
    with pytest.raises(ValidationError, match="endpoint hardware target mismatch"):
        ExternalInputArtifact(provenance=source(), firmware=firmware, delivery=other)


def test_input_architecture_mismatch(firmware, delivery) -> None:
    with pytest.raises(ValidationError, match="architecture mismatch"):
        ExternalInputArtifact(provenance=source(architecture="arm"), firmware=firmware, delivery=delivery)


def declarations(target, firmware, endpoint, delivery) -> list[DomainModel]:
    return [
        target, firmware, endpoint, delivery,
        ProcessorFuzzArtifact(provenance=source(), hardware_target=target),
        GDBFuzzArtifact(provenance=source(), firmware=firmware),
        ExternalInputArtifact(provenance=source(), firmware=firmware, delivery=delivery),
        DebugProvenance(firmware=firmware, producer_profile_id="synthetic-debugger-v1",
                        observation_mode="passive_read", perturbations=("unknown",)),
    ]


@pytest.mark.parametrize("field", [
    "verified", "verification_status", "vulnerability", "triggerable", "satisfied",
    "confidence", "risk_score", "attack_chain_status", "LLM_score", "support_verdict",
    "hardware_applicability", "evidence", "firmware_modified", "raw_bytes", "path",
])
def test_no_verdict_evidence_or_implicit_bytes_fields(target, firmware, endpoint, delivery, field) -> None:
    for item in declarations(target, firmware, endpoint, delivery):
        assert field not in type(item).model_fields
        with pytest.raises(ValidationError, match="extra_forbidden"):
            type(item).model_validate({**item.model_dump(), field: True})


def test_all_declarations_deterministic_detached_frozen_roundtrip(target, firmware, endpoint, delivery) -> None:
    for item in declarations(target, firmware, endpoint, delivery):
        payload = item.model_dump(mode="json")
        before = copy.deepcopy(payload)
        snapshot = type(item).model_validate(payload)
        assert payload == before
        assert snapshot.id == item.id
        assert type(item).model_validate_json(item.model_dump_json()).id == item.id
        assert "id" not in payload  # Derived identity is not accepted as caller authority.
        with pytest.raises(ValidationError, match="extra_forbidden"):
            type(item).model_validate({**payload, "id": item.id})
        field = next(iter(payload))
        with pytest.raises(ValidationError, match="frozen_instance"):
            setattr(snapshot, field, None)
        payload.clear()
        assert snapshot.model_dump(mode="json") == before


def test_mutated_caller_nested_objects_are_detached_and_revalidated(firmware, delivery) -> None:
    testcase = ExternalInputArtifact(provenance=source(), firmware=firmware, delivery=delivery)
    before = testcase.model_dump_json()
    object.__setattr__(firmware.provenance, "artifact_sha256", "invalid")
    object.__setattr__(delivery.endpoint.hardware_target, "architecture", "invalid")
    assert testcase.model_dump_json() == before
    with pytest.raises(ValidationError):
        ExternalInputArtifact(provenance=source(), firmware=firmware, delivery=testcase.delivery)
    with pytest.raises(ValidationError):
        ExternalInputArtifact(provenance=source(), firmware=testcase.firmware, delivery=delivery)
    with pytest.raises(ValidationError):
        testcase.require_firmware(firmware)


def test_binding_revalidates_mutated_source_before_comparing(firmware, delivery) -> None:
    campaign = GDBFuzzArtifact(provenance=source(), firmware=firmware)
    object.__setattr__(campaign.provenance, "architecture", Architecture.ARM)
    with pytest.raises(ValidationError, match="architecture"):
        campaign.require_firmware(firmware)
    testcase = ExternalInputArtifact(provenance=source(), firmware=firmware, delivery=delivery)
    object.__setattr__(testcase.delivery.endpoint.hardware_target, "target_id", "other")
    with pytest.raises(ValidationError, match="target mismatch"):
        testcase.require_firmware(firmware)
