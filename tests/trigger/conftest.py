"""Benign SYNTHETIC_FIXTURE declarations only.

Not a ProcessorFuzz finding, real hardware trigger, vulnerability or decoder output.
No fixture consumes the local confirmed SI or any hardware execution artifact.
"""

import pytest

from chipchain.core import Architecture, ArtifactProvenance, HardwareTargetIdentity
from chipchain.behavior.processor import (
    AccessKind, ControlTransferKind, ExactScalar, MemoryAddress, ProcessorEventKind,
    RegisterClass, RegisterReference,
)
from chipchain.trigger import (
    AnyOperandRequirement, ControlTransferTriggerRequirement, EventTriggerRequirement,
    ExactScalarConstraint, HardwareTriggerSpec, InstructionTriggerRequirement,
    MaskedScalarConstraint, MemoryAccessTriggerRequirement, MemoryStateTriggerRequirement,
    PrivilegeStateTriggerRequirement, RegisterAccessTriggerRequirement,
    RegisterOperandRequirement, RegisterStateTriggerRequirement, ScalarOperandRequirement,
    TextOperandRequirement, TriggerOrderKind, TriggerOrderRequirement,
    TriggerSourceContext, TriggerSourceKind,
)


@pytest.fixture(params=[Architecture.RISC_V, Architecture.ARM], ids=["synthetic-riscv", "synthetic-arm"])
def source(request: pytest.FixtureRequest) -> TriggerSourceContext:
    architecture = request.param
    return TriggerSourceContext(
        source_kind=TriggerSourceKind.SYNTHETIC_FIXTURE,
        artifact=ArtifactProvenance(
            artifact_id="synthetic-trigger-contract-only", artifact_sha256="a" * 64,
            source_kind="synthetic-fixture", architecture=architecture,
            producer_profile_id="synthetic-declaration-v1",
        ),
        hardware_target=HardwareTargetIdentity(
            target_id="synthetic-not-client-target", architecture=architecture,
            hardware_model="Synthetic contract model",
        ),
        producer_profile_id="synthetic-declaration-v1",
    )


@pytest.fixture
def register_ref(source: TriggerSourceContext) -> RegisterReference:
    return RegisterReference(
        architecture=source.architecture, register_class=RegisterClass.SYSTEM,
        namespace="synthetic-system", name="synthetic-control",
    )


@pytest.fixture
def spec(source: TriggerSourceContext, register_ref: RegisterReference) -> HardwareTriggerSpec:
    binding = dict(source_context_id=source.id, architecture=source.architecture)
    exact = ExactScalarConstraint(value=ExactScalar(width_bits=8, value="0x2"))
    masked = MaskedScalarConstraint(
        value=ExactScalar(width_bits=8, value="0x2"), mask=ExactScalar(width_bits=8, value="0x3"),
    )
    preconditions = (
        RegisterStateTriggerRequirement(**binding, requirement_slot=0, register_ref=register_ref, constraint=masked),
        MemoryStateTriggerRequirement(
            **binding, requirement_slot=1,
            memory_address=MemoryAddress(value="0x100", address_space_id="synthetic-data"), constraint=exact,
        ),
        PrivilegeStateTriggerRequirement(
            **binding, requirement_slot=2, profile_id="synthetic-privilege", mode_id="synthetic-mode",
        ),
    )
    steps = (
        InstructionTriggerRequirement(**binding, requirement_slot=3, mnemonic="synthetic.op", operands=(
            AnyOperandRequirement(), RegisterOperandRequirement(register_ref=register_ref),
            ScalarOperandRequirement(constraint=exact), TextOperandRequirement(text="synthetic-token"),
        )),
        RegisterAccessTriggerRequirement(**binding, requirement_slot=4, register_ref=register_ref, access=AccessKind.READ),
        MemoryAccessTriggerRequirement(**binding, requirement_slot=5, access=AccessKind.WRITE),
        ControlTransferTriggerRequirement(
            **binding, requirement_slot=6, transfer=ControlTransferKind.EXCEPTION_RETURN,
        ),
        EventTriggerRequirement(**binding, requirement_slot=7, event=ProcessorEventKind.EXCEPTION),
    )
    orders = (
        TriggerOrderRequirement(**binding, kind=TriggerOrderKind.REQUIRED_PRECEDES,
                                before_id=steps[0].id, after_id=steps[2].id),
        TriggerOrderRequirement(**binding, kind=TriggerOrderKind.REQUIRED_IMMEDIATELY_PRECEDES,
                                before_id=steps[2].id, after_id=steps[3].id),
    )
    return HardwareTriggerSpec(source=source, preconditions=preconditions, steps=steps, order_requirements=orders)
