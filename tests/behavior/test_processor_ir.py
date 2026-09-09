"""V2-2 contract tests only: no parser, decoder, real runtime or vulnerability."""

import pytest
from pydantic import TypeAdapter, ValidationError

from chipchain.core import (
    ArtifactProvenance, HardwareTargetIdentity, ProcessorFuzzArtifact, ProgramAddress,
    deterministic_id,
)
from chipchain.behavior.processor import (
    AccessKind, BehaviorFactNature, BehaviorRelation, BehaviorRelationKind,
    BehaviorSourceContext, BehaviorSourceKind, ControlTransferBehavior, ControlTransferKind,
    DeclaredOperand, ExactScalar, InstructionBehavior, MemoryAccessBehavior, MemoryAddress,
    MemoryStateFact, PrivilegeStateFact, ProcessorBehaviorFragment, ProcessorEvent,
    ProcessorEventKind, RegisterAccessBehavior, RegisterClass, RegisterOperand,
    RegisterReference, RegisterStateFact, ScalarOperand,
)


def binding(context, nature="synthetic_fixture") -> dict:
    return dict(source_context_id=context.id, architecture=context.architecture, nature=nature)


def instruction(context, ordinal=0, **changes) -> InstructionBehavior:
    return InstructionBehavior.model_validate({
        **binding(context), "source_ordinal": ordinal, "mnemonic": "synthetic_op", **changes,
    })


def register(architecture="riscv", **changes) -> RegisterReference:
    return RegisterReference.model_validate({
        "architecture": architecture, "register_class": "gpr", "namespace": "gpr", "name": "x1", **changes,
    })


def relation(context, left, right, kind="source_sequence", nature="synthetic_fixture") -> BehaviorRelation:
    return BehaviorRelation(**binding(context, nature), source_id=left.id, target_id=right.id, relation=kind)


def fragment(context, nature="synthetic_fixture") -> ProcessorBehaviorFragment:
    first, second = instruction(context, nature=nature), instruction(context, 1, nature=nature)
    return ProcessorBehaviorFragment(source=context, elements=[first, second],
                                     relations=[relation(context, first, second, nature=nature)])


def test_instruction_identity_ordinal_address_and_ordered_operands(source_context) -> None:
    operands = [RegisterOperand(register_ref=register()), ScalarOperand(scalar=ExactScalar(width_bits=8, value="0X01"))]
    first = instruction(source_context, 3, operands=operands)
    assert first.program_address is None and first.source_ordinal == 3
    assert first.encoding_hex is None and first.size_bytes is None
    assert first.id == deterministic_id("v2-processor-instruction-v1", first.model_dump(mode="json"))
    assert InstructionBehavior.model_validate_json(first.model_dump_json()).id == first.id
    assert instruction(source_context, 3, operands=list(reversed(operands))).id != first.id
    assert instruction(source_context, 4, operands=operands).id != first.id
    addressed = instruction(source_context, 3, operands=operands, program_address={"value": "0X001000"})
    assert addressed.program_address.value == "0x1000" and addressed.id != first.id
    assert first.mnemonic == addressed.mnemonic  # Does not collapse distinct source records.
    operands.clear()
    assert len(first.operands) == 2


@pytest.mark.parametrize("encoding,size,normalized", [("0100", 2, "0100"), ("AABBCCDD", 4, "aabbccdd"), ("001122334455", 6, "001122334455")])
def test_encoding_variable_length_byte_order_not_decoding(source_context, encoding, size, normalized) -> None:
    item = instruction(source_context, encoding_hex=encoding, size_bytes=size)
    assert item.encoding_hex == normalized and item.size_bytes == size
    assert instruction(source_context, encoding_hex=normalized, size_bytes=size).id == item.id
    # Synthetic byte-width examples only; no assertion that an ISA decoded them.


@pytest.mark.parametrize("encoding,size", [
    ("", 1), ("0", 1), ("abc", 2), ("gg", 1), ("0x0100", 2), ("01 00", 2),
    ("0100\n", 2), (b"0100", 2), ("0100", None), ("0100", 4),
    ("0100", True), (None, 0), (None, -1), (None, "2"),
])
def test_encoding_fail_closed(source_context, encoding, size) -> None:
    with pytest.raises(ValidationError):
        instruction(source_context, encoding_hex=encoding, size_bytes=size)


@pytest.mark.parametrize("ordinal", [-1, True, "0", 1.5])
def test_ordinal_is_strict_nonnegative(source_context, ordinal) -> None:
    with pytest.raises(ValidationError):
        instruction(source_context, ordinal)


@pytest.mark.parametrize("register_class", list(RegisterClass))
def test_register_vocabulary_and_identity(register_class) -> None:
    ref = register(register_class=register_class)
    assert ref.id == RegisterReference.model_validate_json(ref.model_dump_json()).id
    assert not hasattr(ref, "value")
    assert register("arm", register_class=register_class).id != ref.id


@pytest.mark.parametrize("change", [{"name": ""}, {"namespace": " "}, {"architecture": "risc_v"}, {"register_class": "csr"}])
def test_invalid_register_reference(change) -> None:
    with pytest.raises(ValidationError):
        register(**change)


@pytest.mark.parametrize("access", list(AccessKind))
def test_register_and_memory_access_are_not_value_observations(source_context, access) -> None:
    inst = instruction(source_context)
    reg = RegisterAccessBehavior(**binding(source_context), effect_index=0,
                                 instruction_id=inst.id, register_ref=register(), access=access)
    mem = MemoryAccessBehavior(**binding(source_context), effect_index=0,
                               instruction_id=inst.id, access=access, width_bytes=4,
                               memory_address=MemoryAddress(value="0X00001000"))
    result = ProcessorBehaviorFragment(source=source_context, elements=[inst, reg, mem])
    assert len(result.elements) == 3 and result.relations == ()
    assert mem.memory_address.value == "0x1000" and mem.memory_address.address_space_id is None
    assert "value" not in type(reg).model_fields and "value" not in type(mem).model_fields


def test_memory_location_is_not_program_address(source_context) -> None:
    with pytest.raises(ValidationError):
        MemoryAccessBehavior(**binding(source_context), effect_index=0, instruction_id="synthetic-id",
                             access="read", memory_address=ProgramAddress(value="0x1000"))
    for field in ("mmio", "ram", "flash", "cacheable", "device_memory"):
        with pytest.raises(ValidationError):
            MemoryAddress.model_validate({"value": "0x1000", field: True})


def test_memory_source_instruction_can_be_unknown(source_context) -> None:
    event = MemoryAccessBehavior(**binding(source_context), effect_index=0, access="read")
    assert event.instruction_id is None and event.memory_address is None and event.width_bytes is None
    result = ProcessorBehaviorFragment(source=source_context, elements=[event])
    assert result.relations == ()


def test_repeated_program_address_is_not_a_duplicate_source_ordinal(source_context) -> None:
    first = instruction(source_context, 0, program_address={"value": "0x1000"})
    second = instruction(source_context, 1, program_address={"value": "0x1000"})
    result = ProcessorBehaviorFragment(source=source_context, elements=[first, second])
    assert first.id != second.id and len(result.elements) == 2
    assert result.relations == ()  # Neither runtime order nor CFG is inferred.


@pytest.mark.parametrize("width,value", [(0, "0x0"), (8, "0x100"), (True, "0x0"), (8, 0), (8, "unknown"), (8, "symbolic"), (8, "-0x1"), (8, None)])
def test_scalar_rejects_unknown_coercion_and_width_overflow(width, value) -> None:
    with pytest.raises(ValidationError):
        ExactScalar(width_bits=width, value=value)


def test_exact_and_unknown_state_are_different(source_context) -> None:
    scalar = ExactScalar(width_bits=32, value="0X00000000")
    assert scalar.value == "0x0"
    unknown = RegisterStateFact(**binding(source_context), fact_index=0, register_ref=register(), value=None)
    zero = RegisterStateFact(**binding(source_context), fact_index=0, register_ref=register(), value=scalar)
    assert unknown.value is None and unknown.id != zero.id
    assert RegisterStateFact.model_validate_json(unknown.model_dump_json()).value is None
    with pytest.raises(ValidationError):
        RegisterStateFact(**binding(source_context), fact_index=0, register_ref=register())
    memory = MemoryStateFact(**binding(source_context), fact_index=0,
                             memory_address=MemoryAddress(value="0x1000"), value=None)
    assert memory.value is None
    assert ProcessorBehaviorFragment(source=source_context).elements == ()  # Absence is not False.


def test_privilege_profile_and_mode_are_scoped_labels(source_context) -> None:
    state = PrivilegeStateFact(**binding(source_context), fact_index=0, profile_id="synthetic-riscv-priv-v1", mode_id="M")
    assert state.mode_id == "M" and not hasattr(state, "rank")
    unknown = PrivilegeStateFact.model_validate({**state.model_dump(), "mode_id": None})
    assert unknown.mode_id is None and unknown.id != state.id


@pytest.mark.parametrize("transfer", list(ControlTransferKind))
def test_control_transfer_has_no_manufactured_target(source_context, transfer) -> None:
    inst = instruction(source_context)
    event = ControlTransferBehavior(**binding(source_context), instruction_id=inst.id,
                                    effect_index=0, transfer=transfer)
    assert event.target_address is None
    assert len(ProcessorBehaviorFragment(source=source_context, elements=[inst, event]).elements) == 2
    known = ControlTransferBehavior.model_validate({**event.model_dump(), "target_address": {"value": "0x40"}})
    assert event.id != known.id


@pytest.mark.parametrize("event_kind", list(ProcessorEventKind))
def test_event_semantics_do_not_become_runtime(source_context, event_kind) -> None:
    event = ProcessorEvent(**binding(source_context), effect_index=0, event=event_kind,
                           cause_id="synthetic-cause" if event_kind == ProcessorEventKind.OTHER_DECLARED else None)
    assert event.nature == BehaviorFactNature.SYNTHETIC_FIXTURE
    assert event.instruction_id is None
    assert len(ProcessorBehaviorFragment(source=source_context, elements=[event]).elements) == 1


def test_source_kinds_and_exact_bindings(source_context, processor_firmware) -> None:
    si_provenance = ArtifactProvenance.model_validate({**source_context.artifact.model_dump(), "producer_profile_id": "synthetic-producer-v1"})
    si = ProcessorFuzzArtifact(provenance=si_provenance, hardware_target=source_context.hardware_target)
    source = BehaviorSourceContext.model_validate({
        **source_context.model_dump(), "source_kind": "processorfuzz_si",
        "artifact": si_provenance.model_dump(), "processor_fuzz": si.model_dump(),
    })
    assert source.processor_fuzz.id == si.id
    assert source.artifact.artifact_sha256 == si.provenance.artifact_sha256
    declared = fragment(source, nature="source_declared")
    assert declared.relations[0].relation == BehaviorRelationKind.SOURCE_SEQUENCE
    assert declared.relations[0].nature == BehaviorFactNature.SOURCE_DECLARED
    decoded = BehaviorSourceContext.model_validate({
        **source_context.model_dump(), "source_kind": "firmware_artifact",
        "artifact": processor_firmware.provenance.model_dump(), "firmware": processor_firmware.model_dump(),
    })
    decoded.firmware.require_same_target(processor_firmware)
    inst = instruction(decoded, mnemonic="ecall", nature="static_decoded")
    event = ProcessorEvent(**binding(decoded, "static_decoded"), effect_index=0, instruction_id=inst.id, event="environment_call")
    result = ProcessorBehaviorFragment(source=decoded, elements=[inst, event])
    assert all(e.nature == BehaviorFactNature.STATIC_DECODED for e in result.elements)
    with pytest.raises(ValidationError, match="provenance"):
        BehaviorSourceContext.model_validate({**decoded.model_dump(), "artifact": source_context.artifact.model_dump()})
    corrupted = source.model_dump(mode="json")
    corrupted["processor_fuzz"]["provenance"]["artifact_sha256"] = "d" * 64
    with pytest.raises(ValidationError, match="provenance"):
        BehaviorSourceContext.model_validate(corrupted)
    corrupted = decoded.model_dump(mode="json")
    corrupted["firmware"]["provenance"]["artifact_sha256"] = "d" * 64
    with pytest.raises(ValidationError, match="provenance"):
        BehaviorSourceContext.model_validate(corrupted)


@pytest.mark.parametrize("kind", ["operand", "access", "state"])
def test_register_architecture_and_required_reference(source_context, kind) -> None:
    constructors = {
        "operand": lambda ref: instruction(source_context, operands=[RegisterOperand(register_ref=ref)]),
        "access": lambda ref: RegisterAccessBehavior(**binding(source_context), effect_index=0,
                                                      instruction_id="synthetic-instruction", register_ref=ref, access="read"),
        "state": lambda ref: RegisterStateFact(**binding(source_context), fact_index=0, register_ref=ref, value=None),
    }
    with pytest.raises(ValidationError, match="architecture"):
        constructors[kind](register("arm", name="r0"))
    models = {"operand": RegisterOperand, "access": RegisterAccessBehavior, "state": RegisterStateFact}
    assert "register_ref" in models[kind].model_json_schema()["required"]


@pytest.mark.parametrize("kind", ["firmware_artifact", "static_analysis_artifact"])
def test_missing_exact_firmware_source_rejected(source_context, kind) -> None:
    with pytest.raises(ValidationError, match="requires exact firmware"):
        BehaviorSourceContext.model_validate({**source_context.model_dump(), "source_kind": kind})


def test_missing_or_contradictory_source_architecture(source_context) -> None:
    for architecture in (None, "arm"):
        data = source_context.model_dump(mode="json")
        data["artifact"]["architecture"] = architecture
        with pytest.raises(ValidationError, match="target architecture"):
            BehaviorSourceContext.model_validate(data)


def test_processorfuzz_target_mismatch_and_client_binding_rejected(source_context, processor_firmware) -> None:
    provenance = ArtifactProvenance.model_validate({**source_context.artifact.model_dump(), "producer_profile_id": "synthetic-si-tool"})
    si = ProcessorFuzzArtifact(provenance=provenance, hardware_target=source_context.hardware_target)
    payload = {**source_context.model_dump(), "source_kind": "processorfuzz_si",
               "artifact": provenance.model_dump(), "processor_fuzz": si.model_dump()}
    with pytest.raises(ValidationError, match="client firmware"):
        BehaviorSourceContext.model_validate({**payload, "firmware": processor_firmware.model_dump()})
    payload["processor_fuzz"]["hardware_target"]["target_id"] = "synthetic-other-implementation"
    with pytest.raises(ValidationError, match="hardware target mismatch"):
        BehaviorSourceContext.model_validate(payload)


@pytest.mark.parametrize("field,value", [("target_id", "other-target"), ("hardware_revision", "other-revision")])
def test_same_architecture_not_same_target(source_context, processor_firmware, field, value) -> None:
    payload = source_context.model_dump(mode="json")
    payload["firmware"] = processor_firmware.model_dump(mode="json")
    payload["hardware_target"][field] = value
    with pytest.raises(ValidationError, match="hardware target mismatch"):
        BehaviorSourceContext.model_validate(payload)


def test_source_nature_cannot_default_or_upgrade_to_runtime(source_context, processor_firmware) -> None:
    assert "nature" not in BehaviorSourceContext.model_fields
    with pytest.raises(ValidationError, match="extra_forbidden"):
        BehaviorSourceContext.model_validate({**source_context.model_dump(), "nature": "synthetic_fixture"})
    payload = instruction(source_context).model_dump(mode="json")
    del payload["nature"]
    with pytest.raises(ValidationError):
        InstructionBehavior.model_validate(payload)
    with pytest.raises(ValidationError, match="distinct from firmware"):
        BehaviorSourceContext.model_validate({
            **source_context.model_dump(), "source_kind": "runtime_observation_artifact",
            "artifact": processor_firmware.provenance.model_dump(), "firmware": processor_firmware.model_dump(),
        })


@pytest.mark.parametrize("kind", list(BehaviorRelationKind))
def test_each_relation_is_explicit_and_synthetic(source_context, kind) -> None:
    first, second = instruction(source_context), instruction(source_context, 1)
    if kind == BehaviorRelationKind.RUNTIME_PRECEDES:
        first, second = (
            ProcessorEvent(**binding(source_context), effect_index=0,
                           occurrence_ordinal=i, event="trap") for i in (1, 2)
        )
    edge = relation(source_context, first, second, kind)
    result = ProcessorBehaviorFragment(source=source_context, elements=[first, second], relations=[edge])
    assert result.source.source_kind == BehaviorSourceKind.SYNTHETIC_FIXTURE
    assert result.relations[0].relation == kind
    assert all(item.nature == BehaviorFactNature.SYNTHETIC_FIXTURE for item in result.elements)


@pytest.mark.parametrize("nature,kind", [
    ("static_decoded", "runtime_precedes"), ("static_inferred", "runtime_precedes"),
    ("source_declared", "runtime_precedes"), ("source_declared", "static_cfg_successor"),
    ("static_decoded", "data_dependency"), ("source_declared", "control_dependency"),
    ("runtime_observed", "static_cfg_successor"),
])
def test_standalone_relation_nature_gates(source_context, nature, kind) -> None:
    with pytest.raises(ValidationError, match="semantic nature"):
        BehaviorRelation.model_validate({**binding(source_context), "nature": nature,
                                        "relation": kind, "source_id": "a", "target_id": "b"})


def test_static_relations_are_static_only(source_context, processor_firmware) -> None:
    context = BehaviorSourceContext.model_validate({
        **source_context.model_dump(), "source_kind": "static_analysis_artifact",
        "firmware": processor_firmware.model_dump(),
    })
    first, second = instruction(context, nature="static_decoded"), instruction(context, 1, nature="static_decoded")
    edges = [relation(context, first, second, kind, nature="static_inferred") for kind in (
        BehaviorRelationKind.STATIC_CFG_SUCCESSOR, BehaviorRelationKind.DATA_DEPENDENCY,
        BehaviorRelationKind.CONTROL_DEPENDENCY,
    )]
    result = ProcessorBehaviorFragment(source=context, elements=[first, second], relations=edges)
    assert all(item.nature == BehaviorFactNature.STATIC_DECODED for item in result.elements)
    assert all(edge.nature == BehaviorFactNature.STATIC_INFERRED for edge in result.relations)
    assert not any(edge.relation == BehaviorRelationKind.RUNTIME_PRECEDES for edge in result.relations)


def test_fragment_order_is_unordered_except_explicit_semantics(source_context) -> None:
    result = fragment(source_context)
    shuffled = ProcessorBehaviorFragment(source=source_context, elements=list(reversed(result.elements)),
                                          relations=list(reversed(result.relations)))
    assert shuffled.id == result.id and shuffled.model_dump_json() == result.model_dump_json()
    assert ProcessorBehaviorFragment.model_validate_json(result.model_dump_json()).id == result.id
    assert result.id == deterministic_id("v2-processor-behavior-fragment-v1", result.model_dump(mode="json"))


@pytest.mark.parametrize("mutation", ["duplicate_element", "duplicate_relation", "missing_endpoint", "cross_source", "cross_arch", "cross_nature", "ordinal", "reverse_sequence", "wrong_endpoint_type", "bad_instruction", "wrong_instruction_type", "effect_slot", "state_slot"])
def test_fragment_structural_corruption_fails_closed(source_context, mutation) -> None:
    first, second = instruction(source_context), instruction(source_context, 1)
    reg = RegisterAccessBehavior(**binding(source_context), effect_index=0, instruction_id=first.id,
                                 register_ref=register(), access="write")
    elements = [first, second, reg]
    edges = [relation(source_context, first, second)]
    if mutation == "duplicate_element": elements.append(first)
    elif mutation == "duplicate_relation": edges.append(edges[0])
    elif mutation == "missing_endpoint": elements.remove(second)
    elif mutation in ("cross_source", "cross_arch", "cross_nature"):
        field, value = {"cross_source": ("source_context_id", "other-source"),
                        "cross_arch": ("architecture", "arm"), "cross_nature": ("nature", "source_declared")}[mutation]
        elements.append(instruction(source_context, 2, **{field: value}))
    elif mutation == "ordinal": elements.append(instruction(source_context, 0, mnemonic="other"))
    elif mutation == "reverse_sequence": edges = [relation(source_context, second, first)]
    elif mutation == "wrong_endpoint_type": edges = [relation(source_context, first, reg)]
    elif mutation in ("bad_instruction", "wrong_instruction_type"):
        elements[2] = RegisterAccessBehavior.model_validate({**reg.model_dump(), "instruction_id": "missing" if mutation == "bad_instruction" else reg.id})
    elif mutation == "effect_slot": elements.append(RegisterAccessBehavior.model_validate({**reg.model_dump(), "access": "read"}))
    elif mutation == "state_slot":
        elements.extend(PrivilegeStateFact(**binding(source_context), fact_index=0, profile_id="synthetic", mode_id=m) for m in ("M", "S"))
    with pytest.raises(ValidationError):
        ProcessorBehaviorFragment(source=source_context, elements=elements, relations=edges)


def test_runtime_order_cycle_rejected_but_cfg_loop_retained(source_context) -> None:
    first, second = (
        ProcessorEvent(**binding(source_context), effect_index=0,
                       occurrence_ordinal=i, event="trap") for i in (1, 2)
    )
    cyclic = [relation(source_context, first, second, "runtime_precedes"), relation(source_context, second, first, "runtime_precedes")]
    with pytest.raises(ValidationError, match="cyclic order"):
        ProcessorBehaviorFragment(source=source_context, elements=[first, second], relations=cyclic)
    first = instruction(source_context)
    loop = relation(source_context, first, first, "static_cfg_successor")
    assert ProcessorBehaviorFragment(source=source_context, elements=[first], relations=[loop]).relations == (loop,)


def test_nested_caller_mutation_does_not_change_retained_fragment(source_context) -> None:
    first, second = instruction(source_context), instruction(source_context, 1)
    elements = [first, second]
    edges = [relation(source_context, first, second)]
    kept = ProcessorBehaviorFragment(source=source_context, elements=elements, relations=edges)
    before = kept.model_dump_json()
    elements.clear(); edges.clear()
    object.__setattr__(first, "source_ordinal", -1)
    object.__setattr__(source_context.artifact, "artifact_sha256", "invalid")
    assert kept.model_dump_json() == before
    with pytest.raises(ValidationError):
        ProcessorBehaviorFragment(source=kept.source, elements=[first])
    with pytest.raises(ValidationError):
        ProcessorBehaviorFragment(source=source_context)
    payload = kept.model_dump(mode="json")
    copied = ProcessorBehaviorFragment.model_validate(payload)
    payload["elements"].clear()
    assert copied.model_dump_json() == before
    with pytest.raises(ValidationError, match="frozen_instance"):
        copied.elements = ()


def test_synthetic_benign_riscv_contract_fragment(source_context) -> None:
    # Not decoded instructions, not a ProcessorFuzz finding, not client evidence.
    instructions = [instruction(source_context, i, mnemonic=m) for i, m in enumerate(("csrr", "add", "lw", "ecall", "sret"))]
    csr = register(register_class="system", namespace="csr", name="mstatus")
    effects = [
        RegisterAccessBehavior(**binding(source_context), effect_index=0, instruction_id=instructions[0].id, register_ref=csr, access="read"),
        RegisterAccessBehavior(**binding(source_context), effect_index=1, instruction_id=instructions[0].id, register_ref=register(), access="write"),
        MemoryAccessBehavior(**binding(source_context), effect_index=0, instruction_id=instructions[2].id, access="read", width_bytes=4),
        ProcessorEvent(**binding(source_context), effect_index=0, instruction_id=instructions[3].id, event="environment_call"),
        ControlTransferBehavior(**binding(source_context), effect_index=0, instruction_id=instructions[4].id, transfer="exception_return"),
        RegisterStateFact(**binding(source_context), fact_index=0, register_ref=csr, value=None),
        PrivilegeStateFact(**binding(source_context), fact_index=0, profile_id="synthetic-riscv-priv-v1", mode_id="M"),
    ]
    sequence = [relation(source_context, a, b) for a, b in zip(instructions, instructions[1:])]
    result = ProcessorBehaviorFragment(source=source_context, elements=instructions + effects, relations=sequence)
    assert len(result.elements) == 12 and len(result.relations) == 4
    assert result.source.source_kind == BehaviorSourceKind.SYNTHETIC_FIXTURE
    assert all(i.program_address is None for i in instructions)
    assert all(edge.relation == BehaviorRelationKind.SOURCE_SEQUENCE for edge in result.relations)


def test_arm_fragment_needs_no_riscv_csr_semantics(source_context) -> None:
    payload = source_context.model_dump(mode="json")
    payload["hardware_target"]["architecture"] = "arm"
    payload["artifact"]["architecture"] = "arm"
    context = BehaviorSourceContext.model_validate(payload)
    arm_register = register("arm", name="r0")
    inst = instruction(context, mnemonic="mov", operands=[RegisterOperand(register_ref=arm_register), DeclaredOperand(text="r1")])
    state = PrivilegeStateFact(**binding(context), fact_index=0, profile_id="synthetic-arm-priv-v1", mode_id="EL1")
    result = ProcessorBehaviorFragment(source=context, elements=[inst, state])
    assert result.source.architecture.value == "arm"
    assert "csr" not in result.model_dump_json()


@pytest.mark.parametrize("field", ["required", "must_equal", "satisfied", "trigger_condition", "expected_state", "triggerability", "matched", "confidence", "vulnerability", "severity", "attack_chain", "verified", "verification_status", "angr_state", "SUTConnection", "gdbfuzz_trial_path", "processorfuzz_parser_state"])
def test_no_verdict_trigger_or_adapter_fields(source_context, field) -> None:
    models = [source_context, instruction(source_context), fragment(source_context), register(),
              ExactScalar(width_bits=8, value="0x1"), MemoryAddress(value="0x10")]
    for model in models:
        assert field not in type(model).model_fields
        with pytest.raises(ValidationError, match="extra_forbidden"):
            type(model).model_validate({**model.model_dump(), field: True})
    # Check every authoritative processor model in the discriminated fragment schema.
    schema = ProcessorBehaviorFragment.model_json_schema()
    assert all(field not in definition.get("properties", {}) for definition in schema["$defs"].values())


def test_unknown_vocab_and_contract_version_fail_closed(source_context) -> None:
    for enum in (AccessKind, BehaviorFactNature, BehaviorRelationKind, BehaviorSourceKind, ControlTransferKind, ProcessorEventKind, RegisterClass):
        with pytest.raises(ValidationError): TypeAdapter(enum).validate_python("future_unknown")
    with pytest.raises(ValidationError):
        ProcessorBehaviorFragment.model_validate({"source": source_context.model_dump(), "contract": "future_v2"})
    with pytest.raises(ValidationError):
        InstructionBehavior.model_validate({**instruction(source_context).model_dump(), "id": "caller-id"})
