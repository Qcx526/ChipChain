"""Phase 10D Step 8B-2D2-A plan-independent semantic IR tests."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.analysis import (
    PHASE10D_STATIC_SEMANTIC_INSTRUCTION_FACT_CONTRACT,
    PHASE10D_STATIC_SEMANTIC_INVENTORY_CONTRACT,
    StaticSemanticAttribute,
    StaticSemanticAttributeName,
    StaticSemanticFactScope,
    StaticSemanticInstructionFact,
    StaticSemanticInventory,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
    static_semantic_instruction_fact_id,
    static_semantic_inventory_id,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]


def _attribute(
    name: StaticSemanticAttributeName,
    value: str,
) -> StaticSemanticAttribute:
    return StaticSemanticAttribute(name=name, value=value)


def _fact(
    *,
    operation: StaticSemanticOperation = StaticSemanticOperation.MEMORY_LOAD,
    architecture: Architecture = Architecture.ARM,
    artifact_id: str = "artifact:synthetic-plan-independent-ir",
    artifact_sha256: str = "a" * 64,
    decoder_profile_id: str = "decoder-profile:synthetic-audited-v1",
    instruction_set: str = "aarch64",
    instruction_address: str = "0x0000000000001000",
    instruction_bytes: str = "0x200040f9",
    instruction_size: int = 4,
    attributes: list[StaticSemanticAttribute] | None = None,
) -> StaticSemanticInstructionFact:
    return StaticSemanticInstructionFact.create(
        architecture=architecture,
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        decoder_profile_id=decoder_profile_id,
        instruction_set=instruction_set,
        instruction_address=instruction_address,
        instruction_bytes=instruction_bytes,
        instruction_size=instruction_size,
        function_address="0x0000000000001000",
        function_name="synthetic_ir_function",
        basic_block_address="0x0000000000001000",
        operation=operation,
        attributes=attributes or [],
        fact_scope=(
            StaticSemanticFactScope
            .DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
        ),
    )


def _inventory(
    facts: list[StaticSemanticInstructionFact],
    *,
    architecture: Architecture | None = None,
    artifact_id: str | None = None,
    artifact_sha256: str | None = None,
    decoder_profile_id: str | None = None,
    instruction_set: str | None = None,
) -> StaticSemanticInventory:
    first = facts[0]
    return StaticSemanticInventory.create(
        architecture=architecture or first.architecture,
        artifact_id=artifact_id or first.artifact_id,
        artifact_sha256=artifact_sha256 or first.artifact_sha256,
        decoder_profile_id=decoder_profile_id or first.decoder_profile_id,
        instruction_set=instruction_set or first.instruction_set,
        analysis_scope=(
            StaticSemanticInventoryScope
            .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
        ),
        facts=facts,
        diagnostic_codes=[f"semantic_fact_count:{len(facts)}"],
    )


def _recompute(payload: dict, id_function) -> None:
    payload["id"] = id_function(
        {key: value for key, value in payload.items() if key != "id"}
    )


def test_contract_versions_and_closed_vocabularies() -> None:
    assert PHASE10D_STATIC_SEMANTIC_INSTRUCTION_FACT_CONTRACT == (
        "phase10d_static_semantic_instruction_fact_v1"
    )
    assert PHASE10D_STATIC_SEMANTIC_INVENTORY_CONTRACT == (
        "phase10d_static_semantic_inventory_v1"
    )
    assert list(StaticSemanticOperation) == [
        StaticSemanticOperation.MEMORY_LOAD,
        StaticSemanticOperation.MEMORY_STORE,
        StaticSemanticOperation.LOAD_EXCLUSIVE,
        StaticSemanticOperation.STORE_EXCLUSIVE,
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
        StaticSemanticOperation.SYSTEM_REGISTER_WRITE,
        StaticSemanticOperation.MEMORY_BARRIER,
        StaticSemanticOperation.INSTRUCTION_BARRIER,
        StaticSemanticOperation.TLB_INVALIDATE,
        StaticSemanticOperation.EXCEPTION_RETURN,
    ]
    assert list(StaticSemanticAttributeName) == [
        StaticSemanticAttributeName.SYSTEM_REGISTER,
        StaticSemanticAttributeName.EFFECTIVE_MEMORY_TYPE_RESOLUTION,
        StaticSemanticAttributeName.BARRIER_KIND,
        StaticSemanticAttributeName.BARRIER_OPTION,
        StaticSemanticAttributeName.TLB_OPERATION,
        StaticSemanticAttributeName.MEMORY_EXCLUSIVITY,
    ]


def test_fact_canonicalizes_cross_architecture_bytes_and_addresses() -> None:
    first = _fact(
        instruction_address="0x00001000",
        instruction_bytes="0x200040F9",
    )
    second = _fact(
        instruction_address="0x1000",
        instruction_bytes="0x200040f9",
    )
    assert first == second
    assert first.instruction_address == "0x1000"
    assert first.instruction_bytes == "0x200040f9"
    assert first.function_address == "0x1000"
    assert first.basic_block_address == "0x1000"


def test_current_a77_operations_are_representable_without_a_pattern() -> None:
    load = _fact(
        attributes=[
            _attribute(
                StaticSemanticAttributeName
                .EFFECTIVE_MEMORY_TYPE_RESOLUTION,
                "requires_objective_translation_context",
            )
        ]
    )
    store_exclusive = _fact(
        operation=StaticSemanticOperation.STORE_EXCLUSIVE,
        instruction_address="0x1004",
        instruction_bytes="0x417c00c8",
        attributes=[
            _attribute(
                StaticSemanticAttributeName.MEMORY_EXCLUSIVITY,
                "exclusive_store",
            )
        ],
    )
    register_read = _fact(
        operation=StaticSemanticOperation.SYSTEM_REGISTER_READ,
        instruction_address="0x1008",
        instruction_bytes="0x007438d5",
        attributes=[
            _attribute(
                StaticSemanticAttributeName.SYSTEM_REGISTER,
                "par_el1",
            )
        ],
    )
    inventory = _inventory([register_read, store_exclusive, load])
    assert {item.operation for item in inventory.facts} == {
        StaticSemanticOperation.MEMORY_LOAD,
        StaticSemanticOperation.STORE_EXCLUSIVE,
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
    }


def test_future_barrier_tlb_and_exception_semantics_are_representable() -> None:
    barrier = _fact(
        operation=StaticSemanticOperation.MEMORY_BARRIER,
        instruction_bytes="0xbf3b03d5",
        attributes=[
            _attribute(StaticSemanticAttributeName.BARRIER_OPTION, "ish"),
            _attribute(StaticSemanticAttributeName.BARRIER_KIND, "dsb"),
        ],
    )
    tlb = _fact(
        operation=StaticSemanticOperation.TLB_INVALIDATE,
        instruction_address="0x1004",
        instruction_bytes="0x1f8308d5",
        attributes=[
            _attribute(
                StaticSemanticAttributeName.TLB_OPERATION,
                "vmalle1is",
            )
        ],
    )
    exception_return = _fact(
        operation=StaticSemanticOperation.EXCEPTION_RETURN,
        instruction_address="0x1008",
        instruction_bytes="0xe0039fd6",
    )
    assert barrier.operation is StaticSemanticOperation.MEMORY_BARRIER
    assert tlb.operation is StaticSemanticOperation.TLB_INVALIDATE
    assert exception_return.operation is StaticSemanticOperation.EXCEPTION_RETURN


def test_arm_and_risc_v_use_the_same_fact_and_inventory_classes() -> None:
    arm = _fact()
    riscv_load = _fact(
        architecture=Architecture.RISC_V,
        artifact_id="artifact:synthetic-riscv-ir",
        artifact_sha256="b" * 64,
        decoder_profile_id="decoder-profile:synthetic-riscv-v1",
        instruction_set="rv64gc",
        instruction_address="0x80000000",
        instruction_bytes="0x03b50500",
    )
    riscv_barrier = _fact(
        operation=StaticSemanticOperation.MEMORY_BARRIER,
        architecture=Architecture.RISC_V,
        artifact_id=riscv_load.artifact_id,
        artifact_sha256=riscv_load.artifact_sha256,
        decoder_profile_id=riscv_load.decoder_profile_id,
        instruction_set=riscv_load.instruction_set,
        instruction_address="0x80000004",
        instruction_bytes="0x0f003003",
        attributes=[
            _attribute(StaticSemanticAttributeName.BARRIER_KIND, "fence")
        ],
    )
    arm_inventory = _inventory([arm])
    riscv_inventory = _inventory([riscv_barrier, riscv_load])
    assert type(arm) is type(riscv_load) is StaticSemanticInstructionFact
    assert type(arm_inventory) is type(riscv_inventory) is StaticSemanticInventory
    assert riscv_inventory.architecture is Architecture.RISC_V


def test_distinct_semantics_may_share_one_instruction_address() -> None:
    load = _fact()
    store = _fact(
        operation=StaticSemanticOperation.MEMORY_STORE,
        instruction_bytes=load.instruction_bytes,
    )
    inventory = _inventory([store, load])
    assert len(inventory.facts) == 2
    assert inventory.facts[0].instruction_address == (
        inventory.facts[1].instruction_address
    )
    assert inventory.facts[0].id != inventory.facts[1].id


def test_fact_and_inventory_ids_are_deterministic_and_order_independent() -> None:
    first = _fact()
    second = _fact(
        operation=StaticSemanticOperation.MEMORY_STORE,
        instruction_address="0x1004",
        instruction_bytes="0x200000f9",
    )
    assert _fact() == first
    assert _inventory([first, second]) == _inventory([second, first])


def test_stale_and_recomputed_artifact_or_operation_identity() -> None:
    fact = _fact()
    artifact_payload = fact.model_dump(mode="json")
    artifact_payload["artifact_sha256"] = "b" * 64
    with pytest.raises(ValidationError, match="ID mismatch"):
        StaticSemanticInstructionFact.model_validate(artifact_payload)
    _recompute(artifact_payload, static_semantic_instruction_fact_id)
    retargeted = StaticSemanticInstructionFact.model_validate(artifact_payload)
    assert retargeted.id != fact.id
    with pytest.raises(ValidationError, match="crosses inventory provenance"):
        _inventory([retargeted], artifact_sha256=fact.artifact_sha256)

    operation_payload = fact.model_dump(mode="json")
    operation_payload["operation"] = StaticSemanticOperation.MEMORY_STORE.value
    with pytest.raises(ValidationError, match="ID mismatch"):
        StaticSemanticInstructionFact.model_validate(operation_payload)
    _recompute(operation_payload, static_semantic_instruction_fact_id)
    changed = StaticSemanticInstructionFact.model_validate(operation_payload)
    assert changed.operation is StaticSemanticOperation.MEMORY_STORE
    assert changed.id != fact.id


@pytest.mark.parametrize(
    ("instruction_bytes", "instruction_size"),
    [("0x00", 4), ("0x000", 2), ("0x", 1), ("zero", 1)],
)
def test_instruction_bytes_and_size_inconsistency_fails(
    instruction_bytes, instruction_size
) -> None:
    with pytest.raises(ValidationError):
        _fact(
            instruction_bytes=instruction_bytes,
            instruction_size=instruction_size,
        )


def test_duplicate_attributes_and_incompatible_attribute_kinds_fail() -> None:
    duplicate = [
        _attribute(StaticSemanticAttributeName.BARRIER_KIND, "dsb"),
        _attribute(StaticSemanticAttributeName.BARRIER_KIND, "dmb"),
    ]
    with pytest.raises(ValidationError, match="must be unique"):
        _fact(
            operation=StaticSemanticOperation.MEMORY_BARRIER,
            attributes=duplicate,
        )
    with pytest.raises(ValidationError, match="non-barrier"):
        _fact(
            attributes=[
                _attribute(StaticSemanticAttributeName.BARRIER_KIND, "dsb")
            ]
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_id", "/tmp/firmware.bin"),
        ("decoder_profile_id", "~/decoder"),
        ("instruction_set", "file:/local/isa"),
    ],
)
def test_path_like_provenance_identifier_fails(field, value) -> None:
    values = {field: value}
    with pytest.raises(ValidationError, match="path-neutral"):
        _fact(**values)


def test_path_like_attribute_value_fails() -> None:
    with pytest.raises(ValidationError, match="path-neutral"):
        _attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, r"C:\\local")


@pytest.mark.parametrize(
    "value",
    [
        "verified",
        "triggered",
        "triggerable",
        "vulnerable",
        "exploit",
        "causes_deadlock",
        "feasible_attack",
        "runtime_executed",
        "proximity_satisfied",
    ],
)
def test_verdict_like_attribute_values_fail(value) -> None:
    with pytest.raises(ValidationError, match="outcome-neutral"):
        _attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, value)


@pytest.mark.parametrize(
    "address",
    ["1000", "-0x1", "0x", "0xgh", "file:/tmp/address"],
)
def test_invalid_address_fails(address) -> None:
    with pytest.raises(ValidationError, match="hexadecimal"):
        _fact(instruction_address=address)


def test_duplicate_exact_fact_fails_inventory() -> None:
    fact = _fact()
    with pytest.raises(ValidationError, match="must be unique"):
        _inventory([fact, fact])


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("artifact_id", "artifact:other", "provenance"),
        ("artifact_sha256", "b" * 64, "provenance"),
        ("architecture", Architecture.RISC_V, "provenance"),
        ("decoder_profile_id", "decoder-profile:other", "provenance"),
        ("instruction_set", "other-isa", "provenance"),
    ],
)
def test_inventory_rejects_cross_binding(field, value, message) -> None:
    fact = _fact()
    with pytest.raises(ValidationError, match=message):
        _inventory([fact], **{field: value})


def test_pattern_fields_and_unknown_operation_fail_closed() -> None:
    payload = _fact().model_dump(mode="json")
    payload["source_pattern_id"] = "pattern:forbidden"
    with pytest.raises(ValidationError):
        StaticSemanticInstructionFact.model_validate(payload)
    payload = _fact().model_dump(mode="json")
    payload["operation"] = "verified"
    _recompute(payload, static_semantic_instruction_fact_id)
    with pytest.raises(ValidationError):
        StaticSemanticInstructionFact.model_validate(payload)


def test_pattern_firewall_is_absent_from_shared_json_schemas() -> None:
    schemas = (
        StaticSemanticInstructionFact.model_json_schema(),
        StaticSemanticInventory.model_json_schema(),
    )
    forbidden = (
        "aprofilestaticsemanticextractionplan",
        "predicate_candidate",
        "case_order_candidate",
        "source_pattern",
        "attack_pattern",
        "cve",
        "crosslayerinteraction",
        "attackchain",
        "triggerability",
    )
    for schema in schemas:
        serialized = str(schema).lower()
        assert not any(value in serialized for value in forbidden)


def test_shared_source_dependency_firewall() -> None:
    path = ROOT / "src/chipchain/analysis/static_semantic_models.py"
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    forbidden = (
        "chipchain.hardware_trigger",
        "chipchain.knowledge",
        "chipchain.reasoning",
        "chipchain.runtime",
        "chipchain.verification",
    )
    assert not any(
        module.startswith(prefix)
        for module in imported_modules
        for prefix in forbidden
    )


def test_inventory_has_no_plan_pattern_candidate_or_verdict_surface() -> None:
    fields = set(StaticSemanticInstructionFact.model_fields) | set(
        StaticSemanticInventory.model_fields
    )
    forbidden = {
        "source_pattern_id",
        "attack_pattern_reference",
        "case_id",
        "position_index",
        "predicate_ref",
        "predicate_candidate",
        "case_order_candidate",
        "remaining_objective_obligations",
        "cve",
        "vulnerability_id",
        "runtime_execution",
        "causal",
        "verified",
    }
    assert fields.isdisjoint(forbidden)
    fact = _fact()
    assert fact.fact_scope is (
        StaticSemanticFactScope.DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
    )


def test_inventory_id_rejects_stale_diagnostics_tamper() -> None:
    inventory = _inventory([_fact()])
    payload = inventory.model_dump(mode="json")
    payload["diagnostic_codes"] = ["semantic_fact_count:2"]
    with pytest.raises(ValidationError, match="inventory ID mismatch"):
        StaticSemanticInventory.model_validate(payload)
    _recompute(payload, static_semantic_inventory_id)
    changed = StaticSemanticInventory.model_validate(payload)
    assert changed.id != inventory.id
