"""Contracts for architecture-neutral declarative static trigger patterns."""

from __future__ import annotations

import ast
import hashlib
import itertools
import json
from pathlib import Path

from pydantic import ValidationError
import pytest

from chipchain.analysis import (
    PHASE10D_STATIC_TRIGGER_CASE_CONTRACT,
    PHASE10D_STATIC_TRIGGER_PATTERN_CATALOG_CONTRACT,
    PHASE10D_STATIC_TRIGGER_PATTERN_CONTRACT,
    PHASE10D_STATIC_TRIGGER_POSITION_CONTRACT,
    PHASE10D_STATIC_TRIGGER_PREDICATE_CONTRACT,
    PHASE10D_STATIC_TRIGGER_RELATION_REQUIREMENT_CONTRACT,
    StaticSemanticAttribute,
    StaticSemanticAttributeName,
    StaticSemanticOperation,
    StaticTriggerAlternativeSemantics,
    StaticTriggerCase,
    StaticTriggerObjectiveRequirement,
    StaticTriggerPattern,
    StaticTriggerPatternCatalog,
    StaticTriggerPatternUse,
    StaticTriggerPosition,
    StaticTriggerPositionOrder,
    StaticTriggerPredicate,
    StaticTriggerRelationEvaluability,
    StaticTriggerRelationKind,
    StaticTriggerRelationPrecision,
    StaticTriggerRelationRequirement,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIRECTORY = (
    ROOT / "tests/fixtures/phase10d/static_trigger_pattern_v1"
)
FIXTURE = FIXTURE_DIRECTORY / "owned_synthetic_static_trigger_pattern_v1.json"
A77_PATTERN = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_semantic_trigger_pattern_v1.json"
)


def _attribute(
    name: StaticSemanticAttributeName, value: str
) -> StaticSemanticAttribute:
    return StaticSemanticAttribute(name=name, value=value)


def _predicate(
    operation: StaticSemanticOperation,
    *,
    attributes: tuple[StaticSemanticAttribute, ...] = (),
    effective_memory_types: tuple[str, ...] = (),
    execution_contexts: tuple[str, ...] = (),
    objective_requirements: tuple[StaticTriggerObjectiveRequirement, ...] = (),
) -> StaticTriggerPredicate:
    return StaticTriggerPredicate.create(
        operation=operation,
        required_attributes=list(attributes),
        required_effective_memory_types=list(effective_memory_types),
        required_execution_contexts=list(execution_contexts),
        objective_requirements=list(objective_requirements),
    )


def _position(
    index: int, *alternatives: StaticTriggerPredicate
) -> StaticTriggerPosition:
    return StaticTriggerPosition.create(
        position_index=index,
        alternatives=list(alternatives),
    )


def _simple_case(
    reference: str,
    *predicates: StaticTriggerPredicate,
    relation: StaticTriggerRelationRequirement | None = None,
    objective_requirements: tuple[StaticTriggerObjectiveRequirement, ...] = (),
) -> StaticTriggerCase:
    return StaticTriggerCase.create(
        case_reference_id=reference,
        positions=[
            _position(index, predicate)
            for index, predicate in enumerate(predicates, start=1)
        ],
        relation_requirement=relation,
        objective_requirements=list(objective_requirements),
    )


def _owned_pattern(*, permutation: int = 0) -> StaticTriggerPattern:
    reverse_attributes = bool(permutation & 1)
    reverse_cases = bool(permutation & 2)
    reverse_sources = bool(permutation & 4)
    reverse_hardware = bool(permutation & 8)
    par = _predicate(
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
        attributes=(
            _attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, "par_el1"),
        ),
    )
    barrier_attributes = [
        _attribute(StaticSemanticAttributeName.BARRIER_KIND, "dsb"),
        _attribute(StaticSemanticAttributeName.BARRIER_OPTION, "ish"),
    ]
    if reverse_attributes:
        barrier_attributes.reverse()
    dsb = _predicate(
        StaticSemanticOperation.MEMORY_BARRIER,
        attributes=tuple(barrier_attributes),
    )
    tlbi = _predicate(
        StaticSemanticOperation.TLB_INVALIDATE,
        attributes=(
            _attribute(
                StaticSemanticAttributeName.TLB_OPERATION, "vmalle1is"
            ),
        ),
    )
    isb = _predicate(
        StaticSemanticOperation.INSTRUCTION_BARRIER,
        attributes=(
            _attribute(StaticSemanticAttributeName.BARRIER_KIND, "isb"),
        ),
    )
    cases = [
        _simple_case("owned-case-a", par, dsb, isb),
        _simple_case("owned-case-b", par, tlbi, isb),
    ]
    sources = [
        "owned-synthetic-static-trigger-pattern-design-v1",
        "owned-synthetic-static-trigger-pattern-fixture-v1",
    ]
    hardware = [
        "owned-synthetic-hardware-condition-v1",
        "owned-synthetic-benign-condition-family-v1",
    ]
    if reverse_cases:
        cases.reverse()
    if reverse_sources:
        sources.reverse()
    if reverse_hardware:
        hardware.reverse()
    return StaticTriggerPattern.create(
        architecture=Architecture.ARM,
        instruction_set="aarch64",
        pattern_name="owned_synthetic_diamond_static_pattern",
        source_reference_ids=sources,
        hardware_reference_ids=hardware,
        cases=cases,
    )


def _qualitative_relation() -> StaticTriggerRelationRequirement:
    return StaticTriggerRelationRequirement.create(
        relation_kind=StaticTriggerRelationKind.CLOSE_PROXIMITY,
        precision=StaticTriggerRelationPrecision.QUALITATIVE_ONLY,
        quantitative_bound=None,
        evaluability=(
            StaticTriggerRelationEvaluability
            .SOURCE_INSUFFICIENT_FOR_EXACT_STATIC_SATISFACTION
        ),
    )


def _risc_v_pattern() -> StaticTriggerPattern:
    load = _predicate(StaticSemanticOperation.MEMORY_LOAD)
    fence = _predicate(
        StaticSemanticOperation.MEMORY_BARRIER,
        attributes=(
            _attribute(StaticSemanticAttributeName.BARRIER_KIND, "fence"),
        ),
    )
    return StaticTriggerPattern.create(
        architecture=Architecture.RISC_V,
        instruction_set="rv64gc",
        pattern_name="owned_synthetic_risc_v_contract_pattern",
        source_reference_ids=["owned-synthetic-risc-v-pattern-v1"],
        hardware_reference_ids=["owned-synthetic-risc-v-condition-v1"],
        cases=[_simple_case("risc-v-case", load, fence)],
    )


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def test_contracts_and_closed_vocabularies_are_exact() -> None:
    assert PHASE10D_STATIC_TRIGGER_PREDICATE_CONTRACT == (
        "phase10d_static_trigger_predicate_v1"
    )
    assert PHASE10D_STATIC_TRIGGER_POSITION_CONTRACT == (
        "phase10d_static_trigger_position_v1"
    )
    assert PHASE10D_STATIC_TRIGGER_RELATION_REQUIREMENT_CONTRACT == (
        "phase10d_static_trigger_relation_requirement_v1"
    )
    assert PHASE10D_STATIC_TRIGGER_CASE_CONTRACT == (
        "phase10d_static_trigger_case_v1"
    )
    assert PHASE10D_STATIC_TRIGGER_PATTERN_CONTRACT == (
        "phase10d_static_trigger_pattern_v1"
    )
    assert PHASE10D_STATIC_TRIGGER_PATTERN_CATALOG_CONTRACT == (
        "phase10d_static_trigger_pattern_catalog_v1"
    )
    assert list(StaticTriggerAlternativeSemantics) == [
        StaticTriggerAlternativeSemantics.OR
    ]
    assert list(StaticTriggerPositionOrder) == [
        StaticTriggerPositionOrder.PROGRAM_ORDER
    ]
    assert list(StaticTriggerRelationKind) == [
        StaticTriggerRelationKind.CLOSE_PROXIMITY
    ]
    assert list(StaticTriggerRelationPrecision) == [
        StaticTriggerRelationPrecision.QUALITATIVE_ONLY
    ]
    assert list(StaticTriggerRelationEvaluability) == [
        StaticTriggerRelationEvaluability
        .SOURCE_INSUFFICIENT_FOR_EXACT_STATIC_SATISFACTION
    ]
    assert list(StaticTriggerPatternUse) == [
        StaticTriggerPatternUse.OBJECTIVE_STATIC_CANDIDATE_MATCHING_ONLY
    ]


def test_v1_schema_uses_exact_literal_locks() -> None:
    classes = (
        (StaticTriggerPredicate, "phase10d_static_trigger_predicate_v1"),
        (StaticTriggerPosition, "phase10d_static_trigger_position_v1"),
        (
            StaticTriggerRelationRequirement,
            "phase10d_static_trigger_relation_requirement_v1",
        ),
        (StaticTriggerCase, "phase10d_static_trigger_case_v1"),
        (StaticTriggerPattern, "phase10d_static_trigger_pattern_v1"),
        (
            StaticTriggerPatternCatalog,
            "phase10d_static_trigger_pattern_catalog_v1",
        ),
    )
    for model, contract in classes:
        assert model.model_json_schema()["properties"]["contract"][
            "const"
        ] == contract
    assert StaticTriggerPosition.model_json_schema()["properties"][
        "alternative_semantics"
    ]["const"] == "or"
    assert StaticTriggerCase.model_json_schema()["properties"][
        "position_order"
    ]["const"] == "program_order"
    assert StaticTriggerPattern.model_json_schema()["properties"][
        "pattern_use"
    ]["const"] == "objective_static_candidate_matching_only"
    relation_properties = StaticTriggerRelationRequirement.model_json_schema()[
        "properties"
    ]
    assert relation_properties["relation_kind"]["const"] == "close_proximity"
    assert relation_properties["precision"]["const"] == "qualitative_only"
    assert relation_properties["quantitative_bound"]["const"] is None
    assert relation_properties["evaluability"]["const"] == (
        "source_insufficient_for_exact_static_satisfaction"
    )


def test_required_attributes_are_detached_sorted_and_optional() -> None:
    first = _attribute(StaticSemanticAttributeName.BARRIER_OPTION, "ish")
    second = _attribute(StaticSemanticAttributeName.BARRIER_KIND, "dsb")
    predicate = _predicate(
        StaticSemanticOperation.MEMORY_BARRIER,
        attributes=(first, second),
    )

    first.value = "mutated"

    assert [item.name for item in predicate.required_attributes] == [
        StaticSemanticAttributeName.BARRIER_KIND,
        StaticSemanticAttributeName.BARRIER_OPTION,
    ]
    assert predicate.required_attributes[1].value == "ish"
    assert not _predicate(
        StaticSemanticOperation.SYSTEM_REGISTER_READ
    ).required_attributes


def test_duplicate_required_attribute_names_are_rejected() -> None:
    with pytest.raises(ValidationError, match="attribute names must be unique"):
        _predicate(
            StaticSemanticOperation.SYSTEM_REGISTER_READ,
            attributes=(
                _attribute(
                    StaticSemanticAttributeName.SYSTEM_REGISTER, "par_el1"
                ),
                _attribute(
                    StaticSemanticAttributeName.SYSTEM_REGISTER, "sctlr_el1"
                ),
            ),
        )


@pytest.mark.parametrize(
    ("operation", "attribute"),
    [
        (
            StaticSemanticOperation.MEMORY_LOAD,
            _attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, "par_el1"),
        ),
        (
            StaticSemanticOperation.MEMORY_LOAD,
            _attribute(StaticSemanticAttributeName.BARRIER_KIND, "dsb"),
        ),
        (
            StaticSemanticOperation.MEMORY_LOAD,
            _attribute(StaticSemanticAttributeName.TLB_OPERATION, "vmalle1is"),
        ),
        (
            StaticSemanticOperation.MEMORY_BARRIER,
            _attribute(
                StaticSemanticAttributeName.EFFECTIVE_MEMORY_TYPE_RESOLUTION,
                "requires_objective_translation_context",
            ),
        ),
        (
            StaticSemanticOperation.MEMORY_LOAD,
            _attribute(
                StaticSemanticAttributeName.MEMORY_EXCLUSIVITY,
                "exclusive_load",
            ),
        ),
    ],
)
def test_incompatible_operation_attribute_requirements_are_rejected(
    operation: StaticSemanticOperation,
    attribute: StaticSemanticAttribute,
) -> None:
    with pytest.raises(ValidationError):
        _predicate(operation, attributes=(attribute,))


def test_effective_memory_type_requirement_is_external_and_unresolved() -> None:
    predicate = _predicate(
        StaticSemanticOperation.MEMORY_LOAD,
        effective_memory_types=("normal_non_cacheable", "device"),
        objective_requirements=(
            StaticTriggerObjectiveRequirement
            .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
        ),
    )

    assert predicate.required_effective_memory_types == [
        "device",
        "normal_non_cacheable",
    ]
    assert not predicate.required_attributes
    assert (
        StaticSemanticAttributeName.EFFECTIVE_MEMORY_TYPE_RESOLUTION
        not in {item.name for item in predicate.required_attributes}
    )


def test_duplicate_effective_memory_types_are_rejected() -> None:
    with pytest.raises(ValidationError, match="must be unique"):
        _predicate(
            StaticSemanticOperation.MEMORY_LOAD,
            effective_memory_types=("device", "device"),
            objective_requirements=(
                StaticTriggerObjectiveRequirement
                .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
            ),
        )


def test_effective_memory_type_requires_resolution_obligation() -> None:
    with pytest.raises(ValidationError, match="objective resolution"):
        _predicate(
            StaticSemanticOperation.MEMORY_LOAD,
            effective_memory_types=("device",),
        )


def test_effective_memory_type_requires_memory_operation() -> None:
    with pytest.raises(ValidationError, match="memory operation"):
        _predicate(
            StaticSemanticOperation.MEMORY_BARRIER,
            effective_memory_types=("device",),
            objective_requirements=(
                StaticTriggerObjectiveRequirement
                .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
            ),
        )


def test_execution_context_is_declarative_and_requires_obligation() -> None:
    predicate = _predicate(
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
        execution_contexts=("privileged_aarch64", "arm_a_profile"),
        objective_requirements=(
            StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
        ),
    )

    assert predicate.required_execution_contexts == [
        "arm_a_profile",
        "privileged_aarch64",
    ]
    assert not _predicate(
        StaticSemanticOperation.SYSTEM_REGISTER_READ
    ).required_execution_contexts


def test_execution_context_requires_runtime_obligation() -> None:
    with pytest.raises(ValidationError, match="objective runtime"):
        _predicate(
            StaticSemanticOperation.MEMORY_LOAD,
            execution_contexts=("privileged_aarch64",),
        )


def test_duplicate_execution_contexts_are_rejected() -> None:
    with pytest.raises(ValidationError, match="must be unique"):
        _predicate(
            StaticSemanticOperation.MEMORY_LOAD,
            execution_contexts=("arm_a_profile", "arm_a_profile"),
            objective_requirements=(
                StaticTriggerObjectiveRequirement
                .RUNTIME_EXECUTION_CONTEXT_REQUIRED,
            ),
        )


def test_position_supports_sorted_or_alternatives() -> None:
    store = _predicate(StaticSemanticOperation.STORE_EXCLUSIVE)
    register = _predicate(
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
        attributes=(
            _attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, "par_el1"),
        ),
    )
    first = _position(1, store, register)
    second = _position(1, register, store)

    assert first == second
    assert first.alternative_semantics is StaticTriggerAlternativeSemantics.OR
    assert first.alternatives == sorted(
        first.alternatives, key=lambda item: item.id
    )


def test_empty_and_duplicate_position_alternatives_are_rejected() -> None:
    predicate = _predicate(StaticSemanticOperation.MEMORY_LOAD)
    with pytest.raises(ValidationError):
        _position(1)
    with pytest.raises(ValidationError, match="alternatives must be unique"):
        _position(1, predicate, predicate)


def test_case_positions_are_sorted_contiguous_and_program_ordered() -> None:
    load = _predicate(StaticSemanticOperation.MEMORY_LOAD)
    barrier = _predicate(StaticSemanticOperation.MEMORY_BARRIER)
    case = StaticTriggerCase.create(
        case_reference_id="ordered-case",
        positions=[_position(2, barrier), _position(1, load)],
    )

    assert [item.position_index for item in case.positions] == [1, 2]
    assert case.position_order is StaticTriggerPositionOrder.PROGRAM_ORDER


@pytest.mark.parametrize("indices", [(1, 1), (1, 3), (2,)])
def test_duplicate_or_non_contiguous_position_indices_are_rejected(
    indices: tuple[int, ...],
) -> None:
    predicate = _predicate(StaticSemanticOperation.MEMORY_LOAD)
    with pytest.raises(ValidationError):
        StaticTriggerCase.create(
            case_reference_id="invalid-position-case",
            positions=[_position(index, predicate) for index in indices],
        )


def test_qualitative_relation_preserves_unresolved_precision() -> None:
    relation = _qualitative_relation()
    case = _simple_case(
        "qualitative-case",
        _predicate(StaticSemanticOperation.MEMORY_LOAD),
        relation=relation,
        objective_requirements=(
            StaticTriggerObjectiveRequirement
            .RELATION_PROXIMITY_REMAINS_UNRESOLVED,
        ),
    )

    assert relation.quantitative_bound is None
    assert case.relation_requirement == relation


def test_qualitative_relation_rejects_numeric_bound() -> None:
    with pytest.raises(ValidationError):
        StaticTriggerRelationRequirement.create(
            relation_kind=StaticTriggerRelationKind.CLOSE_PROXIMITY,
            precision=StaticTriggerRelationPrecision.QUALITATIVE_ONLY,
            quantitative_bound=3,
            evaluability=(
                StaticTriggerRelationEvaluability
                .SOURCE_INSUFFICIENT_FOR_EXACT_STATIC_SATISFACTION
            ),
        )


@pytest.mark.parametrize("with_relation", [False, True])
def test_relation_and_unresolved_obligation_must_coexist(
    with_relation: bool,
) -> None:
    with pytest.raises(ValidationError, match="must coexist"):
        _simple_case(
            "incomplete-relation-case",
            _predicate(StaticSemanticOperation.MEMORY_LOAD),
            relation=_qualitative_relation() if with_relation else None,
            objective_requirements=(
                ()
                if with_relation
                else (
                    StaticTriggerObjectiveRequirement
                    .RELATION_PROXIMITY_REMAINS_UNRESOLVED,
                )
            ),
        )


@pytest.mark.parametrize(
    "field",
    ["source_reference_ids", "hardware_reference_ids", "cases"],
)
def test_pattern_requires_references_and_cases(field: str) -> None:
    values = {
        "architecture": Architecture.ARM,
        "instruction_set": "aarch64",
        "pattern_name": "required-fields-pattern",
        "source_reference_ids": ["owned-source-v1"],
        "hardware_reference_ids": ["owned-hardware-v1"],
        "cases": [
            _simple_case(
                "required-fields-case",
                _predicate(StaticSemanticOperation.MEMORY_LOAD),
            )
        ],
    }
    values[field] = []

    with pytest.raises(ValidationError):
        StaticTriggerPattern.create(**values)


def test_duplicate_case_references_and_ids_are_rejected() -> None:
    load = _predicate(StaticSemanticOperation.MEMORY_LOAD)
    barrier = _predicate(StaticSemanticOperation.MEMORY_BARRIER)
    first = _simple_case("duplicate-case", load)
    second = _simple_case("duplicate-case", barrier)
    common = {
        "architecture": Architecture.ARM,
        "instruction_set": "aarch64",
        "pattern_name": "duplicate-case-pattern",
        "source_reference_ids": ["owned-source-v1"],
        "hardware_reference_ids": ["owned-hardware-v1"],
    }
    with pytest.raises(ValidationError, match="references must be unique"):
        StaticTriggerPattern.create(cases=[first, second], **common)
    with pytest.raises(ValidationError, match="IDs must be unique"):
        StaticTriggerPattern.create(cases=[first, first], **common)


def test_empty_and_mixed_architecture_catalogs_are_valid() -> None:
    empty = StaticTriggerPatternCatalog.create(patterns=[])
    mixed = StaticTriggerPatternCatalog.create(
        patterns=[_risc_v_pattern(), _owned_pattern()]
    )

    assert not empty.patterns
    assert {pattern.architecture for pattern in mixed.patterns} == {
        Architecture.ARM,
        Architecture.RISC_V,
    }


def test_duplicate_pattern_ids_are_rejected() -> None:
    pattern = _owned_pattern()
    with pytest.raises(ValidationError, match="pattern IDs must be unique"):
        StaticTriggerPatternCatalog.create(patterns=[pattern, pattern])


@pytest.mark.parametrize(
    "field", ["source_reference_ids", "hardware_reference_ids"]
)
@pytest.mark.parametrize(
    "reference",
    ["/tmp/source", "~/source", "C:\\source", "file:/tmp/source"],
)
def test_path_like_references_are_rejected(
    field: str, reference: str
) -> None:
    values = {
        "architecture": Architecture.ARM,
        "instruction_set": "aarch64",
        "pattern_name": "path-neutral-pattern",
        "source_reference_ids": ["owned-source-v1"],
        "hardware_reference_ids": ["owned-hardware-v1"],
        "cases": [
            _simple_case(
                "path-neutral-case",
                _predicate(StaticSemanticOperation.MEMORY_LOAD),
            )
        ],
    }
    values[field] = [reference]
    with pytest.raises(ValidationError, match="path-neutral"):
        StaticTriggerPattern.create(**values)


@pytest.mark.parametrize(
    "field", ["source_reference_ids", "hardware_reference_ids"]
)
def test_duplicate_pattern_references_are_rejected(field: str) -> None:
    values = {
        "architecture": Architecture.ARM,
        "instruction_set": "aarch64",
        "pattern_name": "unique-reference-pattern",
        "source_reference_ids": ["owned-source-v1"],
        "hardware_reference_ids": ["owned-hardware-v1"],
        "cases": [
            _simple_case(
                "unique-reference-case",
                _predicate(StaticSemanticOperation.MEMORY_LOAD),
            )
        ],
    }
    values[field] = ["duplicate-reference", "duplicate-reference"]
    with pytest.raises(ValidationError, match="must be unique"):
        StaticTriggerPattern.create(**values)


def test_duplicate_objective_requirements_are_rejected() -> None:
    requirement = (
        StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED
    )
    with pytest.raises(ValidationError, match="must be unique"):
        _predicate(
            StaticSemanticOperation.MEMORY_LOAD,
            objective_requirements=(requirement, requirement),
        )


def test_nested_children_are_detached_from_caller_mutation() -> None:
    predicate = _predicate(
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
        attributes=(
            _attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, "par_el1"),
        ),
    )
    position = _position(1, predicate)
    predicate.required_attributes.clear()
    assert position.alternatives[0].required_attributes

    case = StaticTriggerCase.create(
        case_reference_id="detached-case", positions=[position]
    )
    position.alternatives.clear()
    assert case.positions[0].alternatives

    pattern = StaticTriggerPattern.create(
        architecture=Architecture.ARM,
        instruction_set="aarch64",
        pattern_name="detached-pattern",
        source_reference_ids=["owned-source-v1"],
        hardware_reference_ids=["owned-hardware-v1"],
        cases=[case],
    )
    case.positions.clear()
    assert pattern.cases[0].positions

    catalog = StaticTriggerPatternCatalog.create(patterns=[pattern])
    pattern.cases.clear()
    assert catalog.patterns[0].cases


def test_nested_retained_id_tampering_is_rejected() -> None:
    payload = _owned_pattern().model_dump(mode="json")
    payload["cases"][0]["positions"][0]["alternatives"][0]["id"] = (
        "static-trigger-predicate:tampered"
    )

    with pytest.raises(ValidationError, match="predicate ID mismatch"):
        StaticTriggerPattern.model_validate(payload)


@pytest.mark.parametrize(
    "kind",
    ["predicate", "position", "relation", "case", "pattern", "catalog"],
)
def test_retained_deterministic_id_tampering_is_rejected(kind: str) -> None:
    predicate = _predicate(StaticSemanticOperation.MEMORY_LOAD)
    position = _position(1, predicate)
    relation = _qualitative_relation()
    case = _simple_case("id-case", predicate)
    pattern = _owned_pattern()
    catalog = StaticTriggerPatternCatalog.create(patterns=[pattern])
    objects = {
        "predicate": predicate,
        "position": position,
        "relation": relation,
        "case": case,
        "pattern": pattern,
        "catalog": catalog,
    }
    value = objects[kind]
    payload = value.model_dump(mode="json")
    payload["id"] = f"static-trigger-{kind}:tampered"

    with pytest.raises(ValidationError, match="ID mismatch"):
        type(value).model_validate(payload)


def test_owned_fixture_is_exact_canonical_pattern() -> None:
    raw = FIXTURE.read_bytes()
    payload = json.loads(raw)
    loaded = StaticTriggerPattern.model_validate(payload)
    expected = _owned_pattern()
    readme = (FIXTURE_DIRECTORY / "README.md").read_text(encoding="utf-8")

    assert loaded == expected
    assert raw == json.dumps(
        expected.model_dump(mode="json"),
        ensure_ascii=False,
        sort_keys=True,
        indent=2,
    ).encode("utf-8") + b"\n"
    for label in ("owned", "synthetic", "benign"):
        assert label in readme.lower()
    assert "not a real hardware vulnerability" in readme.lower()
    assert "not runtime evidence" in readme.lower()
    assert "not a verified attack chain" in readme.lower()


def test_owned_pattern_has_two_address_independent_cases() -> None:
    pattern = _owned_pattern()
    cases = {case.case_reference_id: case for case in pattern.cases}

    assert set(cases) == {"owned-case-a", "owned-case-b"}
    assert [
        position.alternatives[0].operation
        for position in cases["owned-case-a"].positions
    ] == [
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
        StaticSemanticOperation.MEMORY_BARRIER,
        StaticSemanticOperation.INSTRUCTION_BARRIER,
    ]
    assert [
        position.alternatives[0].operation
        for position in cases["owned-case-b"].positions
    ] == [
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
        StaticSemanticOperation.TLB_INVALIDATE,
        StaticSemanticOperation.INSTRUCTION_BARRIER,
    ]
    assert all(case.relation_requirement is None for case in pattern.cases)


def test_generic_unresolved_requirement_shapes_are_representable() -> None:
    store = _predicate(StaticSemanticOperation.STORE_EXCLUSIVE)
    register = _predicate(
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
        attributes=(
            _attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, "par_el1"),
        ),
    )
    alternatives = _position(1, store, register)
    memory = _predicate(
        StaticSemanticOperation.MEMORY_LOAD,
        effective_memory_types=("device", "normal_non_cacheable"),
        execution_contexts=("privileged_aarch64",),
        objective_requirements=(
            StaticTriggerObjectiveRequirement
            .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
            StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
        ),
    )
    case = StaticTriggerCase.create(
        case_reference_id="representational-case",
        positions=[alternatives, _position(2, memory)],
        relation_requirement=_qualitative_relation(),
        objective_requirements=[
            StaticTriggerObjectiveRequirement
            .RELATION_PROXIMITY_REMAINS_UNRESOLVED
        ],
    )
    pattern = StaticTriggerPattern.create(
        architecture=Architecture.ARM,
        instruction_set="aarch64",
        pattern_name="owned_synthetic_unresolved_requirement_pattern",
        source_reference_ids=["owned-synthetic-source-v1"],
        hardware_reference_ids=["owned-synthetic-condition-v1"],
        cases=[case],
        objective_requirements=[
            StaticTriggerObjectiveRequirement
            .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED
        ],
    )

    assert len(alternatives.alternatives) == 2
    assert memory.required_effective_memory_types == [
        "device",
        "normal_non_cacheable",
    ]
    assert case.relation_requirement is not None
    assert pattern.objective_requirements == [
        StaticTriggerObjectiveRequirement
        .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED
    ]


def test_frozen_a77_source_uses_representable_concepts_only() -> None:
    source = json.loads(A77_PATTERN.read_text(encoding="utf-8"))
    serialized = json.dumps(source, sort_keys=True).lower()

    for concept in (
        '"alternative_semantics": "or"',
        '"position_order": "program_order"',
        '"system_register": "par_el1"',
        '"device"',
        '"normal_non_cacheable"',
        '"relation": "close_proximity"',
        '"relation_precision": "qualitative_only"',
        '"quantitative_bound": null',
        '"additional_timing_condition_requirement": '
        '"unresolved_from_public_documentation"',
    ):
        assert concept in serialized


def test_risc_v_uses_the_same_architecture_neutral_contracts() -> None:
    pattern = _risc_v_pattern()

    assert pattern.architecture is Architecture.RISC_V
    assert pattern.instruction_set == "rv64gc"
    assert [
        position.alternatives[0].operation
        for position in pattern.cases[0].positions
    ] == [
        StaticSemanticOperation.MEMORY_LOAD,
        StaticSemanticOperation.MEMORY_BARRIER,
    ]
    assert "risc_v" in pattern.model_dump_json()


def test_nonsemantic_input_permutations_are_deterministic() -> None:
    patterns = [_owned_pattern(permutation=index) for index in range(16)]
    ids = {pattern.id for pattern in patterns}
    hashes = {
        hashlib.sha256(
            _canonical_bytes(pattern.model_dump(mode="json"))
        ).hexdigest()
        for pattern in patterns
    }

    assert len(ids) == 1
    assert len(hashes) == 1


def test_or_external_value_and_objective_permutations_are_deterministic() -> None:
    store = _predicate(StaticSemanticOperation.STORE_EXCLUSIVE)
    register = _predicate(
        StaticSemanticOperation.SYSTEM_REGISTER_READ,
        attributes=(
            _attribute(StaticSemanticAttributeName.SYSTEM_REGISTER, "par_el1"),
        ),
    )
    patterns = []
    for index in range(10):
        alternatives = [store, register]
        memory_types = ["device", "normal_non_cacheable"]
        contexts = ["arm_a_profile", "privileged_aarch64"]
        requirements = [
            StaticTriggerObjectiveRequirement
            .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
            StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
        ]
        if index & 1:
            alternatives.reverse()
        if index & 2:
            memory_types.reverse()
        if index & 4:
            contexts.reverse()
        if index & 8:
            requirements.reverse()
        memory = _predicate(
            StaticSemanticOperation.MEMORY_LOAD,
            effective_memory_types=tuple(memory_types),
            execution_contexts=tuple(contexts),
            objective_requirements=tuple(requirements),
        )
        case = StaticTriggerCase.create(
            case_reference_id="permutation-case",
            positions=[_position(1, *alternatives), _position(2, memory)],
        )
        patterns.append(
            StaticTriggerPattern.create(
                architecture=Architecture.ARM,
                instruction_set="aarch64",
                pattern_name="owned_synthetic_permutation_pattern",
                source_reference_ids=["owned-source-v1"],
                hardware_reference_ids=["owned-hardware-v1"],
                cases=[case],
            )
        )

    assert len({pattern.id for pattern in patterns}) == 1
    assert len(
        {
            hashlib.sha256(
                _canonical_bytes(pattern.model_dump(mode="json"))
            ).hexdigest()
            for pattern in patterns
        }
    ) == 1


def test_catalog_permutations_are_deterministic() -> None:
    patterns = [_owned_pattern(), _risc_v_pattern()]
    catalogs = [
        StaticTriggerPatternCatalog.create(patterns=list(order))
        for order in itertools.islice(itertools.cycle((patterns, patterns[::-1])), 10)
    ]

    assert len({catalog.id for catalog in catalogs}) == 1
    assert len(
        {
            hashlib.sha256(
                _canonical_bytes(catalog.model_dump(mode="json"))
            ).hexdigest()
            for catalog in catalogs
        }
    ) == 1


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | {
            nested
            for item in value.values()
            for nested in _all_keys(item)
        }
    if isinstance(value, list):
        return {nested for item in value for nested in _all_keys(item)}
    return set()


def test_contract_has_no_address_runtime_or_outcome_fields() -> None:
    keys = _all_keys(_owned_pattern().model_dump(mode="json"))

    assert keys.isdisjoint(
        {
            "instruction_address",
            "instruction_bytes",
            "instruction_word",
            "mnemonic",
            "op_str",
            "function_address",
            "basic_block_address",
            "firmware_id",
            "binary_path",
            "fused_graph_id",
            "cfg_edge_ids",
            "candidate_witness",
            "expected_matcher_result",
            "matched",
            "match_success",
            "triggered",
            "triggerable",
            "executed",
            "runtime_reached",
            "caused",
            "verified",
            "vulnerable",
            "attack_chain",
            "exploit_feasible",
            "confidence",
            "probability",
            "score",
        }
    )


def test_dependency_firewall() -> None:
    path = (
        ROOT / "src/chipchain/analysis/static_trigger_pattern_models.py"
    )
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    allowed = {
        "__future__",
        "enum",
        "hashlib",
        "json",
        "re",
        "typing",
        "pydantic",
        "chipchain.analysis.static_semantic_models",
        "chipchain.models.common",
        "chipchain.models.enums",
    }

    assert imports <= allowed
