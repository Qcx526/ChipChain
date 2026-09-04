"""Source-faithful generic AArch64 projection of documented erratum 1508412."""

from __future__ import annotations

import hashlib
from pathlib import Path

from chipchain.analysis import (
    StaticSemanticAttributeName,
    StaticSemanticOperation,
    StaticTriggerObjectiveRequirement,
    translate_documented_erratum_to_aarch64_static_trigger_pattern,
)
from chipchain.hardware_trigger.documented_erratum_models import (
    DocumentedHardwareErratumContract,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
ERRATUM_PATH = (
    ROOT / "data/evaluation/"
    "cve_2023_34320_documented_erratum_1508412_v1.json"
)
GENERATED_PATTERN_PATH = (
    ROOT / "data/evaluation/"
    "cve_2023_34320_generic_aarch64_static_trigger_pattern_v1.json"
)


def _erratum() -> DocumentedHardwareErratumContract:
    return DocumentedHardwareErratumContract.model_validate_json(
        ERRATUM_PATH.read_bytes()
    )


def _pattern():
    return translate_documented_erratum_to_aarch64_static_trigger_pattern(
        _erratum()
    )


def test_adapter_targets_generic_aarch64_without_rewriting_source_scope() -> None:
    pattern = _pattern()
    assert pattern.architecture is Architecture.ARM
    assert pattern.instruction_set == "aarch64"
    assert pattern.hardware_reference_ids == [_erratum().id]
    assert _erratum().id in pattern.source_reference_ids
    assert _erratum().authoritative_source.source_locator in (
        pattern.source_reference_ids
    )
    assert _erratum().public_corpus_id in pattern.source_reference_ids


def test_event_translation_is_exact_and_preserves_cases() -> None:
    pattern = _pattern()
    cases = {case.case_reference_id: case for case in pattern.cases}
    assert set(cases) == {
        "documented-erratum-1508412-case-a",
        "documented-erratum-1508412-case-b",
    }
    case_a = cases["documented-erratum-1508412-case-a"]
    case_b = cases["documented-erratum-1508412-case-b"]
    assert [
        {item.operation for item in position.alternatives}
        for position in case_a.positions
    ] == [
        {
            StaticSemanticOperation.STORE_EXCLUSIVE,
            StaticSemanticOperation.SYSTEM_REGISTER_READ,
        },
        {StaticSemanticOperation.MEMORY_LOAD},
    ]
    assert [
        {item.operation for item in position.alternatives}
        for position in case_b.positions
    ] == [
        {StaticSemanticOperation.MEMORY_LOAD},
        {
            StaticSemanticOperation.STORE_EXCLUSIVE,
            StaticSemanticOperation.SYSTEM_REGISTER_READ,
        },
    ]
    predicates = [
        predicate
        for case in pattern.cases
        for position in case.positions
        for predicate in position.alternatives
    ]
    par = next(
        predicate
        for predicate in predicates
        if predicate.operation is StaticSemanticOperation.SYSTEM_REGISTER_READ
    )
    assert [(item.name, item.value) for item in par.required_attributes] == [
        (StaticSemanticAttributeName.SYSTEM_REGISTER, "par_el1")
    ]


def test_external_requirements_remain_explicitly_unresolved() -> None:
    pattern = _pattern()
    predicates = {
        predicate.id: predicate
        for case in pattern.cases
        for position in case.positions
        for predicate in position.alternatives
    }.values()
    assert all(item.required_execution_contexts for item in predicates)
    assert all(
        StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED
        in item.objective_requirements
        for item in predicates
    )
    loads = [
        item
        for item in predicates
        if item.operation is StaticSemanticOperation.MEMORY_LOAD
    ]
    assert {tuple(item.required_effective_memory_types) for item in loads} == {
        ("device",),
        ("device", "normal_non_cacheable"),
    }
    assert all(
        StaticTriggerObjectiveRequirement
        .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
        in item.objective_requirements
        for item in loads
    )
    assert all(case.relation_requirement is not None for case in pattern.cases)
    assert all(
        StaticTriggerObjectiveRequirement.RELATION_PROXIMITY_REMAINS_UNRESOLVED
        in case.objective_requirements
        for case in pattern.cases
    )
    assert pattern.objective_requirements == [
        StaticTriggerObjectiveRequirement
        .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED
    ]


def test_adapter_is_deterministic_across_ten_runs() -> None:
    patterns = [_pattern() for _ in range(10)]
    assert len({item.id for item in patterns}) == 1
    assert len(
        {
            hashlib.sha256(
                item.model_dump_json().encode("utf-8")
            ).hexdigest()
            for item in patterns
        }
    ) == 1


def test_generated_pattern_is_byte_exact() -> None:
    expected = _pattern().model_dump_json(indent=2, ensure_ascii=False) + "\n"
    assert GENERATED_PATTERN_PATH.read_text(encoding="utf-8") == expected
