"""Phase 10D Step 8B-2B2-A static semantic contract tests."""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

import pytest
from pydantic import ValidationError

from chipchain.hardware_trigger import (
    PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT,
    PHASE10D_A_PROFILE_STATIC_EXTRACTION_RESULT_CONTRACT,
    PHASE10D_A_PROFILE_STATIC_PREDICATE_CANDIDATE_CONTRACT,
    PHASE10D_A_PROFILE_STATIC_SEMANTIC_EXTRACTION_PLAN_CONTRACT,
    PHASE10D_A_PROFILE_STATIC_SEMANTIC_FACT_CONTRACT,
    AProfileExecutionApplicability,
    AProfileMemoryType,
    AProfileSemanticEventKind,
    AProfileSemanticEventPredicate,
    AProfileSemanticTriggerPattern,
    AProfileStaticInstructionSetState,
    AProfileStaticPredicateCandidate,
    AProfileStaticPredicatePlanEntry,
    AProfileStaticSemanticExtractionPlan,
    AProfileStaticSemanticExtractionResult,
    AProfileStaticSemanticInstructionFact,
    AProfileSystemRegister,
    ArmExecutionMode,
    HardwareTriggerSignature,
    RemainingObjectiveObligation,
    StaticEffectiveMemoryTypeResolution,
    StaticFactScope,
    StaticInstructionLocation,
    StaticRecognitionSemantics,
    a_profile_semantic_predicate_ref,
    a_profile_static_predicate_candidate_id,
    build_a_profile_static_semantic_extraction_plan,
    serialize_a_profile_static_semantic_extraction_plan,
    translate_a_profile_pattern_to_static_extraction_plan,
)
from chipchain.models.enums import Architecture


ROOT = Path(__file__).resolve().parents[1]
SOURCE_PATH = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_semantic_trigger_pattern_v1.json"
)
GENERATED_PATH = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_static_semantic_extraction_plan_v1.json"
)
EXPECTED_SOURCE_ID = (
    "a-profile-semantic-trigger-pattern:"
    "25599b751ead0dc36a39787000fad60aa0cea6485913cdf52b248e037ec21d77"
)
EXPECTED_SOURCE_SHA256 = (
    "6a56e75078475fd5133524c8aef28233a431283b151960ea9389d2430ce2ceb0"
)
EXPECTED_PLAN_ID = (
    "a-profile-static-semantic-extraction-plan:"
    "2efffa2cb11cb1fd9983a16341a9b0cb05c08ad9736a4c86c9cd74997ba79d76"
)
EXPECTED_PLAN_SHA256 = (
    "cd7be371e290b05a2d97fb766e89beaa149ec2c532f22c7a840e305dff13b6d8"
)
EXPECTED_A32_SIGNATURE_ID = (
    "hardware-trigger-signature:"
    "6c40f20a04baf56570c4f2994f1859e4b4012371300c78b43143829d16bd26ba"
)


@pytest.fixture(scope="module")
def pattern() -> AProfileSemanticTriggerPattern:
    return AProfileSemanticTriggerPattern.model_validate_json(
        SOURCE_PATH.read_bytes()
    )


@pytest.fixture(scope="module")
def plan() -> AProfileStaticSemanticExtractionPlan:
    return build_a_profile_static_semantic_extraction_plan(
        semantic_pattern_bytes=SOURCE_PATH.read_bytes(),
        expected_source_pattern_id=EXPECTED_SOURCE_ID,
        expected_source_pattern_sha256=EXPECTED_SOURCE_SHA256,
    )


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _entry(
    plan: AProfileStaticSemanticExtractionPlan,
    case_id: str,
    position_index: int,
    kind: AProfileSemanticEventKind,
):
    return next(
        item
        for item in plan.predicate_entries
        if (
            item.case_id,
            item.position_index,
            item.event_kind,
        )
        == (case_id, position_index, kind)
    )


def _fact(
    *,
    kind: AProfileSemanticEventKind = AProfileSemanticEventKind.MEMORY_LOAD,
    address: str = "0x0000000000401234",
    artifact_id: str = "artifact:owned-synthetic-a64",
    artifact_sha256: str = "a" * 64,
) -> AProfileStaticSemanticInstructionFact:
    is_load = kind is AProfileSemanticEventKind.MEMORY_LOAD
    is_register = kind is AProfileSemanticEventKind.SYSTEM_REGISTER_READ
    return AProfileStaticSemanticInstructionFact.create(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        architecture=Architecture.ARM,
        architecture_profile="a_profile",
        instruction_set_state=AProfileStaticInstructionSetState.AARCH64,
        instruction_address=address,
        instruction_word="0xF9400001",
        instruction_size=4,
        basic_block_address="0x0000000000401200",
        function_address="0x0000000000401000",
        function_name="owned_synthetic_function",
        event_kind=kind,
        system_register=AProfileSystemRegister.PAR_EL1 if is_register else None,
        memory_type_resolution=(
            StaticEffectiveMemoryTypeResolution.REQUIRES_OBJECTIVE_TRANSLATION_CONTEXT
            if is_load
            else StaticEffectiveMemoryTypeResolution.NOT_APPLICABLE
        ),
        static_fact_scope=(
            StaticFactScope.DECODED_ARTIFACT_INSTRUCTION_SEMANTICS_ONLY
        ),
    )


def _candidate(
    plan: AProfileStaticSemanticExtractionPlan,
    fact: AProfileStaticSemanticInstructionFact,
    *,
    case_id: str = "case_a",
    position_index: int = 2,
    kind: AProfileSemanticEventKind = AProfileSemanticEventKind.MEMORY_LOAD,
) -> AProfileStaticPredicateCandidate:
    return AProfileStaticPredicateCandidate.create(
        extraction_plan=plan,
        predicate_entry=_entry(plan, case_id, position_index, kind),
        static_instruction_fact=fact,
    )


def _recompute_candidate_id(payload: dict[str, object]) -> dict[str, object]:
    identity_payload = {key: value for key, value in payload.items() if key != "id"}
    payload["id"] = a_profile_static_predicate_candidate_id(identity_payload)
    return payload


def test_exact_contracts_source_binding_and_plan_identity(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    assert plan.contract == (
        PHASE10D_A_PROFILE_STATIC_SEMANTIC_EXTRACTION_PLAN_CONTRACT
    )
    assert plan.id == EXPECTED_PLAN_ID
    assert plan.source_pattern_id == EXPECTED_SOURCE_ID
    assert plan.source_pattern_sha256 == EXPECTED_SOURCE_SHA256
    assert plan.source_pattern_contract == (
        PHASE10D_A_PROFILE_SEMANTIC_TRIGGER_PATTERN_CONTRACT
    )
    assert _sha256(SOURCE_PATH) == EXPECTED_SOURCE_SHA256
    assert _sha256(GENERATED_PATH) == EXPECTED_PLAN_SHA256


def test_plan_is_deterministic_and_artifact_bytes_are_exact(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    rebuilt = build_a_profile_static_semantic_extraction_plan(
        semantic_pattern_bytes=SOURCE_PATH.read_bytes(),
        expected_source_pattern_id=EXPECTED_SOURCE_ID,
        expected_source_pattern_sha256=EXPECTED_SOURCE_SHA256,
    )
    assert rebuilt == plan
    assert serialize_a_profile_static_semantic_extraction_plan(rebuilt) == (
        GENERATED_PATH.read_text(encoding="utf-8")
    )


def test_one_entry_per_exact_source_alternative_without_drop(
    pattern: AProfileSemanticTriggerPattern,
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    source = {
        (
            case.case_id,
            position.position_index,
            json.dumps(
                predicate.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        for case in pattern.cases
        for position in case.positions
        for predicate in position.alternatives
    }
    translated = {
        (
            entry.case_id,
            entry.position_index,
            json.dumps(
                entry.as_predicate().model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
            ),
        )
        for entry in plan.predicate_entries
    }
    assert len(source) == len(translated) == 6
    assert source == translated
    assert {item.case_id for item in plan.case_source_limitations} == {
        "case_a",
        "case_b",
    }


def test_predicate_references_bind_semantics_not_alternative_index(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    first = pattern.cases[0].positions[1].alternatives[0]
    clone = AProfileSemanticEventPredicate.model_validate(
        first.model_dump(mode="json")
    )
    changed = AProfileSemanticEventPredicate(
        kind=AProfileSemanticEventKind.MEMORY_LOAD,
        applicability=AProfileExecutionApplicability.ARM_A_PROFILE,
        memory_type_constraints=[AProfileMemoryType.DEVICE],
        memory_type_semantics=first.memory_type_semantics,
        memory_type_observation_requirement=(
            first.memory_type_observation_requirement
        ),
    )
    arguments = {
        "pattern_id": pattern.id,
        "case_id": "case_a",
        "position_index": 2,
    }
    assert a_profile_semantic_predicate_ref(**arguments, predicate=first) == (
        a_profile_semantic_predicate_ref(**arguments, predicate=clone)
    )
    assert a_profile_semantic_predicate_ref(**arguments, predicate=first) != (
        a_profile_semantic_predicate_ref(**arguments, predicate=changed)
    )


def test_case_requirements_and_par_applicability_are_preserved(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    case_b_load = _entry(
        plan, "case_b", 1, AProfileSemanticEventKind.MEMORY_LOAD
    )
    assert case_b_load.required_memory_type_constraints == [
        AProfileMemoryType.DEVICE
    ]
    par_entries = [
        item
        for item in plan.predicate_entries
        if item.event_kind is AProfileSemanticEventKind.SYSTEM_REGISTER_READ
    ]
    assert par_entries
    assert all(
        item.system_register is AProfileSystemRegister.PAR_EL1
        and item.applicability
        is AProfileExecutionApplicability.PRIVILEGED_AARCH64
        for item in par_entries
    )
    assert all(
        item.static_recognition_semantics
        is StaticRecognitionSemantics.DECODED_INSTRUCTION_SEMANTICS
        for item in plan.predicate_entries
    )


def test_all_remaining_objective_obligations_are_preserved(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    for entry in plan.predicate_entries:
        obligations = set(entry.remaining_objective_obligations)
        assert RemainingObjectiveObligation.RUNTIME_EXECUTION_REQUIRED in obligations
        assert (
            RemainingObjectiveObligation.RELATION_PROXIMITY_REMAINS_UNRESOLVED
            in obligations
        )
        assert (
            RemainingObjectiveObligation.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED
            in obligations
        )
        if entry.event_kind is AProfileSemanticEventKind.MEMORY_LOAD:
            assert (
                RemainingObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
                in obligations
            )
        if entry.applicability is (
            AProfileExecutionApplicability.PRIVILEGED_AARCH64
        ):
            assert (
                RemainingObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED
                in obligations
            )
    assert all(item.quantitative_bound is None for item in plan.case_source_limitations)


def test_static_isa_and_a64_provenance_are_narrow_and_canonical() -> None:
    assert [item.value for item in AProfileStaticInstructionSetState] == [
        "aarch64"
    ]
    fact = _fact(address="0x000000000040ABCD")
    assert fact.instruction_address == "0x000000000040abcd"
    assert fact.instruction_word == "0xf9400001"
    assert fact.instruction_size == 4
    with pytest.raises(ValidationError, match="exactly 16"):
        _fact(address="0x00401234")
    with pytest.raises(ValidationError, match="exactly 8"):
        AProfileStaticSemanticInstructionFact.create(
            **{
                **_fact().model_dump(mode="json", exclude={"id", "contract"}),
                "instruction_word": "0x123456789",
            }
        )


def test_fact_contract_is_static_only_and_identity_is_content_bound() -> None:
    first = _fact()
    second = _fact(address="0x0000000000401238")
    assert first.contract == PHASE10D_A_PROFILE_STATIC_SEMANTIC_FACT_CONTRACT
    assert first.id != second.id
    assert first.static_fact_scope is (
        StaticFactScope.DECODED_ARTIFACT_INSTRUCTION_SEMANTICS_ONLY
    )
    assert "effective_memory_type" not in type(first).model_fields
    assert "executed" not in type(first).model_fields
    assert "runtime_privilege" not in type(first).model_fields


def test_memory_resolution_and_par_shape_fail_closed() -> None:
    load = _fact()
    assert load.memory_type_resolution is (
        StaticEffectiveMemoryTypeResolution.REQUIRES_OBJECTIVE_TRANSLATION_CONTEXT
    )
    store = _fact(kind=AProfileSemanticEventKind.STORE_EXCLUSIVE)
    assert store.memory_type_resolution is (
        StaticEffectiveMemoryTypeResolution.NOT_APPLICABLE
    )
    payload = load.model_dump(mode="json", exclude={"id", "contract"})
    payload["memory_type_resolution"] = "not_applicable"
    with pytest.raises(ValidationError, match="memory-type resolution"):
        AProfileStaticSemanticInstructionFact.create(**payload)
    payload = store.model_dump(mode="json", exclude={"id", "contract"})
    payload["system_register"] = "PAR_EL1"
    with pytest.raises(ValidationError, match="non-system-register"):
        AProfileStaticSemanticInstructionFact.create(**payload)


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "observed",
        "executed",
        "matched",
        "satisfied",
        "triggered",
        "effective_memory_type",
        "runtime_el",
        "runtime_privilege",
        "proximity_satisfied",
        "triggerability_status",
        "feasibility_status",
        "verification_status",
        "primary_ready",
        "confidence",
        "score",
    ],
)
def test_all_new_contracts_reject_outcome_fields(
    plan: AProfileStaticSemanticExtractionPlan,
    forbidden_field: str,
) -> None:
    payload = _fact().model_dump(mode="json")
    payload[forbidden_field] = True
    with pytest.raises(ValidationError):
        AProfileStaticSemanticInstructionFact.model_validate(payload)

    plan_payload = plan.model_dump(mode="json")
    plan_payload[forbidden_field] = True
    with pytest.raises(ValidationError):
        AProfileStaticSemanticExtractionPlan.model_validate(plan_payload)


def test_nested_candidate_and_result_contracts_are_also_extra_forbid(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    fact = _fact()
    candidate = _candidate(plan, fact)
    result = AProfileStaticSemanticExtractionResult.create(
        artifact_id=fact.artifact_id,
        artifact_sha256=fact.artifact_sha256,
        extraction_plan=plan,
        instruction_facts=[fact],
        predicate_candidates=[candidate],
    )
    payloads_and_types = [
        (plan.predicate_entries[0].model_dump(mode="json"), type(plan.predicate_entries[0])),
        (
            plan.case_source_limitations[0].model_dump(mode="json"),
            type(plan.case_source_limitations[0]),
        ),
        (candidate.model_dump(mode="json"), AProfileStaticPredicateCandidate),
        (result.model_dump(mode="json"), AProfileStaticSemanticExtractionResult),
    ]
    for payload, model_type in payloads_and_types:
        payload["verification_status"] = "verified"
        with pytest.raises(ValidationError):
            model_type.model_validate(payload)

    result_payload = result.model_dump(mode="json", exclude={"id", "contract"})
    result_payload["diagnostic_codes"] = ["runtime_execution_observed"]
    with pytest.raises(ValidationError, match="contains an outcome"):
        AProfileStaticSemanticExtractionResult.create(
            artifact_id=result_payload["artifact_id"],
            artifact_sha256=result_payload["artifact_sha256"],
            extraction_plan=plan,
            instruction_facts=result_payload["instruction_facts"],
            predicate_candidates=result_payload["predicate_candidates"],
            diagnostic_codes=result_payload["diagnostic_codes"],
        )


def test_candidate_exact_binding_and_conservative_meaning(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    fact = _fact()
    case_a = _candidate(plan, fact)
    case_b = _candidate(
        plan,
        fact,
        case_id="case_b",
        position_index=1,
    )
    assert case_a.contract == (
        PHASE10D_A_PROFILE_STATIC_PREDICATE_CANDIDATE_CONTRACT
    )
    assert case_a.static_instruction_fact_id == case_b.static_instruction_fact_id
    assert case_a.predicate_ref != case_b.predicate_ref
    assert (
        RemainingObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
        in case_a.remaining_objective_obligations
    )
    assert "satisfied" not in type(case_a).model_fields


def test_standalone_valid_load_candidate_round_trips(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    candidate = _candidate(plan, _fact())

    restored = AProfileStaticPredicateCandidate.model_validate_json(
        candidate.model_dump_json()
    )

    assert restored == candidate
    assert restored.predicate_entry_snapshot == _entry(
        plan,
        "case_a",
        2,
        AProfileSemanticEventKind.MEMORY_LOAD,
    )


def test_standalone_load_candidate_cannot_drop_conditional_obligation(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    payload = _candidate(plan, _fact()).model_dump(mode="json")
    original_id = payload["id"]
    payload["remaining_objective_obligations"].remove(
        RemainingObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED.value
    )
    _recompute_candidate_id(payload)
    assert payload["id"] != original_id

    with pytest.raises(
        ValidationError,
        match="objective obligations do not match predicate-entry snapshot",
    ):
        AProfileStaticPredicateCandidate.model_validate(payload)


def test_standalone_par_candidate_cannot_drop_runtime_context_obligation(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    fact = _fact(kind=AProfileSemanticEventKind.SYSTEM_REGISTER_READ)
    candidate = _candidate(
        plan,
        fact,
        case_id="case_a",
        position_index=1,
        kind=AProfileSemanticEventKind.SYSTEM_REGISTER_READ,
    )
    payload = candidate.model_dump(mode="json")
    original_id = payload["id"]
    payload["remaining_objective_obligations"].remove(
        RemainingObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED.value
    )
    _recompute_candidate_id(payload)
    assert payload["id"] != original_id

    with pytest.raises(
        ValidationError,
        match="objective obligations do not match predicate-entry snapshot",
    ):
        AProfileStaticPredicateCandidate.model_validate(payload)


def test_standalone_candidate_rejects_snapshot_applicability_tamper(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    fact = _fact(kind=AProfileSemanticEventKind.STORE_EXCLUSIVE)
    payload = _candidate(
        plan,
        fact,
        case_id="case_a",
        position_index=1,
        kind=AProfileSemanticEventKind.STORE_EXCLUSIVE,
    ).model_dump(mode="json")
    payload["predicate_entry_snapshot"]["applicability"] = (
        AProfileExecutionApplicability.PRIVILEGED_AARCH64.value
    )
    _recompute_candidate_id(payload)

    with pytest.raises(ValidationError):
        AProfileStaticPredicateCandidate.model_validate(payload)


def test_standalone_candidate_rejects_snapshot_event_kind_tamper(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    fact = _fact(kind=AProfileSemanticEventKind.STORE_EXCLUSIVE)
    payload = _candidate(
        plan,
        fact,
        case_id="case_a",
        position_index=1,
        kind=AProfileSemanticEventKind.STORE_EXCLUSIVE,
    ).model_dump(mode="json")
    payload["predicate_entry_snapshot"]["event_kind"] = (
        AProfileSemanticEventKind.MEMORY_LOAD.value
    )
    _recompute_candidate_id(payload)

    with pytest.raises(ValidationError):
        AProfileStaticPredicateCandidate.model_validate(payload)


def test_standalone_candidate_rejects_snapshot_par_payload_tamper(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    fact = _fact(kind=AProfileSemanticEventKind.SYSTEM_REGISTER_READ)
    payload = _candidate(
        plan,
        fact,
        case_id="case_a",
        position_index=1,
        kind=AProfileSemanticEventKind.SYSTEM_REGISTER_READ,
    ).model_dump(mode="json")
    payload["predicate_entry_snapshot"]["system_register"] = None
    _recompute_candidate_id(payload)

    with pytest.raises(ValidationError):
        AProfileStaticPredicateCandidate.model_validate(payload)


def test_standalone_candidate_rejects_snapshot_memory_constraint_tamper(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    payload = _candidate(plan, _fact()).model_dump(mode="json")
    original_id = payload["id"]
    payload["predicate_entry_snapshot"][
        "required_memory_type_constraints"
    ] = [AProfileMemoryType.DEVICE.value]
    _recompute_candidate_id(payload)
    assert payload["id"] != original_id

    with pytest.raises(
        ValidationError,
        match="predicate reference does not match snapshot semantic content",
    ):
        AProfileStaticPredicateCandidate.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("case_id", "case_other", "case does not match"),
        ("position_index", 1, "position does not match"),
    ],
)
def test_standalone_candidate_rejects_snapshot_location_tamper(
    plan: AProfileStaticSemanticExtractionPlan,
    field: str,
    value: object,
    message: str,
) -> None:
    payload = _candidate(plan, _fact()).model_dump(mode="json")
    payload["predicate_entry_snapshot"][field] = value
    _recompute_candidate_id(payload)

    with pytest.raises(ValidationError, match=message):
        AProfileStaticPredicateCandidate.model_validate(payload)


def test_result_rejects_standalone_valid_snapshot_outside_exact_plan(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    fact = _fact()
    payload = _candidate(plan, fact).model_dump(mode="json")
    snapshot_payload = payload["predicate_entry_snapshot"]
    snapshot_payload["required_memory_type_constraints"] = [
        AProfileMemoryType.DEVICE.value
    ]
    changed_entry = AProfileStaticPredicatePlanEntry.model_validate(
        snapshot_payload
    )
    changed_ref = a_profile_semantic_predicate_ref(
        pattern_id=payload["source_pattern_id"],
        case_id=payload["case_id"],
        position_index=payload["position_index"],
        predicate=changed_entry.as_predicate(),
    )
    snapshot_payload["predicate_ref"] = changed_ref
    payload["predicate_ref"] = changed_ref
    _recompute_candidate_id(payload)
    candidate = AProfileStaticPredicateCandidate.model_validate(payload)

    with pytest.raises(ValidationError, match="outside the plan"):
        AProfileStaticSemanticExtractionResult.create(
            artifact_id=fact.artifact_id,
            artifact_sha256=fact.artifact_sha256,
            extraction_plan=plan,
            instruction_facts=[fact],
            predicate_candidates=[candidate],
        )


def test_result_rejects_post_validation_candidate_snapshot_substitution(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    fact = _fact()
    candidate = _candidate(plan, fact).model_copy(deep=True)
    object.__setattr__(
        candidate,
        "predicate_entry_snapshot",
        _entry(plan, "case_b", 1, AProfileSemanticEventKind.MEMORY_LOAD),
    )

    with pytest.raises(ValidationError, match="predicate reference"):
        AProfileStaticSemanticExtractionResult.create(
            artifact_id=fact.artifact_id,
            artifact_sha256=fact.artifact_sha256,
            extraction_plan=plan,
            instruction_facts=[fact],
            predicate_candidates=[candidate],
        )


def test_candidate_rejects_wrong_fact_or_predicate(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    fact = _fact(kind=AProfileSemanticEventKind.STORE_EXCLUSIVE)
    with pytest.raises(ValueError, match="event kind"):
        _candidate(plan, fact)
    foreign = plan.model_copy(deep=True)
    object.__setattr__(foreign, "id", "a-profile-static-semantic-extraction-plan:" + "0" * 64)
    with pytest.raises(ValidationError):
        AProfileStaticPredicateCandidate.create(
            extraction_plan=foreign,
            predicate_entry=plan.predicate_entries[0],
            static_instruction_fact=fact,
        )


def test_result_contract_exact_bindings_and_deterministic_order(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    load = _fact()
    store = _fact(
        kind=AProfileSemanticEventKind.STORE_EXCLUSIVE,
        address="0x0000000000401200",
    )
    candidates = [
        _candidate(plan, load),
        _candidate(
            plan,
            store,
            case_id="case_a",
            position_index=1,
            kind=AProfileSemanticEventKind.STORE_EXCLUSIVE,
        ),
    ]
    result = AProfileStaticSemanticExtractionResult.create(
        artifact_id=load.artifact_id,
        artifact_sha256=load.artifact_sha256,
        extraction_plan=plan,
        instruction_facts=[load, store],
        predicate_candidates=list(reversed(candidates)),
        diagnostic_codes=["decoded_semantic_candidates_present"],
    )
    assert result.contract == PHASE10D_A_PROFILE_STATIC_EXTRACTION_RESULT_CONTRACT
    assert result.extraction_plan_id == plan.id
    assert result.source_pattern_id == plan.source_pattern_id
    assert result.instruction_facts[0].instruction_address < (
        result.instruction_facts[1].instruction_address
    )
    assert AProfileStaticSemanticExtractionResult.model_validate_json(
        result.model_dump_json()
    ) == result


def test_result_cross_bindings_and_duplicates_fail_closed(
    plan: AProfileStaticSemanticExtractionPlan,
) -> None:
    fact = _fact()
    candidate = _candidate(plan, fact)
    with pytest.raises(ValidationError, match="artifact binding"):
        AProfileStaticSemanticExtractionResult.create(
            artifact_id=fact.artifact_id,
            artifact_sha256="b" * 64,
            extraction_plan=plan,
            instruction_facts=[fact],
            predicate_candidates=[candidate],
        )
    with pytest.raises(ValidationError, match="unique IDs"):
        AProfileStaticSemanticExtractionResult.create(
            artifact_id=fact.artifact_id,
            artifact_sha256=fact.artifact_sha256,
            extraction_plan=plan,
            instruction_facts=[fact, fact],
            predicate_candidates=[candidate],
        )
    with pytest.raises(ValidationError, match="unique IDs"):
        AProfileStaticSemanticExtractionResult.create(
            artifact_id=fact.artifact_id,
            artifact_sha256=fact.artifact_sha256,
            extraction_plan=plan,
            instruction_facts=[fact],
            predicate_candidates=[candidate, candidate],
        )
    valid = AProfileStaticSemanticExtractionResult.create(
        artifact_id=fact.artifact_id,
        artifact_sha256=fact.artifact_sha256,
        extraction_plan=plan,
        instruction_facts=[fact],
        predicate_candidates=[candidate],
    )
    payload = valid.model_dump(mode="json")
    payload["extraction_plan_id"] = "a-profile-static-semantic-extraction-plan:" + "f" * 64
    with pytest.raises(ValidationError, match="extraction-plan binding"):
        AProfileStaticSemanticExtractionResult.model_validate(payload)


def test_no_case_order_proximity_or_verdict_result_exists() -> None:
    from chipchain.hardware_trigger import a_profile_static_semantic_models

    assert not hasattr(
        a_profile_static_semantic_models, "StaticSemanticCaseCandidate"
    )
    forbidden = {
        "program_order_satisfied",
        "proximity_satisfied",
        "instruction_distance",
        "cycle_distance",
        "distance_threshold",
        "window_size",
        "triggerability",
        "verification",
        "feasibility",
    }
    assert forbidden.isdisjoint(
        AProfileStaticSemanticExtractionResult.model_fields
    )


def test_source_drift_and_source_identity_contract_drift_fail_closed(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    changed_bytes = SOURCE_PATH.read_bytes().replace(b"{\n", b"{\n\n", 1)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        build_a_profile_static_semantic_extraction_plan(
            semantic_pattern_bytes=changed_bytes,
            expected_source_pattern_id=EXPECTED_SOURCE_ID,
            expected_source_pattern_sha256=EXPECTED_SOURCE_SHA256,
        )
    changed = pattern.model_copy(deep=True)
    object.__setattr__(
        changed,
        "id",
        "a-profile-semantic-trigger-pattern:" + "0" * 64,
    )
    with pytest.raises(ValidationError):
        translate_a_profile_pattern_to_static_extraction_plan(
            changed,
            source_pattern_sha256=EXPECTED_SOURCE_SHA256,
            expected_source_pattern_id=EXPECTED_SOURCE_ID,
            expected_source_pattern_sha256=EXPECTED_SOURCE_SHA256,
        )
    changed = pattern.model_copy(deep=True)
    object.__setattr__(changed, "contract", "unexpected_contract")
    with pytest.raises(ValidationError):
        translate_a_profile_pattern_to_static_extraction_plan(
            changed,
            source_pattern_sha256=EXPECTED_SOURCE_SHA256,
            expected_source_pattern_id=EXPECTED_SOURCE_ID,
            expected_source_pattern_sha256=EXPECTED_SOURCE_SHA256,
        )


def test_source_precision_relation_and_vocabulary_drift_fail_closed(
    pattern: AProfileSemanticTriggerPattern,
) -> None:
    for field in (
        "quantitative_proximity_source_defined",
        "machine_code_sequence_source_defined",
        "runtime_environment_source_defined",
    ):
        changed = pattern.model_copy(deep=True)
        object.__setattr__(changed.source_precision_obligations, field, True)
        with pytest.raises(ValidationError):
            translate_a_profile_pattern_to_static_extraction_plan(
                changed,
                source_pattern_sha256=EXPECTED_SOURCE_SHA256,
                expected_source_pattern_id=EXPECTED_SOURCE_ID,
                expected_source_pattern_sha256=EXPECTED_SOURCE_SHA256,
            )
    payload = pattern.model_dump(mode="json")
    payload["cases"][0]["quantitative_bound"] = 1
    with pytest.raises(ValidationError):
        AProfileSemanticTriggerPattern.model_validate(payload)
    payload = pattern.model_dump(mode="json")
    payload["cases"][0]["positions"][0]["alternatives"][0]["kind"] = "branch"
    with pytest.raises(ValidationError):
        AProfileSemanticTriggerPattern.model_validate(payload)


def test_new_modules_and_builder_obey_import_firewall() -> None:
    paths = [
        ROOT / "src/chipchain/hardware_trigger/a_profile_static_semantic_models.py",
        ROOT / "src/chipchain/hardware_trigger/a_profile_static_semantic.py",
        ROOT
        / "scripts/build_cve_2023_34320_a_profile_static_semantic_extraction_plan.py",
    ]
    forbidden_roots = {
        "angr",
        "httpx",
        "requests",
        "socket",
        "urllib",
    }
    forbidden_names = (
        "chipchain.runtime",
        "chipchain.qemu",
        "ReasoningProvider",
        "GroundTruth",
        "Evidence",
        "VerificationRecord",
        "TriggerabilityStatus",
        "TriggerabilityAggregationResult",
        "ChainFeasibilityStatus",
        "ChainFeasibilityAssessment",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        imports = {
            alias.name.split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports.update(
            (node.module or "").split(".")[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        )
        assert imports.isdisjoint(forbidden_roots)
        assert all(name not in text for name in forbidden_names)


def test_builder_uses_only_2b1_source_and_check_passes() -> None:
    script_path = (
        ROOT
        / "scripts/build_cve_2023_34320_a_profile_static_semantic_extraction_plan.py"
    )
    script = script_path.read_text(encoding="utf-8")
    assert "cve_2023_34320_a_profile_semantic_trigger_pattern_v1.json" in script
    assert "documented_erratum" not in script
    assert "public_cve" not in script
    result = subprocess.run(
        [sys.executable, str(script_path), "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout == result.stderr == ""


def test_frozen_a32_contract_and_static_address_semantics_are_unchanged() -> None:
    signature_path = (
        ROOT
        / "tests/fixtures/phase9c/arm_a32_trigger_runtime/"
        "hardware_trigger_signature.json"
    )
    signature = HardwareTriggerSignature.model_validate_json(
        signature_path.read_bytes()
    )
    assert [item.value for item in ArmExecutionMode] == ["arm_a32"]
    assert signature.id == EXPECTED_A32_SIGNATURE_ID
    old = StaticInstructionLocation(
        instruction_address="0x00001004",
        instruction_word="0xE3A00001",
        basic_block_address="0x00001000",
    )
    assert old.instruction_address == "0x00001004"
    assert old.instruction_word == "0xe3a00001"
    with pytest.raises(ValidationError, match="exactly 8"):
        StaticInstructionLocation(
            instruction_address="0x0000000000001004",
            instruction_word="0xe3a00001",
            basic_block_address="0x00001000",
        )


def test_all_frozen_upstream_artifacts_are_byte_exact() -> None:
    expected = {
        "data/evaluation/cve_2023_34320_a_profile_semantic_trigger_pattern_v1.json": EXPECTED_SOURCE_SHA256,
        "data/evaluation/cve_2023_34320_documented_erratum_1508412_v1.json": "bd50b8b50313041c3d5245cccaf51a0d4d479914033ad233d79a740180b0c5a1",
        "data/public_cve/objective/cve_2023_34320_erratum_1508412.source.json": "fea66e7375087e543fd4a1fc5ab5d2789f8825880ed624e6a0eca28b1c8e73dd",
        "data/evaluation/runs/phase10d_step8b1d_public_deepseek_20260831_one_shot.json": "5bf1f1268b90a8a7eaf17bb52846ae64f2edc752ec904b3db3125fc0efafdedd",
        "data/evaluation/runs/phase10d_step8b1d_public_deepseek_20260831_offline_summary.json": "d022b22be95269a601c5a263e7e4cd5844f93b53fec93055c3aac089a053df99",
        "data/evaluation/public_documented_arm_secondary_masked_semantic_recovery_v1.json": "425cb9c29a2ce21114938e63d917e815f3aeef917395199d1e914ca6d86bc9e5",
        "data/public_cve/source/arm_cross_layer_seed_v1.source.json": "32a1f9782a2c966123f7f7bc141adb2d82a7ee8452705e06b1d4835e00f0e848",
        "data/public_cve/arm_cross_layer_seed_v1.json": "f8c79abadf98e2a6a36f5e85fc6701136ba44769c22b326a7a528f45cac63d14",
        "data/public_cve/evaluation/arm_secondary_v1.json": "ad4b500e004d5ccfce127df4ff918498a520485bc7891d5cb028e1837dcffa00",
        "data/evaluation/public_documented_arm_secondary_v1.json": "893944a10820ac91abd15ee176894e2caa9f1ac0c774b2ef9124b2e76c3f3ae7",
        "data/evaluation/public_documented_arm_secondary_knowledge_projection_v1.json": "c802a70e0554e0f7686f895fe8cec209ceb96220e51c7375fa07b46f3890e026",
    }
    for relative_path, digest in expected.items():
        assert _sha256(ROOT / relative_path) == digest
