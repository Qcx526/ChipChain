"""Phase 10D Step 8B-2B2-C1 pure static case-order contract tests."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path

import pytest
from pydantic import ValidationError

from chipchain.hardware_trigger import (
    PHASE10D_A_PROFILE_STATIC_CASE_ASSEMBLY_RESULT_CONTRACT,
    PHASE10D_A_PROFILE_STATIC_CASE_ORDER_CANDIDATE_CONTRACT,
    PHASE10D_A_PROFILE_STATIC_FUNCTION_CFG_CONTRACT,
    AProfileStaticCaseAssemblyResult,
    AProfileStaticCaseOrderCandidate,
    AProfileStaticCfgEdge,
    AProfileStaticFunctionCfgSnapshot,
    AProfileStaticInstructionSetState,
    AProfileStaticPredicateCandidate,
    AProfileStaticSemanticExtractionPlan,
    AProfileStaticSemanticExtractionResult,
    AProfileStaticSemanticInstructionFact,
    AProfileSystemRegister,
    ArmExecutionMode,
    HardwareTriggerSignature,
    RemainingObjectiveObligation,
    StaticCaseOrderBasis,
    StaticCaseOrderSemantics,
    StaticCfgScope,
    StaticCfgSemantics,
    StaticEffectiveMemoryTypeResolution,
    StaticFactScope,
    StaticPathWitnessUse,
    a_profile_static_case_order_candidate_id,
    a_profile_static_function_cfg_id,
    assemble_static_case_order_candidates,
)
from chipchain.hardware_trigger.a_profile_semantic_models import (
    AProfileSemanticEventKind,
)
from chipchain.models import Architecture


ROOT = Path(__file__).resolve().parents[1]
PLAN_PATH = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_static_semantic_extraction_plan_v1.json"
)
FIXTURE_DIR = ROOT / "tests/fixtures/phase10d/a_profile_static_semantic_a64"
A32_SIGNATURE = (
    ROOT
    / "tests/fixtures/phase9c/arm_a32_trigger_runtime/"
    "hardware_trigger_signature.json"
)
EXPECTED_A32_SIGNATURE_ID = (
    "hardware-trigger-signature:"
    "6c40f20a04baf56570c4f2994f1859e4b4012371300c78b43143829d16bd26ba"
)


@pytest.fixture(scope="module")
def plan() -> AProfileStaticSemanticExtractionPlan:
    return AProfileStaticSemanticExtractionPlan.model_validate_json(
        PLAN_PATH.read_bytes()
    )


def _entry(plan, case_id, position, kind):
    return next(
        item
        for item in plan.predicate_entries
        if (item.case_id, item.position_index, item.event_kind)
        == (case_id, position, kind)
    )


def _fact(
    *,
    kind: AProfileSemanticEventKind,
    address: str,
    block: str,
    function: str = "0x0000000000401000",
    function_name: str = "owned_toy_function",
    artifact_id: str = "artifact:owned-synthetic-static-case",
    artifact_sha256: str = "a" * 64,
) -> AProfileStaticSemanticInstructionFact:
    is_load = kind is AProfileSemanticEventKind.MEMORY_LOAD
    is_par = kind is AProfileSemanticEventKind.SYSTEM_REGISTER_READ
    words = {
        AProfileSemanticEventKind.MEMORY_LOAD: "0xf9400020",
        AProfileSemanticEventKind.STORE_EXCLUSIVE: "0xc8007c41",
        AProfileSemanticEventKind.SYSTEM_REGISTER_READ: "0xd5387400",
    }
    return AProfileStaticSemanticInstructionFact.create(
        artifact_id=artifact_id,
        artifact_sha256=artifact_sha256,
        architecture=Architecture.ARM,
        architecture_profile="a_profile",
        instruction_set_state=AProfileStaticInstructionSetState.AARCH64,
        instruction_address=address,
        instruction_word=words[kind],
        instruction_size=4,
        basic_block_address=block,
        function_address=function,
        function_name=function_name,
        event_kind=kind,
        system_register=AProfileSystemRegister.PAR_EL1 if is_par else None,
        memory_type_resolution=(
            StaticEffectiveMemoryTypeResolution.REQUIRES_OBJECTIVE_TRANSLATION_CONTEXT
            if is_load
            else StaticEffectiveMemoryTypeResolution.NOT_APPLICABLE
        ),
        static_fact_scope=(
            StaticFactScope.DECODED_ARTIFACT_INSTRUCTION_SEMANTICS_ONLY
        ),
    )


def _candidate(plan, fact, case_id, position):
    return AProfileStaticPredicateCandidate.create(
        extraction_plan=plan,
        predicate_entry=_entry(plan, case_id, position, fact.event_kind),
        static_instruction_fact=fact,
    )


def _result(plan, facts, bindings, *, artifact_id=None, artifact_sha256=None):
    candidates = [
        _candidate(plan, fact, case_id, position)
        for fact, case_id, position in bindings
    ]
    first = facts[0]
    return AProfileStaticSemanticExtractionResult.create(
        artifact_id=artifact_id or first.artifact_id,
        artifact_sha256=artifact_sha256 or first.artifact_sha256,
        extraction_plan=plan,
        instruction_facts=facts,
        predicate_candidates=candidates,
    )


def _case_a_result(
    plan,
    *,
    first_address="0x0000000000401110",
    second_address="0x0000000000401120",
    first_block="0x0000000000401100",
    second_block="0x0000000000401100",
    first_function="0x0000000000401000",
    second_function="0x0000000000401000",
):
    first = _fact(
        kind=AProfileSemanticEventKind.STORE_EXCLUSIVE,
        address=first_address,
        block=first_block,
        function=first_function,
    )
    second = _fact(
        kind=AProfileSemanticEventKind.MEMORY_LOAD,
        address=second_address,
        block=second_block,
        function=second_function,
    )
    return _result(
        plan,
        [first, second],
        [(first, "case_a", 1), (second, "case_a", 2)],
    )


def _cfg(result, blocks, edges=(), *, function="0x0000000000401000"):
    return AProfileStaticFunctionCfgSnapshot.create(
        extraction_result=result,
        function_address=function,
        function_name="owned_toy_function",
        basic_block_addresses=list(blocks),
        directed_edges=[
            AProfileStaticCfgEdge(
                source_basic_block_address=source,
                target_basic_block_address=target,
            )
            for source, target in edges
        ],
    )


def _assemble_case_a(plan, *, first_address, second_address, blocks, edges=()):
    result = _case_a_result(
        plan,
        first_address=first_address,
        second_address=second_address,
        first_block=blocks[0],
        second_block=blocks[-1],
    )
    snapshot = _cfg(result, blocks, edges)
    return result, snapshot, assemble_static_case_order_candidates(
        result, [snapshot]
    )


def _recompute_case_candidate_id(payload):
    payload["id"] = a_profile_static_case_order_candidate_id(
        {key: value for key, value in payload.items() if key != "id"}
    )


def _retarget_nested_cfg(payload, extraction_result_id):
    cfg_payload = payload["function_cfg_snapshot"]
    cfg_payload["extraction_result_id"] = extraction_result_id
    cfg_payload["id"] = a_profile_static_function_cfg_id(
        {key: value for key, value in cfg_payload.items() if key != "id"}
    )
    payload["function_cfg_snapshot_id"] = cfg_payload["id"]
    payload["order_witness"]["function_cfg_snapshot_id"] = cfg_payload["id"]


def test_exact_contract_versions_and_closed_semantic_enums() -> None:
    assert PHASE10D_A_PROFILE_STATIC_FUNCTION_CFG_CONTRACT == (
        "phase10d_a_profile_static_function_cfg_v1"
    )
    assert PHASE10D_A_PROFILE_STATIC_CASE_ORDER_CANDIDATE_CONTRACT == (
        "phase10d_a_profile_static_case_order_candidate_v1"
    )
    assert PHASE10D_A_PROFILE_STATIC_CASE_ASSEMBLY_RESULT_CONTRACT == (
        "phase10d_a_profile_static_case_assembly_result_v1"
    )
    assert list(StaticCfgScope) == [
        StaticCfgScope.FUNCTION_LOCAL_MAIN_OBJECT_EXECUTABLE_CFG
    ]
    assert list(StaticCfgSemantics) == [
        StaticCfgSemantics.FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
    ]
    assert list(StaticCaseOrderBasis) == [
        StaticCaseOrderBasis.SAME_BASIC_BLOCK_INSTRUCTION_ORDER,
        StaticCaseOrderBasis.DIRECTED_FUNCTION_CFG_PATH,
    ]


def test_cfg_snapshot_normalizes_nodes_edges_and_id_deterministically(plan) -> None:
    result = _case_a_result(plan)
    blocks = ["0x0000000000401200", "0x0000000000401100"]
    edges = [
        ("0x0000000000401200", "0x0000000000401200"),
        ("0x0000000000401100", "0x0000000000401200"),
    ]
    first = _cfg(result, blocks, edges)
    second = _cfg(result, list(reversed(blocks)), list(reversed(edges)))
    assert first == second
    assert first.id == second.id
    assert first.basic_block_addresses == sorted(blocks)
    assert first.scope is StaticCfgScope.FUNCTION_LOCAL_MAIN_OBJECT_EXECUTABLE_CFG
    assert first.function_address == "0x0000000000401000"


def test_cfg_addresses_are_canonical_and_invalid_width_is_rejected(plan) -> None:
    result = _case_a_result(plan)
    snapshot = _cfg(result, ["0x000000000040ABCD"])
    assert snapshot.basic_block_addresses == ["0x000000000040abcd"]
    with pytest.raises(ValidationError, match="exactly 16"):
        _cfg(result, ["0x0040abcd"])


def test_duplicate_cfg_nodes_edges_and_foreign_endpoints_fail_closed(plan) -> None:
    result = _case_a_result(plan)
    block = "0x0000000000401100"
    with pytest.raises(ValidationError, match="addresses must be unique"):
        _cfg(result, [block, block])
    with pytest.raises(ValidationError, match="edges must be unique"):
        _cfg(result, [block], [(block, block), (block, block)])
    with pytest.raises(ValidationError, match="outside basic-block"):
        _cfg(result, [block], [(block, "0x0000000000401200")])


def test_same_block_forward_order_creates_exact_static_candidate(plan) -> None:
    result, snapshot, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401120",
        blocks=["0x0000000000401100"],
    )
    assert len(assembly.case_order_candidates) == 1
    candidate = assembly.case_order_candidates[0]
    assert candidate.order_semantics is (
        StaticCaseOrderSemantics.STATIC_CFG_ORDER_COMPATIBLE
    )
    assert candidate.order_witness.order_basis is (
        StaticCaseOrderBasis.SAME_BASIC_BLOCK_INSTRUCTION_ORDER
    )
    assert candidate.order_witness.witness_basic_block_path == [
        "0x0000000000401100"
    ]
    assert candidate.order_witness.path_witness_use is (
        StaticPathWitnessUse.REACHABILITY_AUDIT_ONLY
    )
    assert candidate.function_cfg_snapshot == snapshot
    assert candidate.source_extraction_result_id == result.id
    assert candidate.contract == (
        PHASE10D_A_PROFILE_STATIC_CASE_ORDER_CANDIDATE_CONTRACT
    )
    assert assembly.contract == (
        PHASE10D_A_PROFILE_STATIC_CASE_ASSEMBLY_RESULT_CONTRACT
    )


def test_positive_candidate_and_result_ids_are_deterministic(plan) -> None:
    result = _case_a_result(plan)
    first_cfg = _cfg(result, ["0x0000000000401100"])
    second_cfg = _cfg(result, ["0x0000000000401100"])
    first = assemble_static_case_order_candidates(result, [first_cfg])
    second = assemble_static_case_order_candidates(result, [second_cfg])

    assert first.case_order_candidates[0].id == (
        second.case_order_candidates[0].id
    )
    assert first.id == second.id
    with pytest.raises(ValidationError, match="unique IDs"):
        AProfileStaticCaseAssemblyResult.create(
            extraction_result=result,
            function_cfg_snapshots=[first_cfg, first_cfg],
            case_order_candidates=[],
        )
    with pytest.raises(ValidationError, match="unique IDs"):
        AProfileStaticCaseAssemblyResult.create(
            extraction_result=result,
            function_cfg_snapshots=[first_cfg],
            case_order_candidates=[
                first.case_order_candidates[0],
                first.case_order_candidates[0],
            ],
        )


@pytest.mark.parametrize(
    ("first_address", "second_address"),
    [
        ("0x0000000000401130", "0x0000000000401120"),
        ("0x0000000000401120", "0x0000000000401120"),
    ],
)
def test_same_block_reverse_or_equal_address_produces_no_candidate(
    plan, first_address, second_address
) -> None:
    _, _, assembly = _assemble_case_a(
        plan,
        first_address=first_address,
        second_address=second_address,
        blocks=["0x0000000000401100"],
    )
    assert assembly.case_order_candidates == []


def test_cross_block_directed_reachability_creates_candidate(plan) -> None:
    _, _, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401210",
        blocks=["0x0000000000401100", "0x0000000000401200"],
        edges=[("0x0000000000401100", "0x0000000000401200")],
    )
    candidate = assembly.case_order_candidates[0]
    assert candidate.order_witness.order_basis is (
        StaticCaseOrderBasis.DIRECTED_FUNCTION_CFG_PATH
    )
    assert candidate.order_witness.witness_basic_block_path == [
        "0x0000000000401100",
        "0x0000000000401200",
    ]


@pytest.mark.parametrize(
    "edges",
    [
        [("0x0000000000401200", "0x0000000000401100")],
        [],
    ],
)
def test_reverse_only_or_disconnected_cfg_produces_no_candidate(plan, edges) -> None:
    _, _, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401210",
        blocks=["0x0000000000401100", "0x0000000000401200"],
        edges=edges,
    )
    assert assembly.case_order_candidates == []


def test_cycle_terminates_and_multi_path_witness_is_deterministic(plan) -> None:
    result = _case_a_result(
        plan,
        first_block="0x0000000000401100",
        second_block="0x0000000000401400",
    )
    blocks = [
        "0x0000000000401100",
        "0x0000000000401200",
        "0x0000000000401300",
        "0x0000000000401400",
    ]
    edges = [
        (blocks[0], blocks[2]),
        (blocks[2], blocks[0]),
        (blocks[2], blocks[3]),
        (blocks[0], blocks[1]),
        (blocks[1], blocks[3]),
    ]
    snapshot = _cfg(result, blocks, list(reversed(edges)))
    assembly = assemble_static_case_order_candidates(result, [snapshot])
    assert assembly.case_order_candidates[0].order_witness.witness_basic_block_path == [
        blocks[0],
        blocks[1],
        blocks[3],
    ]


def test_different_functions_do_not_create_case_candidate(plan) -> None:
    result = _case_a_result(
        plan,
        first_function="0x0000000000401000",
        second_function="0x0000000000402000",
        second_block="0x0000000000402100",
    )
    snapshots = [
        _cfg(result, ["0x0000000000401100"]),
        _cfg(
            result,
            ["0x0000000000402100"],
            function="0x0000000000402000",
        ),
    ]
    assert assemble_static_case_order_candidates(
        result, snapshots
    ).case_order_candidates == []


def test_cross_artifact_cfg_and_missing_fact_blocks_fail_closed(plan) -> None:
    result = _case_a_result(plan)
    foreign_facts = [
        _fact(
            kind=AProfileSemanticEventKind.MEMORY_LOAD,
            address="0x0000000000401120",
            block="0x0000000000401100",
            artifact_id="artifact:foreign",
            artifact_sha256="b" * 64,
        )
    ]
    foreign = _result(
        plan,
        foreign_facts,
        [(foreign_facts[0], "case_a", 2)],
    )
    with pytest.raises(ValueError, match="crosses extraction binding"):
        assemble_static_case_order_candidates(
            result, [_cfg(foreign, ["0x0000000000401100"])]
        )
    missing = _cfg(result, ["0x0000000000401300"])
    with pytest.raises(ValueError, match="position-1 block is missing"):
        assemble_static_case_order_candidates(result, [missing])


def test_case_id_is_authoritative_and_cross_case_pairing_is_forbidden(plan) -> None:
    store = _fact(
        kind=AProfileSemanticEventKind.STORE_EXCLUSIVE,
        address="0x0000000000401110",
        block="0x0000000000401100",
    )
    load = _fact(
        kind=AProfileSemanticEventKind.MEMORY_LOAD,
        address="0x0000000000401120",
        block="0x0000000000401100",
    )
    result = _result(
        plan,
        [store, load],
        [(store, "case_a", 1), (load, "case_b", 1)],
    )
    assembly = assemble_static_case_order_candidates(
        result, [_cfg(result, ["0x0000000000401100"])]
    )
    assert assembly.case_order_candidates == []


def test_standalone_candidate_binds_exact_snapshots_positions_and_ids(plan) -> None:
    result, _, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401120",
        blocks=["0x0000000000401100"],
    )
    candidate = assembly.case_order_candidates[0]
    assert candidate.position_1_fact_id == (
        candidate.position_1_fact_snapshot.id
    )
    assert candidate.position_2_fact_id == (
        candidate.position_2_fact_snapshot.id
    )
    assert candidate.position_1_candidate_snapshot.position_index == 1
    assert candidate.position_2_candidate_snapshot.position_index == 2
    assert AProfileStaticCaseOrderCandidate.model_validate_json(
        candidate.model_dump_json()
    ) == candidate
    payload = candidate.model_dump(mode="json")
    payload["position_1_fact_id"] = result.instruction_facts[1].id
    payload["id"] = a_profile_static_case_order_candidate_id(
        {key: value for key, value in payload.items() if key != "id"}
    )
    with pytest.raises(ValidationError, match="fact snapshot ID mismatch"):
        AProfileStaticCaseOrderCandidate.model_validate(payload)


def test_standalone_candidate_rejects_recomputed_fictional_result_retarget(
    plan,
) -> None:
    _, _, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401120",
        blocks=["0x0000000000401100"],
    )
    payload = assembly.case_order_candidates[0].model_dump(mode="json")
    fake_result_id = (
        "a-profile-static-semantic-extraction-result:" + "f" * 64
    )
    payload["source_extraction_result_id"] = fake_result_id
    _retarget_nested_cfg(payload, fake_result_id)
    _recompute_case_candidate_id(payload)

    with pytest.raises(ValidationError, match="source extraction-result ID"):
        AProfileStaticCaseOrderCandidate.model_validate(payload)


def test_standalone_candidate_rejects_foreign_extraction_without_members(plan) -> None:
    result, _, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401120",
        blocks=["0x0000000000401100"],
    )
    foreign = AProfileStaticSemanticExtractionResult.create(
        artifact_id=result.artifact_id,
        artifact_sha256=result.artifact_sha256,
        extraction_plan=plan,
        instruction_facts=[],
        predicate_candidates=[],
    )
    payload = assembly.case_order_candidates[0].model_dump(mode="json")
    payload["source_extraction_result_id"] = foreign.id
    payload["source_extraction_result_snapshot"] = foreign.model_dump(mode="json")
    _retarget_nested_cfg(payload, foreign.id)
    _recompute_case_candidate_id(payload)

    with pytest.raises(ValidationError, match="candidate is outside source"):
        AProfileStaticCaseOrderCandidate.model_validate(payload)


def test_standalone_candidate_rejects_foreign_candidate_snapshot(plan) -> None:
    result, _, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401120",
        blocks=["0x0000000000401100"],
    )
    foreign_fact = _fact(
        kind=AProfileSemanticEventKind.STORE_EXCLUSIVE,
        address="0x0000000000401114",
        block="0x0000000000401100",
    )
    foreign_candidate = _candidate(plan, foreign_fact, "case_a", 1)
    payload = assembly.case_order_candidates[0].model_dump(mode="json")
    payload["position_1_candidate_id"] = foreign_candidate.id
    payload["position_1_candidate_snapshot"] = foreign_candidate.model_dump(
        mode="json"
    )
    _recompute_case_candidate_id(payload)

    assert foreign_candidate.id not in {
        item.id for item in result.predicate_candidates
    }
    with pytest.raises(ValidationError, match="candidate is outside source"):
        AProfileStaticCaseOrderCandidate.model_validate(payload)


def test_standalone_candidate_rejects_foreign_fact_snapshot(plan) -> None:
    result, _, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401120",
        blocks=["0x0000000000401100"],
    )
    foreign_fact = _fact(
        kind=AProfileSemanticEventKind.STORE_EXCLUSIVE,
        address="0x0000000000401114",
        block="0x0000000000401100",
    )
    payload = assembly.case_order_candidates[0].model_dump(mode="json")
    payload["position_1_fact_id"] = foreign_fact.id
    payload["position_1_fact_snapshot"] = foreign_fact.model_dump(mode="json")
    payload["order_witness"]["position_1_fact_id"] = foreign_fact.id
    _recompute_case_candidate_id(payload)

    assert foreign_fact.id not in {item.id for item in result.instruction_facts}
    with pytest.raises(ValidationError, match="fact is outside source"):
        AProfileStaticCaseOrderCandidate.model_validate(payload)


def test_standalone_candidate_rejects_independently_retargeted_plan(plan) -> None:
    _, _, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401120",
        blocks=["0x0000000000401100"],
    )
    plan_values = plan.model_dump(mode="json", exclude={"id", "contract"})
    plan_values["processor"] = "owned-different-processor"
    foreign_plan = AProfileStaticSemanticExtractionPlan.create(**plan_values)
    payload = assembly.case_order_candidates[0].model_dump(mode="json")
    payload["extraction_plan_snapshot"] = foreign_plan.model_dump(mode="json")
    _recompute_case_candidate_id(payload)

    with pytest.raises(ValidationError, match="does not match source extraction"):
        AProfileStaticCaseOrderCandidate.model_validate(payload)


def test_assembly_independently_rejects_candidate_with_foreign_snapshot(plan) -> None:
    result, snapshot, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401120",
        blocks=["0x0000000000401100"],
    )
    foreign = AProfileStaticSemanticExtractionResult.create(
        artifact_id=result.artifact_id,
        artifact_sha256=result.artifact_sha256,
        extraction_plan=plan,
        instruction_facts=result.instruction_facts,
        predicate_candidates=result.predicate_candidates,
        diagnostic_codes=["alternate_neutral_provenance"],
    )
    payload = assembly.case_order_candidates[0].model_dump(mode="json")
    payload["source_extraction_result_id"] = foreign.id
    payload["source_extraction_result_snapshot"] = foreign.model_dump(mode="json")
    _retarget_nested_cfg(payload, foreign.id)
    _recompute_case_candidate_id(payload)
    foreign_candidate = AProfileStaticCaseOrderCandidate.model_validate(payload)

    with pytest.raises(ValidationError, match="snapshot differs from assembly"):
        AProfileStaticCaseAssemblyResult.create(
            extraction_result=result,
            function_cfg_snapshots=[snapshot],
            case_order_candidates=[foreign_candidate],
        )


def test_obligations_are_exact_union_and_none_are_discharged(plan) -> None:
    _, _, assembly = _assemble_case_a(
        plan,
        first_address="0x0000000000401110",
        second_address="0x0000000000401120",
        blocks=["0x0000000000401100"],
    )
    obligations = set(
        assembly.case_order_candidates[0].remaining_objective_obligations
    )
    assert RemainingObjectiveObligation.RUNTIME_EXECUTION_REQUIRED in obligations
    assert (
        RemainingObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
        in obligations
    )
    assert (
        RemainingObjectiveObligation.RELATION_PROXIMITY_REMAINS_UNRESOLVED
        in obligations
    )
    assert (
        RemainingObjectiveObligation.ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED
        in obligations
    )
    payload = assembly.case_order_candidates[0].model_dump(mode="json")
    payload["remaining_objective_obligations"].remove(
        RemainingObjectiveObligation.RELATION_PROXIMITY_REMAINS_UNRESOLVED.value
    )
    payload["id"] = a_profile_static_case_order_candidate_id(
        {key: value for key, value in payload.items() if key != "id"}
    )
    with pytest.raises(ValidationError, match="dropped source obligations"):
        AProfileStaticCaseOrderCandidate.model_validate(payload)


def test_par_case_retains_runtime_context_and_load_resolution(plan) -> None:
    par = _fact(
        kind=AProfileSemanticEventKind.SYSTEM_REGISTER_READ,
        address="0x0000000000401110",
        block="0x0000000000401100",
    )
    load = _fact(
        kind=AProfileSemanticEventKind.MEMORY_LOAD,
        address="0x0000000000401120",
        block="0x0000000000401100",
    )
    result = _result(
        plan,
        [par, load],
        [(par, "case_a", 1), (load, "case_a", 2)],
    )
    candidate = assemble_static_case_order_candidates(
        result, [_cfg(result, ["0x0000000000401100"])]
    ).case_order_candidates[0]
    obligations = set(candidate.remaining_objective_obligations)
    assert RemainingObjectiveObligation.RUNTIME_EXECUTION_CONTEXT_REQUIRED in obligations
    assert (
        RemainingObjectiveObligation.EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED
        in obligations
    )


def test_result_diagnostics_zero_candidates_and_ids_are_deterministic(plan) -> None:
    result = _case_a_result(
        plan,
        first_address="0x0000000000401130",
        second_address="0x0000000000401120",
    )
    snapshot = _cfg(result, ["0x0000000000401100"])
    first = assemble_static_case_order_candidates(result, [snapshot])
    second = assemble_static_case_order_candidates(result, [snapshot])
    assert first == second
    assert first.id == second.id
    assert first.case_order_candidates == []
    assert first.diagnostic_codes == [
        "directed_cfg_order_candidate_count:0",
        "function_cfg_snapshot_count:1",
        "same_block_order_candidate_count:0",
        "static_case_order_candidate_count:0",
    ]


def test_isolated_2b2b_semantic_facts_remain_zero_case(plan) -> None:
    load = _fact(
        kind=AProfileSemanticEventKind.MEMORY_LOAD,
        address="0x0000000000400000",
        block="0x0000000000400000",
        function="0x0000000000400000",
        function_name="owned_load_example",
    )
    store = _fact(
        kind=AProfileSemanticEventKind.STORE_EXCLUSIVE,
        address="0x0000000000400008",
        block="0x0000000000400008",
        function="0x0000000000400008",
        function_name="owned_store_exclusive_example",
    )
    par = _fact(
        kind=AProfileSemanticEventKind.SYSTEM_REGISTER_READ,
        address="0x0000000000400010",
        block="0x0000000000400010",
        function="0x0000000000400010",
        function_name="owned_par_el1_read_example",
    )
    result = _result(
        plan,
        [load, store, par],
        [
            (load, "case_a", 2),
            (load, "case_b", 1),
            (store, "case_a", 1),
            (store, "case_b", 2),
            (par, "case_a", 1),
            (par, "case_b", 2),
        ],
    )
    snapshots = [
        AProfileStaticFunctionCfgSnapshot.create(
            extraction_result=result,
            function_address=fact.function_address,
            function_name=fact.function_name,
            basic_block_addresses=[fact.basic_block_address],
            directed_edges=[],
        )
        for fact in (load, store, par)
    ]
    assert assemble_static_case_order_candidates(
        result, snapshots
    ).case_order_candidates == []


def test_contracts_have_no_runtime_proximity_or_verdict_surface(plan) -> None:
    result = _case_a_result(plan)
    snapshot = _cfg(result, ["0x0000000000401100"])
    assembly = assemble_static_case_order_candidates(result, [snapshot])
    forbidden = {
        "runtime_program_order",
        "program_order_satisfied",
        "symbolic_path_feasible",
        "proximity_satisfied",
        "instruction_distance",
        "cycle_distance",
        "effective_memory_type",
        "triggerability",
        "verification",
        "feasibility",
        "primary_ready",
    }
    for model_type in (
        AProfileStaticFunctionCfgSnapshot,
        AProfileStaticCaseOrderCandidate,
        AProfileStaticCaseAssemblyResult,
    ):
        assert forbidden.isdisjoint(model_type.model_fields)
    payload = assembly.model_dump(mode="json")
    payload["verification"] = "verified"
    with pytest.raises(ValidationError):
        AProfileStaticCaseAssemblyResult.model_validate(payload)


def test_new_production_modules_have_strict_backend_and_verdict_firewall() -> None:
    paths = [
        ROOT / "src/chipchain/hardware_trigger/a_profile_static_case_models.py",
        ROOT / "src/chipchain/hardware_trigger/a_profile_static_case.py",
    ]
    forbidden = (
        "angr",
        "capstone",
        "qemu",
        "chipchain.runtime",
        "ReasoningProvider",
        "GroundTruth",
        "Evidence",
        "VerificationRecord",
        "TriggerabilityStatus",
        "TriggerabilityAggregationResult",
        "ChainFeasibilityAssessment",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        ast.parse(text)
        assert all(item not in text for item in forbidden)


def test_frozen_2b2b_fixture_and_old_a32_identity_are_unchanged() -> None:
    digest, name = (FIXTURE_DIR / "SHA256SUMS").read_text(
        encoding="ascii"
    ).split()
    assert name == "a_profile_static_semantic_a64.elf"
    assert digest == hashlib.sha256(
        (FIXTURE_DIR / name).read_bytes()
    ).hexdigest()
    assert digest == "eacca62d264164cfb8970fd09d0df9c7bc548fbe04f7ee505001c9b594087c69"
    assert [item.value for item in ArmExecutionMode] == ["arm_a32"]
    signature = HardwareTriggerSignature.model_validate_json(
        A32_SIGNATURE.read_bytes()
    )
    assert signature.id == EXPECTED_A32_SIGNATURE_ID
