"""Real-angr and generic graph tests for the C2 AArch64 materializer."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from chipchain.analysis import ProgramArtifact
from chipchain.hardware_trigger import (
    AProfileStaticCaseMaterializationError,
    AProfileStaticSemanticExtractionError,
    AProfileStaticSemanticExtractionPlan,
    AngrAProfileStaticCaseMaterializer,
    AngrAProfileStaticSemanticExtractor,
    InvalidAProfileStaticCaseMaterializationInputError,
)
from chipchain.models import Architecture


angr = pytest.importorskip("angr")
nx = pytest.importorskip("networkx")
pytestmark = pytest.mark.angr

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/a_profile_static_semantic_a64/"
    "a_profile_static_semantic_a64.elf"
)
PLAN_PATH = (
    ROOT
    / "data/evaluation/"
    "cve_2023_34320_a_profile_static_semantic_extraction_plan_v1.json"
)
ARM32_FIXTURE = (
    ROOT
    / "tests/fixtures/phase9c/arm_a32_trigger_match/"
    "arm_a32_trigger_match.elf"
)
EXPECTED_SHA = "eacca62d264164cfb8970fd09d0df9c7bc548fbe04f7ee505001c9b594087c69"


@pytest.fixture(scope="module")
def plan():
    return AProfileStaticSemanticExtractionPlan.model_validate_json(
        PLAN_PATH.read_bytes()
    )


def _artifact(path=FIXTURE, *, artifact_type="elf"):
    return ProgramArtifact(
        id="owned-synthetic-a64-static-semantic-fixture",
        architecture=Architecture.ARM,
        artifact_type=artifact_type,
        path=None if path is None else str(path),
        fixture_identifier="phase10d-a-profile-static-semantic-a64",
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )


@pytest.fixture(scope="module")
def direct_result(plan):
    return AngrAProfileStaticSemanticExtractor().extract(_artifact(), plan)


@pytest.fixture(scope="module")
def result(plan):
    return AngrAProfileStaticCaseMaterializer().materialize(_artifact(), plan)


def test_real_binary_first_result_reuses_exact_semantic_snapshot(
    result, direct_result, plan
) -> None:
    assert result.source_extraction_result_snapshot == direct_result
    assert result.artifact_sha256 == EXPECTED_SHA
    assert result.extraction_plan_id == plan.id
    assert len(direct_result.instruction_facts) == 3
    assert len(direct_result.predicate_candidates) == 6
    assert len(result.function_cfg_snapshots) == 3
    assert result.case_order_candidates == []


def test_relevant_cfg_snapshots_are_complete_canonical_and_exact(result) -> None:
    referenced_fact_ids = {
        item.static_instruction_fact_id
        for item in result.source_extraction_result_snapshot.predicate_candidates
    }
    facts = {
        item.id: item
        for item in result.source_extraction_result_snapshot.instruction_facts
    }
    expected_functions = {
        facts[item].function_address for item in referenced_fact_ids
    }
    assert {item.function_address for item in result.function_cfg_snapshots} == (
        expected_functions
    )
    for snapshot in result.function_cfg_snapshots:
        assert snapshot.extraction_result_id == result.source_extraction_result_id
        assert snapshot.extraction_plan_id == result.extraction_plan_id
        assert snapshot.source_pattern_id == result.source_pattern_id
        assert all(len(address) == 18 for address in snapshot.basic_block_addresses)
        function_facts = [
            fact
            for fact in facts.values()
            if fact.function_address == snapshot.function_address
            and fact.id in referenced_fact_ids
        ]
        assert function_facts
        assert all(
            fact.basic_block_address in snapshot.basic_block_addresses
            for fact in function_facts
        )


def test_real_fixture_result_is_neutral_and_deterministic(result, plan) -> None:
    repeated = AngrAProfileStaticCaseMaterializer().materialize(
        _artifact(), plan
    )
    assert repeated == result
    assert repeated.id == result.id
    assert repeated.model_dump_json() == result.model_dump_json()
    assert result.diagnostic_codes == [
        "directed_cfg_order_candidate_count:0",
        "function_cfg_snapshot_count:3",
        "same_block_order_candidate_count:0",
        "static_case_order_candidate_count:0",
    ]


def test_c2_artifact_drift_fails_closed(monkeypatch, plan) -> None:
    materializer = AngrAProfileStaticCaseMaterializer()
    exact = FIXTURE.read_bytes()
    reads = iter((exact, exact + b"changed"))
    monkeypatch.setattr(
        materializer, "_read_artifact_bytes", lambda path: next(reads)
    )
    with pytest.raises(
        InvalidAProfileStaticCaseMaterializationInputError,
        match="changed during CFG",
    ):
        materializer.materialize(_artifact(), plan)


def test_arm32_malformed_type_and_missing_path_are_rejected(tmp_path, plan) -> None:
    materializer = AngrAProfileStaticCaseMaterializer()
    with pytest.raises(AProfileStaticSemanticExtractionError):
        materializer.materialize(_artifact(ARM32_FIXTURE), plan)
    malformed = tmp_path / "not-an-elf"
    malformed.write_bytes(b"owned malformed input")
    with pytest.raises(AProfileStaticSemanticExtractionError):
        materializer.materialize(_artifact(malformed), plan)
    with pytest.raises(AProfileStaticCaseMaterializationError):
        materializer.materialize(_artifact(artifact_type="raw"), plan)
    with pytest.raises(AProfileStaticCaseMaterializationError):
        materializer.materialize(_artifact(None), plan)


class _Node:
    def __init__(self, address):
        self.addr = address

    def __hash__(self):
        return id(self)


def _fake_project(*, executable_limit=0x1800):
    executable = SimpleNamespace(is_executable=True)
    non_executable = SimpleNamespace(is_executable=False)

    class Main:
        @staticmethod
        def contains_addr(address):
            return 0x1000 <= address < 0x2000

        @staticmethod
        def find_section_containing(address):
            if 0x1000 <= address < executable_limit:
                return executable
            if executable_limit <= address < 0x2000:
                return non_executable
            return None

        @staticmethod
        def find_segment_containing(address):
            return None

    return SimpleNamespace(
        loader=SimpleNamespace(main_object=Main()),
        factory=SimpleNamespace(
            block=lambda address: SimpleNamespace(addr=address, size=4)
        ),
    )


def test_generic_graph_normalization_branch_join_cycle_self_and_filtering() -> None:
    nodes = {
        address: _Node(address)
        for address in (
            0x1000,
            0x1100,
            0x1200,
            0x1300,
            0x1400,
            0x1800,
            0x3000,
        )
    }
    duplicate_1100 = _Node(0x1100)
    graph = nx.MultiDiGraph()
    graph.add_edges_from(
        [
            (nodes[0x1000], nodes[0x1100]),
            (nodes[0x1000], duplicate_1100),
            (nodes[0x1000], nodes[0x1100]),
            (nodes[0x1000], nodes[0x1200]),
            (nodes[0x1100], nodes[0x1300]),
            (nodes[0x1200], nodes[0x1300]),
            (nodes[0x1100], nodes[0x1000]),
            (nodes[0x1300], nodes[0x1300]),
            (nodes[0x1000], nodes[0x1800]),
            (nodes[0x1000], nodes[0x3000]),
            (nodes[0x1000], nodes[0x1400]),
        ]
    )
    function = SimpleNamespace(
        block_addrs_set=set(nodes) - {0x1400},
        graph=graph,
    )
    blocks, edges = AngrAProfileStaticCaseMaterializer()._normalize_function_graph(
        project=_fake_project(), function=function
    )
    assert blocks == [
        "0x0000000000001000",
        "0x0000000000001100",
        "0x0000000000001200",
        "0x0000000000001300",
    ]
    assert [
        (item.source_basic_block_address, item.target_basic_block_address)
        for item in edges
    ] == [
        ("0x0000000000001000", "0x0000000000001100"),
        ("0x0000000000001000", "0x0000000000001200"),
        ("0x0000000000001100", "0x0000000000001000"),
        ("0x0000000000001100", "0x0000000000001300"),
        ("0x0000000000001200", "0x0000000000001300"),
        ("0x0000000000001300", "0x0000000000001300"),
    ]


def test_exact_function_missing_fact_block_and_name_conflict_fail_closed(
    monkeypatch, direct_result
) -> None:
    materializer = AngrAProfileStaticCaseMaterializer()
    project = _fake_project(executable_limit=0x500000)
    empty_cfg = SimpleNamespace(kb=SimpleNamespace(functions={}))
    with pytest.raises(
        InvalidAProfileStaticCaseMaterializationInputError,
        match="exact relevant function is missing",
    ):
        materializer._materialize_relevant_function_cfgs(
            semantic_result=direct_result, project=project, cfg=empty_cfg
        )

    fact = direct_result.instruction_facts[0]
    conflicting = fact.model_copy(update={"function_name": "different_name"})
    monkeypatch.setattr(
        materializer,
        "_relevant_function_facts",
        lambda result: {fact.function_address: [fact, conflicting]},
    )
    with pytest.raises(
        InvalidAProfileStaticCaseMaterializationInputError,
        match="disagree on recovered function name",
    ):
        materializer._materialize_relevant_function_cfgs(
            semantic_result=direct_result, project=project, cfg=empty_cfg
        )

    monkeypatch.setattr(
        materializer,
        "_relevant_function_facts",
        lambda result: {fact.function_address: [fact]},
    )
    function = SimpleNamespace(
        addr=int(fact.function_address, 16),
        is_simprocedure=False,
        is_plt=False,
    )
    cfg = SimpleNamespace(
        kb=SimpleNamespace(
            functions={int(fact.function_address, 16): function}
        )
    )
    exact_project = SimpleNamespace(
        loader=SimpleNamespace(
            main_object=SimpleNamespace(contains_addr=lambda address: True)
        )
    )
    monkeypatch.setattr(
        materializer,
        "_normalize_function_graph",
        lambda **kwargs: (["0x0000000000001000"], []),
    )
    with pytest.raises(
        InvalidAProfileStaticCaseMaterializationInputError,
        match="fact block is missing",
    ):
        materializer._materialize_relevant_function_cfgs(
            semantic_result=direct_result, project=exact_project, cfg=cfg
        )


def test_production_source_has_genericity_and_semantic_branch_firewall() -> None:
    path = ROOT / "src/chipchain/hardware_trigger/a_profile_static_case_angr.py"
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text)
    forbidden = (
        "CVE-2023-34320",
        "cve_2023_34320",
        "1508412",
        "Cortex-A77",
        "cortex_a77",
        "case_a",
        "case_b",
        "AProfileSemanticEventKind",
        "PAR_EL1",
        "STORE_EXCLUSIVE",
        "MEMORY_LOAD",
        "system_register",
        "event_kind",
        "TriggerabilityAggregationResult",
        "VerificationRecord",
        "GroundTruth",
        "ReasoningProvider",
    )
    assert all(item not in text for item in forbidden)
    assert not any(
        isinstance(node, ast.ImportFrom)
        and node.module == "chipchain.hardware_trigger.a_profile_semantic_models"
        for node in ast.walk(tree)
    )
