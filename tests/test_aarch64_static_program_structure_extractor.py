"""Real angr tests for the plan-independent AArch64 structure extractor."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path
import runpy
from types import SimpleNamespace

import pytest

from chipchain.analysis import (
    AARCH64_STATIC_PROGRAM_STRUCTURE_EXTRACTOR_PROFILE_CFGFAST_V1,
    AArch64StaticProgramStructureBackendError,
    AngrAArch64StaticProgramStructureExtractor,
    AngrAArch64StaticSemanticDecoder,
    InvalidAnalysisInputError,
    ProgramArtifact,
    StaticProgramCfgSemantics,
    StaticProgramStructureInventory,
    StaticProgramStructureInventoryScope,
    StaticSemanticOperation,
    UnsupportedArtifactError,
)
from chipchain.analysis import (
    aarch64_static_program_structure_extractor as extractor_module,
)
from chipchain.models import Architecture


pytest.importorskip("angr")
pytestmark = pytest.mark.angr

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIRECTORY = (
    ROOT / "tests/fixtures/phase10d/aarch64_static_program_structure_v1"
)
FIXTURE = FIXTURE_DIRECTORY / "aarch64_static_program_structure_v1.elf"
EXPECTED_PATH = FIXTURE_DIRECTORY / "expected_static_structure.json"
GENERIC_FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/aarch64_generic_static_semantic_v1/"
    "aarch64_generic_static_semantic_v1.elf"
)
A77_FIXTURE = (
    ROOT
    / "tests/fixtures/phase10d/a_profile_static_semantic_a64/"
    "a_profile_static_semantic_a64.elf"
)
ARM32_FIXTURE = (
    ROOT
    / "tests/fixtures/phase9c/arm_a32_trigger_match/"
    "arm_a32_trigger_match.elf"
)
EXPECTED_FIXTURE_SHA256 = (
    "7af2a0422f7d8dcd8e5d506692ea1516284199284d2baa4fa19ac021e5b00cec"
)
EXPECTED_INVENTORY_ID = (
    "static-program-structure-inventory:"
    "7c97b813bf68d6e7aac8d8512f27e48d097b36752db8209f5954bf20e118942c"
)


def _artifact(
    *,
    path: Path | None = FIXTURE,
    architecture: Architecture = Architecture.ARM,
    artifact_type: str = "elf",
    artifact_id: str = "owned-synthetic-aarch64-static-program-structure-v1",
) -> ProgramArtifact:
    return ProgramArtifact(
        id=artifact_id,
        architecture=architecture,
        artifact_type=artifact_type,
        path=None if path is None else str(path),
        fixture_identifier="phase10d-aarch64-static-program-structure-v1",
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )


@pytest.fixture(scope="module")
def expected() -> dict[str, object]:
    return json.loads(EXPECTED_PATH.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def inventory() -> StaticProgramStructureInventory:
    return AngrAArch64StaticProgramStructureExtractor().extract(_artifact())


def _structure(inventory: StaticProgramStructureInventory) -> list[dict]:
    return [
        {
            "function_name": function.function_name,
            "function_address": function.function_address,
            "basic_block_addresses": function.basic_block_addresses,
            "directed_edges": [
                [
                    edge.source_basic_block_address,
                    edge.target_basic_block_address,
                ]
                for edge in function.directed_edges
            ],
        }
        for function in inventory.functions
    ]


def _fake_analysis(
    *,
    functions: list[SimpleNamespace],
    blocks: dict[int, SimpleNamespace],
    symbols: list[SimpleNamespace] | None = None,
) -> tuple[SimpleNamespace, SimpleNamespace]:
    executable_section = SimpleNamespace(is_executable=True)
    non_executable_section = SimpleNamespace(is_executable=False)

    def section(address: int):
        if 0x1000 <= address < 0x1100:
            return executable_section
        if 0x1100 <= address < 0x2000:
            return non_executable_section
        return None

    main_object = SimpleNamespace(
        symbols=[] if symbols is None else symbols,
        contains_addr=lambda address: 0x1000 <= address < 0x2000,
        find_section_containing=section,
        find_segment_containing=lambda _address: None,
    )

    def block(address: int):
        value = blocks.get(address)
        if value is None:
            raise RuntimeError("owned missing fake block")
        return value

    project = SimpleNamespace(
        loader=SimpleNamespace(main_object=main_object),
        factory=SimpleNamespace(block=block),
    )
    cfg = SimpleNamespace(
        kb=SimpleNamespace(
            functions={function.addr: function for function in functions}
        )
    )
    return project, cfg


def _fake_function(
    address: int,
    blocks: set[int],
    edges: list[tuple[int, int]],
    *,
    is_simprocedure: bool = False,
    is_plt: bool = False,
) -> SimpleNamespace:
    graph_edges = [
        (SimpleNamespace(addr=source), SimpleNamespace(addr=target))
        for source, target in edges
    ]
    return SimpleNamespace(
        addr=address,
        is_simprocedure=is_simprocedure,
        is_plt=is_plt,
        block_addrs_set=blocks,
        graph=SimpleNamespace(edges=lambda: graph_edges),
    )


def _extract_fake(
    project: SimpleNamespace,
    cfg: SimpleNamespace,
) -> list:
    return AngrAArch64StaticProgramStructureExtractor()._extract_functions(
        artifact=_artifact(),
        artifact_sha256="a" * 64,
        project=project,
        cfg=cfg,
    )


def test_final_api_accepts_only_one_program_artifact() -> None:
    signature = inspect.signature(
        AngrAArch64StaticProgramStructureExtractor.extract
    )

    assert list(signature.parameters) == ["self", "artifact"]
    assert signature.parameters["artifact"].annotation == "ProgramArtifact"
    assert signature.return_annotation == "StaticProgramStructureInventory"


def test_profile_and_inventory_contract_are_exact(
    inventory: StaticProgramStructureInventory,
) -> None:
    assert AARCH64_STATIC_PROGRAM_STRUCTURE_EXTRACTOR_PROFILE_CFGFAST_V1 == (
        "phase10d_aarch64_static_program_structure_extractor_cfgfast_v1"
    )
    assert type(inventory) is StaticProgramStructureInventory
    assert inventory.architecture is Architecture.ARM
    assert inventory.instruction_set == "aarch64"
    assert inventory.analyzer_profile_id == (
        AARCH64_STATIC_PROGRAM_STRUCTURE_EXTRACTOR_PROFILE_CFGFAST_V1
    )
    assert inventory.analysis_scope is (
        StaticProgramStructureInventoryScope
        .PARTIAL_OBJECTIVE_FUNCTION_LOCAL_CFG_INVENTORY
    )
    assert all(
        function.cfg_semantics
        is StaticProgramCfgSemantics
        .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
        for function in inventory.functions
    )


def test_owned_fixture_is_byte_deterministic_and_auditable(
    expected: dict[str, object],
) -> None:
    digest, filename = (FIXTURE_DIRECTORY / "SHA256SUMS").read_text(
        encoding="ascii"
    ).split()
    namespace = runpy.run_path(str(FIXTURE_DIRECTORY / "generate_fixture.py"))
    generated, generated_expected = namespace["build_elf"]()
    expected_without_hash = dict(expected)
    expected_without_hash.pop("artifact_sha256")

    assert filename == FIXTURE.name
    assert digest == EXPECTED_FIXTURE_SHA256
    assert hashlib.sha256(FIXTURE.read_bytes()).hexdigest() == digest
    assert generated == FIXTURE.read_bytes()
    assert generated_expected == expected_without_hash
    assert expected["fixture_classification"] == {
        "owned": True,
        "synthetic": True,
        "real_vulnerability": False,
        "runtime_execution_evidence": False,
    }
    assert not (FIXTURE_DIRECTORY / "ground_truth.json").exists()


def test_owned_fixture_matches_exact_designed_structure(
    inventory: StaticProgramStructureInventory,
    expected: dict[str, object],
) -> None:
    assert inventory.artifact_sha256 == expected["artifact_sha256"]
    assert inventory.id == expected["expected_inventory_id"]
    assert inventory.id == EXPECTED_INVENTORY_ID
    assert _structure(inventory) == expected["expected_functions"]
    assert inventory.diagnostic_codes == expected["expected_diagnostic_codes"]
    assert not any(
        "0x401000" in function.basic_block_addresses
        for function in inventory.functions
    )


def test_generic_semantic_and_structure_sources_bind_exact_same_artifact() -> None:
    artifact = _artifact(
        path=GENERIC_FIXTURE,
        artifact_id="owned-synthetic-generic-aarch64-v1",
    )
    semantic = AngrAArch64StaticSemanticDecoder().decode(artifact)
    structure = AngrAArch64StaticProgramStructureExtractor().extract(artifact)

    assert (
        semantic.architecture,
        semantic.artifact_id,
        semantic.artifact_sha256,
        semantic.instruction_set,
    ) == (
        structure.architecture,
        structure.artifact_id,
        structure.artifact_sha256,
        structure.instruction_set,
    )
    assert _structure(structure) == [
        {
            "function_name": "owned_generic_semantic_inventory",
            "function_address": "0x400000",
            "basic_block_addresses": ["0x400000"],
            "directed_edges": [],
        }
    ]


def test_eret_semantic_fallback_does_not_fabricate_structure() -> None:
    artifact = _artifact(
        path=GENERIC_FIXTURE,
        artifact_id="owned-synthetic-generic-aarch64-v1",
    )
    semantic = AngrAArch64StaticSemanticDecoder().decode(artifact)
    structure = AngrAArch64StaticProgramStructureExtractor().extract(artifact)
    eret = next(
        fact
        for fact in semantic.facts
        if fact.operation is StaticSemanticOperation.EXCEPTION_RETURN
    )

    assert eret.function_address == "0x400034"
    assert eret.basic_block_address is None
    assert not any(
        function.function_address == eret.function_address
        for function in structure.functions
    )
    assert not any(
        eret.instruction_address in function.basic_block_addresses
        for function in structure.functions
    )


def test_a77_fixture_uses_generic_plan_independent_profile() -> None:
    artifact = _artifact(
        path=A77_FIXTURE,
        artifact_id="owned-synthetic-a77-static-program-structure-v1",
    )
    inventory = AngrAArch64StaticProgramStructureExtractor().extract(artifact)

    assert inventory.artifact_sha256 == (
        "eacca62d264164cfb8970fd09d0df9c7bc548fbe04f7ee505001c9b594087c69"
    )
    assert inventory.analyzer_profile_id == (
        AARCH64_STATIC_PROGRAM_STRUCTURE_EXTRACTOR_PROFILE_CFGFAST_V1
    )
    assert inventory.instruction_set == "aarch64"
    assert _structure(inventory) == [
        {
            "function_name": name,
            "function_address": address,
            "basic_block_addresses": [address],
            "directed_edges": [],
        }
        for name, address in (
            ("owned_load_example", "0x400000"),
            ("owned_store_exclusive_example", "0x400008"),
            ("owned_par_el1_read_example", "0x400010"),
            ("owned_near_miss_examples", "0x400018"),
        )
    ]
    field_names = {
        name.lower()
        for model in (inventory, *inventory.functions)
        for name in type(model).model_fields
    }
    assert not any(
        fragment in name
        for name in field_names
        for fragment in ("a77", "cve", "pattern")
    )


@pytest.mark.parametrize(
    ("path", "artifact_id"),
    [
        (FIXTURE, "owned-synthetic-aarch64-static-program-structure-v1"),
        (GENERIC_FIXTURE, "owned-synthetic-generic-aarch64-v1"),
        (A77_FIXTURE, "owned-synthetic-a77-static-program-structure-v1"),
    ],
)
def test_ten_repeated_extractions_are_byte_deterministic(
    path: Path,
    artifact_id: str,
) -> None:
    artifact = _artifact(path=path, artifact_id=artifact_id)
    results = [
        AngrAArch64StaticProgramStructureExtractor().extract(artifact)
        for _ in range(10)
    ]

    assert len({item.id for item in results}) == 1
    assert len(
        {
            hashlib.sha256(item.model_dump_json().encode("utf-8")).hexdigest()
            for item in results
        }
    ) == 1


def test_artifact_sha_is_derived_from_bytes_not_metadata() -> None:
    artifact = _artifact()
    artifact.metadata["artifact_sha256"] = "0" * 64

    inventory = AngrAArch64StaticProgramStructureExtractor().extract(artifact)

    assert inventory.artifact_sha256 == EXPECTED_FIXTURE_SHA256
    assert inventory.artifact_sha256 != artifact.metadata["artifact_sha256"]


def test_input_is_detached_before_analysis() -> None:
    artifact = _artifact()
    snapshot, path = (
        AngrAArch64StaticProgramStructureExtractor()._validate_input(artifact)
    )
    artifact.metadata["owned"] = False

    assert path == FIXTURE
    assert snapshot is not artifact
    assert snapshot.metadata["owned"] is True


@pytest.mark.parametrize(
    ("artifact", "error", "message"),
    [
        (
            _artifact(architecture=Architecture.RISC_V),
            UnsupportedArtifactError,
            "ARM artifacts only",
        ),
        (
            _artifact(artifact_type="raw"),
            UnsupportedArtifactError,
            "ELF artifacts only",
        ),
        (
            _artifact(path=None),
            InvalidAnalysisInputError,
            "requires an artifact path",
        ),
        (
            _artifact(path=ROOT / "tests/fixtures/does-not-exist.elf"),
            InvalidAnalysisInputError,
            "not a regular file",
        ),
    ],
)
def test_unsupported_or_missing_inputs_fail_closed(
    artifact: ProgramArtifact,
    error: type[Exception],
    message: str,
) -> None:
    with pytest.raises(error, match=message):
        AngrAArch64StaticProgramStructureExtractor().extract(artifact)


def test_non_model_input_is_invalid() -> None:
    with pytest.raises(InvalidAnalysisInputError, match="detached artifact"):
        AngrAArch64StaticProgramStructureExtractor().extract(object())  # type: ignore[arg-type]


def test_arm32_elf_is_rejected_after_backend_architecture_detection() -> None:
    with pytest.raises(UnsupportedArtifactError, match="not AArch64"):
        AngrAArch64StaticProgramStructureExtractor().extract(
            _artifact(path=ARM32_FIXTURE)
        )


def test_missing_optional_backend_has_stable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_angr(name: str):
        assert name == "angr"
        raise ImportError("owned test backend absence")

    monkeypatch.setattr(
        extractor_module.importlib,
        "import_module",
        reject_angr,
    )
    with pytest.raises(
        AArch64StaticProgramStructureBackendError,
        match="optional",
    ):
        AngrAArch64StaticProgramStructureExtractor().extract(_artifact())


def test_project_load_failure_is_invalid_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_angr = SimpleNamespace(
        Project=lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("owned project load failure")
        )
    )
    extractor = AngrAArch64StaticProgramStructureExtractor()
    monkeypatch.setattr(extractor, "_load_backend", lambda: fake_angr)

    with pytest.raises(InvalidAnalysisInputError, match="could not load"):
        extractor.extract(_artifact())


def test_cfg_backend_failure_has_stable_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    project = SimpleNamespace(
        arch=SimpleNamespace(name="AARCH64", bits=64),
        analyses=SimpleNamespace(
            CFGFast=lambda **_values: (_ for _ in ()).throw(
                RuntimeError("owned CFG failure")
            )
        ),
    )
    fake_angr = SimpleNamespace(Project=lambda *_args, **_kwargs: project)
    extractor = AngrAArch64StaticProgramStructureExtractor()
    monkeypatch.setattr(extractor, "_load_backend", lambda: fake_angr)

    with pytest.raises(
        AArch64StaticProgramStructureBackendError,
        match="structure analysis failed",
    ):
        extractor.extract(_artifact())


def test_artifact_mutation_during_analysis_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extractor = AngrAArch64StaticProgramStructureExtractor()
    exact = FIXTURE.read_bytes()
    snapshots = iter((exact, exact + b"changed"))
    monkeypatch.setattr(
        extractor,
        "_read_artifact_bytes",
        lambda _path: next(snapshots),
    )

    with pytest.raises(InvalidAnalysisInputError, match="changed"):
        extractor.extract(_artifact())


def test_function_selection_and_block_filtering_are_fail_closed() -> None:
    eligible = _fake_function(0x1000, {0x1000}, [])
    external = _fake_function(0x3000, {0x3000}, [])
    simprocedure = _fake_function(
        0x1010, {0x1010}, [], is_simprocedure=True
    )
    plt = _fake_function(0x1020, {0x1020}, [], is_plt=True)
    non_executable = _fake_function(0x1200, {0x1200}, [])
    crossing = _fake_function(0x10FC, {0x10FC}, [])
    project, cfg = _fake_analysis(
        functions=[
            external,
            plt,
            crossing,
            eligible,
            non_executable,
            simprocedure,
        ],
        blocks={
            0x1000: SimpleNamespace(addr=0x1000, size=4),
            0x10FC: SimpleNamespace(addr=0x10FC, size=8),
            0x1200: SimpleNamespace(addr=0x1200, size=4),
        },
    )

    functions = _extract_fake(project, cfg)

    assert [item.function_address for item in functions] == ["0x1000"]
    assert functions[0].function_name is None


def test_block_materialization_failure_is_backend_error() -> None:
    function = _fake_function(0x1000, {0x1000}, [])
    project, cfg = _fake_analysis(functions=[function], blocks={})

    with pytest.raises(
        AArch64StaticProgramStructureBackendError,
        match="materialize",
    ):
        _extract_fake(project, cfg)


def test_edges_are_local_deduplicated_and_preserve_self_loop() -> None:
    function = _fake_function(
        0x1000,
        {0x1000, 0x1004},
        [
            (0x1000, 0x1004),
            (0x1000, 0x1004),
            (0x1004, 0x1004),
            (0x1004, 0x3000),
        ],
    )
    project, cfg = _fake_analysis(
        functions=[function],
        blocks={
            0x1000: SimpleNamespace(addr=0x1000, size=4),
            0x1004: SimpleNamespace(addr=0x1004, size=4),
        },
    )

    extracted = _extract_fake(project, cfg)[0]

    assert [
        (
            edge.source_basic_block_address,
            edge.target_basic_block_address,
        )
        for edge in extracted.directed_edges
    ] == [("0x1000", "0x1004"), ("0x1004", "0x1004")]


def test_symbol_names_are_objective_and_aliases_fail_to_none() -> None:
    functions = [
        _fake_function(0x1000, {0x1000}, []),
        _fake_function(0x1004, {0x1004}, []),
    ]
    symbols = [
        SimpleNamespace(
            is_function=True,
            name="owned_alias_a",
            rebased_addr=0x1000,
        ),
        SimpleNamespace(
            is_function=True,
            name="owned_alias_b",
            rebased_addr=0x1000,
        ),
    ]
    project, cfg = _fake_analysis(
        functions=functions,
        blocks={
            0x1000: SimpleNamespace(addr=0x1000, size=4),
            0x1004: SimpleNamespace(addr=0x1004, size=4),
        },
        symbols=symbols,
    )

    extracted = _extract_fake(project, cfg)

    assert [item.function_name for item in extracted] == [None, None]


def test_production_dependency_firewall_and_lazy_angr_import() -> None:
    path = (
        ROOT
        / "src/chipchain/analysis/"
        "aarch64_static_program_structure_extractor.py"
    )
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    forbidden_modules = (
        "chipchain.hardware_trigger",
        "chipchain.knowledge",
        "chipchain.reasoning",
        "chipchain.runtime",
        "chipchain.verification",
        "chipchain.multi_agent",
        "chipchain.analysis.aarch64_static_semantic_decoder",
        "angr",
        "capstone",
    )

    assert not any(
        name == forbidden or name.startswith(f"{forbidden}.")
        for name in imported
        for forbidden in forbidden_modules
    )
    lowered = source.lower()
    for forbidden in (
        "cve",
        "erratum",
        "predicate",
        "attackchain",
        "crosslayerinteraction",
    ):
        assert forbidden not in lowered
