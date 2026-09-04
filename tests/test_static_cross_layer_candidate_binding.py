"""Exact source-backed static cross-layer reference binding tests."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
from pathlib import Path

from pydantic import ValidationError
import pytest

from chipchain.analysis import (
    AngrAArch64StaticProgramStructureExtractor,
    AngrAArch64StaticSemanticDecoder,
    ProgramArtifact,
    StaticDocumentedErratumHardwareReference,
    StaticSemanticAttribute,
    StaticSemanticAttributeName,
    StaticSemanticOperation,
    StaticCrossLayerCandidateMaterialization,
    StaticCrossLayerCandidateObjectiveObligation,
    StaticCrossLayerCandidateProjection,
    StaticHardwareReferenceCatalog,
    StaticOwnedSyntheticHardwareReference,
    StaticTriggerCandidateMaterialization,
    StaticTriggerPattern,
    StaticTriggerPatternCatalog,
    StaticTriggerPosition,
    StaticTriggerPredicate,
    StaticTriggerCase,
    StaticUnresolvedHardwareReferenceReason,
    bind_static_trigger_candidates_to_hardware_references,
    fuse_static_semantic_and_program_structure,
    project_static_semantic_inventory,
    project_static_trigger_candidates,
    render_static_cross_layer_candidate_graph_dot,
    render_static_cross_layer_candidate_summary_markdown,
    static_cross_layer_candidate_binding_id,
    static_cross_layer_candidate_materialization_id,
    static_cross_layer_candidate_projection_id,
    static_hardware_reference_catalog_id,
    static_owned_synthetic_hardware_reference_id,
)
from chipchain.hardware_trigger.documented_erratum_models import (
    DocumentedHardwareErratumContract,
)
from chipchain.models import Architecture


pytest.importorskip("angr")

ROOT = Path(__file__).resolve().parents[1]
ELF = (
    ROOT / "tests/fixtures/phase10d/aarch64_static_fused_behavior_v1/"
    "aarch64_static_fused_behavior_v1.elf"
)
PATTERN = (
    ROOT / "tests/fixtures/phase10d/static_trigger_pattern_v1/"
    "owned_synthetic_static_trigger_pattern_v1.json"
)
ERRATUM = (
    ROOT / "data/evaluation/"
    "cve_2023_34320_documented_erratum_1508412_v1.json"
)


def _rehash(payload: dict, function) -> None:
    payload["id"] = function(
        {key: value for key, value in payload.items() if key != "id"}
    )


@pytest.fixture(scope="module")
def candidate_materialization() -> StaticTriggerCandidateMaterialization:
    artifact = ProgramArtifact(
        id="owned-synthetic-aarch64-static-fused-behavior-v1",
        architecture=Architecture.ARM,
        artifact_type="elf",
        path=str(ELF),
        fixture_identifier="phase10d-aarch64-static-fused-behavior-v1",
        metadata={"owned": True, "synthetic": True, "fixture": True},
    )
    semantic = AngrAArch64StaticSemanticDecoder().decode(artifact)
    graph = project_static_semantic_inventory(semantic)
    structure = AngrAArch64StaticProgramStructureExtractor().extract(artifact)
    fused = fuse_static_semantic_and_program_structure(graph, structure)
    pattern = StaticTriggerPattern.model_validate_json(PATTERN.read_bytes())
    return project_static_trigger_candidates(
        fused, StaticTriggerPatternCatalog.create(patterns=[pattern])
    )


def _reference(
    reference_id: str,
    *,
    architecture: Architecture = Architecture.ARM,
    title: str | None = None,
) -> StaticOwnedSyntheticHardwareReference:
    return StaticOwnedSyntheticHardwareReference.create(
        reference_id=reference_id,
        architecture=architecture,
        title=title or f"{reference_id} reference",
        source_reference_ids=["owned-synthetic-reference-design-v1"],
    )


def _catalog(
    candidates: StaticTriggerCandidateMaterialization,
    *,
    selected_ids: list[str] | None = None,
    architecture_by_id: dict[str, Architecture] | None = None,
    extra_ids: list[str] | None = None,
) -> StaticHardwareReferenceCatalog:
    pattern = candidates.source_pattern_catalog_snapshot.patterns[0]
    selected = (
        list(pattern.hardware_reference_ids)
        if selected_ids is None
        else selected_ids
    )
    references = [
        _reference(
            reference_id,
            architecture=(architecture_by_id or {}).get(
                reference_id, Architecture.ARM
            ),
        )
        for reference_id in [*selected, *(extra_ids or [])]
    ]
    return StaticHardwareReferenceCatalog.create(references=references)


@pytest.fixture(scope="module")
def catalog(candidate_materialization) -> StaticHardwareReferenceCatalog:
    return _catalog(candidate_materialization)


@pytest.fixture(scope="module")
def bound(candidate_materialization, catalog):
    return bind_static_trigger_candidates_to_hardware_references(
        candidate_materialization, catalog
    )


def test_public_api_has_exactly_two_inputs() -> None:
    signature = inspect.signature(
        bind_static_trigger_candidates_to_hardware_references
    )
    assert list(signature.parameters) == [
        "candidate_materialization",
        "hardware_reference_catalog",
    ]


def test_owned_binding_is_exact_complete_and_preserves_obligations(
    candidate_materialization, catalog, bound
) -> None:
    projection = bound.projection
    pattern = candidate_materialization.source_pattern_catalog_snapshot.patterns[0]
    assert len(candidate_materialization.projection.case_candidates) == 2
    assert len(catalog.references) == 2
    assert len(projection.bindings) == 4
    assert projection.unresolved_references == []
    expected_pairs = {
        (candidate.id, reference_id)
        for candidate in candidate_materialization.projection.case_candidates
        for reference_id in pattern.hardware_reference_ids
    }
    assert {
        (item.source_case_candidate_id, item.source_hardware_reference_id)
        for item in projection.bindings
    } == expected_pairs
    candidate_by_id = {
        item.id: item
        for item in candidate_materialization.projection.case_candidates
    }
    expected_cross = set(StaticCrossLayerCandidateObjectiveObligation)
    for binding in projection.bindings:
        assert binding.candidate_remaining_objective_obligations == (
            candidate_by_id[
                binding.source_case_candidate_id
            ].remaining_objective_obligations
        )
        assert set(binding.cross_layer_remaining_objective_obligations) == (
            expected_cross
        )


def test_same_reference_shared_by_two_candidates_remains_two_bindings(bound) -> None:
    grouped: dict[str, set[str]] = {}
    for binding in bound.projection.bindings:
        grouped.setdefault(binding.source_hardware_reference_id, set()).add(
            binding.source_case_candidate_id
        )
    assert all(len(case_ids) == 2 for case_ids in grouped.values())
    assert len({item.id for item in bound.projection.bindings}) == 4


def test_empty_partial_and_architecture_mismatch_catalogs(
    candidate_materialization,
) -> None:
    pattern = candidate_materialization.source_pattern_catalog_snapshot.patterns[0]
    first_id, second_id = pattern.hardware_reference_ids
    empty = bind_static_trigger_candidates_to_hardware_references(
        candidate_materialization,
        StaticHardwareReferenceCatalog.create(references=[]),
    ).projection
    assert len(empty.bindings) == 0
    assert len(empty.unresolved_references) == 4
    assert {
        item.reason for item in empty.unresolved_references
    } == {StaticUnresolvedHardwareReferenceReason.REFERENCE_NOT_IN_CATALOG}

    partial = bind_static_trigger_candidates_to_hardware_references(
        candidate_materialization,
        _catalog(candidate_materialization, selected_ids=[first_id]),
    ).projection
    assert len(partial.bindings) == 2
    assert len(partial.unresolved_references) == 2
    assert {
        item.source_hardware_reference_id
        for item in partial.unresolved_references
    } == {second_id}

    mismatch = bind_static_trigger_candidates_to_hardware_references(
        candidate_materialization,
        _catalog(
            candidate_materialization,
            architecture_by_id={second_id: Architecture.RISC_V},
        ),
    ).projection
    assert len(mismatch.bindings) == 2
    assert len(mismatch.unresolved_references) == 2
    assert all(
        item.reason is (
            StaticUnresolvedHardwareReferenceReason
            .REFERENCE_ARCHITECTURE_MISMATCH
        )
        for item in mismatch.unresolved_references
    )


def test_no_fuzzy_cve_or_alias_binding(candidate_materialization) -> None:
    result = bind_static_trigger_candidates_to_hardware_references(
        candidate_materialization,
        StaticHardwareReferenceCatalog.create(
            references=[_reference("CVE-2023-34320")]
        ),
    ).projection
    assert result.bindings == []
    assert len(result.unresolved_references) == 4


def test_exact_documented_erratum_reference_binds_as_source_metadata(
    candidate_materialization,
) -> None:
    erratum = DocumentedHardwareErratumContract.model_validate_json(
        ERRATUM.read_bytes()
    )
    predicate = StaticTriggerPredicate.create(
        operation=StaticSemanticOperation.SYSTEM_REGISTER_READ,
        required_attributes=[
            StaticSemanticAttribute(
                name=StaticSemanticAttributeName.SYSTEM_REGISTER,
                value="par_el1",
            )
        ],
        required_effective_memory_types=[],
        required_execution_contexts=[],
        objective_requirements=[],
    )
    position = StaticTriggerPosition.create(
        position_index=1, alternatives=[predicate]
    )
    case = StaticTriggerCase.create(
        case_reference_id="documented-reference-binding-contract-case",
        positions=[position],
        relation_requirement=None,
        objective_requirements=[],
    )
    pattern = StaticTriggerPattern.create(
        architecture=Architecture.ARM,
        instruction_set="aarch64",
        pattern_name="documented_reference_binding_contract_pattern",
        source_reference_ids=[erratum.id],
        hardware_reference_ids=[erratum.id],
        cases=[case],
        objective_requirements=[],
    )
    candidates = project_static_trigger_candidates(
        candidate_materialization.source_fused_graph_materialization_snapshot,
        StaticTriggerPatternCatalog.create(patterns=[pattern]),
    )
    reference = StaticDocumentedErratumHardwareReference.create(
        reference_id=erratum.id,
        architecture=Architecture.ARM,
        source_documented_erratum_snapshot=erratum,
    )
    result = bind_static_trigger_candidates_to_hardware_references(
        candidates,
        StaticHardwareReferenceCatalog.create(references=[reference]),
    )

    assert len(result.projection.bindings) == 1
    binding = result.projection.bindings[0]
    assert binding.source_hardware_reference_id == erratum.id
    assert binding.source_hardware_reference_record_id == reference.id
    assert binding.hardware_reference_kind.value == "documented_hardware_erratum"
    summary = render_static_cross_layer_candidate_summary_markdown(result)
    dot = render_static_cross_layer_candidate_graph_dot(result)
    for text in (
        "Documented CVE association: `CVE-2023-34320`",
        "Vendor-documented erratum ID: `1508412`",
        "Vendor-documented processor: `Cortex-A77`",
        "Vendor-documented possible effect: `core_deadlock`",
        "`r0p0`: `affected`",
        "`r1p0`: `affected`",
        "`r1p1`: `fixed`",
    ):
        assert text in summary
    assert 'label="documented CVE association"' in dot
    assert "triggers" not in dot.lower()


def test_fully_rehashed_foreign_reference_passes_projection_not_authority(
    bound,
) -> None:
    payload = bound.model_dump(mode="json")
    projection = payload["projection"]
    binding = projection["bindings"][0]
    binding["source_hardware_reference_id"] = (
        f"owned-synthetic-foreign-reference-{'f' * 64}"
    )
    _rehash(binding, static_cross_layer_candidate_binding_id)
    _rehash(projection, static_cross_layer_candidate_projection_id)
    StaticCrossLayerCandidateProjection.model_validate(projection)
    _rehash(payload, static_cross_layer_candidate_materialization_id)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerCandidateMaterialization.model_validate(payload)


def test_rehashed_valid_but_wrong_source_pattern_is_rejected_by_materialization(
    candidate_materialization,
    catalog,
) -> None:
    source_pattern = (
        candidate_materialization.source_pattern_catalog_snapshot.patterns[0]
    )
    other_pattern = StaticTriggerPattern.create(
        architecture=source_pattern.architecture,
        instruction_set=source_pattern.instruction_set,
        pattern_name="owned_synthetic_valid_alternate_source_pattern_v1",
        source_reference_ids=[
            "owned-synthetic-valid-alternate-source-pattern-v1"
        ],
        hardware_reference_ids=source_pattern.hardware_reference_ids,
        cases=source_pattern.cases,
        objective_requirements=source_pattern.objective_requirements,
    )
    candidates = project_static_trigger_candidates(
        candidate_materialization.source_fused_graph_materialization_snapshot,
        StaticTriggerPatternCatalog.create(
            patterns=[source_pattern, other_pattern]
        ),
    )
    materialization = bind_static_trigger_candidates_to_hardware_references(
        candidates, catalog
    )
    candidate_by_id = {
        candidate.id: candidate
        for candidate in candidates.projection.case_candidates
    }
    payload = materialization.model_dump(mode="json")
    projection = payload["projection"]
    binding = next(
        item
        for item in projection["bindings"]
        if candidate_by_id[item["source_case_candidate_id"]].source_pattern_id
        == source_pattern.id
    )
    binding["source_pattern_id"] = other_pattern.id
    _rehash(binding, static_cross_layer_candidate_binding_id)
    _rehash(projection, static_cross_layer_candidate_projection_id)
    standalone = StaticCrossLayerCandidateProjection.model_validate(projection)
    assert standalone.id == projection["id"]
    _rehash(payload, static_cross_layer_candidate_materialization_id)

    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerCandidateMaterialization.model_validate(payload)


def test_valid_undeclared_catalog_reference_cannot_be_bound(
    candidate_materialization,
) -> None:
    extra_id = "owned-synthetic-valid-but-undeclared-reference-v1"
    catalog = _catalog(candidate_materialization, extra_ids=[extra_id])
    materialization = bind_static_trigger_candidates_to_hardware_references(
        candidate_materialization, catalog
    )
    payload = materialization.model_dump(mode="json")
    projection = payload["projection"]
    binding = projection["bindings"][0]
    extra = next(
        item for item in catalog.references if item.reference_id == extra_id
    )
    binding["source_hardware_reference_id"] = extra.reference_id
    binding["source_hardware_reference_record_id"] = extra.id
    _rehash(binding, static_cross_layer_candidate_binding_id)
    projection["bindings"] = sorted(
        projection["bindings"],
        key=lambda item: (
            item["source_case_candidate_id"],
            item["source_hardware_reference_id"],
            item["id"],
        ),
    )
    _rehash(projection, static_cross_layer_candidate_projection_id)
    StaticCrossLayerCandidateProjection.model_validate(projection)
    _rehash(payload, static_cross_layer_candidate_materialization_id)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerCandidateMaterialization.model_validate(payload)


def test_reference_catalog_snapshot_tamper_is_rejected(
    candidate_materialization, catalog, bound
) -> None:
    payload = bound.model_dump(mode="json")
    catalog_payload = catalog.model_dump(mode="json")
    reference_payload = catalog_payload["references"][0]
    reference_payload["title"] = "changed owned source title"
    _rehash(reference_payload, static_owned_synthetic_hardware_reference_id)
    _rehash(catalog_payload, static_hardware_reference_catalog_id)
    payload["source_hardware_reference_catalog_id"] = catalog_payload["id"]
    payload["source_hardware_reference_catalog_snapshot"] = catalog_payload
    _rehash(payload, static_cross_layer_candidate_materialization_id)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerCandidateMaterialization.model_validate(payload)


def test_candidate_snapshot_tamper_is_rejected(candidate_materialization, bound) -> None:
    alternate = project_static_trigger_candidates(
        candidate_materialization.source_fused_graph_materialization_snapshot,
        StaticTriggerPatternCatalog.create(patterns=[]),
    )
    payload = bound.model_dump(mode="json")
    payload["source_candidate_materialization_id"] = alternate.id
    payload["source_candidate_materialization_snapshot"] = alternate.model_dump(
        mode="json"
    )
    _rehash(payload, static_cross_layer_candidate_materialization_id)
    with pytest.raises(ValidationError, match="source reprojection"):
        StaticCrossLayerCandidateMaterialization.model_validate(payload)


@pytest.mark.parametrize("target", ["binding", "projection", "materialization"])
def test_retained_ids_fail_closed(bound, target: str) -> None:
    payload = bound.model_dump(mode="json")
    if target == "binding":
        payload["projection"]["bindings"][0]["id"] = (
            "static-cross-layer-candidate-binding:bad"
        )
    elif target == "projection":
        payload["projection"]["id"] = (
            "static-cross-layer-candidate-projection:bad"
        )
    else:
        payload["id"] = "static-cross-layer-candidate-materialization:bad"
    with pytest.raises(ValidationError):
        StaticCrossLayerCandidateMaterialization.model_validate(payload)


def test_diagnostic_tamper_fails_closed(bound) -> None:
    payload = bound.model_dump(mode="json")
    payload["projection"]["diagnostic_codes"][0] = "candidate_case_count:999"
    _rehash(payload["projection"], static_cross_layer_candidate_projection_id)
    _rehash(payload, static_cross_layer_candidate_materialization_id)
    with pytest.raises(ValidationError, match="diagnostics mismatch"):
        StaticCrossLayerCandidateMaterialization.model_validate(payload)


def test_caller_mutation_cannot_change_materialization(
    candidate_materialization, catalog
) -> None:
    mutable_candidates = StaticTriggerCandidateMaterialization.model_validate(
        candidate_materialization.model_dump(mode="json")
    )
    mutable_catalog = StaticHardwareReferenceCatalog.model_validate(
        catalog.model_dump(mode="json")
    )
    result = bind_static_trigger_candidates_to_hardware_references(
        mutable_candidates, mutable_catalog
    )
    before = result.model_dump_json()
    mutable_catalog.references.clear()
    mutable_candidates.projection.case_candidates.clear()
    assert result.model_dump_json() == before


def test_binding_is_deterministic_across_ten_runs(
    candidate_materialization, catalog
) -> None:
    outputs = [
        bind_static_trigger_candidates_to_hardware_references(
            candidate_materialization, catalog
        )
        for _ in range(10)
    ]
    assert len({item.projection.id for item in outputs}) == 1
    assert len({item.id for item in outputs}) == 1
    assert len(
        {
            hashlib.sha256(item.model_dump_json().encode()).hexdigest()
            for item in outputs
        }
    ) == 1


def test_core_binding_dependency_firewall() -> None:
    forbidden = {
        "angr",
        "capstone",
        "aarch64_static_semantic_decoder",
        "structure_extractor",
        "ProgramArtifact",
        "runtime",
        "reasoning",
        "provider",
        "knowledge",
    }
    for filename in (
        "static_cross_layer_candidate_models.py",
        "static_cross_layer_candidate_binding.py",
    ):
        tree = ast.parse(
            (ROOT / "src/chipchain/analysis" / filename).read_text(
                encoding="utf-8"
            )
        )
        imported = {
            node.module or ""
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        assert not any(
            any(term in module for term in forbidden) for module in imported
        )


def test_models_expose_no_verdict_fields() -> None:
    forbidden = {
        "verified",
        "vulnerable",
        "triggered",
        "confidence",
        "probability",
        "score",
        "attack_chain",
    }
    for model in (
        StaticCrossLayerCandidateProjection,
        StaticCrossLayerCandidateMaterialization,
    ):
        assert forbidden.isdisjoint(model.model_fields)
