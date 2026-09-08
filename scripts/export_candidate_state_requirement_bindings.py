"""Build and export owned synthetic B2-B source-relevance bindings only."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import runpy

from chipchain.analysis import (
    StaticHardwareReferenceCatalog,
    StaticProgramCfgEdge,
    StaticProgramCfgSemantics,
    StaticProgramFunctionCfg,
    StaticProgramStructureInventory,
    StaticSemanticFactScope,
    StaticSemanticInstructionFact,
    StaticSemanticInventory,
    StaticSemanticInventoryScope,
    StaticSemanticOperation,
    StaticTriggerCase,
    StaticTriggerObjectiveRequirement,
    StaticTriggerPattern,
    StaticTriggerPatternCatalog,
    StaticTriggerPosition,
    StaticTriggerPredicate,
    StaticTriggerRelationEvaluability,
    StaticTriggerRelationKind,
    StaticTriggerRelationPrecision,
    StaticTriggerRelationRequirement,
    bind_static_trigger_candidates_to_hardware_references,
    fuse_static_semantic_and_program_structure,
    project_static_semantic_inventory,
    project_static_trigger_candidates,
)
from chipchain.verification import (
    CandidateEffectiveMemoryTypeObservation,
    CandidateExecutionContextObservation,
    CandidateStateObservationMaterialization,
    CandidateStateObservationSourceManifest,
    bind_candidate_state_observations_to_requirements,
    export_candidate_state_requirement_binding_artifact_bundle,
    project_cross_layer_verification_requirements,
)


ROOT = Path(__file__).resolve().parents[1]
STATE_SOURCE = (
    ROOT
    / "tests/fixtures/phase10d/candidate_state_requirement_binding_v1/"
    "owned_state_source.json"
)


def _owned_synthetic_fused_program():
    """Construct the benign two-instruction source through production APIs."""

    common = {
        "architecture": "arm",
        "artifact_id": "owned-synthetic-requirement-planning-contract",
        "artifact_sha256": "a" * 64,
        "decoder_profile_id": "owned-synthetic-semantic-decoder-v1",
        "instruction_set": "aarch64",
    }
    facts = [
        StaticSemanticInstructionFact.create(
            **common,
            instruction_address="0x500000",
            instruction_bytes="0x01000000",
            instruction_size=4,
            function_address="0x500000",
            function_name="owned_synthetic_requirement_flow",
            basic_block_address="0x500000",
            operation=StaticSemanticOperation.MEMORY_LOAD,
            attributes=[],
            fact_scope=(
                StaticSemanticFactScope
                .DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
            ),
        ),
        StaticSemanticInstructionFact.create(
            **common,
            instruction_address="0x500004",
            instruction_bytes="0x02000000",
            instruction_size=4,
            function_address="0x500000",
            function_name="owned_synthetic_requirement_flow",
            basic_block_address="0x500004",
            operation=StaticSemanticOperation.MEMORY_STORE,
            attributes=[],
            fact_scope=(
                StaticSemanticFactScope
                .DECODED_STATIC_INSTRUCTION_SEMANTICS_ONLY
            ),
        ),
    ]
    inventory = StaticSemanticInventory.create(
        **common,
        analysis_scope=(
            StaticSemanticInventoryScope
            .PARTIAL_AUDITED_STATIC_SEMANTIC_INVENTORY
        ),
        facts=facts,
        diagnostic_codes=["semantic_fact_count:2"],
    )
    semantic_graph = project_static_semantic_inventory(inventory)
    structure_common = {
        "architecture": "arm",
        "artifact_id": common["artifact_id"],
        "artifact_sha256": common["artifact_sha256"],
        "analyzer_profile_id": "owned-synthetic-structure-extractor-v1",
        "instruction_set": "aarch64",
        "function_address": "0x500000",
        "cfg_semantics": (
            StaticProgramCfgSemantics
            .FUNCTION_LOCAL_DIRECTED_BASIC_BLOCK_REACHABILITY_V1
        ),
    }
    edge = StaticProgramCfgEdge.create(
        **structure_common,
        source_basic_block_address="0x500000",
        target_basic_block_address="0x500004",
    )
    function = StaticProgramFunctionCfg.create(
        **structure_common,
        function_name="owned_synthetic_requirement_flow",
        basic_block_addresses=["0x500000", "0x500004"],
        directed_edges=[edge],
    )
    structure = StaticProgramStructureInventory.create(
        architecture="arm",
        artifact_id=common["artifact_id"],
        artifact_sha256=common["artifact_sha256"],
        analyzer_profile_id="owned-synthetic-structure-extractor-v1",
        instruction_set="aarch64",
        functions=[function],
    )
    return fuse_static_semantic_and_program_structure(semantic_graph, structure)


def _state_predicate(operation: str) -> StaticTriggerPredicate:
    return StaticTriggerPredicate.create(
        operation=operation,
        required_effective_memory_types=["owned-synthetic-normal-memory"],
        required_execution_contexts=["owned-synthetic-el1"],
        objective_requirements=[
            StaticTriggerObjectiveRequirement
            .EFFECTIVE_MEMORY_TYPE_RESOLUTION_REQUIRED,
            StaticTriggerObjectiveRequirement.RUNTIME_EXECUTION_CONTEXT_REQUIRED,
        ],
    )


def build_owned_b2b_requirement_materialization():
    """Build a benign all-obligation 2D4-A source with production APIs."""

    relation = StaticTriggerRelationRequirement.create(
        relation_kind=StaticTriggerRelationKind.CLOSE_PROXIMITY,
        precision=StaticTriggerRelationPrecision.QUALITATIVE_ONLY,
        evaluability=(
            StaticTriggerRelationEvaluability
            .SOURCE_INSUFFICIENT_FOR_EXACT_STATIC_SATISFACTION
        ),
    )
    case = StaticTriggerCase.create(
        case_reference_id="owned-synthetic-b2b-state-binding-case",
        positions=[
            StaticTriggerPosition.create(
                position_index=1,
                alternatives=[_state_predicate("memory_load")],
            ),
            StaticTriggerPosition.create(
                position_index=2,
                alternatives=[_state_predicate("memory_store")],
            ),
        ],
        relation_requirement=relation,
        objective_requirements=[
            StaticTriggerObjectiveRequirement
            .RELATION_PROXIMITY_REMAINS_UNRESOLVED
        ],
    )
    pattern = StaticTriggerPattern.create(
        architecture="arm",
        instruction_set="aarch64",
        pattern_name="owned_synthetic_b2b_state_binding_pattern",
        source_reference_ids=["owned-synthetic-b2b-state-binding-design-v1"],
        hardware_reference_ids=["owned-synthetic-b2b-state-hardware-v1"],
        cases=[case],
        objective_requirements=[
            StaticTriggerObjectiveRequirement
            .ADDITIONAL_HARDWARE_TIMING_REMAINS_UNRESOLVED
        ],
    )
    candidates = project_static_trigger_candidates(
        _owned_synthetic_fused_program(),
        StaticTriggerPatternCatalog.create(patterns=[pattern]),
    )
    cross_layer = bind_static_trigger_candidates_to_hardware_references(
        candidates,
        StaticHardwareReferenceCatalog.create(references=[]),
    )
    return project_cross_layer_verification_requirements(cross_layer)


def build_owned_b2b_state_observation_materialization(
) -> CandidateStateObservationMaterialization:
    """Load the exact owned B2-B source snapshot and normalize B2-A records."""

    snapshot = STATE_SOURCE.read_bytes()
    source = json.loads(snapshot)
    manifest = CandidateStateObservationSourceManifest.create(
        **source["manifest"],
        source_artifact_sha256=hashlib.sha256(snapshot).hexdigest(),
    )
    common = {
        key: getattr(manifest, key)
        for key in (
            "architecture",
            "artifact_id",
            "artifact_sha256",
            "instruction_set",
        )
    }
    common["source_manifest_id"] = manifest.id
    return CandidateStateObservationMaterialization.create(
        source_manifest_snapshot=manifest,
        effective_memory_type_observations=[
            CandidateEffectiveMemoryTypeObservation.create(**common, **record)
            for record in source["effective_memory_type_observations"]
        ],
        execution_context_observations=[
            CandidateExecutionContextObservation.create(**common, **record)
            for record in source["execution_context_observations"]
        ],
    )


def build_owned_state_requirement_binding_materialization():
    """Produce the positive owned B2-B relevance-only demonstration."""

    return bind_candidate_state_observations_to_requirements(
        build_owned_b2b_requirement_materialization(),
        [build_owned_b2b_state_observation_materialization()],
    )


def _frozen_requirement_runner() -> dict[str, object]:
    return runpy.run_path(
        str(ROOT / "scripts/export_cross_layer_verification_requirements.py"),
        run_name="phase10d_b2b_frozen_requirement_runner",
    )


def build_owned_diamond_state_requirement_binding_materialization():
    """Bind the frozen ordinary owned requirements to its frozen B2-A source."""

    requirement_runner = _frozen_requirement_runner()
    state_runner = runpy.run_path(
        str(ROOT / "scripts/export_candidate_state_observations.py"),
        run_name="phase10d_b2b_frozen_state_runner",
    )
    return bind_candidate_state_observations_to_requirements(
        requirement_runner["build_owned_verification_requirement_materialization"](),
        [state_runner["build_owned_candidate_state_observations"]()],
    )


def build_public_a77_state_requirement_binding_materialization():
    """Project the frozen public A77 zero-requirement source without state facts."""

    requirement_runner = _frozen_requirement_runner()
    return bind_candidate_state_observations_to_requirements(
        requirement_runner["build_public_a77_verification_requirement_materialization"](),
        [],
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export exact typed-state requirement relevance only."
    )
    parser.add_argument(
        "--mode", choices=("owned", "owned-diamond", "public-a77"), required=True
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    builders = {
        "owned": build_owned_state_requirement_binding_materialization,
        "owned-diamond": (
            build_owned_diamond_state_requirement_binding_materialization
        ),
        "public-a77": build_public_a77_state_requirement_binding_materialization,
    }
    result = export_candidate_state_requirement_binding_artifact_bundle(
        materialization=builders[arguments.mode](),
        output_directory=arguments.output_dir,
    )
    for filename in result.files:
        print(filename)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
