"""Pure adapter from frozen A-profile static analysis to neutral projection."""

from __future__ import annotations

from chipchain.analysis.static_behavior_models import (
    PHASE10D_STATIC_BEHAVIOR_GRAPH_PROJECTION_CONTRACT,
    PHASE10D_STATIC_PATTERN_BINDING_PROJECTION_CONTRACT,
    StaticAssertionClass,
    StaticBehaviorAnalysisProjection,
    StaticBehaviorGraphProjection,
    StaticBehaviorNode,
    StaticBehaviorNodeKind,
    StaticBehaviorProjectionScope,
    StaticBehaviorRelation,
    StaticBehaviorRelationKind,
    StaticPatternBindingKind,
    StaticPatternBindingProjection,
    StaticPatternBindingRecord,
    StaticPatternBindingSemantics,
    StaticSemanticAttributes,
    _cfg_block_source_id,
    _cfg_edge_source_id,
    _graph_diagnostics,
    _pattern_diagnostics,
)
from chipchain.hardware_trigger.a_profile_static_case_models import (
    AProfileStaticCaseAssemblyResult,
)


def _project_source(
    result: AProfileStaticCaseAssemblyResult,
) -> tuple[StaticBehaviorGraphProjection, StaticPatternBindingProjection]:
    """Build the one exact v1 projection expected from a frozen C2 result."""

    extraction = result.source_extraction_result_snapshot
    nodes: list[StaticBehaviorNode] = []
    relations: list[StaticBehaviorRelation] = []
    block_node_by_key: dict[tuple[str, str], StaticBehaviorNode] = {}

    for cfg in result.function_cfg_snapshots:
        function_node = StaticBehaviorNode.create(
            kind=StaticBehaviorNodeKind.FUNCTION,
            architecture=result.architecture,
            artifact_id=result.artifact_id,
            artifact_sha256=result.artifact_sha256,
            source_object_id=cfg.id,
            function_address=cfg.function_address,
            function_name=cfg.function_name,
            assertion_class=StaticAssertionClass.OBJECTIVE_STATIC_FACT,
        )
        nodes.append(function_node)
        for block_address in cfg.basic_block_addresses:
            block_source_id = _cfg_block_source_id(cfg.id, block_address)
            block_node = StaticBehaviorNode.create(
                kind=StaticBehaviorNodeKind.BASIC_BLOCK,
                architecture=result.architecture,
                artifact_id=result.artifact_id,
                artifact_sha256=result.artifact_sha256,
                source_object_id=block_source_id,
                function_address=cfg.function_address,
                function_name=cfg.function_name,
                basic_block_address=block_address,
                assertion_class=StaticAssertionClass.OBJECTIVE_STATIC_FACT,
            )
            block_node_by_key[(cfg.function_address, block_address)] = block_node
            nodes.append(block_node)
            relations.append(
                StaticBehaviorRelation.create(
                    relation_kind=(
                        StaticBehaviorRelationKind
                        .FUNCTION_CONTAINS_BASIC_BLOCK
                    ),
                    architecture=result.architecture,
                    artifact_id=result.artifact_id,
                    artifact_sha256=result.artifact_sha256,
                    source_node_id=function_node.id,
                    target_node_id=block_node.id,
                    source_object_ids=[cfg.id, block_source_id],
                    assertion_class=(
                        StaticAssertionClass.OBJECTIVE_STRUCTURAL_RELATION
                    ),
                )
            )
        for edge in cfg.directed_edges:
            source_node = block_node_by_key[
                (cfg.function_address, edge.source_basic_block_address)
            ]
            target_node = block_node_by_key[
                (cfg.function_address, edge.target_basic_block_address)
            ]
            relations.append(
                StaticBehaviorRelation.create(
                    relation_kind=StaticBehaviorRelationKind.CFG_SUCCESSOR,
                    architecture=result.architecture,
                    artifact_id=result.artifact_id,
                    artifact_sha256=result.artifact_sha256,
                    source_node_id=source_node.id,
                    target_node_id=target_node.id,
                    source_object_ids=[
                        cfg.id,
                        _cfg_edge_source_id(
                            cfg.id,
                            edge.source_basic_block_address,
                            edge.target_basic_block_address,
                        ),
                    ],
                    assertion_class=(
                        StaticAssertionClass.OBJECTIVE_STRUCTURAL_RELATION
                    ),
                )
            )

    predicate_fact_ids = {
        item.static_instruction_fact_id
        for item in extraction.predicate_candidates
    }
    fact_node_by_id: dict[str, StaticBehaviorNode] = {}
    unprojected_nonpredicate_fact_count = 0
    for fact in extraction.instruction_facts:
        key = (fact.function_address, fact.basic_block_address)
        block_node = block_node_by_key.get(key) if fact.function_address else None
        if block_node is None:
            if fact.id in predicate_fact_ids:
                raise ValueError(
                    "predicate-referenced fact is outside materialized CFG graph"
                )
            unprojected_nonpredicate_fact_count += 1
            continue
        semantic_attributes = StaticSemanticAttributes(
            memory_type_resolution=fact.memory_type_resolution.value,
            static_fact_scope=fact.static_fact_scope.value,
            system_register=(
                fact.system_register.value
                if fact.system_register is not None
                else None
            ),
        )
        fact_node = StaticBehaviorNode.create(
            kind=StaticBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT,
            architecture=result.architecture,
            artifact_id=result.artifact_id,
            artifact_sha256=result.artifact_sha256,
            source_object_id=fact.id,
            function_address=fact.function_address,
            function_name=fact.function_name,
            basic_block_address=fact.basic_block_address,
            instruction_address=fact.instruction_address,
            instruction_word=fact.instruction_word,
            instruction_size=fact.instruction_size,
            semantic_operation=fact.event_kind.value,
            semantic_attributes=semantic_attributes,
            assertion_class=StaticAssertionClass.OBJECTIVE_STATIC_FACT,
        )
        fact_node_by_id[fact.id] = fact_node
        nodes.append(fact_node)
        cfg = next(
            item
            for item in result.function_cfg_snapshots
            if item.function_address == fact.function_address
        )
        relations.append(
            StaticBehaviorRelation.create(
                relation_kind=(
                    StaticBehaviorRelationKind
                    .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT
                ),
                architecture=result.architecture,
                artifact_id=result.artifact_id,
                artifact_sha256=result.artifact_sha256,
                source_node_id=block_node.id,
                target_node_id=fact_node.id,
                source_object_ids=[cfg.id, fact.id],
                assertion_class=(
                    StaticAssertionClass.OBJECTIVE_STRUCTURAL_RELATION
                ),
            )
        )

    graph = StaticBehaviorGraphProjection.create(
        contract=PHASE10D_STATIC_BEHAVIOR_GRAPH_PROJECTION_CONTRACT,
        architecture=result.architecture,
        artifact_id=result.artifact_id,
        artifact_sha256=result.artifact_sha256,
        source_static_analysis_result_id=result.source_extraction_result_id,
        nodes=nodes,
        relations=relations,
        projection_scope=(
            StaticBehaviorProjectionScope.BINARY_STATIC_PROGRAM_ANALYSIS
        ),
        unprojected_nonpredicate_fact_count=(
            unprojected_nonpredicate_fact_count
        ),
        diagnostic_codes=_graph_diagnostics(
            nodes,
            relations,
            unprojected_nonpredicate_fact_count=(
                unprojected_nonpredicate_fact_count
            ),
        ),
    )

    records: list[StaticPatternBindingRecord] = []
    for candidate in extraction.predicate_candidates:
        fact_node = fact_node_by_id.get(candidate.static_instruction_fact_id)
        if fact_node is None:
            raise ValueError("predicate candidate has no semantic-fact graph node")
        records.append(
            StaticPatternBindingRecord.create(
                binding_kind=StaticPatternBindingKind.PREDICATE_CANDIDATE,
                binding_semantics=(
                    StaticPatternBindingSemantics
                    .CANDIDATE_FOR_PATTERN_PREDICATE
                ),
                architecture=result.architecture,
                artifact_id=result.artifact_id,
                artifact_sha256=result.artifact_sha256,
                source_pattern_id=candidate.source_pattern_id,
                extraction_plan_id=candidate.extraction_plan_id,
                case_id=candidate.case_id,
                source_candidate_id=candidate.id,
                source_fact_id=candidate.static_instruction_fact_id,
                position_index=candidate.position_index,
                predicate_ref=candidate.predicate_ref,
                semantic_fact_node_id=fact_node.id,
                remaining_objective_obligations=[
                    item.value
                    for item in candidate.remaining_objective_obligations
                ],
                assertion_class=(
                    StaticAssertionClass.DETERMINISTIC_PATTERN_CANDIDATE
                ),
            )
        )
    for candidate in result.case_order_candidates:
        first_node = fact_node_by_id.get(candidate.position_1_fact_id)
        second_node = fact_node_by_id.get(candidate.position_2_fact_id)
        if first_node is None or second_node is None:
            raise ValueError("case-order candidate has no exact fact graph node")
        records.append(
            StaticPatternBindingRecord.create(
                binding_kind=StaticPatternBindingKind.CASE_ORDER_CANDIDATE,
                binding_semantics=(
                    StaticPatternBindingSemantics
                    .STATIC_ORDER_COMPATIBLE_PATTERN_CANDIDATE
                ),
                architecture=result.architecture,
                artifact_id=result.artifact_id,
                artifact_sha256=result.artifact_sha256,
                source_pattern_id=candidate.source_pattern_id,
                extraction_plan_id=candidate.extraction_plan_id,
                case_id=candidate.case_id,
                source_case_order_candidate_id=candidate.id,
                position_1_predicate_candidate_id=(
                    candidate.position_1_candidate_id
                ),
                position_2_predicate_candidate_id=(
                    candidate.position_2_candidate_id
                ),
                position_1_fact_node_id=first_node.id,
                position_2_fact_node_id=second_node.id,
                function_cfg_snapshot_id=candidate.function_cfg_snapshot_id,
                order_basis=candidate.order_witness.order_basis.value,
                witness_basic_block_path=(
                    candidate.order_witness.witness_basic_block_path
                ),
                path_witness_use=(
                    candidate.order_witness.path_witness_use.value
                ),
                remaining_objective_obligations=[
                    item.value
                    for item in candidate.remaining_objective_obligations
                ],
                assertion_class=(
                    StaticAssertionClass.DETERMINISTIC_PATTERN_CANDIDATE
                ),
            )
        )
    pattern_bindings = StaticPatternBindingProjection.create(
        contract=PHASE10D_STATIC_PATTERN_BINDING_PROJECTION_CONTRACT,
        architecture=result.architecture,
        artifact_id=result.artifact_id,
        artifact_sha256=result.artifact_sha256,
        source_static_analysis_result_id=result.source_extraction_result_id,
        source_case_assembly_result_id=result.id,
        source_pattern_id=result.source_pattern_id,
        extraction_plan_id=result.extraction_plan_id,
        records=records,
        diagnostic_codes=_pattern_diagnostics(records),
    )
    return graph, pattern_bindings


def project_static_behavior_analysis(
    result: AProfileStaticCaseAssemblyResult,
) -> StaticBehaviorAnalysisProjection:
    """Project one detached C2 result without I/O or backend execution."""

    detached = AProfileStaticCaseAssemblyResult.model_validate(
        result.model_dump(mode="json")
    )
    return StaticBehaviorAnalysisProjection.create(
        source_case_assembly_result=detached
    )
