"""Pure deterministic matching of fused static facts to trigger patterns."""

from __future__ import annotations

from collections import deque
import hashlib
import itertools
import json
from typing import Literal

from pydantic import field_validator, model_validator

from chipchain.analysis.static_fused_behavior_fusion import (
    StaticFusedBehaviorGraphMaterialization,
)
from chipchain.analysis.static_fused_behavior_models import (
    StaticFusedBehaviorNode,
    StaticFusedBehaviorNodeKind,
    StaticFusedBehaviorRelation,
    StaticFusedBehaviorRelationKind,
)
from chipchain.analysis.static_trigger_candidate_models import (
    StaticTriggerCandidateObjectiveObligation,
    StaticTriggerCandidateProjection,
    StaticTriggerCaseCandidate,
    StaticTriggerOrderBasis,
    StaticTriggerOrderWitness,
    StaticTriggerPathWitnessUse,
    StaticTriggerPositionCandidate,
)
from chipchain.analysis.static_trigger_pattern_models import (
    StaticTriggerCase,
    StaticTriggerPattern,
    StaticTriggerPatternCatalog,
    StaticTriggerPosition,
    StaticTriggerPredicate,
)
from chipchain.models.common import DomainModel, Identifier


PHASE10D_STATIC_TRIGGER_CANDIDATE_MATERIALIZATION_CONTRACT = (
    "phase10d_static_trigger_candidate_materialization_v1"
)


def _canonical_json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def static_trigger_candidate_materialization_id(payload: object) -> str:
    """Return one deterministic authoritative materialization ID."""

    digest = hashlib.sha256(_canonical_json_bytes(payload)).hexdigest()
    return f"static-trigger-candidate-materialization:{digest}"


def _detached_sources(
    fused: StaticFusedBehaviorGraphMaterialization,
    catalog: StaticTriggerPatternCatalog,
) -> tuple[StaticFusedBehaviorGraphMaterialization, StaticTriggerPatternCatalog]:
    return (
        StaticFusedBehaviorGraphMaterialization.model_validate(
            fused.model_dump(mode="json")
        ),
        StaticTriggerPatternCatalog.model_validate(catalog.model_dump(mode="json")),
    )


def _predicate_matches(
    predicate: StaticTriggerPredicate,
    fact: StaticFusedBehaviorNode,
) -> bool:
    if fact.kind is not StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT:
        return False
    if fact.operation is not predicate.operation:
        return False
    fact_attributes = {(item.name, item.value) for item in fact.attributes}
    return all(
        (attribute.name, attribute.value) in fact_attributes
        for attribute in predicate.required_attributes
    )


class _GraphIndex:
    def __init__(self, fused: StaticFusedBehaviorGraphMaterialization) -> None:
        projection = fused.projection
        self.node_by_id = {node.id: node for node in projection.nodes}
        self.fact_nodes = [
            node
            for node in projection.nodes
            if node.kind is StaticFusedBehaviorNodeKind.SEMANTIC_INSTRUCTION_FACT
        ]
        self.block_for_fact: dict[str, str] = {}
        self.outgoing: dict[
            str, list[tuple[str, StaticFusedBehaviorRelation]]
        ] = {}
        for relation in projection.relations:
            if relation.relation_kind is (
                StaticFusedBehaviorRelationKind
                .BASIC_BLOCK_CONTAINS_SEMANTIC_FACT
            ):
                self.block_for_fact[relation.target_node_id] = (
                    relation.source_node_id
                )
            elif relation.relation_kind is (
                StaticFusedBehaviorRelationKind.CFG_SUCCESSOR
            ):
                self.outgoing.setdefault(relation.source_node_id, []).append(
                    (relation.target_node_id, relation)
                )
        for edges in self.outgoing.values():
            edges.sort(key=self._edge_sort_key)

    def _edge_sort_key(
        self, edge: tuple[str, StaticFusedBehaviorRelation]
    ) -> tuple[int, str]:
        target = self.node_by_id[edge[0]]
        return (int(target.basic_block_address or "0x0", 16), target.id)

    def canonical_cfg_path(
        self, source_id: str, target_id: str
    ) -> tuple[list[str], list[str]] | None:
        """Return the deterministic shortest directed reachability witness."""

        queue: deque[tuple[str, list[str], list[str]]] = deque(
            [(source_id, [source_id], [])]
        )
        visited = {source_id}
        while queue:
            current, nodes, relations = queue.popleft()
            for neighbor, relation in self.outgoing.get(current, []):
                if neighbor in visited:
                    continue
                next_nodes = [*nodes, neighbor]
                next_relations = [*relations, relation.id]
                if neighbor == target_id:
                    return next_nodes, next_relations
                visited.add(neighbor)
                queue.append((neighbor, next_nodes, next_relations))
        return None


def _position_candidates(
    *,
    fused: StaticFusedBehaviorGraphMaterialization,
    pattern: StaticTriggerPattern,
    case: StaticTriggerCase,
    position: StaticTriggerPosition,
    graph: _GraphIndex,
) -> list[StaticTriggerPositionCandidate]:
    projection = fused.projection
    candidates = []
    for predicate in position.alternatives:
        for fact in graph.fact_nodes:
            if not _predicate_matches(predicate, fact):
                continue
            candidates.append(
                StaticTriggerPositionCandidate.create(
                    architecture=projection.architecture,
                    artifact_id=projection.artifact_id,
                    artifact_sha256=projection.artifact_sha256,
                    instruction_set=projection.instruction_set,
                    position_index=position.position_index,
                    source_pattern_id=pattern.id,
                    source_case_id=case.id,
                    source_position_id=position.id,
                    source_predicate_id=predicate.id,
                    source_fused_fact_node_id=fact.id,
                    source_semantic_fact_ids=fact.semantic_source_fact_ids,
                    function_address=fact.function_address,
                    basic_block_address=fact.basic_block_address,
                    instruction_address=fact.instruction_address,
                    operation=fact.operation,
                )
            )
    return sorted(
        candidates,
        key=lambda item: (
            item.position_index,
            item.source_predicate_id,
            item.source_fused_fact_node_id,
            item.id,
        ),
    )


def _order_witness(
    source: StaticTriggerPositionCandidate,
    target: StaticTriggerPositionCandidate,
    graph: _GraphIndex,
) -> StaticTriggerOrderWitness | None:
    if source.function_address != target.function_address:
        return None
    source_block = graph.block_for_fact.get(source.source_fused_fact_node_id)
    target_block = graph.block_for_fact.get(target.source_fused_fact_node_id)
    if source_block is None or target_block is None:
        return None
    if source_block == target_block:
        if int(source.instruction_address, 16) >= int(
            target.instruction_address, 16
        ):
            return None
        return StaticTriggerOrderWitness.create(
            from_position_index=source.position_index,
            to_position_index=target.position_index,
            source_position_candidate_id=source.id,
            target_position_candidate_id=target.id,
            order_basis=(
                StaticTriggerOrderBasis
                .SAME_BASIC_BLOCK_STATIC_INSTRUCTION_ORDER
            ),
            function_address=source.function_address,
            witness_basic_block_node_ids=[source_block],
            witness_cfg_relation_ids=[],
            path_witness_use=None,
        )
    if source.function_address is None or target.function_address is None:
        return None
    path = graph.canonical_cfg_path(source_block, target_block)
    if path is None:
        return None
    block_ids, relation_ids = path
    if any(
        graph.node_by_id[block_id].function_address != source.function_address
        for block_id in block_ids
    ):
        return None
    return StaticTriggerOrderWitness.create(
        from_position_index=source.position_index,
        to_position_index=target.position_index,
        source_position_candidate_id=source.id,
        target_position_candidate_id=target.id,
        order_basis=StaticTriggerOrderBasis.DIRECTED_FUNCTION_CFG_PATH,
        function_address=source.function_address,
        witness_basic_block_node_ids=block_ids,
        witness_cfg_relation_ids=relation_ids,
        path_witness_use=StaticTriggerPathWitnessUse.REACHABILITY_AUDIT_ONLY,
    )


def _candidate_obligations(
    *,
    pattern: StaticTriggerPattern,
    case: StaticTriggerCase,
    selected_predicates: list[StaticTriggerPredicate],
    witnesses: list[StaticTriggerOrderWitness],
) -> list[StaticTriggerCandidateObjectiveObligation]:
    obligations = {
        StaticTriggerCandidateObjectiveObligation.RUNTIME_EXECUTION_REQUIRED
    }
    source_requirements = {
        *pattern.objective_requirements,
        *case.objective_requirements,
        *(
            requirement
            for predicate in selected_predicates
            for requirement in predicate.objective_requirements
        ),
    }
    for requirement in source_requirements:
        obligations.add(
            StaticTriggerCandidateObjectiveObligation(requirement.value)
        )
    if any(
        witness.order_basis is StaticTriggerOrderBasis.DIRECTED_FUNCTION_CFG_PATH
        for witness in witnesses
    ):
        obligations.add(
            StaticTriggerCandidateObjectiveObligation
            .SYMBOLIC_PATH_FEASIBILITY_REMAINS_UNRESOLVED
        )
    return sorted(obligations, key=lambda item: item.value)


def _case_candidates(
    *,
    fused: StaticFusedBehaviorGraphMaterialization,
    pattern: StaticTriggerPattern,
    case: StaticTriggerCase,
    graph: _GraphIndex,
) -> list[StaticTriggerCaseCandidate]:
    candidate_sets = [
        _position_candidates(
            fused=fused,
            pattern=pattern,
            case=case,
            position=position,
            graph=graph,
        )
        for position in case.positions
    ]
    if any(not candidates for candidates in candidate_sets):
        return []
    predicate_by_id = {
        predicate.id: predicate
        for position in case.positions
        for predicate in position.alternatives
    }
    projection = fused.projection
    results = []
    for combination in itertools.product(*candidate_sets):
        fact_ids = [item.source_fused_fact_node_id for item in combination]
        if len(fact_ids) != len(set(fact_ids)):
            continue
        functions = {item.function_address for item in combination}
        if len(functions) != 1:
            continue
        witnesses = []
        valid = True
        for source, target in itertools.pairwise(combination):
            witness = _order_witness(source, target, graph)
            if witness is None:
                valid = False
                break
            witnesses.append(witness)
        if not valid:
            continue
        selected_predicates = [
            predicate_by_id[item.source_predicate_id] for item in combination
        ]
        results.append(
            StaticTriggerCaseCandidate.create(
                architecture=projection.architecture,
                artifact_id=projection.artifact_id,
                artifact_sha256=projection.artifact_sha256,
                instruction_set=projection.instruction_set,
                source_pattern_id=pattern.id,
                source_case_id=case.id,
                case_reference_id=case.case_reference_id,
                function_address=combination[0].function_address,
                position_candidates=list(combination),
                order_witnesses=witnesses,
                remaining_objective_obligations=_candidate_obligations(
                    pattern=pattern,
                    case=case,
                    selected_predicates=selected_predicates,
                    witnesses=witnesses,
                ),
            )
        )
    return results


def _project_static_trigger_candidates(
    fused: StaticFusedBehaviorGraphMaterialization,
    catalog: StaticTriggerPatternCatalog,
) -> StaticTriggerCandidateProjection:
    projection = fused.projection
    compatible = [
        pattern
        for pattern in catalog.patterns
        if pattern.architecture is projection.architecture
        and pattern.instruction_set == projection.instruction_set
    ]
    compatible_ids = sorted(pattern.id for pattern in compatible)
    incompatible_ids = sorted(
        pattern.id
        for pattern in catalog.patterns
        if pattern.id not in compatible_ids
    )
    graph = _GraphIndex(fused)
    case_candidates = [
        candidate
        for pattern in compatible
        for case in pattern.cases
        for candidate in _case_candidates(
            fused=fused,
            pattern=pattern,
            case=case,
            graph=graph,
        )
    ]
    return StaticTriggerCandidateProjection.create(
        architecture=projection.architecture,
        artifact_id=projection.artifact_id,
        artifact_sha256=projection.artifact_sha256,
        instruction_set=projection.instruction_set,
        source_fused_graph_materialization_id=fused.id,
        source_fused_graph_projection_id=projection.id,
        source_pattern_catalog_id=catalog.id,
        compatible_pattern_ids=compatible_ids,
        incompatible_pattern_ids=incompatible_ids,
        case_candidates=case_candidates,
    )


class _StaticTriggerCandidateMaterializationBody(DomainModel):
    contract: Literal[
        "phase10d_static_trigger_candidate_materialization_v1"
    ]
    source_fused_graph_materialization_id: Identifier
    source_fused_graph_materialization_snapshot: (
        StaticFusedBehaviorGraphMaterialization
    )
    source_pattern_catalog_id: Identifier
    source_pattern_catalog_snapshot: StaticTriggerPatternCatalog
    projection: StaticTriggerCandidateProjection

    @field_validator("source_fused_graph_materialization_snapshot")
    @classmethod
    def detach_fused(
        cls, value: StaticFusedBehaviorGraphMaterialization
    ) -> StaticFusedBehaviorGraphMaterialization:
        return StaticFusedBehaviorGraphMaterialization.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("source_pattern_catalog_snapshot")
    @classmethod
    def detach_catalog(
        cls, value: StaticTriggerPatternCatalog
    ) -> StaticTriggerPatternCatalog:
        return StaticTriggerPatternCatalog.model_validate(
            value.model_dump(mode="json")
        )

    @field_validator("projection")
    @classmethod
    def detach_projection(
        cls, value: StaticTriggerCandidateProjection
    ) -> StaticTriggerCandidateProjection:
        return StaticTriggerCandidateProjection.model_validate(
            value.model_dump(mode="json")
        )

    @model_validator(mode="after")
    def validate_source_reprojection(
        self,
    ) -> "_StaticTriggerCandidateMaterializationBody":
        fused = self.source_fused_graph_materialization_snapshot
        catalog = self.source_pattern_catalog_snapshot
        if self.source_fused_graph_materialization_id != fused.id:
            raise ValueError("candidate materialization fused source ID mismatch")
        if self.source_pattern_catalog_id != catalog.id:
            raise ValueError("candidate materialization catalog source ID mismatch")
        if self.projection != _project_static_trigger_candidates(fused, catalog):
            raise ValueError(
                "candidate projection differs from deterministic source reprojection"
            )
        return self


class StaticTriggerCandidateMaterialization(
    _StaticTriggerCandidateMaterializationBody
):
    """Authoritative detached sources plus deterministic candidate projection."""

    id: Identifier

    @classmethod
    def create(
        cls,
        *,
        fused_graph_materialization: StaticFusedBehaviorGraphMaterialization,
        pattern_catalog: StaticTriggerPatternCatalog,
    ) -> "StaticTriggerCandidateMaterialization":
        fused, catalog = _detached_sources(
            fused_graph_materialization, pattern_catalog
        )
        values = {
            "contract": (
                PHASE10D_STATIC_TRIGGER_CANDIDATE_MATERIALIZATION_CONTRACT
            ),
            "source_fused_graph_materialization_id": fused.id,
            "source_fused_graph_materialization_snapshot": fused,
            "source_pattern_catalog_id": catalog.id,
            "source_pattern_catalog_snapshot": catalog,
            "projection": _project_static_trigger_candidates(fused, catalog),
        }
        body = _StaticTriggerCandidateMaterializationBody.model_validate(values)
        payload = body.model_dump(mode="json")
        return cls(
            id=static_trigger_candidate_materialization_id(payload), **payload
        )

    @model_validator(mode="after")
    def validate_deterministic_id(
        self,
    ) -> "StaticTriggerCandidateMaterialization":
        payload = self.model_dump(mode="json", exclude={"id"})
        if self.id != static_trigger_candidate_materialization_id(payload):
            raise ValueError("static trigger candidate materialization ID mismatch")
        return self


def project_static_trigger_candidates(
    fused_graph_materialization: StaticFusedBehaviorGraphMaterialization,
    pattern_catalog: StaticTriggerPatternCatalog,
) -> StaticTriggerCandidateMaterialization:
    """Match exactly two frozen inputs without rerunning analysis or inference."""

    return StaticTriggerCandidateMaterialization.create(
        fused_graph_materialization=fused_graph_materialization,
        pattern_catalog=pattern_catalog,
    )
