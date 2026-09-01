"""Pure deterministic function-local static case-order assembly."""

from __future__ import annotations

from itertools import product

from chipchain.hardware_trigger.a_profile_static_case_models import (
    AProfileStaticCaseAssemblyResult,
    AProfileStaticCaseOrderCandidate,
    AProfileStaticFunctionCfgSnapshot,
    StaticCaseOrderBasis,
    _deterministic_cfg_path,
)
from chipchain.hardware_trigger.a_profile_static_semantic_models import (
    AProfileStaticPredicateCandidate,
    AProfileStaticSemanticExtractionResult,
)


def assemble_static_case_order_candidates(
    extraction_result: AProfileStaticSemanticExtractionResult,
    function_cfg_snapshots: list[AProfileStaticFunctionCfgSnapshot],
) -> AProfileStaticCaseAssemblyResult:
    """Assemble every function-local static CFG order-compatible pair.

    The evaluator is backend-independent and structural only. A candidate does
    not imply runtime execution, symbolic feasibility, proximity, or any
    triggerability or vulnerability outcome.
    """

    extraction = AProfileStaticSemanticExtractionResult.model_validate(
        extraction_result.model_dump(mode="json")
    )
    snapshots = [
        AProfileStaticFunctionCfgSnapshot.model_validate(
            item.model_dump(mode="json")
        )
        for item in function_cfg_snapshots
    ]
    snapshot_by_function: dict[str, AProfileStaticFunctionCfgSnapshot] = {}
    for snapshot in snapshots:
        expected_binding = (
            extraction.artifact_id,
            extraction.artifact_sha256,
            extraction.id,
            extraction.extraction_plan_id,
            extraction.source_pattern_id,
            extraction.architecture,
            extraction.architecture_profile,
            extraction.instruction_set_state,
        )
        actual_binding = (
            snapshot.artifact_id,
            snapshot.artifact_sha256,
            snapshot.extraction_result_id,
            snapshot.extraction_plan_id,
            snapshot.source_pattern_id,
            snapshot.architecture,
            snapshot.architecture_profile,
            snapshot.instruction_set_state,
        )
        if actual_binding != expected_binding:
            raise ValueError("function CFG snapshot crosses extraction binding")
        if snapshot.function_address in snapshot_by_function:
            raise ValueError("multiple CFG snapshots target the same function")
        snapshot_by_function[snapshot.function_address] = snapshot

    fact_by_id = {item.id: item for item in extraction.instruction_facts}
    candidates_by_case_and_position: dict[
        tuple[str, int], list[AProfileStaticPredicateCandidate]
    ] = {}
    for candidate in extraction.predicate_candidates:
        candidates_by_case_and_position.setdefault(
            (candidate.case_id, candidate.position_index), []
        ).append(candidate)
    for candidates in candidates_by_case_and_position.values():
        candidates.sort(key=lambda item: item.id)

    assembled_by_id: dict[str, AProfileStaticCaseOrderCandidate] = {}
    case_ids = sorted(
        item.case_id
        for item in extraction.extraction_plan_snapshot.case_source_limitations
    )
    for case_id in case_ids:
        position_1_candidates = candidates_by_case_and_position.get(
            (case_id, 1), []
        )
        position_2_candidates = candidates_by_case_and_position.get(
            (case_id, 2), []
        )
        for candidate_1, candidate_2 in product(
            position_1_candidates,
            position_2_candidates,
        ):
            fact_1 = fact_by_id[candidate_1.static_instruction_fact_id]
            fact_2 = fact_by_id[candidate_2.static_instruction_fact_id]
            if (
                fact_1.function_address is None
                or fact_2.function_address is None
                or fact_1.function_address != fact_2.function_address
            ):
                continue
            cfg = snapshot_by_function.get(fact_1.function_address)
            if cfg is None:
                continue
            if fact_1.basic_block_address not in cfg.basic_block_addresses:
                raise ValueError("position-1 block is missing from function CFG")
            if fact_2.basic_block_address not in cfg.basic_block_addresses:
                raise ValueError("position-2 block is missing from function CFG")

            if fact_1.basic_block_address == fact_2.basic_block_address:
                if int(fact_1.instruction_address, 16) >= int(
                    fact_2.instruction_address, 16
                ):
                    continue
                order_basis = (
                    StaticCaseOrderBasis.SAME_BASIC_BLOCK_INSTRUCTION_ORDER
                )
            else:
                path = _deterministic_cfg_path(
                    cfg,
                    fact_1.basic_block_address,
                    fact_2.basic_block_address,
                )
                if path is None:
                    continue
                order_basis = StaticCaseOrderBasis.DIRECTED_FUNCTION_CFG_PATH

            assembled = AProfileStaticCaseOrderCandidate.create(
                extraction_result=extraction,
                function_cfg_snapshot=cfg,
                position_1_candidate=candidate_1,
                position_2_candidate=candidate_2,
                order_basis=order_basis,
            )
            previous = assembled_by_id.setdefault(assembled.id, assembled)
            if previous != assembled:
                raise ValueError("static case-order candidate ID collision")

    return AProfileStaticCaseAssemblyResult.create(
        extraction_result=extraction,
        function_cfg_snapshots=snapshots,
        case_order_candidates=list(assembled_by_id.values()),
    )
