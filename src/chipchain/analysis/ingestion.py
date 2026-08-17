"""Atomic preflight ingestion from analysis results into graph repositories."""

from __future__ import annotations

from pydantic import ValidationError

from chipchain.analysis.errors import AnalysisIngestionError
from chipchain.analysis.models import ProgramAnalysisResult
from chipchain.graph import GraphError, GraphRepository


def ingest_analysis_result(
    result: ProgramAnalysisResult,
    repository: GraphRepository,
) -> None:
    """Preflight and ingest a complete result without expected partial writes.

    The result is reconstructed first so in-place mutation of nested Pydantic
    objects cannot bypass its cross-field invariants. All repository ID collisions
    are checked before mutation. A defensive rollback handles backend errors during
    the subsequent insertion sequence.
    """

    try:
        validated = ProgramAnalysisResult.model_validate(
            result.model_dump(mode="json")
        )
    except ValidationError as exc:
        raise AnalysisIngestionError("analysis result failed preflight validation") from exc

    existing_node_ids = {node.id for node in repository.list_nodes()}
    existing_edge_ids = {edge.id for edge in repository.list_edges()}
    new_node_ids = {node.id for node in validated.nodes}
    new_edge_ids = {edge.id for edge in validated.edges}

    node_collisions = sorted(existing_node_ids.intersection(new_node_ids))
    edge_collisions = sorted(existing_edge_ids.intersection(new_edge_ids))
    if node_collisions or edge_collisions:
        details = []
        if node_collisions:
            details.append(f"node IDs: {', '.join(node_collisions)}")
        if edge_collisions:
            details.append(f"edge IDs: {', '.join(edge_collisions)}")
        raise AnalysisIngestionError(
            "repository ID collision during preflight: " + "; ".join(details)
        )

    added_node_ids: list[str] = []
    added_edge_ids: list[str] = []
    try:
        for node in validated.nodes:
            repository.add_node(node)
            added_node_ids.append(node.id)
        for edge in validated.edges:
            repository.add_edge(edge)
            added_edge_ids.append(edge.id)
    except Exception as exc:
        for edge_id in reversed(added_edge_ids):
            try:
                repository.remove_edge(edge_id)
            except GraphError:
                pass
        for node_id in reversed(added_node_ids):
            try:
                repository.remove_node(node_id)
            except GraphError:
                pass
        raise AnalysisIngestionError("repository insertion failed and was rolled back") from exc
