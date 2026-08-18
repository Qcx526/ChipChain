"""Deterministic local architecture-knowledge document loading."""

from __future__ import annotations

from pathlib import Path

from chipchain.reasoning.models import ArchitectureKnowledgeDocument


def load_architecture_knowledge_documents(
    directory: str | Path,
) -> list[ArchitectureKnowledgeDocument]:
    """Load every JSON document in stable filename order with strict validation."""

    root = Path(directory)
    return [
        ArchitectureKnowledgeDocument.model_validate_json(
            path.read_text(encoding="utf-8")
        )
        for path in sorted(root.glob("*.json"))
    ]
