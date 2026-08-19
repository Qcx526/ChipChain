"""Deterministic version-1 JSON persistence for runtime traces."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from chipchain.runtime.errors import RuntimeCapabilityError, RuntimePersistenceError
from chipchain.runtime.models import RuntimeTrace


def revalidate_runtime_trace(trace: RuntimeTrace) -> RuntimeTrace:
    """Return a detached snapshot after rerunning every runtime invariant.

    The JSON-mode dump is intentional: validating an existing Pydantic model
    instance may reuse that instance and miss post-validation container
    mutations.
    """

    return RuntimeTrace.model_validate(trace.model_dump(mode="json"))


def serialize_runtime_trace(trace: RuntimeTrace) -> str:
    """Serialize a validated trace to canonical, human-readable JSON."""

    validated = revalidate_runtime_trace(trace)
    return json.dumps(
        validated.model_dump(mode="json"),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"


def save_runtime_trace(trace: RuntimeTrace, path: str | Path) -> None:
    """Atomically save a fully revalidated runtime trace."""

    destination = Path(path)
    temporary = destination.with_suffix(f"{destination.suffix}.tmp")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary.write_text(serialize_runtime_trace(trace), encoding="utf-8")
        temporary.replace(destination)
    except OSError as exc:
        raise RuntimePersistenceError(
            f"failed to save runtime trace to {destination}"
        ) from exc


def load_runtime_trace(path: str | Path) -> RuntimeTrace:
    """Load untrusted JSON and revalidate identities, ordering, and capabilities."""

    source = Path(path)
    try:
        raw_data = json.loads(source.read_text(encoding="utf-8"))
        return RuntimeTrace.model_validate(raw_data)
    except (OSError, json.JSONDecodeError, ValidationError, RuntimeCapabilityError) as exc:
        raise RuntimePersistenceError(
            f"failed to load valid runtime trace from {source}"
        ) from exc
