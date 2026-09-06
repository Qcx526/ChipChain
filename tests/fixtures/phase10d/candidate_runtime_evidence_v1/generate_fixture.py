"""Generate the owned benign RuntimeTrace used by Phase 10D 2D4-B1."""

from __future__ import annotations

import hashlib
from pathlib import Path

from chipchain.runtime import (
    RuntimeBackendKind,
    RuntimeBackendManifest,
    RuntimeCapability,
    RuntimeEventKind,
    RuntimeObservation,
    RuntimeRunMode,
    RuntimeTrace,
    RuntimeTraceManifest,
)


ROOT = Path(__file__).resolve().parent
TRACE_PATH = ROOT / "owned_diamond_runtime_trace.json"
SHA_PATH = ROOT / "SHA256SUMS"
ARTIFACT_ID = "owned-synthetic-aarch64-static-fused-behavior-v1"
ARTIFACT_SHA256 = (
    "3d92da1b6f160605df23514a43c04631"
    "e0c64f275cd707720988765f727e3262"
)
FIXTURE_METADATA = {
    "fixture": True,
    "not_benchmark": True,
    "not_real_vulnerability": True,
    "owned": True,
    "synthetic": True,
}


def build_owned_diamond_runtime_trace() -> RuntimeTrace:
    """Build a deterministic trace without executing any runtime backend."""

    backend = RuntimeBackendManifest.create(
        backend_kind=RuntimeBackendKind.OWNED_FIXTURE,
        backend_name="phase10d-candidate-runtime-evidence-fixture",
        backend_version="1",
        architecture="arm",
        system_emulation=False,
        capabilities=[RuntimeCapability.INSTRUCTION_EXECUTION],
        metadata=FIXTURE_METADATA,
    )
    manifest = RuntimeTraceManifest.create(
        run_id="owned-synthetic-phase10d-2d4-b1-run-v1",
        scenario_id="owned-synthetic-diamond-runtime-observations-v1",
        architecture="arm",
        backend_manifest_id=backend.id,
        run_mode=RuntimeRunMode.BASELINE,
        artifact_id=ARTIFACT_ID,
        artifact_sha256=ARTIFACT_SHA256,
        machine="owned-synthetic-contract-machine",
        cpu="owned-synthetic-contract-cpu",
        vcpu_count=1,
        metadata=FIXTURE_METADATA,
    )
    pcs = ("0x400000", "0x400008", "0x400018", "0x400000", "0x400010", "0x400018")
    observations = [
        RuntimeObservation.create(
            trace_id=manifest.id,
            architecture="arm",
            sequence_index=index,
            vcpu_index=0,
            event_kind=RuntimeEventKind.INSTRUCTION_EXEC,
            pc=pc,
            metadata=FIXTURE_METADATA,
        )
        for index, pc in enumerate(pcs)
    ]
    return RuntimeTrace(
        backend_manifest=backend,
        manifest=manifest,
        observations=observations,
    )


def main() -> int:
    """Write the trace and its exact byte hash."""

    payload = build_owned_diamond_runtime_trace().model_dump_json(indent=2) + "\n"
    TRACE_PATH.write_text(payload, encoding="utf-8")
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    SHA_PATH.write_text(
        f"{digest}  {TRACE_PATH.name}\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
