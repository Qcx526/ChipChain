"""Owned runtime fixtures and public contract demo regressions."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from chipchain.runtime import (
    RuntimeBackendManifest,
    RuntimeEventKind,
    RuntimeIntervention,
    RuntimeRunMode,
    RuntimeTraceManifest,
    load_runtime_trace,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures" / "runtime"
BOUNDARY_FLAGS = {
    "fixture",
    "synthetic",
    "owned",
    "not_real_vulnerability",
    "not_benchmark",
}


def test_owned_arm_mmio_fixture_is_a_valid_contract_trace() -> None:
    trace = load_runtime_trace(FIXTURES / "arm_mmio_runtime_trace.json")
    mmio = next(
        item
        for item in trace.observations
        if item.event_kind is RuntimeEventKind.MMIO_WRITE
    )

    assert trace.manifest.vcpu_count == 1
    assert mmio.pc.value == "0x10008"
    assert mmio.physical_address.value == "0x40000000"
    assert mmio.metadata["capture_backend_simulated_for_contract"] is True
    assert all(trace.manifest.metadata[key] is True for key in BOUNDARY_FLAGS)


def test_owned_interrupt_fixture_expresses_no_vulnerability_causality() -> None:
    trace = load_runtime_trace(FIXTURES / "arm_interrupt_contract_trace.json")

    assert trace.observations[0].event_kind is RuntimeEventKind.INTERRUPT_DISCONTINUITY
    serialized = trace.model_dump_json()
    assert "caused" not in serialized
    assert "vulnerability_id" not in serialized
    assert all(trace.backend_manifest.metadata[key] is True for key in BOUNDARY_FLAGS)


def test_type3_fixture_separates_baseline_intervention_and_observation() -> None:
    raw = json.loads(
        (FIXTURES / "arm_type3_intervention_contract.json").read_text(
            encoding="utf-8"
        )
    )
    backend = RuntimeBackendManifest.model_validate(raw["backend_manifest"])
    baseline = RuntimeTraceManifest.model_validate(raw["baseline_manifest"])
    intervention_run = RuntimeTraceManifest.model_validate(raw["intervention_manifest"])
    intervention = RuntimeIntervention.model_validate(raw["intervention"])

    assert baseline.run_mode is RuntimeRunMode.BASELINE
    assert intervention_run.run_mode is RuntimeRunMode.INTERVENTION
    assert baseline.scenario_id == intervention_run.scenario_id
    assert baseline.input_fingerprint == intervention_run.input_fingerprint
    assert baseline.environment_fingerprint == intervention_run.environment_fingerprint
    assert intervention.controller_backend == backend.id
    assert "observations" not in raw
    assert raw["metadata"]["verification_result_generated"] is False
    assert raw["metadata"]["type3_verified"] is False
    assert all(raw["metadata"][key] is True for key in BOUNDARY_FLAGS)


def test_runtime_evidence_contract_demo_prints_meaning_boundary() -> None:
    completed = subprocess.run(
        [sys.executable, "examples/runtime_evidence_contract_demo.py"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "Backend: owned-arm-mmio-contract" in completed.stdout
    assert "Architecture: arm" in completed.stdout
    assert "MMIO Observation: mmio_write" in completed.stdout
    assert "Physical Address: 0x40000000" in completed.stdout
    assert (
        "This runtime evidence verifies an observation, not a vulnerability or attack chain."
        in completed.stdout
    )
