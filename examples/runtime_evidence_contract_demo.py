"""Display the owned Phase 9B0 ARM MMIO runtime evidence contract."""

from pathlib import Path

from chipchain.runtime import (
    RuntimeEventKind,
    RuntimeEvidenceNormalizer,
    load_runtime_trace,
)


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "runtime" / "arm_mmio_runtime_trace.json"


def main() -> None:
    """Load a synthetic contract fixture and print its non-verification meaning."""

    trace = load_runtime_trace(FIXTURE)
    mmio = next(
        item
        for item in trace.observations
        if item.event_kind is RuntimeEventKind.MMIO_WRITE
    )
    evidence = RuntimeEvidenceNormalizer().normalize(mmio, trace)
    print(f"Backend: {trace.backend_manifest.backend_name}")
    print(f"Architecture: {trace.manifest.architecture.value}")
    print(
        "Capabilities: "
        + ", ".join(item.value for item in trace.backend_manifest.capabilities)
    )
    print(f"Trace ID: {trace.manifest.id}")
    print(f"Observation Count: {len(trace.observations)}")
    print(f"MMIO Observation: {mmio.event_kind.value}")
    print(f"Dynamic Evidence ID: {evidence.id}")
    print(f"Physical Address: {mmio.physical_address.value}")
    print("Runtime Evidence Meaning: validated synthetic runtime observation")
    print(
        "This runtime evidence verifies an observation, not a vulnerability or attack chain."
    )


if __name__ == "__main__":
    main()
