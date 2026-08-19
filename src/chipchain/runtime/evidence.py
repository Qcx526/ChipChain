"""Interaction-agnostic normalization of runtime observations to Evidence."""

from __future__ import annotations

import hashlib
import json

from chipchain.models import Evidence, EvidenceType
from chipchain.runtime.enums import RuntimeBackendKind, RuntimeEventKind
from chipchain.runtime.models import RuntimeObservation, RuntimeTrace
from chipchain.runtime.trace import revalidate_runtime_trace


class RuntimeEvidenceNormalizer:
    """Convert a contract-validated observation into deterministic Evidence."""

    def normalize(
        self,
        observation: RuntimeObservation,
        trace: RuntimeTrace,
    ) -> Evidence:
        """Preserve runtime provenance without assigning interaction truth."""

        validated_trace = revalidate_runtime_trace(trace)
        validated_observation = RuntimeObservation.model_validate(
            observation.model_dump(mode="json")
        )
        trace_observation = next(
            (
                item
                for item in validated_trace.observations
                if item.id == validated_observation.id
            ),
            None,
        )
        if trace_observation is None or trace_observation != validated_observation:
            raise ValueError("runtime Evidence requires an observation from the validated trace")
        observation = trace_observation
        backend = validated_trace.backend_manifest
        identity_payload = [observation.id, backend.id]
        digest = hashlib.sha256(
            json.dumps(identity_payload, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        metadata: dict[str, object] = {
            "architecture": observation.architecture.value,
            "backend_manifest_id": backend.id,
            "runtime_event_kind": observation.event_kind.value,
            "runtime_observation_id": observation.id,
            "runtime_trace_id": observation.trace_id,
            "sequence_index": observation.sequence_index,
            "vcpu_index": observation.vcpu_index,
        }
        _add_event_metadata(metadata, observation)
        if backend.backend_kind is RuntimeBackendKind.OWNED_FIXTURE:
            metadata.update(
                {
                    "fixture": True,
                    "not_benchmark": True,
                    "not_real_vulnerability": True,
                    "owned": True,
                    "synthetic": True,
                }
            )
        return Evidence(
            id=f"runtime-evidence:{digest}",
            type=EvidenceType.DYNAMIC_ANALYSIS,
            source=backend.id,
            artifact=observation.trace_id,
            address=observation.pc.value if observation.pc is not None else None,
            confidence=1.0,
            verified=True,
            metadata=metadata,
        )


def _add_event_metadata(
    metadata: dict[str, object], observation: RuntimeObservation
) -> None:
    if observation.event_kind in {RuntimeEventKind.MMIO_READ, RuntimeEventKind.MMIO_WRITE}:
        metadata.update(
            {
                "access_size": observation.access_size,
                "address_space_id": observation.address_space_id,
                "is_io": observation.is_io,
                "physical_address": observation.physical_address.value,
                "value": observation.value,
                "value_width_bits": observation.value_width_bits,
                "virtual_address": (
                    observation.virtual_address.value
                    if observation.virtual_address is not None
                    else None
                ),
            }
        )
    if observation.event_kind in {
        RuntimeEventKind.INTERRUPT_DISCONTINUITY,
        RuntimeEventKind.EXCEPTION_DISCONTINUITY,
    }:
        metadata.update(
            {
                "from_pc": observation.from_pc.value,
                "to_pc": observation.to_pc.value,
            }
        )
    if observation.event_kind in {RuntimeEventKind.DMA_READ, RuntimeEventKind.DMA_WRITE}:
        metadata.update(
            {
                "access_size": observation.access_size,
                "address_space_id": observation.address_space_id,
                "device_id": observation.device_id,
                "physical_address": observation.physical_address.value,
                "value": observation.value,
                "value_width_bits": observation.value_width_bits,
            }
        )
