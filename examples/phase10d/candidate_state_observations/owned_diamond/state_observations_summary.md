# Typed Candidate State Observations

Typed state observations only; no verification requirement has been evaluated.

State-source instruction addresses do not assert runtime execution.
For effective-memory-type records, instruction/address association does not establish that the instruction performed that memory access.
Declared source artifact hash is not independent raw-file verification.
audited_translation_resolution is a producer-profile-declared deterministic normalization basis, not independent ChipChain translation verification.
The typed materialization is authoritative; producer profiles are provenance, not trust scores.
Owned fixtures are synthetic, not real runtime measurements.

- Materialization ID: `candidate-state-observation-materialization:6f8793378247dc3cf51a32ba773a7d807657be902c661e0b01fe6eb4d5639f6b`
- Source manifest ID: `candidate-state-source-manifest:1e7499745e3b0b4583da14c7784c6796619b4c599ad5cb64405806c7ad5d8f3e`
- Architecture / instruction set: `arm` / `aarch64`
- Artifact ID / SHA-256: `owned-synthetic-aarch64-static-fused-behavior-v1` / `3d92da1b6f160605df23514a43c04631e0c64f275cd707720988765f727e3262`
- Source kind: `owned_fixture`
- Producer: `owned-synthetic-state-record-author` / `1`
- Normalization profile: `owned-synthetic-explicit-state-v1`
- Declared source artifact: `owned-synthetic-diamond-state-records-v1` / `1c9fb7fe3d5a840eaebf44e40ba8d65dab48d6a805a45b014c4be54d1219bc47`
- Memory observations: 2
- Context observations: 1

## Source record `record:000001`

```json
{
  "access_address": {
    "value": "0x80000000"
  },
  "access_address_kind": "virtual_address",
  "architecture": "arm",
  "artifact_id": "owned-synthetic-aarch64-static-fused-behavior-v1",
  "artifact_sha256": "3d92da1b6f160605df23514a43c04631e0c64f275cd707720988765f727e3262",
  "contract": "phase10d_candidate_effective_memory_type_observation_v1",
  "id": "candidate-effective-memory-type-observation:0176f6855726ea9886164d394513cfaf1f85adcab464faac46b7a2360a2d6a08",
  "instruction_address": {
    "value": "0x400008"
  },
  "instruction_set": "aarch64",
  "observation_semantics": "objective_source_observation_only",
  "observed_effective_memory_type_id": "owned-synthetic-normal-memory",
  "resolution_basis": "direct_typed_source",
  "source_manifest_id": "candidate-state-source-manifest:1e7499745e3b0b4583da14c7784c6796619b4c599ad5cb64405806c7ad5d8f3e",
  "source_record_locator": "record:000001"
}
```

## Source record `record:000002`

```json
{
  "access_address": {
    "value": "0x90000000"
  },
  "access_address_kind": "physical_address",
  "architecture": "arm",
  "artifact_id": "owned-synthetic-aarch64-static-fused-behavior-v1",
  "artifact_sha256": "3d92da1b6f160605df23514a43c04631e0c64f275cd707720988765f727e3262",
  "contract": "phase10d_candidate_effective_memory_type_observation_v1",
  "id": "candidate-effective-memory-type-observation:fade4ba018d594819d1247ee8a7844a45c6946ae5c761f80920b3103b2045982",
  "instruction_address": {
    "value": "0x400010"
  },
  "instruction_set": "aarch64",
  "observation_semantics": "objective_source_observation_only",
  "observed_effective_memory_type_id": "owned-synthetic-device-memory",
  "resolution_basis": "direct_typed_source",
  "source_manifest_id": "candidate-state-source-manifest:1e7499745e3b0b4583da14c7784c6796619b4c599ad5cb64405806c7ad5d8f3e",
  "source_record_locator": "record:000002"
}
```

## Source record `record:000003`

```json
{
  "architecture": "arm",
  "artifact_id": "owned-synthetic-aarch64-static-fused-behavior-v1",
  "artifact_sha256": "3d92da1b6f160605df23514a43c04631e0c64f275cd707720988765f727e3262",
  "contract": "phase10d_candidate_execution_context_observation_v1",
  "id": "candidate-execution-context-observation:64239221e5e7675e92ea8df59b25f8d8c337da69165ed417ae426aba0f37e274",
  "instruction_address": {
    "value": "0x400000"
  },
  "instruction_set": "aarch64",
  "observation_semantics": "objective_source_observation_only",
  "observed_execution_context_ids": [
    "owned-synthetic-el1",
    "owned-synthetic-nonsecure"
  ],
  "source_manifest_id": "candidate-state-source-manifest:1e7499745e3b0b4583da14c7784c6796619b4c599ad5cb64405806c7ad5d8f3e",
  "source_record_locator": "record:000003"
}
```
