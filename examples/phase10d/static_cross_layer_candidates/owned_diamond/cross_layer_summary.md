# Static Cross-Layer Reference Candidates

This output records source-declared reference candidates only.

- Architecture: `arm`
- Instruction set: `aarch64`
- Firmware artifact ID: `owned-synthetic-aarch64-static-fused-behavior-v1`
- Firmware artifact SHA-256: `3d92da1b6f160605df23514a43c04631e0c64f275cd707720988765f727e3262`
- Candidate materialization ID: `static-trigger-candidate-materialization:b4ae8a0deb96bb2096e940487eec75b1ed246b19b5577587f998c802718d5931`
- Hardware reference catalog ID: `static-hardware-reference-catalog:d124ab435860b72f76d6b0faf844eecf068c7acf3cbab7eddbf184fcf4af8051`
- Cross-layer projection ID: `static-cross-layer-candidate-projection:27d8f702fc24425de7e2fef0d94c967359cf5e07dc6a490498c0ed5b8fddff9a`
- Cross-layer materialization ID: `static-cross-layer-candidate-materialization:c1d21c9daa63a2f78e0c38623e21fd05bdc874cbc18286b55c85e890f3fb23d6`
- Binding count: 4
- Unresolved reference count: 0

Dataset provenance: owned, synthetic, and benign.

## Binding 1

- Binding ID: `static-cross-layer-candidate-binding:44b403af340c08bcd8e60aeebd8a0cbee164cca579681d815050980776737765`
- Case candidate ID: `static-trigger-case-candidate:bf14c1c4bf7b42e5e7d59bda063a1956bcdf47da0b06d15f9c007ba99e8a54e2`
- Source pattern ID: `static-trigger-pattern:4eb60094d04fcb7d9674b39227449bd144847b36525fa4203d6c3e5159fcf3f3`
- Pattern-declared hardware reference ID: `owned-synthetic-benign-condition-family-v1`
- Hardware reference record ID: `static-owned-hardware-reference:505f53db505fc20f70c6b92bea7c57addb438b86702f8af72255de13db18f464`
- Reference kind: `owned_synthetic_condition`
- Binding semantics: `static_pattern_declared_hardware_reference_candidate_only`

### Candidate remaining obligations

- `runtime_execution_required`
- `symbolic_path_feasibility_remains_unresolved`

### Cross-layer remaining obligations

- `hardware_effect_observation_required`
- `target_hardware_applicability_required`
- `target_hardware_identity_required`

## Binding 2

- Binding ID: `static-cross-layer-candidate-binding:93efed7af1c4dde840beed9a9f235f419341912a02760bd39d12b018b0e4652b`
- Case candidate ID: `static-trigger-case-candidate:bf14c1c4bf7b42e5e7d59bda063a1956bcdf47da0b06d15f9c007ba99e8a54e2`
- Source pattern ID: `static-trigger-pattern:4eb60094d04fcb7d9674b39227449bd144847b36525fa4203d6c3e5159fcf3f3`
- Pattern-declared hardware reference ID: `owned-synthetic-hardware-condition-v1`
- Hardware reference record ID: `static-owned-hardware-reference:206abe0fd5a3d85a533b5257a6b671759ab753bbb5a2c720ecd6cd82dcdf04e9`
- Reference kind: `owned_synthetic_condition`
- Binding semantics: `static_pattern_declared_hardware_reference_candidate_only`

### Candidate remaining obligations

- `runtime_execution_required`
- `symbolic_path_feasibility_remains_unresolved`

### Cross-layer remaining obligations

- `hardware_effect_observation_required`
- `target_hardware_applicability_required`
- `target_hardware_identity_required`

## Binding 3

- Binding ID: `static-cross-layer-candidate-binding:0b5c1fe6ff970af561af1741fe59e442432539f60e4a9e8970b36e23a61ebe43`
- Case candidate ID: `static-trigger-case-candidate:ff25b43401a79ef60c8bc2882d6a2d6aa53ae07192e64965f2dd9d3830a76050`
- Source pattern ID: `static-trigger-pattern:4eb60094d04fcb7d9674b39227449bd144847b36525fa4203d6c3e5159fcf3f3`
- Pattern-declared hardware reference ID: `owned-synthetic-benign-condition-family-v1`
- Hardware reference record ID: `static-owned-hardware-reference:505f53db505fc20f70c6b92bea7c57addb438b86702f8af72255de13db18f464`
- Reference kind: `owned_synthetic_condition`
- Binding semantics: `static_pattern_declared_hardware_reference_candidate_only`

### Candidate remaining obligations

- `runtime_execution_required`
- `symbolic_path_feasibility_remains_unresolved`

### Cross-layer remaining obligations

- `hardware_effect_observation_required`
- `target_hardware_applicability_required`
- `target_hardware_identity_required`

## Binding 4

- Binding ID: `static-cross-layer-candidate-binding:bbd945614284555ed49b865a9472073da2c8aae4278838d107c8dbbddb4a854b`
- Case candidate ID: `static-trigger-case-candidate:ff25b43401a79ef60c8bc2882d6a2d6aa53ae07192e64965f2dd9d3830a76050`
- Source pattern ID: `static-trigger-pattern:4eb60094d04fcb7d9674b39227449bd144847b36525fa4203d6c3e5159fcf3f3`
- Pattern-declared hardware reference ID: `owned-synthetic-hardware-condition-v1`
- Hardware reference record ID: `static-owned-hardware-reference:206abe0fd5a3d85a533b5257a6b671759ab753bbb5a2c720ecd6cd82dcdf04e9`
- Reference kind: `owned_synthetic_condition`
- Binding semantics: `static_pattern_declared_hardware_reference_candidate_only`

### Candidate remaining obligations

- `runtime_execution_required`
- `symbolic_path_feasibility_remains_unresolved`

### Cross-layer remaining obligations

- `hardware_effect_observation_required`
- `target_hardware_applicability_required`
- `target_hardware_identity_required`

Static cross-layer reference candidate only; runtime execution, target applicability, and hardware effect remain unresolved.

Cross-Layer Reference Candidate != Vulnerability Verification.

Pattern Hardware Reference != Hardware Trigger Observation.

Documented Affected Revision != Observed Target Revision.

Documented Possible Effect != Runtime Observed Effect.

Candidate -> Erratum Reference != Candidate Triggers Erratum.

CVE Association != Firmware Vulnerability Verdict.

Static Candidate != Runtime Execution.

Static CFG Witness != Runtime Path.

Unresolved Requirement != Satisfied Requirement.

Cross-Layer Candidate != Verified AttackChain.
