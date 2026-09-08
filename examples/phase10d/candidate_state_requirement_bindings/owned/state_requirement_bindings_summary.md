# Candidate State Requirement Bindings

Source relevance only; requirement satisfaction has not been evaluated.

Program-location state association does not establish runtime execution or a memory access by that instruction.
Value equality is not evaluated by this binding layer.
Binding gaps record absence of relevant acquired observations, not requirement failure.

- Binding materialization ID: `candidate-state-requirement-binding-materialization:18b2423b44dfb65e33c218206c75fb1531179b6bd34d3439004fd80547d00c72`
- Binding projection ID: `candidate-state-requirement-binding-projection:15ec8e953d667481b48c12663dd257ff5c4f4daea48749903bfc219912bce011`
- Requirement materialization ID: `static-cross-layer-verification-requirement-materialization:1590b0db6cc1a6d4c41e02efcad84f4bda36f67ae2cc24b9c4cbad572415b3ac`
- Requirement projection ID: `static-cross-layer-verification-requirement-projection:dd050def67141e1da4a46b1f2a7492456aad608122924b2cdb7202cfc29d5b54`
- State source count: 1
- Binding count: 2
- Acquisition gap count: 0
- Out-of-scope requirement count: 4

- acquisition_gap_count:0
- compatible_state_source_count:1
- context_binding_count:1
- context_requirement_count:1
- incompatible_state_source_count:0
- memory_binding_count:1
- memory_requirement_count:1
- out_of_scope_requirement_count:4
- requirements_with_state_observation_binding_count:2
- requirements_without_state_observation_binding_count:0
- state_source_count:1

## Source-Relevance Binding 1

- Binding ID: `candidate-state-requirement-observation-binding:c447e708f5ed096f3da710f04d0552f2e31d0a696745696a202139563eb63dd1`
- Requirement ID: `static-candidate-verification-requirement:0ed4d2ba94d542cf9167b10c9a512e9ba59d477b11f5951fced5ee560cc5a0da`
- Requirement kind: `execution_context_evidence_required`
- Case candidate ID: `static-trigger-case-candidate:6f951e30d5e19d766eda1d4fcf568b8655a25716a0233e34f2ce37006d83a9a4`
- State materialization ID: `candidate-state-observation-materialization:f8eadb73a3b4d79fefb82921879249f227222d1ade65e3a5beed3862f4259603`
- State manifest ID: `candidate-state-source-manifest:0a5ef7d87333325b0b5718a5cf57a0b3ca801bfe1fda4424c376effafeb8bcb6`
- Observation ID: `candidate-execution-context-observation:362a8bc892056ec9ade4394dee375224ecdbe21a0b522e7644399b2f6676760f`
- Observation family: `execution_context`
- Source-associated program location: `0x500004`
- Matched subject position candidate IDs:
  - `static-trigger-position-candidate:9919ad95fcc346b4ac5a81d08fa0923d5431ccd7d45fea6257d95d539da40372`
- Matched subject fused fact node IDs:
  - `static-fused-behavior-node:bd3084c0f1602bd686833173db868cd2aaf9134c043b7c95a30d92ad2b4c86a3`
- Source observation execution context IDs: `owned-synthetic-el2`

## Source-Relevance Binding 2

- Binding ID: `candidate-state-requirement-observation-binding:4e3de877be650cceade871db5cd6819ae1f91389cba6804c8ec527c4d44cfedc`
- Requirement ID: `static-candidate-verification-requirement:60ba0055d49946b2f66d462e29fd00b2f97bf4b15ac8b8fdaf0027f4b2ae9322`
- Requirement kind: `effective_memory_type_evidence_required`
- Case candidate ID: `static-trigger-case-candidate:6f951e30d5e19d766eda1d4fcf568b8655a25716a0233e34f2ce37006d83a9a4`
- State materialization ID: `candidate-state-observation-materialization:f8eadb73a3b4d79fefb82921879249f227222d1ade65e3a5beed3862f4259603`
- State manifest ID: `candidate-state-source-manifest:0a5ef7d87333325b0b5718a5cf57a0b3ca801bfe1fda4424c376effafeb8bcb6`
- Observation ID: `candidate-effective-memory-type-observation:9d9ad4cd1cd299c5dd773107e7ba644b9439587b79fabfc9ff67fbf799924874`
- Observation family: `effective_memory_type`
- Source-associated program location: `0x500000`
- Matched subject position candidate IDs:
  - `static-trigger-position-candidate:dfa8baeeefcd05d015e16867b84000b31e10be448380a4ad3710a52559a2a248`
- Matched subject fused fact node IDs:
  - `static-fused-behavior-node:38efd9f49c6a098f3a7fba56c334db62f14c2f37a836cfee469b85536b91c36b`
- Source observation access address: `0x80000000`
- Source observation address kind: `virtual_address`
- Source observation memory type: `owned-synthetic-device-memory`

Typed Observation != Requirement Binding.

Requirement Binding != Requirement Satisfaction.

Evidence Relevance != Evidence Sufficiency.
