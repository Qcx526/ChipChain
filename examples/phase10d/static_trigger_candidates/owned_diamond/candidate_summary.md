# Static Trigger Candidates

This bundle is owned, synthetic, and benign.

- Architecture: `arm`
- Instruction set: `aarch64`
- Firmware artifact ID: `owned-synthetic-aarch64-static-fused-behavior-v1`
- Firmware artifact SHA-256: `3d92da1b6f160605df23514a43c04631e0c64f275cd707720988765f727e3262`
- Fused graph materialization ID: `static-fused-behavior-graph-materialization:cd0fa460aa4b345864b4a7b92229a9e41768065091eb7a88fffbdd467cba65d3`
- Pattern catalog ID: `static-trigger-pattern-catalog:aa51b3b9a059d445e577e092785aff472a7ca83e9357b468f9c4bf0f74335ee5`
- Candidate projection ID: `static-trigger-candidate-projection:ea67ef6b0e55f72bf7ece2e655d31efa76c25de46eefb5fc283c81cdd5adf8b6`
- Candidate materialization ID: `static-trigger-candidate-materialization:b4ae8a0deb96bb2096e940487eec75b1ed246b19b5577587f998c802718d5931`
- Case candidate count: 2

## Candidate 1: owned-case-a

- Pattern: `owned_synthetic_diamond_static_pattern`
- Pattern ID: `static-trigger-pattern:4eb60094d04fcb7d9674b39227449bd144847b36525fa4203d6c3e5159fcf3f3`
- Case: `owned-case-a`
- Case ID: `static-trigger-case:4b8759c6616bb48c281080c16477937bd25f128d3c5e1925172005cba1148f17`
- Candidate ID: `static-trigger-case-candidate:bf14c1c4bf7b42e5e7d59bda063a1956bcdf47da0b06d15f9c007ba99e8a54e2`
- Function: `0x400000`

### Positions

1.
   - Predicate ID: `static-trigger-predicate:8b92c5e32e3528c267082ae2a43207f9ae5bdf8c0a013ca50858a16044854336`
   - Operation: `system_register_read`
   - Semantic fact node ID: `static-fused-behavior-node:c8744704a139de78f8b644217a9f0964940922de7ebf5e08646dde73ee9dff1d`
   - Semantic source fact IDs: `static-semantic-instruction-fact:f86b256ecbb3115a04f4fa3aeb1ece82153579dfc1bc2a088809c176a376557a`
   - Instruction address: `0x400000`
   - Basic-block address: `0x400000`

2.
   - Predicate ID: `static-trigger-predicate:c2d22cea1035815e4ad7c79f410ebf9a9632667d3247f4a74d86158e8d7c4a1f`
   - Operation: `memory_barrier`
   - Semantic fact node ID: `static-fused-behavior-node:43734798e1f309d61b64c543198db12a802ee15f1024a9c6b9479723d672db34`
   - Semantic source fact IDs: `static-semantic-instruction-fact:9af57e0cfa1e236f31e29efa90b1c398d907ba778486780ba3a9e84d395c56e9`
   - Instruction address: `0x400008`
   - Basic-block address: `0x400008`

3.
   - Predicate ID: `static-trigger-predicate:5eb2d0f77ed95e5c43e88abd6c81313888a40719ac8361dca03929fbc76ebbe7`
   - Operation: `instruction_barrier`
   - Semantic fact node ID: `static-fused-behavior-node:ce27536ad8128a310898ec6d85ef1bc9cdb9bc36a668883f370a388bca9cc510`
   - Semantic source fact IDs: `static-semantic-instruction-fact:5b6d937a0bf2a980176e89db24263e3eabb808b239a174853a2051ac7045f296`
   - Instruction address: `0x400018`
   - Basic-block address: `0x400018`

### Static order witnesses

- 1 -> 2
  - Basis: `directed_function_cfg_path`
  - Block-node path: `static-fused-behavior-node:7a8c2939df575dca4ccb36af49a22d175feed4a6acbe62f0ba972f20c28bf81c -> static-fused-behavior-node:ab12981393e758d410fe0a07a1ff23259c0583a6fca7c8d1deb87b8279048341`
  - CFG relation IDs: `static-fused-behavior-relation:ccaf93eb8bf4e79aefea822171ab08f78cc21b5a27d31dec542798cce845a03b`
- 2 -> 3
  - Basis: `directed_function_cfg_path`
  - Block-node path: `static-fused-behavior-node:ab12981393e758d410fe0a07a1ff23259c0583a6fca7c8d1deb87b8279048341 -> static-fused-behavior-node:bae7849b5f1769ebf6383434ad2927697b889a72d0e668c26dedc692e31fb106`
  - CFG relation IDs: `static-fused-behavior-relation:ae8c5d3a1c66d8dd59489fb49a8e05960ab37ddb4d22e7a7a187366d060e1897`

### Remaining objective obligations

- `runtime_execution_required`
- `symbolic_path_feasibility_remains_unresolved`

Candidate interpretation: static structural pattern candidate only.

## Candidate 2: owned-case-b

- Pattern: `owned_synthetic_diamond_static_pattern`
- Pattern ID: `static-trigger-pattern:4eb60094d04fcb7d9674b39227449bd144847b36525fa4203d6c3e5159fcf3f3`
- Case: `owned-case-b`
- Case ID: `static-trigger-case:522354bcdc43f1339e82a0b7104e0402ea364c6f8d6df447691c1830ec3bf5c5`
- Candidate ID: `static-trigger-case-candidate:ff25b43401a79ef60c8bc2882d6a2d6aa53ae07192e64965f2dd9d3830a76050`
- Function: `0x400000`

### Positions

1.
   - Predicate ID: `static-trigger-predicate:8b92c5e32e3528c267082ae2a43207f9ae5bdf8c0a013ca50858a16044854336`
   - Operation: `system_register_read`
   - Semantic fact node ID: `static-fused-behavior-node:c8744704a139de78f8b644217a9f0964940922de7ebf5e08646dde73ee9dff1d`
   - Semantic source fact IDs: `static-semantic-instruction-fact:f86b256ecbb3115a04f4fa3aeb1ece82153579dfc1bc2a088809c176a376557a`
   - Instruction address: `0x400000`
   - Basic-block address: `0x400000`

2.
   - Predicate ID: `static-trigger-predicate:8c622025fdde4d4984f3af3ac4d0450b766aedec8595faccbf434ca334f00779`
   - Operation: `tlb_invalidate`
   - Semantic fact node ID: `static-fused-behavior-node:ad3ee6b3e63f83a413f0155f5629c42dab7ac02d320b0c6ac4927b2df0f5d983`
   - Semantic source fact IDs: `static-semantic-instruction-fact:a723ac456659bc86f05145f0d549fc24a55099560f8c75a0bbaf356aec28cad2`
   - Instruction address: `0x400010`
   - Basic-block address: `0x400010`

3.
   - Predicate ID: `static-trigger-predicate:5eb2d0f77ed95e5c43e88abd6c81313888a40719ac8361dca03929fbc76ebbe7`
   - Operation: `instruction_barrier`
   - Semantic fact node ID: `static-fused-behavior-node:ce27536ad8128a310898ec6d85ef1bc9cdb9bc36a668883f370a388bca9cc510`
   - Semantic source fact IDs: `static-semantic-instruction-fact:5b6d937a0bf2a980176e89db24263e3eabb808b239a174853a2051ac7045f296`
   - Instruction address: `0x400018`
   - Basic-block address: `0x400018`

### Static order witnesses

- 1 -> 2
  - Basis: `directed_function_cfg_path`
  - Block-node path: `static-fused-behavior-node:7a8c2939df575dca4ccb36af49a22d175feed4a6acbe62f0ba972f20c28bf81c -> static-fused-behavior-node:33e48ae99595bdc7da7398b4ff1b92f7254c81e499a237ca504eb5b8bbe3382f`
  - CFG relation IDs: `static-fused-behavior-relation:c4172c7a356afd3db8fbca2a283cbd9adc172c2273ae4298a719dba26dbf2960`
- 2 -> 3
  - Basis: `directed_function_cfg_path`
  - Block-node path: `static-fused-behavior-node:33e48ae99595bdc7da7398b4ff1b92f7254c81e499a237ca504eb5b8bbe3382f -> static-fused-behavior-node:bae7849b5f1769ebf6383434ad2927697b889a72d0e668c26dedc692e31fb106`
  - CFG relation IDs: `static-fused-behavior-relation:f897eaad4911f6e6ba2a45aa3f72307a7c4136091ae06bd0e43988a6adaaf3b9`

### Remaining objective obligations

- `runtime_execution_required`
- `symbolic_path_feasibility_remains_unresolved`

Candidate interpretation: static structural pattern candidate only.

Candidate != Runtime Execution.

Static CFG Witness != Runtime Path.

CFG Reachability != Symbolic Feasibility.

Pattern Candidate != Triggerability.

Pattern Hardware Reference != Candidate Hardware Binding.

Program Order Candidate != Runtime Order.

Unresolved Requirement != Satisfied Requirement.

Candidate != AttackChain.
