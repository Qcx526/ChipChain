# Static Program Structure Inventory

- Artifact ID: `owned-synthetic-aarch64-static-program-structure-v1`
- Artifact SHA-256: `7af2a0422f7d8dcd8e5d506692ea1516284199284d2baa4fa19ac021e5b00cec`
- Architecture: `arm`
- Instruction set: `aarch64`
- Analyzer profile: `phase10d_aarch64_static_program_structure_extractor_cfgfast_v1`
- Inventory ID: `static-program-structure-inventory:7c97b813bf68d6e7aac8d8512f27e48d097b36752db8209f5954bf20e118942c`
- Inventory scope: `partial_objective_function_local_cfg_inventory`

## Counts

- Function count: 3
- Basic-block count: 5
- Directed CFG-edge count: 3
- Zero-edge function count: 1

## Functions

### owned_branching_structure @ `0x400000`

Blocks:

- `0x400000`
- `0x400004`
- `0x40000c`

Static CFG edges:

- `0x400000` -> `0x400004`
- `0x400000` -> `0x40000c`

### owned_leaf_structure @ `0x400014`

Blocks:

- `0x400014`

Static CFG edges:

No directed CFG edges recovered under this extractor profile.

### owned_self_loop_structure @ `0x400018`

Blocks:

- `0x400018`

Static CFG edges:

- `0x400018` -> `0x400018`
