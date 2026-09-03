# Static Semantic Inventory

- Artifact ID: `owned-synthetic-generic-aarch64-v1`
- Artifact SHA-256: `854db6b28d22363a7943ea53bea83e18b25bb38d1dc6d25d99140e61a5374c0b`
- Architecture: `arm`
- Instruction set: `aarch64`
- Decoder profile: `phase10d_aarch64_static_semantic_decoder_audited_partial_v1`
- Inventory ID: `static-semantic-inventory:234bffafb5a7fee63f1385a3c31cea5965766f5870935ce36fe82d7912a43db3`
- Inventory scope: `partial_audited_static_semantic_inventory`

## Counts

- Semantic fact count: 11

### Operations

| Operation | Count |
|---|---:|
| `memory_load` | 1 |
| `memory_store` | 1 |
| `load_exclusive` | 1 |
| `store_exclusive` | 1 |
| `system_register_read` | 1 |
| `system_register_write` | 1 |
| `memory_barrier` | 2 |
| `instruction_barrier` | 1 |
| `tlb_invalidate` | 1 |
| `exception_return` | 1 |

## Facts

| Instruction address | Instruction bytes | Operation | Function name | Function address | Basic block address | Attributes |
|---|---|---|---|---|---|---|
| `0x400000` | `0x200040f9` | `memory_load` | owned_generic_semantic_inventory | 0x400000 | 0x400000 | effective_memory_type_resolution=requires_objective_translation_context |
| `0x400004` | `0x200000f9` | `memory_store` | owned_generic_semantic_inventory | 0x400000 | 0x400000 | effective_memory_type_resolution=requires_objective_translation_context |
| `0x400008` | `0x417c5fc8` | `load_exclusive` | owned_generic_semantic_inventory | 0x400000 | 0x400000 | effective_memory_type_resolution=requires_objective_translation_context; memory_exclusivity=exclusive_load |
| `0x40000c` | `0x417c00c8` | `store_exclusive` | owned_generic_semantic_inventory | 0x400000 | 0x400000 | effective_memory_type_resolution=requires_objective_translation_context; memory_exclusivity=exclusive_store |
| `0x400010` | `0x007438d5` | `system_register_read` | owned_generic_semantic_inventory | 0x400000 | 0x400000 | system_register=par_el1 |
| `0x400014` | `0x007418d5` | `system_register_write` | owned_generic_semantic_inventory | 0x400000 | 0x400000 | system_register=par_el1 |
| `0x400018` | `0x9f3b03d5` | `memory_barrier` | owned_generic_semantic_inventory | 0x400000 | 0x400000 | barrier_kind=dsb; barrier_option=ish |
| `0x40001c` | `0xbf3b03d5` | `memory_barrier` | owned_generic_semantic_inventory | 0x400000 | 0x400000 | barrier_kind=dmb; barrier_option=ish |
| `0x400020` | `0xdf3f03d5` | `instruction_barrier` | owned_generic_semantic_inventory | 0x400000 | 0x400000 | barrier_kind=isb |
| `0x400024` | `0x1f8308d5` | `tlb_invalidate` | owned_generic_semantic_inventory | 0x400000 | 0x400000 | tlb_operation=vmalle1is |
| `0x400034` | `0xe0039fd6` | `exception_return` | owned_exception_return_semantic | 0x400034 | None | None |

## Static Semantic Graph

- Projection ID: `static-semantic-graph-projection:84b4725dd7bb5e57f779a6e91a0eb4cbe1977e25476695502f1e7b783f446f26`
- Materialization ID: `static-semantic-graph-materialization:3670df7365cf13e6c2d18956f3db1c2848ae673d08d7bc705c80cb1ff3b16934`

### Node counts

- FUNCTION: 2
- BASIC_BLOCK: 1
- SEMANTIC_INSTRUCTION_FACT: 11

### Relation counts

- FUNCTION_CONTAINS_BASIC_BLOCK: 1
- BASIC_BLOCK_CONTAINS_SEMANTIC_FACT: 10
- FUNCTION_CONTAINS_SEMANTIC_FACT: 1
- Uncontained semantic fact count: 0

Static containment != runtime execution.

Static containment != causality.
