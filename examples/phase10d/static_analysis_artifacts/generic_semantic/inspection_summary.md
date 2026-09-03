# Static Analysis Inspection Summary

## Independent sources

### Semantic source

- Inventory ID: `static-semantic-inventory:234bffafb5a7fee63f1385a3c31cea5965766f5870935ce36fe82d7912a43db3`
- Decoder profile: `phase10d_aarch64_static_semantic_decoder_audited_partial_v1`

### Semantic graph

- Projection ID: `static-semantic-graph-projection:84b4725dd7bb5e57f779a6e91a0eb4cbe1977e25476695502f1e7b783f446f26`
- Materialization ID: `static-semantic-graph-materialization:3670df7365cf13e6c2d18956f3db1c2848ae673d08d7bc705c80cb1ff3b16934`

### Structure source

- Inventory ID: `static-program-structure-inventory:4f0053f2aa5b9d18c565548d9910fea44047d516211189bb0aa6941b8f5e2cf2`
- Analyzer profile: `phase10d_aarch64_static_program_structure_extractor_cfgfast_v1`

## Independent source provenance comparison

| Field | Semantic source | Structure source | Equal |
|---|---|---|---|
| `architecture` | `arm` | `arm` | `true` |
| `artifact_id` | `owned-synthetic-generic-aarch64-v1` | `owned-synthetic-generic-aarch64-v1` | `true` |
| `artifact_sha256` | `854db6b28d22363a7943ea53bea83e18b25bb38d1dc6d25d99140e61a5374c0b` | `854db6b28d22363a7943ea53bea83e18b25bb38d1dc6d25d99140e61a5374c0b` | `true` |
| `instruction_set` | `aarch64` | `aarch64` | `true` |

## Semantic-only static provenance under current source profiles

### `exception_return` at `0x400034`

- instruction_address = `0x400034`
- function_address = `0x400034`
- basic_block_address = `None`
- structure function `0x400034` = `absent`
- semantic basic-block provenance = `not provided`

Semantic source provides no basic-block provenance for this fact.

Instruction Address != Basic-Block Provenance.

No function-level CFG support was independently recovered under the structure source profile.

Presentation != fusion.

Inspection summary != vulnerability verdict.
