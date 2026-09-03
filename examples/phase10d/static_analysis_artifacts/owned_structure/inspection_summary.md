# Static Analysis Inspection Summary

## Independent sources

### Semantic source

- Inventory ID: `static-semantic-inventory:016ae199942a56b91ae0a49d4fb6aaeb8072456a19dcf65e93c10527b8b6b3a3`
- Decoder profile: `phase10d_aarch64_static_semantic_decoder_audited_partial_v1`

### Semantic graph

- Projection ID: `static-semantic-graph-projection:bccacd75e5719652fe20d0c44e1a18621ce186745b90174e074797a88ec0103e`
- Materialization ID: `static-semantic-graph-materialization:3e0befa6214962f7836640be2f3b97a71d0510f95c561ff8f053cd1e85ff42b7`

### Structure source

- Inventory ID: `static-program-structure-inventory:7c97b813bf68d6e7aac8d8512f27e48d097b36752db8209f5954bf20e118942c`
- Analyzer profile: `phase10d_aarch64_static_program_structure_extractor_cfgfast_v1`

## Independent source provenance comparison

| Field | Semantic source | Structure source | Equal |
|---|---|---|---|
| `architecture` | `arm` | `arm` | `true` |
| `artifact_id` | `owned-synthetic-aarch64-static-program-structure-v1` | `owned-synthetic-aarch64-static-program-structure-v1` | `true` |
| `artifact_sha256` | `7af2a0422f7d8dcd8e5d506692ea1516284199284d2baa4fa19ac021e5b00cec` | `7af2a0422f7d8dcd8e5d506692ea1516284199284d2baa4fa19ac021e5b00cec` | `true` |
| `instruction_set` | `aarch64` | `aarch64` | `true` |

## Semantic-only static provenance under current source profiles

No source-coverage differences observed.

Presentation != fusion.

Inspection summary != vulnerability verdict.
