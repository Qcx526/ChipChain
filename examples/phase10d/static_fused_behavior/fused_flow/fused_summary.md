# Static Fused Behavior Graph

- Architecture: `arm`
- Artifact ID: `owned-synthetic-aarch64-static-fused-behavior-v1`
- Artifact SHA-256: `3d92da1b6f160605df23514a43c04631e0c64f275cd707720988765f727e3262`
- Instruction set: `aarch64`
- Semantic inventory ID: `static-semantic-inventory:2c377f5ebd2d290faa93158a38e234c1035f486b18fcc68a34a6267aaa41c46f`
- Semantic graph materialization ID: `static-semantic-graph-materialization:289734ced6d0c4bb9288fe918b09863eb0524f5d533bf7e28ff941389a0e4baf`
- Structure inventory ID: `static-program-structure-inventory:d9c6d2415ee381f79fc001d511e1189987938336f2f811d0e93b5553d1274b9c`
- Fused projection ID: `static-fused-behavior-graph-projection:355be42e9944877bff55952c4b421cf5043085b03b2c03b0a63fa62d3068b758`
- Fused materialization ID: `static-fused-behavior-graph-materialization:cd0fa460aa4b345864b4a7b92229a9e41768065091eb7a88fffbdd467cba65d3`

## Counts

- Function count: 1
- Basic-block count: 4
- Semantic-fact count: 4
- CFG successor count: 4

## Function / Block / Semantic Fact / Static CFG

| Function | Block | Source support | Semantic facts in block | Static CFG successors |
|---|---|---|---|---|
| owned_fused_static_flow @ 0x400000 | 0x400010 | semantic+structure | tlb_invalidate @ 0x400010 | 0x400018 |
| owned_fused_static_flow @ 0x400000 | 0x400000 | semantic+structure | system_register_read @ 0x400000 | 0x400008, 0x400010 |
| owned_fused_static_flow @ 0x400000 | 0x400008 | semantic+structure | memory_barrier @ 0x400008 | 0x400018 |
| owned_fused_static_flow @ 0x400000 | 0x400018 | semantic+structure | instruction_barrier @ 0x400018 | None |

## Function-contained semantic facts

None.

Static Fact != Runtime Execution.

CFG_SUCCESSOR != Runtime Execution.

CFG Reachability != Runtime Reachability.

CFG Reachability != Symbolic Feasibility.

CFG Reachability != Causality.

Fusion != Verification.

Fusion != Vulnerability.

Instruction Address != Basic-Block Provenance.
