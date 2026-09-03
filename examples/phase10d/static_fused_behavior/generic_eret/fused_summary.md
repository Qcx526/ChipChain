# Static Fused Behavior Graph

- Architecture: `arm`
- Artifact ID: `owned-synthetic-generic-aarch64-v1`
- Artifact SHA-256: `854db6b28d22363a7943ea53bea83e18b25bb38d1dc6d25d99140e61a5374c0b`
- Instruction set: `aarch64`
- Semantic inventory ID: `static-semantic-inventory:234bffafb5a7fee63f1385a3c31cea5965766f5870935ce36fe82d7912a43db3`
- Semantic graph materialization ID: `static-semantic-graph-materialization:3670df7365cf13e6c2d18956f3db1c2848ae673d08d7bc705c80cb1ff3b16934`
- Structure inventory ID: `static-program-structure-inventory:4f0053f2aa5b9d18c565548d9910fea44047d516211189bb0aa6941b8f5e2cf2`
- Fused projection ID: `static-fused-behavior-graph-projection:44c60b841b4470ee3aa3c7cf204df8b2e12e0417a002921562651fcfea1dfe22`
- Fused materialization ID: `static-fused-behavior-graph-materialization:7dc8da71990fcf8519a6a4521685cce565b757f2729525302cf0defb5daa6e01`

## Counts

- Function count: 2
- Basic-block count: 1
- Semantic-fact count: 11
- CFG successor count: 0

## Function / Block / Semantic Fact / Static CFG

| Function | Block | Source support | Semantic facts in block | Static CFG successors |
|---|---|---|---|---|
| owned_generic_semantic_inventory @ 0x400000 | 0x400000 | semantic+structure | memory_load @ 0x400000, memory_store @ 0x400004, load_exclusive @ 0x400008, store_exclusive @ 0x40000c, system_register_read @ 0x400010, system_register_write @ 0x400014, memory_barrier @ 0x400018, memory_barrier @ 0x40001c, instruction_barrier @ 0x400020, tlb_invalidate @ 0x400024 | None |

## Function-contained semantic facts

- `0x400034` -> `exception_return` at `0x400034`

Static Fact != Runtime Execution.

CFG_SUCCESSOR != Runtime Execution.

CFG Reachability != Runtime Reachability.

CFG Reachability != Symbolic Feasibility.

CFG Reachability != Causality.

Fusion != Verification.

Fusion != Vulnerability.

Instruction Address != Basic-Block Provenance.
