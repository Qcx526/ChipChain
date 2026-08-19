# QEMU Runtime Plan

本文只规划 Phase 9B1，不表示当前已实现、编译或运行 QEMU plugin。

## Version and Capability Probe

具体 QEMU TCG plugin API 必须按实际版本进行 compile/runtime capability probe。不能假定所有
版本都支持 interrupt callback、register access/mutation、guest memory mutation、device DMA
visibility 或 physical-address translation。Probe 结果写入 `RuntimeBackendManifest` 的明确
version/capability，不以 backend 名称猜能力。

首个 observer 只依赖优先级最高的 passive subset：instruction callback、memory callback、
physical address 和 IO classification。Memory value、interrupt/exception discontinuity 与 DMA
只有 probe 成功并有 owned validation 后才启用。9B1 不启用 active capabilities。

## Proposed Structure

```text
runtime/qemu/
  capability_probe
  trace_parser
  observer_adapter

external C plugin
  → stable JSONL raw events only

Python
  → schema validation
  → RuntimeObservation normalization
  → trace/capability validation
  → Dynamic Evidence generation
```

C plugin 保持 dumb observer，不输出 vulnerability ID、interaction ID、verification status、
score 或自然语言推理，也不包含 Verification logic。

## Raw JSONL Shape

未来 raw event 的最小逻辑字段为：

```json
{
  "run_id": "owned-run-id",
  "sequence_index": 0,
  "vcpu": 0,
  "event_kind": "mmio_write",
  "pc": "0x10008",
  "vaddr": null,
  "paddr": "0x40000000",
  "is_io": true,
  "access_size": 4,
  "value": null
}
```

Parser 必须把 raw event 与已知 TraceManifest/backend manifest 组合后才创建严格 Observation；
不得信任 raw ID、顺序或 architecture。

## Single-vCPU MVP

首个 ARM QEMU observer 固定单 vCPU，以提供清晰、可复现的全局 sequence ordering。多 vCPU
需要单独设计 per-vCPU order、global merge/clock 与并发语义，不能把 host timestamp 当作
确定性排序依据。

## Phase 9B1 Exit Direction

9B1 应在 owned ARM program 上证明 passive trace 可重复采集、parser fail-closed、manifest
version/capability 准确、MMIO observation 与现有 Memory Map 一致，并保持 Evidence
interaction-agnostic。它仍不实现 intervention、causal inference、reverse BehaviorEdge 或
完整 Interaction verification；这些属于后续 9B2 设计。
