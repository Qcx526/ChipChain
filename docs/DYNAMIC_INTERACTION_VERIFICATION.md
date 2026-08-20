# Dynamic Interaction Verification

Phase 9B2A 在不修改 Phase 9B1 Runtime Evidence contract、Phase 9A-R verification semantics
或 `RuntimeEvidenceNormalizer` boundary 的前提下，为显式 trigger fact 增加动态观察验证与
Static/Dynamic aggregation。当前范围仅支持同一 ARM 架构内 Type I/II
software→hardware 的 `mmio_read` / `mmio_write`；Type III objective causal verification
仍为 `not_implemented`。

## Architecture

```text
Phase 9B1 Runtime Evidence
            |
            v
     DynamicTriggerFact
            |
            v
   Dynamic Verification
            |
            v
Static/Dynamic Aggregation
```

每一层保持独立职责：

- Phase 9B1 产生 interaction-agnostic RuntimeTrace、RuntimeObservation 与 Dynamic Evidence。
- `DynamicTriggerFact` 声明 Interaction 中已有 trigger behavior 的预期 MMIO 事实。
- Dynamic Verification 证明一个经重验证的 runtime observation 是否与该 fact 精确匹配。
- Static/Dynamic Aggregation 只读合并静态与动态 Record 状态，不修改任何上游结果。

## Models and binding contract

`DynamicTriggerFact` 固定 interaction ID、architecture、interaction type、direction、
`trigger_behavior` reference、event kind、program address、physical address、access size，以及
可选 memory map/address space。Fact 必须引用 `CrossLayerInteraction.trigger_behavior_ids`
中的 ID；metadata 不参与确定性身份。

`DynamicTriggerObservationBinding` 将一个 fact ID 显式关联到 Dynamic Evidence ID、
RuntimeTrace ID、RuntimeObservation ID 与可选 run ID。Binding 自身携带 interaction linkage，
但不会修改或重新标记 Runtime Evidence。

`DynamicInteractionVerificationInput` 对 fact/binding 做 detached snapshot、确定性排序、唯一性
和 linkage/cardinality 校验。同一 observation 不能绑定到相互冲突的 facts；重复 binding、
linkage 或 Evidence ID 均 fail closed。

## Dynamic verification

`phase9b2a_dynamic_trigger_observation_v1` 按以下顺序验证：

1. 验证 Interaction identity，并拒绝 Type III 或非 ARM/非 software→hardware 输入。
2. detached revalidate `DynamicTriggerFact` 与 `DynamicTriggerObservationBinding`。
3. 执行 explicit binding legality、architecture、reference role 和 MMIO event checks。
4. detached serialized snapshot revalidate `RuntimeTrace`。
5. 从 snapshot 中按 binding 的 `runtime_observation_id` 查找 `RuntimeObservation`。
6. 使用未修改的 `RuntimeEvidenceNormalizer` 重新生成 Dynamic Evidence。
7. 要求输入 Evidence 与重新生成的 Evidence 完全一致。
8. 精确比较 architecture、event kind、PC、physical address、access size、memory map ID 和
   address space ID。

Observation 无法解析时产生 UNKNOWN；字段明确冲突时产生 REJECTED；全部匹配时只产生：

```text
VerificationRecord(
    subject_kind=DYNAMIC_TRIGGER_OBSERVATION,
    status=VERIFIED,
)
```

这里的 Dynamic VERIFIED 只有一个含义：

> runtime observation matches explicit trigger fact

它不表示：

- vulnerability verified；
- `CrossLayerInteraction` verified；
- causality verified；
- attack chain verified。

Dynamic Record 不进入 Phase 9A-R `InteractionVerificationResult`，不修改 required fact、
status、score 或 location。运行时事件也不会被转换为 BehaviorEdge。

## Static/Dynamic aggregation

`StaticDynamicFactAggregation` 接收同一 interaction、architecture 与 trigger reference 的一条
Phase 9A-R static trigger participant `VerificationRecord` 和一条或多条 Dynamic
`DYNAMIC_TRIGGER_OBSERVATION` Record。输入先 detached revalidate；输入顺序不影响结果。

单一静态状态与归并后的动态状态使用以下 3×3 policy：

| Static | Dynamic | Aggregation status |
| --- | --- | --- |
| VERIFIED | VERIFIED | `corroborated` |
| VERIFIED | UNKNOWN | `static_only` |
| VERIFIED | REJECTED | `conflict` |
| UNKNOWN | VERIFIED | `dynamic_only` |
| UNKNOWN | UNKNOWN | `insufficient` |
| UNKNOWN | REJECTED | `dynamic_rejected` |
| REJECTED | VERIFIED | `conflict` |
| REJECTED | UNKNOWN | `static_rejected` |
| REJECTED | REJECTED | `both_rejected` |

多条 Dynamic Record 中 VERIFIED 与 REJECTED 并存时，无论静态状态为何都输出
`conflict`。聚合结果分别保留 static/dynamic Record ID、inspected Evidence ID 与 supporting
Evidence ID；它不覆盖输入 Record，也不写入 Evidence。

Aggregation status 是独立的 observation/fact correlation 状态，不是 Phase 9A-R
`InteractionVerificationStatus`，不会影响 verification score。

## Immutable boundaries

- Runtime Observation != Vulnerability
- Runtime Event != BehaviorEdge
- Dynamic Evidence != CrossLayerInteraction truth
- Temporal Order != Causality
- Fault Intervention != Fault Observation
- Dynamic VERIFIED != vulnerability/Interaction/causality/AttackChain verified
- Static/Dynamic aggregation != Phase 9A-R status or score mutation

Phase 9B2A 不创建 BehaviorEdge、AttackChain 或 reverse propagation；不写 Runtime/Evidence；
不调用 QEMU；不执行 fault、interrupt 或 DMA injection。Type III hardware→software objective
causal verification 必须由未来独立 intervention/observation contract 实现，不能从 temporal
order、单次 passive trace、interrupt-after-MMIO correlation 或 synthetic reverse edge 推导。
