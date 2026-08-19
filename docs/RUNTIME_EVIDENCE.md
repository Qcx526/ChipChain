# Runtime Evidence Contract

Phase 9B0 定义 backend-neutral、可审计、可离线验证的运行时数据合同。它不集成或运行
QEMU，不实现 active mutation、reverse verifier 或 VerificationPipeline aggregation。

```text
Runtime Backend → Trace Manifest → RuntimeObservation → Dynamic Evidence
                                                        ↓ future only
                                             Explicit Interaction Binding
```

五个不等式是硬边界：Runtime Observation != Vulnerability；Runtime Event != BehaviorEdge；
Temporal Order != Causality；Fault Intervention != Fault Observation；Dynamic Evidence !=
Verified Interaction。

## Backend 与 Capability

`RuntimeBackendKind` 只有 `qemu_tcg_plugin`、`external_trace`、`owned_fixture`。Fixture backend
只能用于 contract test/demo，不能计入正式 Benchmark。Manifest 显式保留 backend version，
并把 architecture、name/version、system-emulation 和排序后的 capabilities 纳入 identity。

Passive capabilities 包括 instruction/memory/physical-address/IO/value/register/discontinuity/
DMA observation；active capabilities 包括 state mutation、interrupt injection、fault injection。
Capability 是工具声明，不是 Evidence、VerificationStatus 或 Interaction capability。

## Trace、排序与持久化

`RuntimeRunMode` 区分 baseline、trigger、intervention。Intervention run 本身不证明因果。
Trace manifest 保存 artifact SHA-256、machine/CPU/vCPU、可选 Memory Map 以及 input/environment
fingerprint。模型不硬限制单 vCPU；Phase 9B1 observer 将先限定 `vcpu_count=1`。

Observation 用 `sequence_index` 作为 deterministic core ordering。可选 host timestamp 只用于
诊断，不参与 identity 或 verification。Trace 要求 sequence 与 observation ID 唯一、trace/
architecture 一致、vCPU index 有效，并按 sequence 排序。JSON envelope 是
`chipchain_runtime_trace` / version 1；load 会重新执行全部 Pydantic、identity、ordering 与
capability 校验，不信任磁盘内容。

## Event Contract

| Event | Required semantic fields | Required backend capability |
|---|---|---|
| instruction_exec | pc | instruction_execution |
| mmio_read/write | pc, physical_address, is_io=true, access_size | memory_access, physical_address, io_classification |
| interrupt_discontinuity | from_pc, to_pc | interrupt_discontinuity |
| exception_discontinuity | from_pc, to_pc | exception_discontinuity |
| dma_read/write | physical_address, access_size, device_id | device_dma_observation |

任何 event 带 value 时还要求 `value_width_bits` 与 backend `memory_value` capability。Interrupt
合同不强制 IRQ number；DMA 不强制 CPU PC。`address_space_id` 可为空，但多地址空间 resolver
不得仅以 paddr 模糊匹配。

## Intervention Boundary

`RuntimeIntervention` 使用独立 `RuntimeInterventionKind`，表示 interrupt assertion、DMA write、
device/MMIO response/register state override 等 controlled action。它不是 event，不会自动产生
Observation。Phase 9B0 没有 executor，不写 guest memory/register、不 raise IRQ、不注入 DMA
或 fault。Owned intervention fixture 带完整 synthetic/owned/non-benchmark provenance。

## Dynamic Evidence Meaning

Normalizer 只接受已验证 Trace 中的成员 Observation，复用 `EvidenceType.DYNAMIC_ANALYSIS`，
source=backend manifest ID，artifact=trace ID，
并保存 observation ID、event kind、sequence、vCPU 与相应地址/value/discontinuity 字段。
Evidence 保持 interaction-agnostic，不含 reference role/ID。`verified=true` 只表示 runtime
observation contract/integrity verified，不表示 vulnerability、causality 或 attack chain。

## Future Interaction Semantics

Type I runtime data可支持 trigger/transition occurred，但两侧漏洞需独立 provenance。Type II
runtime sequence 是重要证据，但 normal behavior observed 不确认 hardware vulnerability。
Type III 必须分开 Intervention、Observation、Inference、Verification；最低 causal design 是
可比 baseline + intervention runs，只改变受控 intervention，并观察 propagation/affected
execution 且 baseline 无等价 deviation。单纯 `A before B` 不构成 causal support。

未来同一 fact 可同时拥有 Static 与 Dynamic VerificationRecord。两者不得互相覆盖；需要
显式 multi-verifier aggregation 和 conflict policy，Phase 9B0 不实现。
