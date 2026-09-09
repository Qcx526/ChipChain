# V2 架构

## 已实现：冻结 core/behavior/adapter + 本地 V2-4 requirement IR

V2-2 冻结于 `chipchain-v2-2-stable` / `48f8925792a1afa829d20bc25841010e1a12faa2`。

```text
chipchain root       仅包版本
__main__ → cli       help/version shell
core                models / architecture / identity / provenance / address
                    target / artifacts / input / debug（仅声明与一致性校验）
behavior.processor  指令/访问/状态/事件/关系及单来源 fragment（数据合同）
adapters.processorfuzz  exact bytes → raw SI；raw + PF descriptor → SOURCE_DECLARED fragment
trigger             来源/目标 + 状态 preconditions + 行为/event steps + 显式 required order
```

core 只依赖 Python 标准库与 Pydantic；它不加载 decoder、分析器、运行后端、模型服务或业务子系统。
`Architecture` 是共享词汇，`ProgramAddress` 是数值地址，`ArtifactProvenance` 是不可变来源声明。
当前没有 graph、analysis 或 verification package，也没有研究操作命令。
SI adapter 仅依赖 stdlib/Pydantic/core/behavior；core/behavior/root/CLI 不反向导入 adapter。
Parser 不需要 hardware metadata，也不读文件；mapper 才 detached revalidate raw/source、核对 RISC-V 与 SHA。
Raw 保留每条原始指令行，重建 bytes 复核 SHA/length，避免反序列化修改字段后沿用旧 provenance。
V2-3B 已冻结于 `chipchain-v2-3b-stable` / `7d42e325beb0385a0e8df16b204c7f8ea296eb5a`。

V2-4 的 `trigger → 公开 behavior/core` 是单向依赖，不导入 adapter 或 behavior 私有工具；
trigger 自有 identity/binding helpers。core/behavior/adapters/root/CLI 均不反向导入 trigger。
IR 只做要求的内部合法性检查，未连接 parser/mapper，不做提取、求值、匹配、运行或 verification。
规范性 requirement 没有 BehaviorFactNature，不能冒充已发生事实。
单一 source context 保留完整 hardware target 与声明的 artifact/producer；ProcessorFuzz 来源还需 exact descriptor。
preconditions/steps 为无序语义集合，slot 只标识节点，顺序只由 required order 声明。
SOURCE_SEQUENCE != REQUIRED_PRECEDES；required adjacency != observed adjacency。

`HardwareTargetIdentity` 区分 client 与 ProcessorFuzz hardware；同架构不是同目标。
`ImmutableFirmwareArtifact` 组合来源 SHA、架构、硬件目标与可选 ISA profile。
`GDBFuzzArtifact` 和 `ExternalInputArtifact` 各自持有 detached exact firmware snapshot，
未来消费者用 `require_firmware(expected)` 显式复核，不通过模型名称推断绑定。
`ExternalInputEndpoint` 区分 transport 与 application protocol；delivery 单独保存主机工具、adapter、
framing、同步及 reset profile。`DebugProvenance` 分离原始镜像身份与运行扰动，不是观察 trace。

依赖方向为 behavior → core；core/root/CLI 不导入 behavior，二者均不依赖后端。
`BehaviorSourceContext` 复用 V2-1 firmware/ProcessorFuzz descriptors，显式绑定 artifact ID/SHA、target、
producer profile。一个 `ProcessorBehaviorFragment` 只包含同一 context 的事实集合；每条事实独立声明 nature。
instruction ordinal 不生成 program address；数据地址是独立 `MemoryAddress`，不推断 MMIO。
register access 不携带 value；精确/未知 state fact 独立存在，也不是 Trigger requirement。
SOURCE_SEQUENCE、STATIC_CFG_SUCCESSOR、DATA/CONTROL_DEPENDENCY 与 RUNTIME_PRECEDES 不互相替代。
同一 firmware context 可组合 STATIC_DECODED 指令与 STATIC_INFERRED 关系；混合 nature 不放宽来源/目标绑定。
InstructionBehavior 是源指令描述，不是运行 occurrence；ProcessorEvent 的 occurrence_ordinal 显式区分重复执行。
RUNTIME_PRECEDES 只连接 runtime/显式 synthetic occurrences，不连接静态 CFG 节点，不表示 causality。

## 后续设计方向

Hardware Case Bundle 仅是文档级来源分类，不是 Python production contract。
当前硬件团队报告有效的 SI 是 V2-3B 的 real-format anchor；配套 compiled artifacts、ISA/RTL
trace/log、signatures 和 context/build outputs 不会自动成为 ChipChain Evidence 或漏洞结论。
完整材料保持 local-only，现有文件位置不被自动重组。

```text
ProcessorFuzz SI → SI Adapter → Processor Behavior IR → Trigger Extraction / Reduction → Hardware Trigger IR
External Input → Original Immutable Firmware → Firmware Execution → Processor Behavior IR
Hardware Trigger IR + Processor Behavior IR → Trigger Matching + Anchored Reachability
                                           → 后续 evidence-backed Verification
```

上图已实现 Processor Behavior IR、confirmed SI structural adapter 与 Hardware Trigger requirement IR；
执行、提取、匹配、可达性与验证均未实现。真实 confirmed SI 尚未缩减或构造为真实 trigger spec。
核心问题是 `FirmwareExecutionPath |= HardwareTriggerSpecification ?`，当前合同不回答该问题。
Trigger IR 合同可先于 Extractor 开发，但运行时提取结果进入 IR；两种顺序不能混淆。
V2-3B 的首个 adapter 只做 confirmed SI 结构解析与 SOURCE_DECLARED 指令/操作数/顺序投影。
V2-4 定义 Trigger IR 后，V2-5A 先专项审计 case 输出的实际语义与 provenance，V2-5B 再提取/缩减，
再讨论 feature extraction、reduction、root-cause localization 和跨层验证规划；当前不实现这些能力。
行为归一化与来源适配分离，架构专用 backend/profile 不改变核心的架构中立边界。
每次连接必须绑定同架构、同原始 firmware identity 与声明的分析范围。
RISC-V-first != RISC-V-only；架构标签不能作为实现声明。

LLM 未来承担 coordinator/reasoner，knowledge 提供上下文；两者都不能制造 processor ground truth。
历史能力只在 `archive/phase10-foundation` 保留，后续依据新合同迁移，不保留兼容 import 路径。

GDBFuzz `SUTConnection` 是 host-side abstraction，不是固件 API。bundled SerialConnection 的
ready-marker/length/testcase 协议需要匹配的示例固件逻辑；不能据此宣称任意固件无需适配。
客户端必须保持 original firmware，由未来 host adapter 适配已有 UART/CAN/USB 等端点协议。
Hardware breakpoint halt、single-step、reset 与软件断点可能扰动运行；文件 SHA 相同并不证明自然时序。

合同细节见 [DATA_CONTRACTS.md](DATA_CONTRACTS.md)，阶段安排见 [PLANS.md](../PLANS.md)。
