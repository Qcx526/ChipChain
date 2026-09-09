# V2 架构

## 已实现：R0 foundation + V2-1 source/target contracts

```text
chipchain root       仅包版本
__main__ → cli       help/version shell
core                models / architecture / identity / provenance / address
                    target / artifacts / input / debug（仅声明与一致性校验）
```

core 只依赖 Python 标准库与 Pydantic；它不加载 decoder、分析器、运行后端、模型服务或业务子系统。
`Architecture` 是共享词汇，`ProgramAddress` 是数值地址，`ArtifactProvenance` 是不可变来源声明。
当前没有 graph、analysis、adapter 或 verification package，也没有研究操作命令。

`HardwareTargetIdentity` 区分 client 与 ProcessorFuzz hardware；同架构不是同目标。
`ImmutableFirmwareArtifact` 组合来源 SHA、架构、硬件目标与可选 ISA profile。
`GDBFuzzArtifact` 和 `ExternalInputArtifact` 各自持有 detached exact firmware snapshot，
未来消费者用 `require_firmware(expected)` 显式复核，不通过模型名称推断绑定。
`ExternalInputEndpoint` 区分 transport 与 application protocol；delivery 单独保存主机工具、adapter、
framing、同步及 reset profile。`DebugProvenance` 分离原始镜像身份与运行扰动，不是观察 trace。

## 后续设计方向

```text
ProcessorFuzz SI → SI Adapter → Trigger Extraction / Reduction → Hardware Trigger IR
External Input → Original Immutable Firmware → Firmware Execution → Processor Behavior IR
Hardware Trigger IR + Processor Behavior IR → Trigger Matching + Anchored Reachability
                                           → 后续 evidence-backed Verification
```

上图全部研究模块尚未实现。核心问题是 `FirmwareExecutionPath |= HardwareTriggerSpecification ?`。
Trigger IR 合同可先于 Extractor 开发，但运行时提取结果进入 IR；两种顺序不能混淆。
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
