# V2 架构

## 已实现：R0 foundation

```text
chipchain root       仅包版本
__main__ → cli       help/version shell
core                models / architecture / identity / provenance / address
```

core 只依赖 Python 标准库与 Pydantic；它不加载 decoder、分析器、运行后端、模型服务或业务子系统。
`Architecture` 是共享词汇，`ProgramAddress` 是数值地址，`ArtifactProvenance` 是不可变来源声明。
当前没有 graph、analysis、adapter 或 verification package，也没有研究操作命令。

## 后续设计方向

```text
ProcessorFuzz → RISC-V SI → Trigger Extraction → Hardware Trigger IR
GDBFuzz → immutable original firmware → firmware behavior artifact
                  ↓
          Processor Behavior IR
                  ↓
       Trigger Matching + Anchored Reachability
                  ↓
         后续 evidence-backed Verification
```

上图全部研究模块尚未实现。核心问题是 `FirmwareExecutionPath |= HardwareTriggerSpecification ?`。
行为归一化与来源适配分离，架构专用 backend/profile 不改变核心的架构中立边界。
每次连接必须绑定同架构、同原始 firmware identity 与声明的分析范围。
RISC-V-first != RISC-V-only；架构标签不能作为实现声明。

LLM 未来承担 coordinator/reasoner，knowledge 提供上下文；两者都不能制造 processor ground truth。
历史能力只在 `archive/phase10-foundation` 保留，后续依据新合同迁移，不保留兼容 import 路径。

合同细节见 [DATA_CONTRACTS.md](DATA_CONTRACTS.md)，阶段安排见 [PLANS.md](../PLANS.md)。
