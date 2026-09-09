# ChipChain V2 路线图

当前 V2-R0 建立最小 foundation，后续阶段均为 planned / NOT IMPLEMENTED。
RISC-V 为主实验架构；RISC-V-first != RISC-V-only。公共合同保持架构中立，
backend/profile/adapter 分别承担具体架构能力，架构标签不代表已有实现。

## 阶段顺序与退出条件

| 阶段 | 目标 | 退出条件 |
| --- | --- | --- |
| V2-R0 | Clean Mainline Reset | 最小 core、CLI、离线回归、依赖隔离和精简文档通过审查；归档引用不变 |
| V2-1 | Core Contracts | 依据实际来源补齐版本化身份、来源与目标合同；不提前定义业务结果 |
| V2-2 | Processor Behavior IR | 定义架构中立行为词汇、来源、部分信息与未知项边界 |
| V2-3 | ProcessorFuzz RISC-V SI Adapter | 从已审阅真实格式解析 SI，保留原始 bytes/SHA 与 tool profile |
| V2-4 | Hardware Trigger IR | 显式表达行为、前置条件与硬件来源，不冒充 firmware 可达性 |
| V2-5 | Trigger Extraction / Reduction | 来源可重放的提取与缩减，保留未知条件与适用范围 |
| V2-6 | GDBFuzz Artifact Adapter | 绑定原始不可变 firmware、外部输入与 execution artifacts |
| V2-7 | RISC-V Firmware / angr → Processor Behavior IR | 审计实际 decoder/profile 输出，分离静态语义与运行观察 |
| V2-8 | Deterministic Trigger Matcher | 明确匹配规则、负例与未知项，不把候选称为漏洞 |
| V2-9 | Anchored Reachability / Feasibility | 将路径锚定具体目标、输入及假设，区分静态与实际到达 |
| V2-10 | RISC-V Type-II Minimal End-to-End | 同架构、同 firmware SHA 的最小闭环；不伪造 software vulnerability |
| V2-11 | Type-I Firmware Issue Integration | 独立证明 software issue 对硬件触发的 enabling link |

后续另行设计：历史 verification 迁移、JTAG evidence、Type III、其他架构、knowledge/RAG、
multi-agent reasoning。每项经过 Plan → Implement → Test → Review → Fix → Document。
未经独立安排，不以当前阶段名义提前实现后续模块。

## 未来客户端来源与不可变目标

ProcessorFuzz RISC-V hardware fuzzing → SI hardware testcase → Hardware Trigger。
GDBFuzz → original immutable firmware external-input fuzzing → firmware behavior artifact。
ChipChain 以 Processor Behavior + Trigger Extraction + Trigger Matching + Reachability 连接两侧。
共同研究问题是 `FirmwareExecutionPath |= HardwareTriggerSpecification ?`。

固定 client hardware 与原始 firmware 的 exact SHA 是目标边界。任何 patch、recompile、instruction insertion
或 JTAG/software-breakpoint code mutation 都不能替代原始目标的证据；注入状态不是自然到达状态。
LLM 后续仅负责协同与推理，knowledge 仅提供上下文，均不能替代确定性 processor facts。

## 历史与冻结流程

Phase-10 完整基础保存在只读 `archive/phase10-foundation` 与 `phase-10-foundation-final`，
共同指向 `769736f1279fa9d90847801670a8852a5579323e`；使用 `git show <ref>:<path>` 审阅。
V2 是同一仓库的普通后继开发，不使用 orphan、history rewrite 或旧 API compatibility shims。
V2-R0 工作树修改需审阅后独立授权 commit/push/tag；不得移动 main、archive 或 stable tags。
