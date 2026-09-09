# ChipChain V2 路线图

V2-R0 已由 `chipchain-v2-r0-stable` 冻结于 `7e5a9c28e18f6b262a1e9dfca1200796e17fb4a8`。
V2-1 已由 `chipchain-v2-1-stable` 冻结于 `c7a0d7832e6da13c9fb0a68f3fd4fe3fbfef8c91`。
V2-2 Processor Behavior IR v1 已由 `chipchain-v2-2-stable` 冻结于
`48f8925792a1afa829d20bc25841010e1a12faa2`，包括 R1 的来源/性质分离与 occurrence 端点限制。
V2-3A.1 仅更新 confirmed-case 输入基线和文档；V2-3B 及以后能力均为 planned / NOT IMPLEMENTED。
RISC-V 为主实验架构；RISC-V-first != RISC-V-only。公共合同保持架构中立，
backend/profile/adapter 分别承担具体架构能力，架构标签不代表已有实现。

## 阶段顺序与退出条件

| 阶段 | 目标 | 退出条件 |
| --- | --- | --- |
| V2-R0 | Clean Mainline Reset | 最小 core、CLI、离线回归、依赖隔离和精简文档通过审查；归档引用不变 |
| V2-1 | Target / Source / External Input / Debug Contracts | 已冻结；精确固件绑定、来源分离、调试扰动词汇及离线负例；不定义业务结果 |
| V2-2 | Processor Behavior IR v1 | 已冻结；指令/访问/状态/事件、来源性质、分型关系、引用完整性与 synthetic 回归；无分析 |
| V2-3B | Confirmed ProcessorFuzz SI Structural Parser | 以当前 confirmed case 的 exact SI 为首要真实验收输入；保留 raw bytes/SHA 与 tool profile，仅投影 SOURCE_DECLARED |
| V2-4 | Hardware Trigger IR | 显式表达行为、前置条件与硬件来源，不冒充 firmware 可达性 |
| V2-5 | Trigger Extraction / Reduction | 先完成 case 输出及生产者语义专项审计，再实现来源可重放的提取/缩减，保留未知条件与适用范围 |
| V2-6 | GDBFuzz Artifact / External Input Adapter | 绑定原始不可变 firmware、既有端点与 execution artifacts |
| V2-7 | RISC-V Firmware / angr → Processor Behavior IR | 审计实际 decoder/profile 输出，分离静态语义与运行观察 |
| V2-8 | Deterministic Trigger Matcher | 明确匹配规则、负例与未知项，不把候选称为漏洞 |
| V2-9 | Anchored Reachability / Feasibility | 将路径锚定具体目标、输入及假设，区分静态与实际到达 |
| V2-10 | RISC-V Type-II Minimal End-to-End | 同架构、同 firmware SHA 的最小闭环；不伪造 software vulnerability |
| V2-11 | Type-I Firmware Issue Integration | 独立证明 software issue 对硬件触发的 enabling link |

后续另行设计：历史 verification 迁移、JTAG evidence、Type III、其他架构、knowledge/RAG、
multi-agent reasoning、大规模 benchmark。每项经过 Plan → Implement → Test → Review → Fix → Document。
未经独立安排，不以当前阶段名义提前实现后续模块。

## 当前真实硬件输入与下一步

当前 real-format anchor 是完整 Hardware Case Bundle 中由硬件团队报告有效的 SI
（hardware-team-confirmed valid SI testcase），不是 ChipChain 独立验证的硬件漏洞。
本地 case 路径与 exact SI SHA 见 [数据合同](docs/DATA_CONTRACTS.md#本地-hardware-case-bundle文档级概念)。
V2-3A 的旧 19-SI candidate-corpus 审计已被此次输入更正取代；旧候选集合不作为必需回归集、
benchmark、confirmed bug dataset 或权威 parser acceptance set。

V2-3B 首先回答能否结构化解析该 exact confirmed SI：指令映射到
`InstructionBehavior(SOURCE_DECLARED)`，操作数只在确定性支持时映射到
`RegisterOperand` / `DeclaredOperand`，文本顺序映射到 `SOURCE_SEQUENCE`。
没有额外语义依据时不生成 access、control-transfer、event、privilege/register/memory state facts。
真实材料保持 local-only；默认测试使用 synthetic/授权 owned fixture，不依赖本地 case。

V2-4 先定义 Hardware Trigger IR；V2-5 之前或其初始阶段专项审计 ISA/RTL trace/log、signatures、
transition database、compiled artifacts 的实际内容和生产者语义，再进入 Trigger Extraction / Reduction。
Confirmed SI + ISA-side artifact + RTL-side artifact + signature/comparison material 将来可能支持
trigger feature extraction、reduction、root-cause localization 与跨层验证规划；这些能力当前均未实现。

## 未来客户端来源与不可变目标

运行数据流：ProcessorFuzz SI → SI Adapter → Processor Behavior IR → Trigger Extraction / Reduction → Hardware Trigger IR。
External Input → Original Immutable Firmware → Firmware Execution → Processor Behavior IR。
开发时 V2-4 先定义 Trigger IR、V2-5 再实现提取；开发顺序不等于运行数据流。
GDBFuzz 是未来 host-side 外部输入来源；主机适配器必须匹配既有固件协议，不添加 firmware harness。
ChipChain 以 Processor Behavior + Trigger Extraction + Trigger Matching + Reachability 连接两侧。
共同研究问题是 `FirmwareExecutionPath |= HardwareTriggerSpecification ?`。

固定 client hardware 与原始 firmware 的 exact SHA 是目标边界。任何 patch、recompile、instruction insertion
或 JTAG/software-breakpoint code mutation 都不能替代原始目标的证据；注入状态不是自然到达状态。
LLM 后续仅负责协同与推理，knowledge 仅提供上下文，均不能替代确定性 processor facts。

## 历史与冻结流程

Phase-10 完整基础保存在只读 `archive/phase10-foundation` 与 `phase-10-foundation-final`，
共同指向 `769736f1279fa9d90847801670a8852a5579323e`；使用 `git show <ref>:<path>` 审阅。
V2 是同一仓库的普通后继开发，不使用 orphan、history rewrite 或旧 API compatibility shims。
冻结 V2-2 不因本次文档更新而变化；后续工作需审阅后独立授权 commit/push/tag，不得移动 main、archive 或 stable tags。
