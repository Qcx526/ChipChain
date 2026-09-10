# ChipChain V2 路线图

V2-R0 已由 `chipchain-v2-r0-stable` 冻结于 `7e5a9c28e18f6b262a1e9dfca1200796e17fb4a8`。
V2-1 已由 `chipchain-v2-1-stable` 冻结于 `c7a0d7832e6da13c9fb0a68f3fd4fe3fbfef8c91`。
V2-2 Processor Behavior IR v1 已由 `chipchain-v2-2-stable` 冻结于
`48f8925792a1afa829d20bc25841010e1a12faa2`，包括 R1 的来源/性质分离与 occurrence 端点限制。
V2-3A.1 已由 `chipchain-v2-3a1-stable` 冻结于 `2b6b61b8cd8abcb5c68760c9a0f39a99dd59c6d0`。
V2-3B confirmed-profile raw parser 与保守 mapper 已由 `chipchain-v2-3b-stable` 冻结于
`7d42e325beb0385a0e8df16b204c7f8ea296eb5a`。
V2-4 已由 `chipchain-v2-4-stable` 冻结于 `798d7ee99b4529a00007874c886c5ec8a39d0a28`。
V2-5A Confirmed Case Output Semantics Audit 已完成（READ-ONLY），并未证明完整 run provenance。
V2-5A.1 为 CURRENT：Case Evidence IR、deterministic output adapters 与 non-causal alignment；待审查冻结。
V2-5A.2 SI/ELF/Trace Anchor Binding 与 V2-5B LLM-assisted Trigger Candidate Extraction / Reduction 均为 PLANNED。
RISC-V 为主实验架构；RISC-V-first != RISC-V-only。公共合同保持架构中立，
backend/profile/adapter 分别承担具体架构能力，架构标签不代表已有实现。

## 阶段顺序与退出条件

| 阶段 | 目标 | 退出条件 |
| --- | --- | --- |
| V2-R0 | Clean Mainline Reset | 最小 core、CLI、离线回归、依赖隔离和精简文档通过审查；归档引用不变 |
| V2-1 | Target / Source / External Input / Debug Contracts | 已冻结；精确固件绑定、来源分离、调试扰动词汇及离线负例；不定义业务结果 |
| V2-2 | Processor Behavior IR v1 | 已冻结；指令/访问/状态/事件、来源性质、分型关系、引用完整性与 synthetic 回归；无分析 |
| V2-3B | Confirmed ProcessorFuzz SI Structural Adapter | FROZEN；exact bytes/raw roundtrip、SOURCE_DECLARED-only mapper；不解码 |
| V2-4 | Hardware Trigger IR v1 | FROZEN；仅要求合同，来源/target、slot、位宽、引用与无环顺序检查；无提取或满足性判断 |
| V2-5A | Confirmed Case Output Semantics Audit | COMPLETED / READ-ONLY；输出语义部分可解释，不把 mismatch 当 trigger proof |
| V2-5A.1 | Case Evidence IR + Deterministic Adapters | CURRENT；exact bytes、lossless 分型、显式字段比较与连续 key 对齐；无因果/trigger/verification |
| V2-5A.2 | SI / ELF / Trace Anchor Binding | PLANNED；显式绑定经复核的跨 artifact anchors，不能依赖 stale disassembly |
| V2-5B | LLM-assisted Trigger Candidate Extraction / Reduction | PLANNED；下游 reasoning 不替代客观证据；缩减/候选需独立授权 |
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

V2-3B 已结构化解析该 exact confirmed SI：指令映射到
`InstructionBehavior(SOURCE_DECLARED)`，操作数只在确定性支持时映射到
`RegisterOperand` / `DeclaredOperand`，文本顺序映射到 `SOURCE_SEQUENCE`。
没有额外语义依据时不生成 access、control-transfer、event、privilege/register/memory state facts。
真实材料保持 local-only；默认测试使用 synthetic/授权 owned fixture，不依赖本地 case。
Parser profile `processorfuzz_si_confirmed_v1` 只覆盖当前 confirmed-case 语法，不是通用格式承诺。
Header/标签分组/尾列/data 布局仍未知，保留 raw，不投影为 state/CFG/runtime。
项目负责人补充声明 architecture=RISC-V、hardware model=Rocket、producer family=ProcessorFuzz 后，
允许以 `rocket-unspecified-config` / `processorfuzz-unspecified-profile` 进行当前 real SI 映射验收；
具体 revision/configuration、RV32/RV64、ISA extensions、工具 version/configuration 均不推断。
缺少来源声明的其他 real SI 仍只能先 structural parse，不得套用 synthetic provenance。

V2-4 只定义 Hardware Trigger requirements：状态 preconditions 与行为/event steps 分开；
slot 支持 A/B/A 重复节点但不隐含顺序，显式 order 只引用本 spec steps 并检查无环。
requirements 不是 facts，更不是 satisfied requirements 或漏洞结论；SOURCE_SEQUENCE 不自动转换成 required order。
真实 confirmed SI（包括其 368 条 behavior records）尚未提取/缩减为真实 trigger spec。
V2-5A 已专项审计这些输出及生产者语义。supplied disassembly 的 348 个可比较编码中 278 个与当前 ELF
不一致，保持隔离；note 未绑定当前 SI；transition records 混合/累积，缺少稳定 run identity。
全 bundle 只可声明 correlated artifact set，不能声称 authenticated single run。
V2-5A.1 实现 ISA CSV/log、RTL log 与 signatures 的局部格式合同：exact SHA/length、source side、
版本化 profile、分型 raw record + 只读 typed views；默认只比较八个经审计共同字段。
连续 common-program file order + PC + encoding 支持审计中的 293 对；不使用 COV、模糊匹配或插删猜测。
首次差异仅针对声明 scope；前一条指令是上下文，不是因果证据。CSV/log 对应保留为本地验收检查，
不扩大为生成来源证明。不投影 RUNTIME_OBSERVED behavior、不构造真实 trigger spec、不运行任何 simulator。
独立冻结后再讨论 V2-5A.2 与 V2-5B；当前不启动 anchor binding、LLM、提取或缩减。
本地验证：两种完整 pytest 调用均 739 passed；evidence/adapters `-W error` 为 243 passed，
dependency firewall 为 10 passed；compileall、两种 CLI help 与 diff 检查通过。
默认 tests 之后的真实只读验收复现 293 对、首个 scope 差异 index 128、signature 第 38/45/49 行差异；
真实值未进入永久 tests。101 个本地 case 文件的 SHA/长度不变；该验收不是模拟器重跑或漏洞验证。
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
