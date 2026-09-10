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
V2-5A.1 已冻结于 `chipchain-v2-5a1-stable` / `677f3228488f0f567cdf223850955530b8c546d4`。
V2-5A.2 Hardware-Test SI/ELF/Trace Anchor Binding 已 FROZEN 于 `chipchain-v2-5a2-stable` /
`9e65cec9bca12a8e9512396a3d923371a2fe2cbb`。
V2-5B.1 Evidence-Bound Trigger Candidate Contract + Deterministic Candidate Context Builder
已 FROZEN 于 `chipchain-v2-5b1-stable` / `7fa3360f75799c3acc9cefa2a00e7aaac6f894a8`。
V2-5B.2 LLM-Assisted Hardware Trigger Candidate Proposal Boundary 为 CURRENT / under review；
V2-5B.2R real-provider validation 与 firmware-side integration 为 NOT IMPLEMENTED。
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
| V2-5A.1 | Case Evidence IR + Deterministic Adapters | FROZEN；exact bytes、lossless 分型、显式字段比较与连续 key 对齐；无因果/trigger/verification |
| V2-5A.2 | SI / Hardware-Test ELF / Trace Anchor Binding | FROZEN；exact bytes、unique symbol/LOAD、保留部分映射；不绑定 client firmware |
| V2-5B.1 | Evidence-Bound Trigger Candidate / Bounded Context | FROZEN；typed scoped refs、HYPOTHESIS-only proposals、有界事实视图与未解决项 |
| V2-5B.2 | LLM-Assisted Candidate Proposal Boundary | CURRENT，待审查；strict JSON、exact context refs、ABSTAIN；离线 fake-only 测试 |
| V2-5B.2R | Real-provider validation | NOT IMPLEMENTED；须冻结当前合同后独立授权 |
| V2-6 | GDBFuzz Artifact / External Input Adapter | NOT IMPLEMENTED；绑定原始不可变 firmware、既有端点与 execution artifacts |
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
V2-5A.1 已冻结；以下为该阶段历史验收，不代表 V2-5A.2 的测试计数。
V2-5A.1 本地验证：两种完整 pytest 调用均 739 passed；evidence/adapters `-W error` 为 243 passed，
dependency firewall 为 10 passed；compileall、两种 CLI help 与 diff 检查通过。
默认 tests 之后的真实只读验收复现 293 对、首个 scope 差异 index 128、signature 第 38/45/49 行差异；
真实值未进入永久 tests。101 个本地 case 文件的 SHA/长度不变；该验收不是模拟器重跑或漏洞验证。

V2-5A.2 新增独立 anchors 层：只解析 hardware-test ELF 的 ELF64 LE/RISC-V/ET_EXEC 局部 profile，
以 exact SI record label + unique defined ELF symbol 建立相关关系，以 unique file-backed LOAD bytes
核对 32-bit textual trace word。创建/组合入口都重新消费 exact ELF bytes 并复现 parsed view，
同时重新验证 SI/trace snapshots；不能用 caller-mutated descriptor 制造来源。
当前 ELF 是硬件团队实验侧 testcase，不是 client/deployed/GDBFuzz firmware；项目尚未接入固件团队 artifact。
203/208 是前期审计的标签存在性结果，不是 368 条 SI 指令的编译映射证明；无标签、缺失和歧义项不推算地址。
本轮不实现完整 .S compilation mapping、提取、缩减、因果、LLM、固件可达性或跨层候选。
V2-5A.2 真实只读验收：203 个 unique label anchors、5 个缺失、0 个歧义；ISA 293 条与 RTL 321 条
instruction observations 独立 byte-anchor，5 条 RTL boot records 无 LOAD mapping，DELAYED 34 条独立。
SI-label/ELF/trace composed anchors 每侧仅 10 个。首差异两侧 bytes 同源，但没有对应 SI label anchor；
不反推 source instruction、不作因果结论。四份消费 artifact 的前后 SHA/长度完全一致。
V2-5A.2 本地验证：完整离线 pytest 852 passed；anchors + dependency firewall 的 `-W error`
为 123 passed；compileall、两种 CLI help 与 diff 检查通过。上述为 V2-5A.2 历史验收；现已冻结。
Confirmed SI + ISA-side artifact + RTL-side artifact + signature/comparison material 将来可能支持
trigger feature extraction、reduction、root-cause localization 与跨层验证规划；这些能力当前均未实现。

## V2-5B.1 已冻结范围

新增独立 `candidates` 层，单向消费公开 core/behavior/evidence/anchors/trigger。
经项目负责人单独批准，只有 context builder 可直接导入
`chipchain.adapters.processorfuzz.models.RawProcessorFuzzSI`，用于冻结 anchor API 的 exact-source
重建；不是允许 candidates 直接使用 parser/mapper 或一般 adapter 能力。冻结 production 层不修改。

`build_trigger_candidate_context` detached revalidate raw/source/ELF/alignment/divergence，检查成员关系，
选择 before/after 各 0..8 的邻近窗口，再用冻结 APIs 重现 anchors。默认 5/3，至多 17 对；
compact JSON 上限 256 KiB，不包含完整 SI/trace/ELF、signatures 或隔离材料。
只列入成功组成窗口内 observation correlation 的 SI records/optional existing behaviors。
缺少 SI/ELF/trace linkage 必须保留，不传播标签、不回溯推算、不排名。

`HardwareTriggerCandidate` 独立包裹 proposed V2-4 requirements；每个要求/顺序都有唯一 support，
有参考只能 HYPOTHESIZED，无参考必须 UNSUPPORTED，不能通过观察或共识变成满足性结论。
typed reference 同时绑定 kind、原 fact ID 与 source/parent owner，避免重复 comparison ID 串用。
validate 只返回 detached hypothesis；所有 context 未解决项保持开放。rationale 不是事实或 evidence level。
上下文生成不是提取：真实只读验收不得生成 candidate 或 HardwareTriggerSpec。
本阶段不实现 provider、prompt、缩减、因果、matcher、固件输入与可达性。下述为 V2-5B.1 历史验收。

V2-5B.1 本地只读验收：重现原 293 对 alignment，selected divergence ordinal 128；默认 before=5/after=3
得到 123–131 共 9 对。两侧合计 18 个 ELF trace anchors，窗口内 direct SI composed anchors 为 0，
18 个 NO_DIRECT_SI_LABEL_ANCHOR 与 9 个来源/科研未解决项保留。前后四份源文件 SHA/长度相同，
重复构建与序列化完全一致；构造器 guard 确认未生成真实 candidate/HardwareTriggerSpec。
该验收不重跑模拟器，不回答因果、必要/充分性或 client firmware reachability。
本地验证：完整离线 pytest 989 passed；candidates + dependency firewall 的 `-W error` 检查
148 passed；compileall、两种 CLI help、`git diff --check` 通过。所有冻结 production 文件与 CLI
portability test 无 diff，真实材料无 tracked entries；现已由 V2-5B.1 stable tag 冻结。

## V2-5B.2 当前实施范围（under review）

独立 `reasoning.trigger_candidate` 只直接消费公开 core/candidates/trigger；不修改冻结 production。
请求绑定 frozen context ID/view、派生 fact-reference / unresolved-ID 索引、固定规则、schema 和 declared provider。
system instructions 与 untrusted context DATA 通过确定性 JSON envelope 分开，不把来源文本拼入规则。
这不是对任意 LLM prompt injection 的免疫证明；最终 strict parsing 与 frozen candidate validation 不可跳过。

v1 proposal DTO 支持 mnemonic-only instruction、gpr/system register-access、exact register-state 及显式
required order；不支持其他 V2-4 类型或指令 operands。局部 proposal IDs 只用于响应内部引用，
source/architecture/最终 requirement IDs 由确定性代码绑定，sorted local IDs 分配的 slot 不代表执行顺序。
每个 requirement/order 都需要唯一非空 support，材料化后仅为 HYPOTHESIZED。
ABSTAIN 要求无 requirements/orders/supports，仍保留全部 unresolved IDs；不是已验证的 negative result。

parser 拒绝 Markdown、额外 prose/多文档、重复键、float/NaN/Infinity、未知字段、非法类型/引用；
无自动 repair/retry/fallback。response provenance 只保存 declared provider/model/request/context 与 exact raw SHA/长度，
不把 transport metadata 写入 candidate。响应上限 64 KiB；所有永久 provider 测试离线、deterministic fake-only。
V2-5B.2R 真实 provider、网络/密钥加载、多 agent、RAG、缩减、verification、因果、固件分析及跨层匹配均未实现。

V2-5B.2 本地检查：完整离线 pytest 1137 passed；reasoning + dependency firewall 的 `-W error`
为 168 passed；compileall、两种 CLI help 与 diff 检查通过。冻结 production 与 CLI portability test 无 diff。
tests 后真实只读 request-only 验收：沿用原 context ID，118 个 fact refs、27 个 unresolved conditions，
其中 18 个 missing SI linkage（selected divergence 两侧均保留）；prompt 89396 UTF-8 bytes。
重复 request/prompt 一致，四份源文件前后 SHA/长度一致；provider calls=0，candidate/spec 构造 guard 通过。
本轮未暂存、未 commit/push/tag，V2-5B.2 仍待人工审查。

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
