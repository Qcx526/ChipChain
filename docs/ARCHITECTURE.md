# V2 架构

## 已实现：冻结至 V2-5A.2 + V2-5B.1 candidate contracts（待审查）

V2-2 冻结于 `chipchain-v2-2-stable` / `48f8925792a1afa829d20bc25841010e1a12faa2`。

```text
chipchain root       仅包版本
__main__ → cli       help/version shell
core                models / architecture / identity / provenance / address
                    target / artifacts / input / debug（仅声明与一致性校验）
behavior.processor  指令/访问/状态/事件/关系及单来源 fragment（数据合同）
adapters.processorfuzz  exact bytes → raw SI；raw + PF descriptor → SOURCE_DECLARED fragment
trigger             来源/目标 + 状态 preconditions + 行为/event steps + 显式 required order
evidence            byte-bound artifact / typed observation / scoped non-causal comparison
adapters.hardware_case  bytes → confirmed ISA CSV/log / RTL log / opaque signature records
anchors             SI labeled record ↔ hardware-test ELF symbol ↔ exact ELF bytes / trace PC+word
candidates          bounded source-backed context → explicit hypothesis proposal / reference consistency
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

V2-4 已冻结。V2-5A.1 新增的 `evidence → core / 公开 behavior` 与
`adapters.hardware_case → core / evidence` 为单向依赖；不导入 trigger、SI adapter 或 behavior 私有 helper。
core/behavior/trigger/root/CLI 及冻结 SI adapter 不反向加载 evidence/hardware-case adapter。
Evidence 的 `_profiles` 仅做局部词法一致性校验，无文件/后端访问，供 detached IR validation 使用；
adapter 接收单一 immutable bytes，计算 SHA，并创建源/记录。完整 artifact 再重建 exact bytes 复核 SHA/length。
raw_line 是规范载荷；PC、encoding、字段值等只读视图不作为第二份可独立修改的 serialized data。
记录 source ID + ordinal + raw payload 定义身份；相同 PC 的不同 occurrence 不会合并。

`AlignmentScope` 显式声明两方完整 source descriptors、common start、profile 和字段集。
alignment 只接受单一连续 ISA CSV 序列与唯一 RTL common start 后的连续 instruction-key 序列；
DELAYED 不强行归属任何 PC，boot/tail/delayed 未配对记录留在结果中。完整结果保留双方 artifact，
反序列化重新验证来源字节、逐对成员关系、顺序和比较，不能用内部一致的伪造 pair 替代原记录。
`RELIABLE_KEYS_PARTIAL_SEMANTICS` 不是单一 valid/verified boolean。
FieldComparison 只做 EQUAL/DIFFERENT/NOT_COMPARABLE/MISSING_LEFT/MISSING_RIGHT；
DivergenceObservation 绑定 scope/pair/field 和精确值/XOR，既不是 Processor Behavior fact，也不是 Trigger IR。
helper 的首个差异和前后 context 仅限该显式范围，不是 global first error 或 causal slice。

V2-5A.1 已由 `chipchain-v2-5a1-stable` 冻结于 `677f3228488f0f567cdf223850955530b8c546d4`。
新增 anchors 只依赖 stdlib/Pydantic、公开 core/behavior/evidence/ProcessorFuzz adapter 及自身模块。
所有下层与 root/CLI 均不反向导入 anchors；不导入 trigger、hardware_case adapter、firmware backend 或外部工具。
HardwareTestProgramELF 是硬件实验 test-program，不是 ImmutableFirmwareArtifact；当前没有固件团队输入。
小型 stdlib ELF parser 只保留 header/LOAD/section/symtab 必需视图。所有 anchor 服务重新解析 exact ELF bytes，
比较整个 view，并重新验证 SI/trace sources。持久化 anchor 模型只检查声明内部一致性，不能单靠反序列化认证 bytes；
对外 source-backed composition 必须携带原 sources 再现两侧 anchor。
可选 behavior reference 使用冻结 SOURCE_DECLARED mapper 再现 supplied fragment，不添加/解释额外语义。

关联仅为 SI 显式 label ↔ exact ELF symbol/address ↔ 32-bit LE trace word 的 file-backed bytes。
不向无标签邻居传播地址，不以 mnemonic/ordinal/假定步长制造编译映射；重复 trace occurrence 保留独立 ID。
ELF 地址始终是 hardware-test virtual address，不是 physical/MMIO/client firmware address。

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
V2-5A 只读审计已完成：bundle 并非 provenance-complete，stale disassembly 隔离，note unbound，
transition.db 混合且未解决。V2-5A.1 ingestion 支持受限 293-key common alignment；LLM 仍在下游。
V2-5A.2 hardware-side anchor binding 为 FROZEN；V2-5B.1 合同与有界上下文为 CURRENT / under review，
V2-5B.2 real/model reasoning 与 LLM-assisted extraction/reduction 未实现；
当前不实现提取、缩减、root-cause localization、firmware reachability 或跨层候选。
行为归一化与来源适配分离，架构专用 backend/profile 不改变核心的架构中立边界。
未来固件侧连接必须绑定同架构、同原始 firmware identity 与声明的分析范围；
当前 hardware-test anchors 仅绑定硬件实验 artifact sources，不能冒充固件侧连接。
RISC-V-first != RISC-V-only；架构标签不能作为实现声明。

LLM 未来承担 coordinator/reasoner，knowledge 提供上下文；两者都不能制造 processor ground truth。
历史能力只在 `archive/phase10-foundation` 保留，后续依据新合同迁移，不保留兼容 import 路径。

GDBFuzz `SUTConnection` 是 host-side abstraction，不是固件 API。bundled SerialConnection 的
ready-marker/length/testcase 协议需要匹配的示例固件逻辑；不能据此宣称任意固件无需适配。
客户端必须保持 original firmware，由未来 host adapter 适配已有 UART/CAN/USB 等端点协议。
Hardware breakpoint halt、single-step、reset 与软件断点可能扰动运行；文件 SHA 相同并不证明自然时序。

合同细节见 [DATA_CONTRACTS.md](DATA_CONTRACTS.md)，阶段安排见 [PLANS.md](../PLANS.md)。

## V2-5B.1：证据引用与候选假设分层

`candidates.facts` 是 compact source projection/typed reference/未解决项合同；`models` 是独立候选、
proposal support 与 rationale；`validation` 只检查同一 context/source/architecture 和引用闭包。
`context` 接收已经解析的 sources，以冻结 alignment/anchor APIs 构建上下文，不解析 SI，不直接调用 mapper。
candidate context has a narrow read-only dependency on the frozen ProcessorFuzz raw SI representation
solely to satisfy exact-source anchor reconstruction：唯一直接 adapter import 为 context.py 中的
`from chipchain.adapters.processorfuzz.models import RawProcessorFuzzSI`。
base/enums/facts/models/validation 不导入 adapter，所有冻结下层、root、CLI 不反向导入 candidates。
冻结 ProcessorFuzz 包初始化/anchor 内部仍可加载原 parser/mapper；该传递加载不是候选层直接调用授权。
AST 与 fresh-process firewall 分别约束直接依赖和上下层加载方向。

builder 重验完整 snapshots，但只输出有界 compact projections；逐标签 source inventory 检查不是
不受限的运行历史搜索，输出只保留与窗口 trace 成功组成的标签。不存在第二套 anchor 算法。
每一引用的 kind/fact_id/owner_id 一起解析：comparison 的 owner 是 pair，observation 的 owner 是 trace，
pair/divergence 的 owner 是 alignment result，anchor 的 owner 是 exact hardware-test ELF source。
原始 fact ID 保持不变。JSON 反序列化验证内部闭包，不能认证未提供的原始字节；source-backed builder
才重新消费实际 sources，候选验证也不将引用一致性宣传为来源认证或漏洞验证。

上下文不生成提议；独立 `HardwareTriggerCandidate` 内部使用 `HardwareTriggerSpec` 作为规范性 proposal
容器，不导出“已满足 trigger”。要求与 required order 始终 HYPOTHESIZED/UNSUPPORTED，候选固定 HYPOTHESIS。
rationale 与候选一起参与候选 ID，但不能更改 context/fact/requirement 身份或成为引用目标。
Evidence != Hypothesis；Candidate != Trigger Verification；Candidate != Vulnerability。
