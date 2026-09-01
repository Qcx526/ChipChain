# ChipChain 阶段计划

## 当前状态

Phase 0～Phase 9B2C、Phase 9C Step 1～3A 与 Step 4、Phase 10A Step 1～3、Phase 10B、Phase 10C、Phase 10D Step 1～7、Step 8A、Step 8B-0、Step 8B-1A～1E、Step 8B-2B0、Step 8B-2B1、Step 8B-2B2-A、Step 8B-2B2-B、Step 8B-2B2-C1 与 Step 8B-2B2-C2 已完成并冻结；Step 8B-2D1 已完成实现、等待 final review；
Step 3B 仍未实现。Phase 9A-R
在不改变 Phase 4B～8 API 的前提下，将旧版
非 LLM verification primitives 迁移到三类 interaction，并引入显式 binding、类型化
requirements/score、能力状态和角色化定位。

Phase 9A-R1 进一步收紧 Evidence subject linkage、Node binding、substantive status、
capability ceiling、feature scope/provenance 与 supporting-evidence localization。
Phase 9A-R2 最终强化 binding-aware transition、Evidence collision、vulnerability Evidence
boundary 与 result type/direction identity。
Phase 9A-R3 强制每个 semantic interaction reference 至多一个 source binding，并对结果中
各 VerificationRecord 集合增加 deterministic ID uniqueness 防御。Phase 9B0 已建立独立、
backend-neutral Runtime Trace/Observation/Intervention contract 与 Dynamic Evidence normalization；
Phase 9B1 topology-grounded observer 已在 Ubuntu 22.04、QEMU 11.0.3、ARM32
`virt` / `cortex-a15` / 单 vCPU 环境通过 real acceptance，并由 `phase-9b1-stable` 封存。
Phase 9B2A 已完成显式 Dynamic Trigger Fact/Observation Binding、detached runtime
observation verification 与只读 Static/Dynamic aggregation。Phase 9B2B Step 1～7 已完成
非验证 reasoning contracts、固定多 Agent 编排、离线知识检索、Mock reasoning engine、
feedback loop 与 dynamic evidence context binding。
Phase 9B2C Step 1 已将现有 OpenAI-compatible transport 桥接到单角色 ReasoningEngine，
通过由 parser DTO 生成的 strict JSON Schema 完成 provider 结构约束，并在真实 CODE role
acceptance 中通过 constrained parser。Step 2 已完成 provider-backed 四角色串行 workflow、
LLM semantic proposal 与确定性 Context/role binding 分离，并通过真实四角色 acceptance。
Step 3 已完成 reduced semantic contract v2 版本化、旧 v1 fail-closed 拒绝、实际 Provider
调用观测与顺序/同 Context release acceptance hardening；Phase 9B2C 已完成。

Phase 9B0-R1 为 Persistence 与 Dynamic Evidence normalization 建立统一 detached snapshot
revalidation，阻断 RuntimeTrace/backend container 的 post-validation mutation 绕过。

## Phase 0：工程初始化（已完成）

目标：建立可安装、可运行、可测试的最小 Python 工程。

- [x] 明确 ARM MVP 的项目范围和非目标
- [x] 设计总体架构、数据模型和评测方法
- [x] 建立 `src/chipchain`、`tests`、`docs`、`examples`、`data`、`configs`、`scripts`
- [x] 提供基础 CLI 和模块入口
- [x] 在项目环境中安装开发依赖并运行测试
- [x] 验证已安装的 `chipchain --help`

退出条件：CLI 两种调用方式均可工作，全部基础测试通过，文档和实际工程一致。

## Phase 1：数据模型（已完成）

目标：把漏洞、行为、证据和攻击链定义为严格、可序列化的数据契约。

- [x] 使用 Pydantic 实现漏洞、行为、硬件、图、证据和线性攻击链模型
- [x] 实现 JSON 序列化、反序列化、Schema 导出和跨字段校验
- [x] 增加明确标记为 `fixture` 的 ARM 漏洞样本与候选攻击链
- [x] 覆盖来源、枚举、额外字段、跨架构、顺序、连接、评分和证据测试

退出条件：所有模型可 round-trip，非法数据被可靠拒绝，fixture 来源和性质清晰。

## Phase 2：Graph MVP（已完成）

目标：建立存储无关、可持久化、可确定性查询的跨层行为图基础。

- [x] 实现 `GraphRepository` 抽象与明确异常类型
- [x] 使用 NetworkX `MultiDiGraph` 实现节点、并行边和方向查询
- [x] 实现 architecture、layer 和 relation 过滤
- [x] 实现按 hop、node ID、edge ID 稳定排序的有向简单路径搜索
- [x] 实现版本化 JSON `GraphSnapshot` 保存和重新校验加载
- [x] 保留并行 Edge 与 `evidence_ids`
- [x] 提供明确标记为 fixture 的 ARM Demo Graph 和示例脚本
- [x] 覆盖重复 ID、悬空端点、跨架构、循环、过滤、持久化与损坏输入测试

退出条件：GraphRepository、MultiDiGraph、ARM Demo、过滤、路径搜索、确定性、并行边、JSON round-trip、Evidence ID 和全部回归测试均通过。

## Phase 3：Program Analysis MVP（已完成）

目标：以存储无关 ProgramAnalyzer 和可审计 DemoProgramSpec 打通程序观察到 Behavior Graph 的确定性闭环。

- [x] 实现 `ProgramAnalyzer`、`ProgramArtifact` 和 `ProgramAnalysisResult`
- [x] 实现独立的 DemoProgramSpec 输入模型及跨字段校验
- [x] 从 JSON fixture 转换 Function、CALLS、ioctl 和 MMIO 观察
- [x] 为每条行为 Edge 生成分离的 Static Evidence 和 call-site/MMIO 位置
- [x] 使用 metadata 标记 Sensitive Function，不产生漏洞结论
- [x] 实现 AnalysisResult 到 GraphRepository 的 preflight、重校验和防御性回滚
- [x] 实现 Program Spec → Analyzer → Repository → GraphPath 示例
- [x] 记录 planned / not implemented 的 angr 集成和真实 MMIO 技术风险
- [x] 覆盖输入、确定性、Evidence、架构、原子性和端到端回归测试

退出条件：抽象、结果契约、DemoAnalyzer、Evidence、Ingestion、ARM Demo、GraphPath、全部回归测试和 angr 计划均完成，且未实现 angr 或 Phase 4。

## Phase 4：Real ARM Static Analysis / AngrAnalyzer（已完成）

目标：使用可选 angr 后端，把自有 ARM ELF 的真实机器码转换成现有程序分析
结果和行为图事实，不执行漏洞检测或攻击链推理。

- [x] 在 Windows / Python 3.14.6 隔离环境验证 angr 9.3.2 安装、导入、Project 和 CFGFast
- [x] 将 angr 固定在独立 optional dependency group，基础与 dev 安装不强制引入
- [x] 实现 `AngrAnalyzer(ProgramAnalyzer)`，保持 `ProgramAnalysisResult` 契约
- [x] 限定 ARM ELF、`auto_load_libs=False`、CFGFast 和 main object 分析范围
- [x] 恢复 Function address/name 和稳定无符号名称，不按名称推断安全语义
- [x] 恢复对象内 CALLS，并为每条 Edge 生成精确 call-site Static Evidence
- [x] 统计未解析间接调用，不生成猜测 callee 或伪造 CALLS
- [x] 建立自有可重复生成的 synthetic ARM A32 ELF、源码、脚本、SHA-256 和 Ground Truth
- [x] 复用现有 Ingestion 与 GraphRepository，查询真实机器码恢复的 GraphPath
- [x] 提供端到端 Demo、可选测试 marker、错误包装、确定性和完整回归测试
- [x] 将真实 MMIO 地址解析明确延后，不把普通 LDR/STR 当作 MMIO

退出条件：当前隔离环境可运行 angr；可审计 ARM ELF 能生成 Function、CALLS 和
call-site Evidence；结果可 round-trip、Ingest 和查询 GraphPath；未解析调用不被
伪造；全部测试通过；未产生漏洞结论或提前实现后续阶段。

## Phase 4B：Real ARM MMIO / Cross-Layer Observation（已完成）

目标：从真实 ARM load/store 的可解析 effective address 出发，只有命中显式
Memory Map 时才生成软件到硬件 MMIO 行为边。

- [x] 为 `ProgramArtifact` 增加默认 firmware、严格限于 firmware/driver 的 `program_layer`
- [x] 实现架构绑定、规范十六进制、包含端点、无重叠的 `MemoryMap` / `MemoryRegion`
- [x] 通过 `AngrAnalyzer(memory_map=...)` 注入配置，保持 `analyze(artifact)` 契约
- [x] 使用未优化 VEX IR 做块内寄存器/临时变量常量传播，不按指令类型猜 MMIO
- [x] 建立独立自有 ARM MMIO ELF、源码、生成脚本、SHA-256、Memory Map 和 Ground Truth
- [x] 恢复已解析 MMIO_READ/MMIO_WRITE、确定性 Hardware Node 和 Static Evidence
- [x] 普通 RAM 与 unresolved/symbolic 地址只记录诊断，不生成 MMIO Edge
- [x] 保留 Function、CALLS、call-site Evidence 和 unresolved call 语义
- [x] 复用 `ProgramAnalysisResult`、Ingestion、GraphRepository 和 GraphPath
- [x] 完成 Driver Function → Hardware Register 真实跨层 Demo 和完整回归测试

退出条件：Program Layer 与 Memory Map 输入严格可验证；只有真实 load/store 的
可靠地址命中显式 MMIO region 才产生 Edge；RAM/unresolved 不误判；CALLS 保持；
结果可 round-trip、Ingest 并查询 software→hardware GraphPath；未生成漏洞结论，
未开始 Phase 5。

## Phase 5：Vulnerability Knowledge Graph MVP（已完成）

目标：把严格 `VulnerabilitySample` 确定性转换为独立、可持久化、保留证据的
ARM 漏洞知识图，不执行候选链搜索或跨图融合。

- [x] 实现独立 KnowledgeNode/KnowledgeEdge/KnowledgeGraphBundle 和知识关系枚举
- [x] 只允许全局 CWE/CAPEC 省略 architecture，具体实体和 Edge 保持 ARM 一致
- [x] 实现确定性 VulnerabilityKnowledgeBuilder 与稳定、样本作用域实体 ID
- [x] 对 Evidence 做 `sample:<sample-id>:evidence:<local-id>` 命名空间复制
- [x] 将 Trigger/Precondition 保留为节点，不发明缺失证据
- [x] 实现独立 KnowledgeGraphRepository 和 NetworkX MultiDiGraph 后端
- [x] 实现 `chipchain_knowledge_graph` v1 JSON 快照、Evidence 目录和重新校验加载
- [x] 定义 address、Memory Map、component 和 interface canonical match keys
- [x] 建立与 Phase 4B `0x40000000` 硬件锚点一致的自有 synthetic ARM fixture
- [x] 强化 Register MemoryRegion 必须为单地址，并完成测试、Demo 和文档

退出条件：知识模型、转换、证据命名空间、存储、持久化、全局 taxonomy 去重、
ARM 硬件匹配键和完整回归均通过；两张图仍无跨图 Edge，未实现 Phase 6。

## Phase 6：Exact Entity Linking + Candidate Search（已完成）

目标：保持 Behavior Graph 与 Knowledge Graph 独立，以精确硬件身份锚点关联可达
程序路径和已有漏洞知识上下文，生成未验证的结构候选。

- [x] 实现独立 EntityLink、EntityLinkResult 和 exact_canonical_key 方法
- [x] 仅链接 Register/HardwareResource → Knowledge HardwareResource
- [x] architecture 先行过滤并支持一个 Behavior Anchor 对多个 Knowledge Resource
- [x] 为 GraphRepository 增加遍历期 `allowed_relations` 向后兼容过滤
- [x] 实现 CrossGraphCandidate、稳定 ID、跨层和 Hardware layer 约束
- [x] 从 linkable anchor 反推目标路径，不枚举全部无目标路径
- [x] 按原方向发现 Vulnerability → TARGETS_RESOURCE → HardwareResource
- [x] 收集 Vulnerability 的一跳 Trigger/Precondition/CWE/CAPEC/Impact 等上下文
- [x] 聚合 Behavior/Knowledge Evidence ID 并保留缺失知识证据状态
- [x] 完成多漏洞展开、只读性、负向测试及 Phase 4B + Phase 5 真实 fixture Demo

退出条件：Exact Linker 与 Candidate Search 可独立测试；一个寄存器可产生多个链接
和候选；搜索结果确定、跨层、保留原 KG 方向和 Evidence ID；源 Repository 不变；
未生成 AttackChain，未启动 LLM/RAG/Multi-Agent。

## Phase 7：Architecture RAG + LLM Provider MVP（已完成）

目标：为 CrossGraphCandidate 组装完整只读事实，通过 ARM/global 文档的本地确定性
检索和固定 Prompt Contract 生成严格、不可表达验证结论的 Semantic Assessment。

- [x] 实现 CandidateContext、EvidenceResolver 和严格 ID→Domain Object 解析
- [x] 实现 ArchitectureKnowledgeDocument、RetrievedKnowledgeChunk 和 provenance
- [x] 实现 architecture filter before scoring 的 LocalLexicalKnowledgeRetriever
- [x] 建立 owned ARM/global/RISC-V distractor fixture corpus
- [x] 实现确定性 CandidateRetrievalQueryBuilder 和 CandidatePromptBuilder
- [x] 明确 retrieved content 是 reference data，不能成为 Prompt instruction
- [x] 实现 vendor-neutral LLMProvider 和 deterministic MockLLMProvider
- [x] 实现 CandidateSemanticAssessment 非验证状态与 unresolved 条件保留
- [x] 实现 Evidence/Chunk/Candidate/Architecture citation post-validation
- [x] 实现可选 OpenAICompatibleLLMProvider、两种显式协议和 JSON/Pydantic 校验
- [x] 外部化 API Key/Base URL/Model/API style/JSON mode/timeout 并提供 smoke script
- [x] 完成 Phase 4B→7 ARM RAG + Mock Provider 端到端 Demo

退出条件：Context 引用完整可解析；RISC-V 文档不进入 ARM scoring/prompt；Mock
Provider 可离线完成结构化语义解释；幻觉引用被拒绝；源图、Candidate 和 Evidence
保持不变；未生成 Verified AttackChain，未实现 Multi-Agent 或最终评分。

## Phase 7R：Real Provider Validation + Hardening（已完成）

目标：用人工脚本验证用户显式配置的 OpenAI-compatible Provider，同时保持库代码
环境注入、默认 pytest 离线和 Phase 7 非验证边界。

- [x] `llm` 可选依赖加入 `python-dotenv`，仅人工脚本显式加载根目录 `.env`
- [x] 核心 `OpenAICompatibleLLMProvider.from_env()` 继续只读取传入环境或 `os.environ`
- [x] 人工连接脚本只记录 API style、model、成功状态和脱敏 HTTP status
- [x] 增加真实 ARM ELF→Candidate→RAG→Provider→Assessment reasoning 脚本
- [x] Qwen 3.8 Max Chat Completions 连接返回 HTTP 200
- [x] 显式 none/2048 预算下真实 Assessment 通过 JSON、Pydantic 和后校验
- [x] CandidateContext 强制五类节点的精确 KnowledgeNodeKind
- [x] CandidateContext 强制 knowledge anchor 属于 resolved knowledge_nodes
- [x] 验证性结论扫描覆盖所有自由文本输出字段
- [x] 默认 pytest 继续使用 Mock Provider/Client，不读取 `.env` 或访问网络
- [x] 记录 lexical Retriever 对正式中文语料的 tokenizer 限制

退出条件：离线回归通过；真实连接和完整 Reasoning 均由人工脚本成功验证；真实响应
通过 JSON、Pydantic 和 CandidateReasoner 后校验；密钥不进入日志；未开始 Phase 8。

## Phase 8：Typed Multi-Agent Collaborative Reasoning（已完成）

目标：在一次 Context Assembly 与一次 ARM RAG 上固定执行 Evidence Analyst、
Security Reasoner 和 Critic，保留引用、架构、条件与验证边界。

- [x] 实现 MultiAgentContext，共享同一 CandidateContext/query/chunks
- [x] 实现 EvidenceAnalysis、SecurityReasoningAssessment、SemanticHypothesis
- [x] 实现 CriticReview 和三组封闭非验证状态枚举
- [x] 实现三个独立 Prompt Contract 和 strict JSON Schema
- [x] 实现 StructuredOutputProvider，复用 Phase 7 OpenAI-compatible transport
- [x] 保持 Phase 7 LLMProvider.generate() 和 CandidateReasoner 兼容
- [x] 实现 Evidence/Chunk/Condition/Hypothesis 跨 Agent 引用校验
- [x] 统一 Phase 7/8 forbidden verification claim validator
- [x] 实现固定三角色 deterministic Coordinator 和透明 final-status 规则
- [x] 实现失败即停、无 Agent retry、无 fallback 的 AgentExecutionError
- [x] 实现无时间戳参与身份的 SHA-256 AgentExecutionRecord
- [x] 实现 deterministic MockStructuredOutputProvider 与 ARM 端到端 Demo
- [x] 完成真实 qwen3.8-max 三次串行 Agent 人工验证
- [x] 保留全部 unresolved Trigger/Precondition 和只读 Source Repository

退出条件：三个类型化 Agent、共享 RAG、引用/架构/条件校验、固定 Trace、失败隔离、
Mock/真实 Provider 闭环和全部回归测试通过；未生成 Verified AttackChain，未实现
Evidence Verification、Scoring 或 Root Cause 定位。

## Phase 8R：Cross-Layer Semantics Refactor（已完成）

目标：把跨层对象从默认的“软件漏洞→硬件弱点”扩展为严格的三类双向领域语义，
同时保留现有 software→hardware Candidate primitive。

- [x] CrossLayerInteractionType、CrossLayerDirection 与确定映射
- [x] 独立 CrossLayerInteraction、稳定 SHA-256 ID 和三类约束
- [x] Initiating Root Cause / Trigger Point / Affected Execution Point 角色
- [x] software→hardware exact-anchor / hardware→software not-implemented capability
- [x] 三份 owned synthetic semantic fixture 和 legacy Candidate identity 测试
- [x] 三分类 Hit@K 与分角色位置 Ground Truth 评测契约
- [x] 只读审计 `phase-9a-old-semantics` 并形成迁移矩阵

退出条件：导师三类进入领域模型；Type II 不伪造软件漏洞；Type III 不要求固件漏洞；
旧 Candidate/Search/RAG/Multi-Agent 不变；不迁移 Verification、不创建反向 BehaviorEdge。

## 后续路线（尚未实施）

### Phase 9A-R：Verification Migration to New Cross-Layer Semantics（已完成）

- [x] Interaction identity 排除 Evidence/provenance/metadata
- [x] 迁移三态、地址、Record、EvidenceCatalog 和 CALLS/MMIO/EntityLink verifier
- [x] 建立 InteractionVerificationInput、Reference/Condition Binding 和 legacy adapter
- [x] 建立 Type I/II/III requirements、capability、type-aware score 与 role-aware location
- [x] 完成 owned synthetic ARM Type II ELF 端到端；Type III 保持 not implemented

### Phase 9B0：Runtime Evidence Contract（已完成）

- [x] Backend kind/version/capability manifest 与 passive/active capability 边界
- [x] Baseline/trigger/intervention run、trace manifest 和 canonical SHA-256 identity
- [x] instruction/MMIO/discontinuity/DMA observation 的严格事件约束
- [x] `chipchain_runtime_trace` v1 排序、完整性、capability 校验和 JSON persistence
- [x] RuntimeIntervention 与 RuntimeObservation 分离，不执行任何 active mutation
- [x] Interaction-agnostic Dynamic Evidence normalization 与 owned fixture provenance
- [x] ARM MMIO、interrupt、Type III intervention contract fixtures 和离线 demo
- [x] Type I/II runtime meaning、Type III causal minimum 和 QEMU capability plan 文档
- [x] R1：mutable trace/backend 在 persistence 或 Evidence upgrade 前统一 detached revalidation

### Phase 9B1 R2：Topology-Grounded QEMU MMIO（已完成并封存）

- [x] ARM32 `virt` / `cortex-a15` / 单 vCPU strict environment 与两层 probe contract
- [x] dumb passive TCG plugin source：instruction 与带可靠 paddr 的 raw memory callback
- [x] `chipchain_qemu_raw_trace` v2 header/event/end JSONL strict parser
- [x] `-S` + QMP 同进程 `info mtree -f`、严格 ID 响应与 raw topology SHA-256
- [x] 唯一 `memory` FlatView 选择、semantic memory map ID 与 full-range classifier
- [x] RAM 不晋升、boundary/overflow/ambiguous/malformed fail closed、raw sequence gap 保留
- [x] raw/topology provenance、RuntimeTrace adapter 与 detached revalidation
- [x] safe argv/timeout fail-closed runner 与 interaction-agnostic Dynamic Evidence
- [x] owned synthetic STRB ELF、无 section table header、ground truth 和 offline tests
- [x] PL011 trace 仅作 reference fixture independent oracle，不参与生产分类
- [x] 在 Ubuntu 22.04 matching QEMU 11.0.3 环境重编 plugin 并完成 R2 smoke + real integration

封存基线为 `phase-9b1-stable`。验证环境是 Ubuntu 22.04、QEMU 11.0.3、ARM system
emulation、`virt`、`cortex-a15`、单 vCPU；real QEMU integration 与 Ubuntu/Windows
regression 均通过。Ubuntu 是 canonical runtime validation 环境，Windows 只用于 portability
regression。Phase 9B1 的 passive observation semantics 不因 Phase 9B2A 改变。

### Phase 9B2：Dynamic Interaction Fact Verification / Static-Dynamic Aggregation

#### Phase 9B2A：Explicit Dynamic Trigger Observation Binding（已完成）

- [x] `DynamicTriggerFact`：ARM Type I/II software→hardware 的显式 MMIO trigger fact
- [x] `DynamicTriggerObservationBinding`：fact、Runtime Evidence、Trace 与 Observation 的显式绑定
- [x] `DynamicInteractionVerificationInput`：detached、确定性、fail-closed 输入合同
- [x] `phase9b2a_dynamic_trigger_observation_v1`：重新验证 Trace、定位 Observation、重新生成并精确比较 Evidence
- [x] `DYNAMIC_TRIGGER_OBSERVATION` VerificationRecord subject
- [x] `StaticDynamicFactAggregation`：3×3 policy、多 Dynamic conflict 与双方 Evidence ID 保留

数据流为：

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

Dynamic VERIFIED 只表示 runtime observation matches explicit trigger fact。它不验证
vulnerability 或 Interaction，不修改 Phase 9A-R status/scoring，不创建 BehaviorEdge、
AttackChain 或 causality。Type III causal verification 仍未实现；不得由 temporal order、
单次 MMIO observation 或 synthetic reverse edge 推出因果。

#### Phase 9B2B：Evidence-Guided Multi-Agent Reasoning Contracts（Step 1～7 已完成）

- [x] 非验证 Hypothesis、EvidenceRequest 与 ReasoningResult contracts
- [x] Code → Hardware → Vulnerability → AttackChain 固定顺序 deterministic mock workflow
- [x] CVE/CWE/CAPEC 与 Hardware knowledge 的离线确定性 retrieval
- [x] Provider/Prompt/Parser contract 与 evidence-guided feedback loop
- [x] 多 Agent hypothesis/request/result 收集，conflict fail closed 且 confidence 保守聚合
- [x] CrossLayerInteraction、RuntimeObservation 与 KnowledgeRetrievalResult 的 detached ReasoningContext 绑定
- [x] runtime context 可影响未验证 hypothesis；缺失 runtime context 只产生 EvidenceRequest

Step 7 不修改 RuntimeEvidence、Phase 9A-R verification 或 scoring。RuntimeObservation 不会
自动进入 `supporting_evidence_ids`，knowledge hit 也不会升级为 Evidence。多 Agent 输出仍只有
Hypothesis、EvidenceRequest 和 ReasoningResult；不生成 VerificationRecord、vulnerability
judgement 或 AttackChain。

#### Phase 9B2C：Real LLM Reasoning Integration & Acceptance

##### Step 1：Real LLM Reasoning Provider Bridge / Strict Schema Hardening（已完成）

- [x] `OpenAICompatibleReasoningProvider` 实现现有 `ReasoningProvider` contract
- [x] 复用 `OpenAICompatibleLLMProvider` 的 Chat Completions / Responses transport
- [x] 复用既有 environment、timeout、JSON mode、reasoning effort 与 token limit 配置
- [x] Provider 只返回 raw text，并强制经过 `ConstrainedReasoningOutputParser`
- [x] strict JSON Schema 由 parser 使用的同一 Pydantic transport DTO 确定性生成
- [x] Chat Completions 使用 `response_format.type=json_schema`；Responses 使用 SDK 明确定义的
  `text.format.type=json_schema`，均设置 `strict=true`
- [x] Provider schema 只承担结构约束；context reference、role isolation 与 forbidden truth
  仍由 parser fail closed
- [x] strict schema transport 失败时不降级到 JSON Object、不 fallback 到 Mock
- [x] fake SDK client 离线覆盖两种协议、错误边界、legacy compatibility 与 CODE role 闭环
- [x] 提供显式单角色真实 Provider smoke script，不自动加载 `.env` 到核心库
- [x] `qwen3.8-max` Chat Completions 真实 CODE role acceptance 通过

##### Step 2：Real Four-Role Workflow Integration（已完成）

- [x] `ProviderBackedReasoningAgent` 缓存单次 `ReasoningEngine` 解析结果
- [x] 固定 Code → Hardware → Vulnerability → AttackChain；每个角色一次调用且共享同一 detached Context
- [x] 复用既有 Coordinator merge/dedup/min-confidence/feedback 语义，不复制编排器
- [x] Provider DTO 只允许模型创作 description/confidence、required_fact、reasoning steps 与白名单 Evidence ID 选择
- [x] component、attack pattern、Evidence category/priority、dynamic trigger 由 Context/role contract 确定性构造
- [x] immutable field 额外输出、未知 Evidence、forbidden truth 或任一角色失败均 fail closed
- [x] AttackChain 只进入 session hypotheses，其 request/result 被排除
- [x] 无 prior-agent free-text chaining、retry、Provider switch 或 Mock fallback
- [x] `qwen3.8-max` Chat Completions strict-schema 四角色真实 acceptance 通过

##### Step 3：Contract Versioning & Release Acceptance Hardening（已完成）

- [x] Phase 9B2C 当时冻结 reduced semantic provider schema v2；Phase 10A Step 3 以显式 v3
  model-claim transport contract 取代它，不提供隐式兼容
- [x] 不兼容旧 `phase9b2b_reasoning_output_v1` 在 Mock 与真实 Provider bridge 均 fail closed
- [x] prompt、strict transport schema 与 constrained parser 使用同一当前版本契约
- [x] 透明观测器只记录 role 与 Context ID，不保存 prompt、raw response、secret 或 transport 细节
- [x] 四角色真实验收以实际调用断言恰好四次、固定顺序及同一 Context，不依赖静态计数
- [x] 任一角色失败时观测截止到失败角色，不 retry、不恢复、不切换 Provider、不 fallback Mock
- [x] Provider 连接、单角色 reasoning、四角色 workflow 三项 release acceptance 按序通过

Step 1～3 不创建 Evidence、VerificationRecord、AttackChain 或 vulnerability verdict，不修改
Phase 9A/9B2A verification/scoring，也不改变 legacy Phase 7/8 provider 公共行为。

### Phase 9C：Hardware Trigger Signature & Triggerability Verification

#### Step 1：Hardware Trigger Signature Contract（已完成）

- [x] 独立 `chipchain.hardware_trigger` 包，不重载通用 VulnerabilitySample Trigger/Precondition
- [x] ARM-only、`arm_a32`、地址无关的有序精确 32-bit instruction word contract
- [x] exact register、A32 privilege 与 exact memory-value typed preconditions
- [x] register mismatch / assertion violation primary hardware failure effect
- [x] golden-model mismatch / assertion violation hardware-side proof provenance
- [x] 从 trigger semantic contract 生成并重校验 SHA-256 ID，排除 proof/metadata wording
- [x] owned synthetic ARM A32 JSON fixture、严格负向测试与 round-trip

Step 1 只记录已有硬件侧知识 `T + P -> known hardware failure`。签名不是 Evidence、
VerificationRecord 或 AttackChain，也不证明 firmware 可以执行 T 或满足 P。

#### Step 2：Static Firmware Trigger Matching（已完成）

- [x] backend-neutral `FirmwareTriggerMatcher` detached input revalidation contract
- [x] 私有 function/block/decoded-instruction CFG view，不扩展 `ProgramAnalysisResult`
- [x] exact ordered A32 word finite matching，支持同 block 与合法 same-function successor
- [x] function-entry structural reachability、loop state dedup 与 deterministic multi-match sorting
- [x] `StaticInstructionLocation`、content-bound `StaticFirmwareTriggerMatch` 与 zero-match result
- [x] artifact actual ELF bytes SHA-256 binding，不序列化 host path
- [x] 可选 lazy `AngrFirmwareTriggerMatcher`：main-object executable A32 only、CFGFast normalize
- [x] owned synthetic ELF：一个 exact executable occurrence、一个 near miss、一个 `.data` raw copy
- [x] backend-neutral 离线测试与真实 angr owned-ELF integration

Step 2 只确认 firmware 中存在 exact T 的 function-local structural CFG occurrence。它不确认实际
runtime execution、具体输入可行性或任何 register/memory/privilege precondition，不创建 Evidence、
VerificationRecord、AttackChain、vulnerability/triggerability verdict 或 score。

#### Step 3A：Runtime Trigger Sequence Confirmation（已完成）

- [x] 独立 passive QEMU trigger observer，不修改 Phase 9B1 observer/raw v2/RuntimeObservation
- [x] translation 阶段通过 `qemu_plugin_insn_vaddr/size/data` 复制 metadata，execution callback 才发事件
- [x] `chipchain_qemu_trigger_sequence_trace` v1 strict header/event/end 与 exact raw SHA-256
- [x] ARM A32 little-endian、`virt`/`cortex-a15`/单 vCPU/TCG strict runner 与前后 ELF hash binding
- [x] path-neutral `RuntimeTriggerExecutionTrace` 与 exact contiguous `(PC, word)` matching
- [x] occurrence 绑定 raw content、artifact SHA、signature 与 `StaticFirmwareTriggerMatch.id`
- [x] owned ELF 两个 static exact occurrences、仅一个实际执行 occurrence 的 real QEMU acceptance
- [x] R1：generic runner 不发明 fixture/synthetic/owned/benchmark provenance，stderr 脱敏并限长

Step 3A 只确认一个具体 runtime trace 实际执行 exact T。PC-only 不足以保存机器指令身份，因此
地址和由 runtime raw little-endian bytes 转换的 logical A32 word 必须同时精确一致。它不读取 register、
CPSR 或 guest memory，不判断 privilege/register/memory preconditions，也不表示 hardware failure、
vulnerability、triggerability 或 AttackChain 已验证。A32 是当前 runner 与 fixture 的 declared
execution scope，不是对 CPSR.T 的动态观察；instrumentation overhead 可能影响执行 timing，Step 3A
不声明 timing non-interference。

#### Step 3B：Precondition-State Confirmation（planned / not implemented）

仅当后续真实样本证明有必要时，另行设计 declared P 的 register/memory/privilege 被动确认。不得把
Step 3A 的 exact T occurrence 当作 `T + P`，也不得把未观察的 P 标记为 satisfied 或 rejected。

#### Step 4：Triggerability Aggregation（已完成）

- [x] detached Signature / static result / runtime result 三方重校验与全量 cross-object binding
- [x] exact signature↔static words、static semantic hash/ID set、runtime↔static PC+word 校验
- [x] runtime result semantic SHA-256 与 deterministic `triggerability-aggregation:<sha256>` identity
- [x] `triggerable`、`insufficient_precondition_evidence`、`not_observed_in_runtime`、
  `no_static_trigger_match` 四态封闭策略
- [x] typed declared-P policy；metadata/proof wording/diagnostics 不影响状态或 identity
- [x] owned synthetic empty-P fixture 的 Step 1→2→3A→4 closure 与 real-QEMU opt-in acceptance

`TRIGGERABLE` 仅表示 supplied firmware 已实际执行 prevalidated hardware-trigger contract 的 exact T，
且该 Signature 没有 additional declared P。它不表示 QEMU 重现 hardware failure、hardware
vulnerability 动态重现、CrossLayerInteraction/AttackChain verified 或漏洞确认。非空 P 保持
`INSUFFICIENT_PRECONDITION_EVIDENCE`，等待未来 Step 3B 或另一个显式设计的客观 precondition oracle。

Step 4 结果本身不是项目级“关联漏洞命中率 >= 80%”的分子。Phase 10A Step 2 只允许它在完整
绑定的 Type II candidate-side objective path 中参与单条链 feasibility assessment；Phase 10B 还需
claim alignment 与 exact Ground Truth match 才能计入 strict hit。

### Phase 10：Evaluation（进行中；10A、10B 与 10C 完成）

#### Phase 10A Step 1：Benchmark Ground Truth and Finalized Candidate Contracts（已完成）

- [x] 固定“一次完整 ReasoningSession → 一个 finalized candidate”，只采用 `merged_hypothesis`
- [x] detached `FinalizedCandidateRecord`，confidence/metadata 不影响 deterministic identity
- [x] ARM-only、path-neutral、SHA-256 bound `BenchmarkArtifactReference`
- [x] typed `GroundTruthChain`，保持三类 `CrossLayerInteraction` 原始方向和 participant 约束
- [x] positive/negative case、四类 source provenance 与 predeclared evaluation scope
- [x] versioned deterministic `BenchmarkManifest`、稳定排序、重复 ID fail closed
- [x] 一个 owned synthetic Type II positive 与一个 owned synthetic negative contract fixture

当前 strict project metric 的 denominator 已冻结为：predeclared primary scope 中产生的所有完整
ReasoningSession 各自贡献一个 finalized candidate。内部四角色 hypothesis 不分别计数；缺少 typed
interaction 的弱候选也不得静默移除。此步骤只定义合同，不执行 chain-level feasibility 判断，未计算
“关联漏洞命中率 >= 80%”。未来 secondary verifier-conditioned rate 必须单独报告，且不能替代 strict
metric；还需 companion GroundTruthChainRecall 防止通过少发候选虚增命中率。

#### Phase 10A Step 2：Candidate-Side Objective Chain Feasibility Oracle（已完成）

- [x] Ground-Truth-free detached oracle API 与 evaluation typed error hierarchy
- [x] `CONFIRMED_FEASIBLE`、`NOT_SUPPORTED`、`UNRESOLVED`、`UNSUPPORTED`、`INFRA_FAILURE` 封闭状态
- [x] Candidate/interaction/artifact/target hardware vulnerability/triggerability exact binding
- [x] Type II exact-T closure、Type I enabling-link gap、Type III capability gap 的严格矩阵
- [x] bounded deterministic `ObjectiveEvaluationFailure` 与 infra/model/contract failure 分离
- [x] deterministic assessment ID、closed reason codes、shape/status/ID tamper rejection

Oracle 评估 finalized whole-system candidate：`merged_hypothesis` 是 reasoning proposition；只有其
显式 `ModelAuthoredChainClaim` 字段才记录模型 authored chain semantics。Optional interaction
ID/type/direction 是 ReasoningContext 提供的 candidate-side typed binding，不能据此
宣称 LLM 独立预测了 interaction。Ground Truth、BenchmarkCase、Manifest、EvaluationScope 均不是 oracle
输入。当前只有 Type II + exact bindings + Phase 9C `TRIGGERABLE` 可确认；Type I 保持 unresolved，
Type III 保持 unsupported。Step 2 每次只产生一个 assessment，不执行 benchmark runner 或指标。

#### Phase 10A Step 3：Model-Authored Chain Claim and Candidate Binding（已完成）

- [x] 独立 proposal-shaped `ModelAuthoredChainClaim`，不复用 truth-shaped `CrossLayerInteraction`
- [x] provider schema 显式升级为 `phase10a_model_authored_chain_claim_v3`；只有 ATTACK_CHAIN role
  可 author interaction type 与 participant lists，architecture/role/ID 由 ChipChain 绑定
- [x] 缺失、错误或不完整 claim 保持可测量，不从 ReasoningContext 或 Ground Truth 修复
- [x] coordinator 至多保留一个 source claim；default deterministic Mock 不伪造 model authorship
- [x] `FinalizedCandidateRecord` 条件绑定 claim snapshot，并保持 no-claim legacy identities
- [x] Ground-Truth-free `ModelClaimBinder` 与 `ALIGNED`、`INCOMPLETE`、`MISMATCHED`、`UNBOUND`、
  `MISSING` 五态 closed assessment
- [x] Step 3-R1：strict provider schema 递归要求全部 object properties，以 required nullable
  `chain_claim` 表示缺失 claim；Mock 显式输出 null，普通 parser 仍兼容省略字段
- [x] Step 3-R1：required references 保持 exact，optional non-empty references 使用集合子集兼容；
  Coordinator 按实际 source Agent role 独立拒绝非 ATTACK_CHAIN claim

Context interaction 只是 candidate-side typed context，不等于模型 authorship；model claim 只是未验证
proposal，不等于 domain truth。`CONFIRMED_FEASIBLE` 与 claim alignment 是独立维度；Phase 10B strict
hit 还要求同一 case 的 exact Ground Truth match。Phase 10A 自身不实现 runner、metric 或“>=80%”计算。

#### Phase 10B：Deterministic Benchmark Evaluation Runner and Metrics（已完成）

- [x] 每个 manifest case 恰好一个 `BenchmarkCaseRunRecord`：candidate、pre-finalization failure 或
  预声明 excluded；missing/duplicate/extra case fail closed
- [x] truth-neutral `CandidateEvaluationBundle` exact-bind candidate、claim binding、feasibility 与必要的
  detached triggerability
- [x] post-finalization exact Ground Truth interaction、attack-pattern 与 declared signature matching
- [x] `BenchmarkCandidateAssessment`、per-chain recovery 与 deterministic top-level report
- [x] `VerificationHitRate`、`GroundTruthChainRecall`、`NegativeControlFalsePositiveRate`、
  `PrimaryCaseCoverage` exact cohort metrics；零 denominator 显式 undefined
- [x] primary scope completeness、全 claim/feasibility status counts、confidence/metadata/input-order neutral IDs
- [x] owned synthetic acceptance：`1/2`、`1/1`、`0/1`、`2/2`，仅验证合同且不产生 >=80% 结论

#### Phase 10C：Ablation Protocol and Prompt Visibility Firewall（已完成）

- [x] 冻结 `FULL_CONTEXT_MODEL`、`MASKED_CHAIN_CONTEXT_MODEL`、`NO_MODEL_BASELINE`、
  `CONTEXT_OBJECTIVE_UPPER_BOUND` 四条件与单次 repetition 的 deterministic plan
- [x] 默认 FULL prompt byte-for-byte 保持既有行为；MASKED 只改变 model-visible serialization，
  使用仅绑定可见字段的 `reasoning-prompt-view:<sha256>`，不暴露完整 Context ID
- [x] masked prompt 至少隐藏 typed interaction、attack pattern 与 dynamic trigger reference；完整
  Context 仍供 candidate finalization、claim binding 与 objective oracle 使用
- [x] constrained parser 继续对完整 trusted Context 校验；错误、缺失或错误类型的 model claim
  保持可测量，不由 Context 修复
- [x] exact-reference `PromptVisibilityAudit` 只进行 post-construction PASS/LEAK_DETECTED 质量检查，
  不干预 prompt、reasoning、candidate 或 Phase 10B metric
- [x] 三个普通条件原样消费 frozen `BenchmarkEvaluationReport`；upper-bound diagnostic 仅移除
  model-claim gate，仍要求 `CONFIRMED_FEASIBLE` 与 exact Ground Truth，negative 永不命中
- [x] all-condition accounting、explicit execution failure、same-manifest/version/runner contract、
  complete identical primary coverage 与 exact rational delta contracts
- [x] 仅用 owned synthetic/offline fixture 验收；未运行真实模型、未计算 >=80%、未作因果效应声明

#### Phase 10D Step 1：Real-Model Experiment Provenance Contracts（已完成）

- [x] sanitized `RealModelProviderDescriptor`，只绑定 model/API style/strict schema/reasoning effort/
  token limit/schema name；排除 secret、base URL、timeout、retry 与 host state
- [x] `OFFLINE_CONTRACT` / `REAL_PROVIDER` mode 与同一 descriptor 驱动的 frozen four-condition plan
- [x] exact condition×case×fixed-role×repetition-0 invocation key，以及逐角色 prompt/response SHA-256
- [x] FULL/MASKED 每 case 固定 Code → Hardware → Vulnerability → AttackChain 四个 slot；
  NO_MODEL/UPPER_BOUND 为零 provider invocation
- [x] 串行 fail-stop 的 `COMPLETED` / `FAILED` / `NOT_ATTEMPTED` 完整 accounting；后续未调用角色显式绑定
  blocking failed role，不伪造第二个 provider failure
- [x] 每条件 report/result/failure 与 MASKED attempted-role prompt audit exact binding
- [x] 顶层 artifact 派生 provider/benchmark comparability、prompt visibility validity 与 execution completeness
- [x] secret/path/traceback/raw-stderr metadata hygiene、deterministic identity 与 JSON roundtrip
- [x] 仅完成 offline contract fixture；没有真实 provider call、真实模型结果或 >=80% 结论

#### Phase 10D Step 2：Explicit Opt-In Real-Provider Execution Harness（已完成实现）

- [x] detached `RealExperimentCaseInput` / `RealExperimentInputSet` exact-bind plan、case、完整
  `ReasoningContext` 与可选 objective triggerability，不含 Ground Truth
- [x] FULL/MASKED 对每 case 使用同一完整 Context 和同一 provider descriptor，仅 prompt visibility 不同
- [x] recorder 只委托 frozen prompt/provider/parser/workflow；canonical provenance 仅保存 exact SHA-256
- [x] MASKED hidden-reference audit 在 provider transport 前执行，leak fail closed 且不产生 response hash
- [x] 每 case 固定四角色 workflow，失败形成 `COMPLETED* / FAILED / NOT_ATTEMPTED*`，后续 case 继续
- [x] 成功 case 原样进入 finalized candidate、claim binder、objective oracle 与 Phase 10B runner
- [x] NO_MODEL 零 provider 调用；UPPER 从 exact NO_MODEL case-run cohort 派生
- [x] Step 1 condition/artifact 与 Phase 10C comparison exact cross-binding；Step 2 archive 绑定输入、parsed
  sessions 与 FULL/MASKED/NO_MODEL case runs
- [x] `chipchain experiment real-model` 只有显式 `--execute-real-provider` 后才允许从环境创建 Provider
- [x] 默认 pytest 使用 deterministic fake/Mock provider，未执行网络模型、未计算 >=80% 项目结论

#### Phase 10D Step 6：Objective Triggerability Input Materialization（已完成实现）

- [x] 将 trigger runner 的唯一 ARM/A32 raw-trace normalization 抽为公开纯函数，runner 继续复用且
  output identity 不变
- [x] path-neutral、deterministic、candidate-side-only `ObjectiveTriggerabilitySource`，不含 label、GT、
  expected status 或 expected derived output
- [x] actual ELF/signature/raw trace hash、run/scenario、interaction/target 的 fail-closed binding
- [x] 只经 actual Angr matcher、raw parser、runtime matcher 与 production aggregator 派生 status
- [x] persistent `ObjectiveTriggerabilityMaterializationRecord` exact-bind source、Context 与全部 bounded
  static/runtime/aggregation provenance，并随 input/archive roundtrip
- [x] `RealExperimentCaseInput` 可选扩展保持 Step 2～5 legacy ID/JSON；REAL_PROVIDER create/preflight
  对 triggerability 缺 record 双重拒绝，OFFLINE 保持历史兼容
- [x] owned positive 真实派生 `TRIGGERABLE`；独立 negative Context 保持 triggerability/materialization
  均为空，不伪造 negative objective status
- [x] production materializer 不接受 Manifest/Case/GroundTruth/runner/comparator，完全离线且不启动 QEMU、
  Provider 或网络

#### Phase 10D Step 7：Collision-Safe Masked Prompt Projection（已完成实现）

- [x] reasoning-layer `masked_chain_hidden_reference_ids()` 集中冻结 interaction、attack-pattern 与
  dynamic-trigger hidden policy，projection 与 executor audit 复用同一 API
- [x] MASKED 对 subject/components/facts/evidence/knowledge identifiers 采用与 audit 相同的 substring
  collision rule；subject 或 all-components collision 在 transport 前 fail closed
- [x] provider-visible runtime observation / knowledge retrieval 若包含 hidden reference 则整项省略，
  不构造 placeholder、hash alias 或 invalid partial object
- [x] `provider_authority.supporting_evidence_ids_allowed_values` 只来自 projected evidence IDs；完整 trusted
  Context 继续进入 parser/system-owned bindings
- [x] FULL 与 collision-free historical MASKED prompt byte identity 保持；DS5 positive resource collision
  被移除且 exact-reference audit PASS
- [x] 新 plan identity 绑定 `phase10d_collision_safe_masked_projection_v1`；Step 1～6 缺字段的历史 ID/JSON
  保持可读，legacy/wrong REAL_PROVIDER plan 在 provider call 前 fail closed
- [x] archive validator 按 archived plan protocol 精确重建 prompt：legacy `None` 恢复 Step 1～6 MASKED
  bytes/current contract 恢复 collision-safe bytes；历史 hash 不跳过、不接受双解
- [x] preserved DS5 archive SHA/plan/archive IDs 原样通过只读 validation；legacy execution gate 仍为零调用拒绝
- [x] provider descriptor、strict schema bundle、Responses completion contract、parser 与 evaluation semantics
  均未改变

#### Phase 10D Step 8A：Public CVE Corpus Intake and Admission Staging（已完成实现）

- [x] 独立 `chipchain.corpus` 合同保存公开 CVE 研究事实、ARM A/M profile、closed classification、
  admission status/blocker 与 deterministic identity，不创建 verdict 或 evaluation result
- [x] 七条 public ARM seed record 与七个既有 `VulnerabilityKnowledgeEntry(CVE)` 一一精确绑定
- [x] `underlying_issue_key` 与 `related_cve_ids` 区分 CVE record、底层问题和相关软件 mitigation；
  CVE-2026-53354 仅为关系引用，不作为第八条独立 seed record
- [x] M-profile、目标硬件漏洞不清楚和当前 verifier 缺口均 fail closed；公开 CVE 不进入 owned
  Phase 10A/10D fixture、`PRIMARY_TARGET`、oracle、triggerability 或 Ground Truth
- [x] corpus summary 分别报告 record/underlying-issue、classification 和 admission counts；加载与
  retrieval 完全离线，不保存 raw HTML、host path 或 exploit/PoC payload

#### Phase 10D Step 8B-0：Single-Source Public CVE Build Pipeline（已完成实现）

- [x] `chipchain_public_cve_source_v1` 只保存 curator facts，不允许 source/document/record 携带任何
  generated ID、knowledge duplication、metadata、evaluation 或 execution 字段
- [x] source record 与 generated sample 复用同一 CVE/profile/classification/admission/path safety policy；
  source document 强制唯一 CVE、in-source reciprocal relation 与 CVE 排序
- [x] pure builder 一次性派生既有 `VulnerabilityKnowledgeEntry`、knowledge binding、sample identity、
  corpus identity 与冻结 metadata，不引入第二种 knowledge entry
- [x] deterministic UTF-8/indent-2/final-newline writer 与 `--check`/`--write` 离线维护脚本；committed
  generated snapshot 可由唯一 source byte-for-byte 重建
- [x] frozen Step 8A 七条事实、knowledge/sample IDs、corpus ID、ordering 与 metadata exact 保持；
  expansion、mutation propagation、source-order independence 和 safety 均有离线 regression

#### Phase 10D Step 8B-1A：Public-Documented SECONDARY Cohort and Prompt Readiness（已完成实现）

- [x] 仅用单一 public source 与 deterministic corpus，为五条预选 A-profile CVE 派生
  `PUBLIC_DOCUMENTED` / `SECONDARY_ONLY` cases；selection 文件只保存 CVE 与软件 source-layer 选择
- [x] 每 case 绑定 source-record canonical SHA-256、path-neutral artifact reference、一个最小 Type I/II
  documented interaction、一个 retrieval-only knowledge ID 与 detached `ReasoningContext`
- [x] `POSITIVE_FEASIBLE` 仅表达 public documentation 描述了 vulnerability scenario，不表示 objective
  triggerability、oracle confirmation 或独立漏洞验证；五条 case 均无 signature/runtime/Evidence/triggerability
- [x] 对 5×4 roles 分别构造 FULL/MASKED prompt；20 个 MASKED exact-reference audit 全部 PASS，且 artifact
  只保存 prompt SHA-256、audit 与可见性布尔事实，不保存 prompt/model/provider output
- [x] 实际 provider-visible payload 仅包含 CVE ID、affected components 与 knowledge-entry reference，不包含
  stable public references 或描述性公开漏洞文本，因此 readiness fail closed 为
  `REFERENCE_CONTENT_INSUFFICIENT`；本步骤不修改 prompt/RAG/projection
- [x] 现有 oracle 对无 triggerability 的四个 Type II 与一个 Type I 均保持 `UNRESOLVED`；SECONDARY case
  不进入 verification hit rate、Ground Truth recall、negative-control false-positive rate 或 PRIMARY coverage

#### Phase 10D Step 8B-1B：Versioned Public Knowledge Content Projection（已完成实现）

- [x] 新增 `phase10d_public_knowledge_content_projection_v1`，只从 Context 精确引用的 validated
  `VulnerabilityKnowledgeEntry(CVE)` 投影 entry ID/kind、external ID、architecture、title、summary、
  affected components 与 references；metadata 和 curator/evaluation/objective 字段均不进入 projection
- [x] `ReasoningContext` 继续只承担 reference binding，identity 与字段未改变；projection 是单独、typed、
  deterministic 的 provider-visible attachment，缺失/额外/重复/跨架构/non-CVE/stale entry 全部拒绝
- [x] 新增显式 `build_with_knowledge_projection()`；legacy `build()`/`build_for_projection_contract()` 未改
  byte semantics，冻结 Step 8B-1A public Prompt SHA 有 exact regression
- [x] FULL/MASKED 使用同一 projection；5×4×2 prompts 均暴露 external ID、entry ID、title、summary、
  components 与 references，20 个 MASKED hidden-reference audit 全部 PASS
- [x] versioned structured-label leakage audit 检查最终 serialized prompt 的 forbidden keys 与 exact values；
  全部 40 个 prompt 为 PASS，detected value 仅允许以 SHA-256 记账
- [x] 新 readiness artifact 精确引用 frozen Step 8B-1A cohort 并保持全部 case/interaction/context/knowledge
  IDs；结果为 `READY_FOR_PUBLIC_PROVIDER`，但本步骤未连接或调用 Provider，也不产生性能结论

#### Phase 10D Step 8B-1C：Public Knowledge Real-Provider Wiring（已完成实现）

- [x] 用独立 `phase10d_public_knowledge_execution_binding_v1` 连接既有 experiment plan、五案 frozen
  SECONDARY manifest/input、Step 8B-1B readiness 与精确重建的 knowledge projection；不向历史
  plan/input/archive 增加 optional 字段
- [x] 每案绑定 FULL/MASKED × 固定四角色的 8 个 expected prompt record，共精确 40 个 SHA-256；缺失、
  重复、额外、case/context/entry/projection/readiness/plan/manifest crosswire 全部 fail closed
- [x] 新显式 `execute_with_public_knowledge()` 仍使用官方 frozen prompt builder；legacy `execute()` 不进入
  projected builder，历史 input/plan identity、legacy prompt hash 与 archive parsing 保持不变
- [x] transport 前离线重建 prompt 并依次约束 structured leakage、exact frozen hash 与 MASKED visibility；
  runtime recorder 再做 defense-in-depth gate，不一致时 provider call 为 0 且无 legacy fallback/retry
- [x] `phase10d_public_knowledge_execution_archive_v1` wrapper 绑定 public input provenance、实际 reached
  prompt hashes 与 PASS leakage audits；不保存 raw assembled prompt、raw response、secret 或 endpoint
- [x] 受控脚本提供 `--preflight-only` 和显式 `--execute-real-provider`；preflight 不读取 Provider 环境、
  不实例化 Provider、不访问网络，本步骤没有运行真实 Provider
- [x] deterministic fake Provider 完整走过官方 Executor/Engine/four-Agent/parser/evaluation 路径并产生
  40 次 model-condition invocation；NO_MODEL/UPPER 零调用，所有 SECONDARY/PRIMARY metric denominator 为 0

#### Phase 10D Step 8B-1D：Public Provider One-Shot（已完成并冻结）

- [x] 在独立审批下对 frozen 五案 SECONDARY cohort 执行一次 public-provider run，并保存 hash-only
  `phase10d_public_knowledge_execution_archive_v1`；不保存 raw prompt/response、secret 或 endpoint
- [x] frozen archive、public binding、plan、manifest 与 input set 均由 exact ID/SHA-256 绑定；FULL/MASKED
  各四角色保持固定顺序与完整记账
- [x] one-shot 不是 PRIMARY benchmark、验证命中率、模型准确率或 `>=80%` 结论；reasoning 与 claim 仍不是
  Evidence、VerificationRecord、AttackChain 或 vulnerability verdict

#### Phase 10D Step 8B-1E：Masked Semantic Recovery Diagnostic（已完成并冻结）

- [x] 新增 `phase10d_masked_semantic_recovery_diagnostic_v1`，只离线读取 exact frozen Step 8B-1D archive
  与运行前已冻结的 authoritative public source；不调用 Provider、网络、QEMU 或第二个 LLM judge
- [x] 保持三轴分离：Axis A 为既有 exact `ModelClaimBinder`，Axis B 为新 type/content diagnostic，Axis C
  为既有 `ChainFeasibilityOracle`；不修改 binder、oracle、metric、prompt、parser 或 masking
- [x] R1 按 workflow contract 从唯一携带 claim 的 ATTACK_CHAIN hypothesis 提取 description；仅当 archive
  存在 exact same-hypothesis `ReasoningResult` 时才允许附加 steps。当前五案均显式记录 result ID 为 null、
  steps unavailable 与 description-only source，不读取 merged/final/other-role/FULL 文本
- [x] exact type recovery 保持 MATCH/MISMATCH/CLAIM_MISSING；participant diagnostic 只解释既有 binder
  reason 与 visible/hidden reference 关系，不修复或替换 opaque participant ID
- [x] `phase10d_semantic_tokenization_v1` 使用统一 NFKC/lowercase/generic-stopword 规则，对 trigger、
  precondition、hardware effect 分别生成 content 与 visible-summary-subtracted held-out exact fractions；只保存
  counts 与 token-set SHA-256，无 threshold、weighted score、PASS/FAIL 或 semantic-success 字段
- [x] 当前 artifact 固定为 `RETROSPECTIVE_DIAGNOSTIC` / `prospective_metric_eligible=false`，只能描述为
  ATTACK_CHAIN hypothesis-description content coverage；后续 contract freeze 后的新 run 才可 prospective 使用
- [x] 当前派生结构结果为 type recovery 4 MATCH/1 MISMATCH、MASKED exact binder 3 INCOMPLETE/2 MISMATCHED、
  objective feasibility 5 UNRESOLVED；这些是多轴描述，不合成为模型成功率

#### Phase 10D Step 8B-2B0：Authoritative Documented Erratum Contract Freeze（已完成并冻结）

- [x] 新增 `phase10d_documented_erratum_source_v1` 人工审阅输入与
  `phase10d_documented_hardware_erratum_v1` 确定性生成合同，只冻结 Arm SDEN-1152370 v11.0 对
  CVE-2023-34320 / Cortex-A77 erratum 1508412 的 concise documented semantics
- [x] 精确编码 r0p0/r1p0 affected、r1p1 fixed，以及有向 Case A/Case B event alternatives；Case A load
  支持 Device/Normal Non-cacheable，Case B first load 严格 Device-only，PAR_EL1 只标记 privileged AArch64
- [x] `CLOSE_PROXIMITY` 固定为 `QUALITATIVE_ONLY`、`quantitative_bound=null`；额外 timing conditions 未由
  public source 完整定义，effect 只可为 possible core deadlock
- [x] 只保存 documentation-only mitigation categories，不保存实现定义寄存器序列、机器码或 observed
  mitigation state；source precision 显式声明没有 unique machine-code sequence、runtime environment 或
  hardware failure observation
- [x] builder 只离线读取 exact frozen public-source bytes 与新 curation source，fail closed 校验 source-file
  SHA、CVE record canonical SHA 与 corpus ID；不读取 Ground Truth、Provider、QEMU 或网络
- [x] `SEMANTIC_PATTERN_REFERENCE_ONLY` 不创建或复用 `HardwareTriggerSignature`、`HardwareTriggerProof`、
  `TriggerabilityAggregationResult`、Evidence、VerificationRecord、AttackChain 或 feasibility assessment
- [x] CVE 继续是 public-source `NEXT_OBJECTIVE_CANDIDATE` / evaluation `SECONDARY_ONLY`，没有 PRIMARY
  admission 或 benchmark metric 变化

#### Phase 10D Step 8B-2B1：Versioned ARM A-profile Semantic Trigger Pattern（已完成并冻结）

- [x] 新增通用 `phase10d_a_profile_semantic_trigger_pattern_v1`，只表达 future objective analyzer 所需的
  `MEMORY_LOAD`、`STORE_EXCLUSIVE`、`SYSTEM_REGISTER_READ(PAR_EL1)` predicates，不创建 occurrence 或 observation
- [x] 翻译器只读取 byte/hash/ID/contract 精确冻结的 2B0 generated artifact，不读取人工 curation、Arm 文档、
  Ground Truth、Provider、QEMU、angr 或网络
- [x] positions 1/2 保持 `PROGRAM_ORDER`，同 position alternatives 固定为 OR；Case A 与 Case B 的方向、
  Device/Normal-NC 限制以及 PAR_EL1 privileged-AArch64 applicability 完整翻译
- [x] load memory-type semantics 固定为 `EFFECTIVE_ARCHITECTURAL_MEMORY_TYPE`，并携带
  `OBJECTIVE_EFFECTIVE_MEMORY_TYPE_REQUIRED`；opcode/MMIO/address-range 不能单独满足该义务
- [x] `CLOSE_PROXIMITY` 保持 qualitative-only/null bound，并显式声明 source 不足以进行 exact software-only
  satisfaction；额外 timing conditions 保持 unresolved from public documentation
- [x] effect 与 mitigation 只作为 documented reference，revision scope 不构成 runtime CPU observation；pattern
  identity 绑定全部 predicates、source obligations 与 2B0 provenance
- [x] 2B1 不实现 2B2 static occurrence extraction 或 2B3 runtime observation，不修改旧 A32 enums、signature、
  matcher、aggregator、fixture identity 或 PRIMARY admission

#### Phase 10D Step 8B-2B2-A：A-profile Static Semantic Extraction Contract（已完成并冻结）

- [x] 新增独立 A64 static namespace 与四个版本化合同：deterministic extraction plan、objective decoded
  instruction fact、fact-to-predicate candidate，以及只包含 facts/candidates/diagnostics 的 extraction result
- [x] plan builder 的唯一输入是 byte/hash/ID/contract 精确冻结的 2B1 artifact；每个 source alternative
  恰好映射一个由 pattern ID、case ID、position 与 canonical predicate content 共同确定的 predicate ref
- [x] v1 static ISA 只允许 AArch64；新事实独立使用 16-hex-digit code address 与 8-hex-digit A64 logical
  instruction word，不扩大或修改 Phase 9C A32 `ArmExecutionMode`、address、signature、matcher 或 fixture
- [x] static fact 只表示不可变 artifact 中存在一个 decoded instruction；load 的 effective memory type 固定为
  `REQUIRES_OBJECTIVE_TRANSLATION_CONTEXT`，PAR_EL1 静态识别也不证明 runtime privilege 或 execution
- [x] candidate 始终保留 runtime execution、适用时 runtime context/effective memory type，以及 qualitative
  proximity/additional hardware timing 等 objective obligations；candidate 不表示 predicate satisfied
- [x] result 对 plan/source/artifact/fact/predicate references 做 exact cross-binding 与 deterministic ordering，
  不产生 Case A/B assembly、CFG/program-order outcome、proximity outcome、triggerability、verification 或 feasibility
- [x] 生成 artifact 只包含 extraction plan，不含 ELF occurrence；2B2-B extractor、2B2-C1 pure order contract
  与 2B2-C2 generic real-angr materialization 已分别在独立边界实现

#### Phase 10D Step 8B-2B2-B：AArch64 Static Semantic Event Extractor（已完成并冻结）

- [x] 新增 `AngrAProfileStaticSemanticExtractor`，只接受 detached ARM/A-profile/AArch64 plan 与实际加载为
  AArch64/64-bit 的 immutable ELF；分析前后 exact SHA-256 不一致即 fail closed
- [x] 使用 `CFGFast(normalize=True)`，仅确定性遍历 main-object、non-SimProcedure、non-PLT function 的
  executable blocks/instructions，不向 public result 暴露 CFG edge/path
- [x] partial v1 recognition 只使用 closed Capstone instruction IDs + structured operands：`LDR(REG,MEM)`、
  六个 STXR/STLXR word/byte/halfword variants `(REG,REG,MEM)`、exact `MRS(REG,PAR_EL1)`
- [x] 普通 STR、LDXR、MSR PAR_EL1、MRS FAR_EL1 与未支持 LDUR 均不产生 semantic fact；非执行 `.data`
  中的相同 bytes 也不产生事实
- [x] recognized fact 只保存 16-digit A64 address、8-digit logical instruction word、function/block provenance
  与 unresolved memory state；candidate 仅通过 frozen plan 和官方 `create()` 生成
- [x] 同一 load/PAR/store-exclusive fact 分别绑定两条 exact plan entry，并保留全部 conditional/universal
  obligations；不复制 instruction fact，也不声称 predicate satisfied
- [x] owned synthetic ELF 的四个隔离函数互不调用，不构成 CVE trigger/reproducer；fixture 自带 generator、
  source、SHA256SUMS、非执行 byte-copy negative control 与非 Ground-Truth expectations
- [x] 不实现 2B2-C Case/CFG/program-order assembly，不计算 proximity，不解析 effective memory type，不创建
  runtime observation、triggerability、feasibility、verification 或 PRIMARY 结果

#### Phase 10D Step 8B-2B2-C1：Function-Local Static CFG Order Candidate Contract（已完成并冻结）

- [x] 新增 versioned function CFG snapshot、directed edge、static case-order candidate 与 assembly result；所有
  identity 绑定 exact artifact/result/plan/source/candidate/fact/CFG snapshots，不含 path、time 或 backend object
- [x] pure evaluator 不导入 angr/Capstone，只按 exact case/position 做 deterministic Cartesian pairing；同块只接受
  instruction-address forward order，跨块只接受同函数 directed CFG reachability
- [x] directed witness 使用 successor-address sorted BFS，保存 shortest-edge-count path 仅供
  `REACHABILITY_AUDIT_ONLY`，不计算或暗示 proximity、symbolic feasibility 或 runtime execution
- [x] standalone candidate 保留 exact predicate/fact/plan/CFG snapshots，并强制 remaining obligations 为双方精确并集；
  load memory type、PAR_EL1 runtime context、proximity 与 additional timing 均未解决
- [x] 零候选是中性有效结果；现有 2B2-B owned fixture 的三个 positive facts 位于隔离函数，因此在 C1 function-local
  语义下仍为零 case-order candidate
- [x] C1 本身不实现 real-angr CFG snapshot/candidate materialization，不创建 runtime observation、triggerability、
  feasibility、verification、vulnerability 或 PRIMARY 结果

#### Phase 10D Step 8B-2B2-C2：Generic AArch64 Binary CFG Materialization（已完成并冻结）

- [x] 新增 `AngrAProfileStaticCaseMaterializer.materialize(artifact, extraction_plan)` binary-first API；内部复用冻结
  2B2-B extractor 的 exact semantic result，并将同一 immutable ELF 的 CFG 输入冻结 C1 pure assembler
- [x] C2 CFG pass 前后独立读取并校验 artifact SHA，要求与 semantic result 完全一致；实际 angr project 必须为
  `AARCH64`/64-bit 且 `auto_load_libs=False`，bytes 漂移、ARM32、malformed/non-ELF 均 typed fail closed
- [x] relevant function set 仅来自 predicate-referenced facts 的 non-null exact function address；每个 required function
  必须 exact main-object、non-SimProcedure、non-PLT、executable 且恢复恰好一次，不能 nearest-function 猜测
- [x] function name 仅采用同函数 facts 一致的 non-null name，否则为 `None` 或冲突失败；所有 referenced fact block
  必须存在于 normalized snapshot，缺失不能伪装成零候选
- [x] block 与 edge 只保留 exact function-local main-object executable set，确定性去重/数值排序，过滤 callee、external、
  PLT、SimProcedure 与 non-executable endpoint；C2 不复制 C1 BFS/pairing/path semantics
- [x] production backend 不包含 CVE/处理器/erratum/Case A/B hardcoding，也不读取 semantic event kind/system register；
  同一 backend 可不改源码地分析其他兼容 AArch64 ELF 或 Linux kernel/firmware build
- [x] 当前 frozen owned fixture 的 real-angr 结果为 3 facts、6 predicate candidates、3 CFG snapshots、0 case candidates；
  零候选保持中性，不表示安全、runtime execution、symbolic feasibility、proximity 或 triggerability
- [x] ELF 是当前 loader adapter boundary；未来 raw/firmware loader 应复用相同 semantic/CFG IR，不重设计核心合同
- [x] 不创建 runtime observation、Evidence、VerificationRecord、`TriggerabilityAggregationResult`、feasibility、
  vulnerability 或 PRIMARY 结果，不运行 QEMU/Provider/network/symbolic execution

#### Phase 10D Step 8B-2D1：Typed Static Behavior Analysis Projection（已完成实现，待 final review）

- [x] 新增三个版本化的 architecture-neutral projection 合同：objective static program graph、独立 pattern
  binding projection 与 generic top-level analysis projection；shared models 不导入 `hardware_trigger`/A-profile
- [x] 新增 `phase10d_a_profile_static_behavior_projection_materialization_v1` adapter envelope；仅该层保存
  exact frozen C2 snapshot，并包含同一 architecture-neutral `StaticBehaviorAnalysisProjection`
- [x] program graph v1 只含 FUNCTION/BASIC_BLOCK/SEMANTIC_INSTRUCTION_FACT 节点及 function containment、
  fact containment、CFG successor 三类 objective structural relations；所有 relation 固定非 causal、非 runtime、
  非 symbolic-feasibility
- [x] pattern predicate/case-order candidates 只进入 sibling binding records，不进入 program graph relation；
  semantic labels 保持 candidate-only，不表示 matched/satisfied/triggered
- [x] semantic fact node 保留 operation、instruction address/word/size、function/block、system register、
  memory-resolution state、static scope 与 exact source fact ID，不声称 execution、effective memory type、
  privilege legality 或 hardware effect
- [x] FUNCTION 与 BASIC_BLOCK 各按 exact CFG source identity 唯一投影；CFG successor 只保存 exact normalized
  function-local edge provenance，path 不解释为 causality
- [x] predicate/case-order records 精确绑定 semantic-fact graph node，并原样保留全部 runtime/context/memory/
  proximity/timing obligations；projection 不解除任何 objective obligation
- [x] generic top-level 只校验 architecture/artifact/source-analysis/subprojection 与 fact-node references；A-profile
  envelope 从 exact C2 snapshot 重建预期 graph/bindings，artifact/fact/CFG/candidate retarget 即使重算 ID 也拒绝
- [x] non-predicate fact 若不在 C2 relevant CFG set 中确定性省略并以中性 count 记账；predicate-referenced fact
  不可解析到 exact function/block graph 时直接拒绝
- [x] legacy Behavior Graph、`BehaviorType`/`NodeKind`/`RelationType`、knowledge graph、ReasoningContext 与
  CrossLayerInteraction 均未修改；不创建 Evidence、VerificationRecord、Triggerability、AttackChain 或 verdict
- [x] 当前 frozen owned fixture 投影为 3 function、3 block、3 semantic-fact nodes，3+3 containment relations、
  0 CFG successor、6 predicate bindings、0 case-order bindings；覆盖范围仍受 narrow A-profile v1 decoder 限制

后续工作：对 `NEXT_OBJECTIVE_CANDIDATE`
仍须另行完成证据审查与 objective input 设计后，才能提出 PRIMARY admission 变更。`TRIGGERABLE` 仍不能
脱离 Type II exact candidate binding 被通用映射为 `CONFIRMED_FEASIBLE`。

### Phase 11：API / Visualization

核心算法稳定后再提供 FastAPI 与可解释可视化，不把 API 层变成算法或存储层。

### Phase 12：Additional Architectures

仅在 ARM 闭环稳定并完成评测后，讨论并验证第二种架构；不进行跨架构拼接。

任何阶段都不得为了展示功能而跳过其退出条件。
