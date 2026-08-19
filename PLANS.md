# ChipChain 阶段计划

## 当前状态

Phase 0～Phase 9B0 已完成。Phase 9A-R 在不改变 Phase 4B～8 API 的前提下，将旧版
非 LLM verification primitives 迁移到三类 interaction，并引入显式 binding、类型化
requirements/score、能力状态和角色化定位。下一步计划为 Phase 9B。

Phase 9A-R1 进一步收紧 Evidence subject linkage、Node binding、substantive status、
capability ceiling、feature scope/provenance 与 supporting-evidence localization。
Phase 9A-R2 最终强化 binding-aware transition、Evidence collision、vulnerability Evidence
boundary 与 result type/direction identity。
Phase 9A-R3 强制每个 semantic interaction reference 至多一个 source binding，并对结果中
各 VerificationRecord 集合增加 deterministic ID uniqueness 防御。Phase 9B0 已建立独立、
backend-neutral Runtime Trace/Observation/Intervention contract 与 Dynamic Evidence normalization；
下一步为 Phase 9B1 QEMU Passive Runtime Observer。

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

### Phase 9B1：QEMU Passive Runtime Observer（下一阶段）

按版本探测 QEMU TCG plugin capability，首个 ARM observer 仅运行单 vCPU，优先采集
instruction、memory access、physical address 和 IO classification。C plugin 只输出稳定
JSONL raw event；Python 负责 schema、normalization 和 Evidence。不得实现 mutation。

### Phase 9B2：Hardware→Firmware Causal Verification

在 baseline/intervention 可比性、实际 propagation observation 和 affected execution evidence
具备后设计 reverse-direction verifier。不得仅用 temporal order 声称 causality，也不得用
synthetic reverse edge 代替实际证据。

### Phase 10：Evaluation

固定 ARM Ground Truth、指标、错误分类、消融实验和可复现报告。

### Phase 11：API / Visualization

核心算法稳定后再提供 FastAPI 与可解释可视化，不把 API 层变成算法或存储层。

### Phase 12：Additional Architectures

仅在 ARM 闭环稳定并完成评测后，讨论并验证第二种架构；不进行跨架构拼接。

任何阶段都不得为了展示功能而跳过其退出条件。
