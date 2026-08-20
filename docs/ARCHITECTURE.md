# 系统架构

## 总体数据流

```text
上游固件/硬件漏洞结果
          │
          ▼
    数据标准化与校验 ───────────────┐
          │                         │
          ▼                         ▼
  Vulnerability Knowledge Graph   目标固件
          │                         │
          │                  ProgramAnalyzer
          │                         │
          │                         ▼
          │              Cross-Layer Behavior Graph
          └──────────────┬──────────┘
                         ▼
              Candidate Chain Search
                         │
                  Architecture RAG
                         │
           Typed Multi-Agent 协作推理（可选）
                         │
                         ▼
                Candidate Attack Chains
                         │
                         ▼
           Evidence + Architecture Verifier
                         │
                         ▼
           Scoring + Root Cause Localization
                         │
                         ▼
               JSON / 可解释报告 / 评测
```

候选搜索先于 LLM。验证器只消费结构化候选链和证据，不信任自然语言结论。

Phase 8 的协作推理固定复用一次 CandidateContext Assembly 和一次 ARM/global RAG，
依次执行 Evidence Analyst、Security Reasoner、Critic。Coordinator 是确定性 Python
编排器，不是第四个 LLM；Agent 输出、共识和 Critic Review 均不等于 Evidence 或
Verification。详细契约见 `docs/MULTI_AGENT_REASONING.md`。

## 双向 Cross-Layer Semantics

Phase 8R 的正式语义同时覆盖两个物理方向：

```text
Software/Firmware Side
  └─ instruction / MMIO / data / control / shared state
       └─> Hardware Side

Hardware Side
  └─ fault / interrupt / DMA / returned state / memory effect
       └─> Software/Firmware Side
            (semantic contract; future evidence-backed implementation)
```

第一条当前只有 `CrossGraphCandidate` software→hardware exact-anchor structural
primitive；它可服务未来 Type I/II，但不能区分两者。第二条目前只有
`CrossLayerInteraction` Type III 数据契约和明确的 not-implemented search capability，
没有检测算法或猜测型 BehaviorEdge。

## 分层与职责

### Domain Models

Pydantic 模型定义漏洞、行为、接口、硬件资源、证据、根因和攻击链。它们是模块间数据契约，不包含图搜索或外部服务逻辑。

Phase 8R 的 `CrossLayerInteraction` 是独立关联对象，不是 Graph Edge、AttackChain、
Verified Result 或 VulnerabilitySample。它显式保存 InteractionType、Direction、两侧
Layer、漏洞/行为/fault state/affected execution 引用，并以 canonical semantic JSON
的 SHA-256 建立身份。类型由 dataset annotation 或确定性输入提供，LLM 不分类。

### Ingestion and Normalization

把上游异构结果转换成领域模型，保留来源、样本类型和验证状态。无法确认的事实应明确为未知，不能由模型补写成真实事实。

### Program Analysis

`ProgramAnalyzer` 只负责从 artifact 提取可观察程序行为，不依赖 NetworkX、不写入 GraphRepository，也不返回 AttackChain。`ProgramArtifact` 为 fixture、ELF、raw binary 或 firmware payload 预留统一入口；`ProgramAnalysisResult` 复用 BehaviorNode、BehaviorEdge 和 Evidence，并严格校验 ID、端点、架构和 Evidence 引用。

MVP 的确定性 `DemoAnalyzer` 读取独立 DemoProgramSpec JSON。Spec 表达函数、调用点、ioctl 交互和明确 fixture MMIO 访问，而不是预制 BehaviorNode/Edge。Adapter 将其转换为 Function/DriverFunction/Interface/Register 节点，以及 CALLS、ISSUES、INVOKES、MMIO_READ/WRITE Edge。Sensitive Function 只通过 metadata 表示“值得进一步分析”，不代表漏洞。

`ingest_analysis_result` 位于 Analyzer 与 Repository 之间：先重建 Result 以阻止嵌套原地修改绕过校验，再检查 Repository 的全部 Node/Edge ID 冲突，最后插入；意外后端错误触发防御性回滚。DemoAnalyzer 本身完全不知道 Repository。

Phase 4A 的可选 `AngrAnalyzer` 使用 `angr.Project(auto_load_libs=False)` 和
`CFGFast` 分析 ARM ELF，只保留 main object 内非 SimProcedure/PLT 的 Function，
并将已解析的对象内调用转换为带 call-site Static Evidence 的 CALLS Edge。未解析
间接调用只进入 result diagnostics，不产生猜测 Edge。angr 依赖在执行 adapter 时
才动态导入；基础安装和 DemoAnalyzer 不依赖它。实现、环境矩阵和真实 MMIO
地址解析边界见 `docs/ANGR_INTEGRATION_PLAN.md`。

Phase 4B 为 `ProgramArtifact` 增加向后兼容的 firmware/driver 程序层，并通过
`AngrAnalyzer(memory_map=...)` 接收严格、显式、架构绑定的 Memory Map。Adapter
在每个函数 basic block 的未优化 VEX IR 上进行有限常量传播；只有真实 Load/Store
地址解析为常量且落入配置 region 时，才生成 Function → Register/HardwareResource
的 MMIO_READ/MMIO_WRITE。具体 RAM 地址和 unresolved 地址分别计入 diagnostics，
均不产生 MMIO Edge。

### Graph Storage

`GraphRepository` 统一节点、边、方向邻接和路径查询，不向调用者暴露 NetworkX 类型。MVP 的 `NetworkXGraphRepository` 使用 `MultiDiGraph`，以全局唯一的 `BehaviorEdge.id` 作为 edge key，因此相同 source/target 之间的 CALLS、DATA_FLOWS_TO 等关系可以共存。

搜索在遍历过程中同时检查 Node 和 Edge architecture；可选 `allowed_layers` 要求路径中所有 Node 都属于允许集合。只返回有向 simple `GraphPath`，其中 `max_hops` 和 `hop_count` 都表示 Edge 数量。结果按 hop count、node IDs、edge IDs 确定性排序。`GraphPath` 不是 `AttackChain`，不会产生漏洞或可利用性结论。

JSON 快照使用 `chipchain_graph` / format version 1 信封，保存排序后的 Phase 1 Node/Edge 数据和 metadata。加载时重新执行 Pydantic、端点、唯一 ID 和架构一致性验证，不信任由本项目自身生成的 JSON。

### Vulnerability Knowledge Graph

Phase 5 的 Knowledge Graph 与 Behavior Graph 是两个独立边界。它使用
`KnowledgeNode`、`KnowledgeEdge`、`KnowledgeRelationType` 和
`KnowledgeGraphRepository`，不复用 BehaviorNode/RelationType，也不提供
`find_paths`。`VulnerabilityKnowledgeBuilder` 只依赖领域模型，负责将一个或多个
`VulnerabilitySample` 确定性转换为 `KnowledgeGraphBundle`；它不知道 NetworkX、
AttackChain、LLM 或分析器。

`NetworkXKnowledgeGraphRepository` 同样使用 `MultiDiGraph`，但独立维护 Node、
Edge 和 Evidence 目录。Repository 由单一 architecture 约束；CWE/CAPEC 是唯一
允许 architecture 为空的全局 taxonomy 节点，连接它们的 Edge 仍使用样本 ARM
architecture。重复 ID、悬空 endpoint/evidence 和跨架构实体立即失败。

知识快照使用独立 `chipchain_knowledge_graph` / format version 1 信封，包含
architecture、sample IDs、nodes、edges、evidence 和 metadata。加载时全部重新
构造为 Pydantic 模型并检查跨实体不变量，不能被 Behavior Graph loader 接受。

两张图仅通过结构化字段生成相同 canonical match keys；Phase 5 不消费这些键进行
链接，也不创建跨图 Edge。完整键格式和 Phase 6 保守建议见 `ENTITY_LINKING.md`。

### Candidate Search

Phase 6 不合并两张图。`ExactHardwareEntityLinker` 只读两个 Repository，以
architecture 为第一层过滤，并对 Behavior Hardware Node 推导的 canonical keys
与 Knowledge HardwareResource.match_keys 求精确交集。每个交集产生独立
`EntityLink`；一个寄存器关联多个漏洞资源时保留全部链接。

`CrossGraphCandidateSearcher` 先取得 linkable Behavior anchor，再以 anchor 为明确
target 调用有界 `GraphRepository.find_paths`。路径遍历只允许 firmware、driver、
interface、hardware layer，以及 CALLS、ISSUES、INVOKES、DATA_FLOWS_TO、
MMIO_READ、MMIO_WRITE、ACCESSES relation。路径必须跨至少两个 layer 且包含
hardware。`allowed_relations` 在 GraphRepository 遍历过程中应用，旧调用保持兼容。

对于每个可达链接，Searcher 查询指向 Knowledge HardwareResource 的 incoming
TARGETS_RESOURCE Edge，并要求其原始 source 是 Vulnerability。它不会反转或新增
KnowledgeEdge，而是收集该 Vulnerability 的一跳 Trigger、Precondition、CWE、
CAPEC、Component、Behavior、Interface、HardwareResource、SecurityMechanism、
Impact 和 RootCause 上下文。

结果 `CrossGraphCandidate` 保存 GraphPath、EntityLink、原向知识 Edge ID、上下文
Node ID 和 Evidence ID。它只是“行为路径末端通过精确身份锚点关联到漏洞知识”的
未验证结构相关性，不是 AttackChain，不包含可利用性、权限提升或概率评分。
完整语义见 `docs/CANDIDATE_SEARCH.md`。

### Knowledge Retrieval and LLM

Phase 7 由三个职责边界组成：

1. `CandidateContextAssembler` 将 Candidate 的 ID 引用严格解析为 Behavior/
   Knowledge Node、Edge 和完整 Evidence；任一引用缺失立即失败。
2. `CandidateRetrievalQueryBuilder` 确定性抽取 architecture、relation、硬件 match
   keys、taxonomy 和条件术语；`LocalLexicalKnowledgeRetriever` 在评分前只保留
   目标架构文档和明确 global 文档。
3. `CandidatePromptBuilder` 只序列化当前 Context 和 top-k chunks；`LLMProvider`
   返回严格 `CandidateSemanticAssessment`，由 `CandidateReasoner` 做引用后校验。

Retrieved document 被标为 reference data，不能覆盖固定 Prompt instruction、架构
限制或 verification boundary。默认测试和 Demo 使用 deterministic
`MockLLMProvider`，不依赖网络或 API Key。

可选 `OpenAICompatibleLLMProvider` 通过环境变量显式选择 `responses` 或
`chat_completions`，不会失败后自动切换。JSON Mode 是显式 capability；无论使用
哪种协议，最终结果均通过 `json.loads` 和 Pydantic，而不是正则修复。API Key 不
进入可序列化配置、日志或异常文本。详细契约见 `docs/RAG_REASONING.md`。

### Verification and Scoring

Phase 9A-R 以 `CrossLayerInteraction + InteractionVerificationInput` 为顶层入口。显式
binding 把 interaction role 映射到 source fact；legacy Candidate 只通过只读 adapter 为
Type I/II 提供 software→hardware facts。验证器逐字段检查 CALLS/MMIO 静态 Evidence、
Exact EntityLink、KG provenance、participant layer 与 ARM rules。

评分按 InteractionType 使用配置化 profile；空 required evidence 为 0.0，Type II 不包含
initiating firmware vulnerability component，Type III profile disabled 且 score 为 None。
该值只是 evidence support；LLM objective weight 固定为 0.0。

### Runtime Evidence Contract

Phase 9B0 在 Program/Behavior Graph 与 Verification 之外建立独立 runtime boundary：

```text
Runtime Backend Manifest
  → Runtime Trace Manifest
  → ordered RuntimeObservation[]
  → Dynamic Evidence normalization
  → future explicit Interaction binding / dynamic verifier
```

Runtime backend 通过 versioned manifest 声明 capability；Trace 在构造和加载时检查架构、
backend identity、全局 `sequence_index`、Observation identity、vCPU 范围与 capability。
`vcpu_count` 模型允许未来扩展，但 Phase 9B1 首个 observer 只支持单 vCPU deterministic
ordering。Trace 使用独立 `chipchain_runtime_trace` v1 JSON，不写入 Behavior Graph。

`RuntimeIntervention` 是 controlled action，不是 Observation。Phase 9B0 没有 executor、QEMU
plugin、fault injection 或 causal verifier，也没有修改 9A-R Pipeline。Dynamic Evidence
仍是 interaction-agnostic observation provenance；显式 binding 和 fact verification 留给后续。

### ARM QEMU Passive Adapter

Phase 9B1 R2 在 runtime core 外增加 `runtime/qemu` adapter：两层 capability probe、backend-specific
raw v2 parser、同进程 QMP FlatView capture、topology classifier、RuntimeTrace mapping 和 safe
subprocess runner。C plugin 只报告 execution 与 raw physical memory access；plugin IO boolean
只是诊断。Python 以 captured resolved topology 分类 MMIO，再执行 identity/capability validation
和 Evidence normalization。Raw trace 与 RuntimeTrace 都不进入 Behavior Graph。

```text
owned ARM32 ELF → QEMU -S/QMP → info mtree -f artifact
                    ↓ cont                 ↓ semantic ID + SHA-256
                 TCG plugin → untrusted raw v2 physical events
                                      ↓ strict parse + topology classify
                 RuntimeBackendManifest + RuntimeTraceManifest
                                      ↓ detached revalidation
                    RuntimeObservation → Dynamic Evidence
```

该 adapter 固定 ARM32 `virt`/`cortex-a15`/单 vCPU，不声明 memory value、register、
discontinuity、DMA 或 active capability。只有完整访问落入唯一 I/O leaf 才产生 Runtime MMIO；
RAM、boundary、overflow、ambiguous 和 malformed 输入均 fail closed。当前离线实现完整，但
本机 matching QEMU/plugin R2 revalidation 受工具链缺失阻塞。

### Evaluation and Presentation

评测模块比较结构化预测链与 Ground Truth，统计检索、节点、边和根因指标及失败原因。CLI 是首个用户入口，核心算法稳定后再增加 FastAPI。

## ARM MVP 的最小闭环

```text
用户可控输入
  → Firmware Function
  → ioctl Interface
  → Driver Function
  → MMIO_WRITE
  → ARM Register / Hardware Resource
  → Hardware Weakness
  → Security Impact
```

该闭环优先验证数据契约和逐边证据链。TrustZone、SMC、DMA、异常级切换等能力按明确用例逐步加入。

## 关键依赖方向

- 领域模型不依赖图数据库、分析器或 LLM SDK。
- 搜索服务依赖 `GraphRepository` 抽象，不依赖 NetworkX 细节。
- Pipeline 依赖 `ProgramAnalyzer`、`KnowledgeRetriever`、`LLMProvider` 抽象。
- 外部适配器依赖核心接口，核心模块不反向导入适配器。
- CLI/API 调用应用服务，不直接承载算法。

## Program Analysis 数据流

```text
DemoProgramSpec JSON        ARM ELF + explicit MemoryMap
        ↓ validate             ↓ CFGFast + VEX resolver
DemoAnalyzer                   AngrAnalyzer
        └──────────────┬────────────┘
                       ↓ normalize
ProgramAnalysisResult
  ├─ BehaviorNode[]
  ├─ BehaviorEdge[]
  └─ Evidence[]
        ↓ preflight + rollback guard
GraphRepository
        ↓
GraphPath
```

Program Analysis 路径在 Register/HardwareResource 观察处停止。Hardware Weakness、Impact、CVE/CWE、Exploitability 和 Verified AttackChain 均属于后续模块。

## GraphRepository API 语义

- 重复 Node/Edge ID、悬空 Edge 和跨架构 Edge 立即失败，不静默覆盖。
- `successors` / `predecessors` 返回按 ID 排序的唯一相邻节点；并行 Edge 通过 `list_edges` / `get_edge` 保留。
- `find_paths` 在指定 target 时返回起点到目标的全部受限简单路径；未指定 target 时返回 1 到 `max_hops` 内的可达非空路径。
- target 与 start 相同时允许一个 0-hop GraphPath。
- `max_results` 在完整确定性排序后截断。该实现优先保证科研复现性，不面向超大稠密图的无界枚举。
- `save` 使用稳定 JSON；`load` 返回新 Repository，避免失败加载污染已有实例。

## 当前实现边界

Phase 0～9B0-R1 已实现 Python 包、CLI、严格领域模型、GraphRepository、NetworkX
MultiDiGraph、JSON 图快照、ProgramAnalyzer、DemoAnalyzer、可选 AngrAnalyzer、
Analysis Ingestion，以及 synthetic ARM ELF 到 Function/CALLS/MMIO Hardware
Node/GraphPath 的端到端闭环；另有独立 Vulnerability Knowledge Graph、确定性
Sample 转换、Evidence 目录、canonical match keys、Exact Hardware EntityLink 和
CrossGraphCandidate Search；Phase 7 增加只读 Context、Architecture RAG、Mock/
optional compatible Provider 和 Semantic Assessment 后校验。通用地址分析、
Candidate 到 AttackChain 投影、动态条件观察以及 API 仍未实现。Phase 8 增加共享
Context/RAG、三个固定类型化 Agent、确定性
Coordinator、Citation/Architecture/Condition 校验、失败隔离和 digest-only Trace。
Phase 8R 新增三类 CrossLayerInteraction。Phase 9A-R 增加 Type I/II 部分非 LLM
Evidence Verification、显式 condition assessment、type-aware score 与 trigger-point
localization；现有 Candidate/Search/RAG/Multi-Agent API 保持不变。Phase 9B0 新增独立
Runtime backend/trace/observation/intervention contract、v1 persistence 与 Dynamic Evidence
normalization。Phase 9B1 R2 已实现 ARM QEMU raw physical observer、same-process FlatView、
topology classifier、adapter、runner 与 owned STRB fixture；真实 R2 acceptance 仍因本机缺少
matching QEMU/headers/build environment 而未复验。Hardware→software causal Verification 与
反向 BehaviorEdge 仍未实现。
