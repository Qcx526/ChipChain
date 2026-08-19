# 数据模型当前实现说明

## 实现状态

Phase 1 已使用 Pydantic v2 实现 ChipChain 的第一版领域数据契约。模型位于 `src/chipchain/models/`，不依赖 NetworkX、Neo4j、程序分析器或 LLM SDK。

模型层允许 ARM、RISC-V、PowerPC、SPARC 和 LoongArch 数据独立存在。当前只实现 ARM MVP 是 Pipeline / Search 层的限制；领域模型不会永久禁止未来架构。与此同时，单条 `AttackChain` 和单个 `VulnerabilitySample` 内的架构专有实体必须保持一致。

## 公共约定

- JSON 字段使用 snake_case，枚举序列化为稳定的小写字符串。
- 所有模型继承 `DomainModel`，默认 `extra="forbid"`，字段拼写错误不会被静默忽略。
- ID 和必要文本不能为空，输入两端空白会被移除。
- 所有 confidence、score、score component 和 evidence coverage 都限制在 `[0, 1]`。
- 列表和字典使用 `default_factory`，实例之间不共享可变默认值。
- metadata 只允许 JSON 可序列化值。
- 地址使用非空字符串，可保存 `0x401020`、地址范围或符号地址；Phase 1 不对未来地址形式做过度限制。
- `created_at` 必须是 timezone-aware datetime，默认使用 UTC。

## 模块划分

| 模块 | 当前模型 |
| --- | --- |
| `enums.py` | Architecture、Layer、SampleType、EvidenceType、BehaviorType、NodeKind、RelationType、ChainStatus、EdgeVerificationStatus |
| `evidence.py` | Evidence |
| `behavior.py` | Behavior、Interface |
| `hardware.py` | HardwareResource、SecurityMechanism、Impact、RootCause |
| `vulnerability.py` | Component、Trigger、Precondition、VulnerabilitySample |
| `graph.py` | BehaviorNode、BehaviorEdge |
| `chain.py` | AttackChainNode、AttackChainEdge、AttackChain |

公共模型从 `chipchain.models` 导出，调用者无需依赖内部文件布局。

Phase 5 的独立知识图数据契约位于 `src/chipchain/knowledge/`，不放入上述 Behavior
Graph 模型：

| 模块 | 当前模型或职责 |
| --- | --- |
| `enums.py` | KnowledgeNodeKind、KnowledgeRelationType |
| `models.py` | KnowledgeNode、KnowledgeEdge、KnowledgeGraphBundle、KnowledgeGraphSnapshot |
| `builder.py` | VulnerabilitySample 的确定性转换与 Evidence 命名空间 |
| `repository.py` | KnowledgeGraphRepository 抽象 |
| `networkx_repository.py` | 独立 MultiDiGraph、Evidence 目录和 JSON 持久化 |
| `match_keys.py` | 精确 canonical entity match keys |

Phase 6 的第三类相关性对象位于 `src/chipchain/candidate/`：

| 模块 | 当前模型或职责 |
| --- | --- |
| `enums.py` | 仅支持 `exact_canonical_key` 的 EntityLinkMethod |
| `models.py` | EntityLink、EntityLinkResult、CrossGraphCandidate |
| `linking.py` | Hardware-only exact key intersection |
| `search.py` | 受限 Behavior target search 与一跳漏洞上下文收集 |
| `errors.py` | 架构与非法知识上下文异常 |

Phase 7 的只读解析、检索和解释契约位于 `src/chipchain/reasoning/`：

| 模块 | 当前模型或职责 |
| --- | --- |
| `context.py` | EvidenceResolver、InMemoryEvidenceResolver、CandidateContextAssembler |
| `documents.py` | 本地 ArchitectureKnowledgeDocument 严格加载 |
| `query.py` | CandidateRetrievalQueryBuilder |
| `retrieval.py` | KnowledgeRetriever、LocalLexicalKnowledgeRetriever |
| `prompts.py` | CandidatePromptBuilder 与固定信任边界 |
| `provider.py` | LLMProvider、可选 OpenAICompatibleLLMProvider |
| `mock_provider.py` | deterministic offline structured assessment |
| `reasoning.py` | 单体 CandidateReasoner 与 citation post-validation |
| `models.py` | Context、Document、Chunk、Query、Prompt、Assessment、Config、Result |

Phase 8R 的正式跨层语义位于 `src/chipchain/models/cross_layer.py`：

| 模型/枚举 | 语义 |
| --- | --- |
| `CrossLayerInteractionType` | 导师定义的 Type I / II / III，封闭且无 other/unknown |
| `CrossLayerDirection` | software_to_hardware / hardware_to_software |
| `CrossLayerLocationRole` | initiating root cause / trigger point / affected execution point |
| `CrossLayerInteraction` | 独立、未验证的跨层 hypothesis/known scenario 数据契约 |
| `SOFTWARE_SIDE_LAYERS` | firmware、driver、interface |
| `HARDWARE_SIDE_LAYERS` | hardware |

## CrossLayerInteraction

三类约束为：

1. Type I：软件侧 initiating vulnerability、trigger behavior、硬件侧 target
   vulnerability 均非空，方向 software→hardware；
2. Type II：initiating vulnerability 必须为空，trigger behavior 与硬件 target
   vulnerability 非空，方向 software→hardware；
3. Type III：硬件侧 initiating vulnerability 与 affected execution 非空，方向
   hardware→software，target firmware vulnerability 允许为空。

`fault_state_ids` 可显式引用 Type III 传播中的异常状态。所有 ID list 去重并排序；
Interaction ID 对除 metadata 外的规范语义字段执行 canonical JSON + 完整 SHA-256。
可选 `referenced_architectures` 只用于拒绝能够显式验证的跨架构引用；opaque ID 本身
不会被猜测解析。

`firmware_*` 类型名遵循正式分类，其中 firmware-side 表示现有 firmware/driver/
interface 软件执行侧，不扩大到尚未建模的 OS/application。

### 三种位置角色

- `initiating_root_cause`：漏洞或异常真正起因；
- `cross_layer_trigger_point`：使状态跨层传播的指令、接口、寄存器访问或硬件状态；
- `affected_execution_point`：另一层实际受影响的执行位置。

三者可能是不同实体。Type II 的 MMIO instruction 是 trigger point，不能自动称为
firmware root cause；Type III 的 firmware branch 是 affected point，不能称为 software
root cause。历史 `RootCause` 模型保持原义，未来 revised localization 再消费新角色。

### 与既有对象的边界

`VulnerabilitySample != CrossLayerInteraction`：前者继续表达一个原子漏洞/弱点，
不会被强制增加 interaction 字段。`CrossGraphCandidate != CrossLayerInteraction`：
前者保持 software→hardware exact-anchor primitive、原 API 和原 deterministic ID，
不会自动分类 Type I/II，也不支持 Type III。

## 稳定枚举

- Architecture：`arm`、`risc_v`、`powerpc`、`sparc`、`loongarch`
- Layer：`firmware`、`driver`、`architecture`、`hardware`、`interface`、`impact`
- SampleType：`real`、`synthetic`、`demo`、`fixture`
- EvidenceType：`knowledge_graph`、`static_analysis`、`dynamic_analysis`、`architecture_rule`、`source_reference`、`llm_semantic`
- ChainStatus：`candidate`、`partially_verified`、`verified`、`rejected`
- EdgeVerificationStatus：`unverified`、`verified`、`rejected`
- BehaviorType：`call`、`syscall`、`ioctl`、`mmio_read`、`mmio_write`、`register_access`、`dma_read`、`dma_write`、`interrupt`、`privilege_transition`、`data_flow`
- NodeKind：`vulnerability`、`function`、`driver_function`、`interface`、`register`、`hardware_resource`、`security_mechanism`、`weakness`、`impact`
- RelationType：`calls`、`invokes`、`issues`、`data_flows_to`、`mmio_read`、`mmio_write`、`accesses`、`triggers`、`exploits`、`leads_to`
- CrossLayerInteractionType：`firmware_vulnerability_to_hardware`、
  `firmware_behavior_to_hardware`、`hardware_vulnerability_to_firmware`
- CrossLayerDirection：`software_to_hardware`、`hardware_to_software`
- CrossLayerLocationRole：`initiating_root_cause`、`cross_layer_trigger_point`、
  `affected_execution_point`

## Evidence

`Evidence` 保存证据 ID、类型、来源、artifact、地址、指令、规则 ID、置信度、验证标记、引用和 metadata。行为事实与证据保持分离：例如 `mmio_write` 属于 Behavior/Edge，观察到该写操作的指令和位置属于 Evidence。

Evidence 本身不判断程序分析结果是否真实；它只保证数据完整、可引用和可序列化。

## VulnerabilitySample

`VulnerabilitySample` 聚合：

- CVE/CWE/CAPEC 标识；
- Component、Trigger、Precondition；
- Behavior 和 Interface；
- HardwareResource 和 SecurityMechanism；
- Impact、Evidence 和 RootCause；
- sample type、来源、引用和验证状态。

当前跨字段校验：

1. `sample_type=real` 时，`source` 或 `references` 至少一个非空。
2. Component、Behavior、Interface、HardwareResource、SecurityMechanism 和 RootCause 的 architecture 必须与样本一致。
3. Evidence ID 在样本内唯一。
4. Trigger、Precondition、Behavior、Interface 和 RootCause 引用的 Evidence ID 必须存在于样本的 Evidence 目录。

fixture、demo 和 synthetic 不会被自动赋予 CVE 或真实来源。仓库 fixture 使用 `FIXTURE-*` 和 `chipchain-test-fixture` 明确标识。

## Behavior Graph 数据契约

`BehaviorNode` 使用稳定 ID、NodeKind、Architecture 和 Layer，可直接通过 `model_dump(mode="json")` 转换成当前 GraphRepository 后端需要的属性字典。

`BehaviorEdge` 使用 `source_id` / `target_id` 引用节点，以 RelationType 限定核心关系，并通过 Evidence ID 引用证据。Phase 1 模型本身不检查节点是否存在；Phase 2 GraphRepository 在插入和加载时负责端点、全局 Edge ID 和架构一致性验证。

## 线性 AttackChain

第一版仅支持 linear chain，不支持 DAG 或分支攻击图。

`AttackChainNode` 是底层实体的有序视图，包含 `entity_id`、`order`、`kind`、`architecture`、`layer` 和 `label`。`AttackChainEdge` 连接相邻实体，并使用三态 `verification_status` 区分尚未验证、验证成功和验证失败。

`AttackChain` 内嵌 Evidence 目录，Edge 和 RootCause 通过 ID 引用。这使单个 JSON 自包含，也允许模型检查 verified chain 的最低证据条件。

当前跨字段校验：

1. 至少存在一个节点。
2. 节点按列表顺序形成从 0 开始的连续 order，且 entity ID 唯一。
3. `len(edges) == len(nodes) - 1`。
4. 第 i 条 Edge 必须连接第 i 和第 i+1 个节点。
5. Node、Edge 和 RootCause architecture 必须与 Chain architecture 相同。
6. Edge ID 和 Evidence ID 在链内唯一，Evidence 引用不得悬空。
7. `status=verified` 时每条 Edge 必须为 verified，必须引用 Evidence，且至少包含一条 `verified=true` 的非 `llm_semantic` Evidence。
8. score、score components 和 evidence coverage 必须在 `[0, 1]`。
9. `created_at` 必须携带时区。

第 7 条只是最低结构/类型门槛，不替代 Phase 7 的真实性、架构规则和动态证据验证算法。

## RootCause 的 register 字段

Pydantic 新版本的 BaseModel 已有同名属性。为避免字段遮蔽警告，Python 内部字段名为 `register_name`，外部 JSON 始终使用需求规定的 `register`；`root_cause.register` 只读属性仍可访问该值。其他 RootCause 定位字段包括 function、binary address、instruction、MMIO address、hardware resource 和 security mechanism。

## JSON 与 Schema

加载和 round-trip：

```python
chain = AttackChain.model_validate_json(json_text)
json_text = chain.model_dump_json(indent=2)
```

运行：

```powershell
python scripts/export_schema.py
```

会生成 `VulnerabilitySample` 与 `AttackChain` 的 JSON Schema 到 `artifacts/schema/`。该目录已被 Git 忽略：模型代码是唯一来源，生成文件可随时重建，因此不提交重复副本。

## Program Analysis 契约

Phase 3 在 `chipchain.analysis` 中增加两个存储无关模型：

- `ProgramArtifact`：artifact ID、architecture、artifact type、可选 path / fixture identifier、JSON metadata，以及默认 firmware、只允许 firmware/driver 的 `program_layer`；至少要有一种定位方式。
- `ProgramAnalysisResult`：Artifact、architecture、BehaviorNode、BehaviorEdge、Evidence 和 metadata。

ProgramAnalysisResult 保证：

1. Artifact、Result、所有 Node 和所有 Edge architecture 一致；
2. Node、Edge、Evidence ID 分别唯一；
3. Edge endpoint 都存在于 Result Node；
4. 每条分析 Edge 至少引用一条 Evidence；
5. 所有 Edge Evidence ID 在 Result 中存在；
6. 支持稳定 JSON round-trip。

DemoProgramSpec、DemoFunctionSpec、DemoCallSpec、DemoIoctlSpec 和 DemoMMIOAccessSpec 是 DemoAnalyzer 私有输入格式，不从 `chipchain.models` 公共 API 导出。它们描述分析输入语义，DemoAnalyzer 再转换成全局领域模型。

函数的 `sensitive` / `sensitive_reasons` 放在 BehaviorNode metadata，避免为一个分析 marker 扩大领域模型。CALL XRef 通过 CALLS Edge 引用带 call-site address 的 Evidence 表示。MMIO Register Node 保存 fixture address，MMIO Edge 和 Evidence 分别保存关系与指令位置。

Phase 4B 的 `MemoryMap` / `MemoryRegion` 是 Analyzer 配置模型，不是漏洞知识图谱。
Region 使用规范十六进制 inclusive range，绑定 architecture，拒绝倒置范围、重复 ID
和重叠；`resource_kind` 仅允许 Register/HardwareResource，Register 还必须满足
`start == end`。它只把已由真实 IR
可靠解析且命中 region 的地址分类为 MMIO。

## Vulnerability Knowledge Graph 数据契约

`KnowledgeNode` 包含稳定 ID、kind、label、可选 layer、external IDs、match keys、
Evidence 引用和 metadata。只有 CWE/CAPEC 可使用 `architecture=None` 且不得声明
layer；Vulnerability、Component、Trigger、Precondition、Behavior、Interface、
HardwareResource、SecurityMechanism、Impact 和 RootCause 都必须带具体架构。

`KnowledgeEdge` 使用独立的语义关系：HAS_CWE、HAS_CAPEC、AFFECTS_COMPONENT、
HAS_TRIGGER、REQUIRES_PRECONDITION、INVOLVES_BEHAVIOR、USES_INTERFACE、
TARGETS_RESOURCE、INVOLVES_SECURITY_MECHANISM、LEADS_TO_IMPACT 和
HAS_ROOT_CAUSE。CALLS、MMIO_READ/MMIO_WRITE 等程序观察关系不属于知识枚举。

`KnowledgeGraphBundle` 自包含 architecture、sample IDs、nodes、edges、Evidence
目录和 metadata，并检查：

1. Node、Edge、Evidence 和 sample ID 各自唯一；
2. Edge endpoint 存在；
3. Node/Edge architecture 与 bundle 一致，允许 endpoint 是全局 taxonomy；
4. Node/Edge 的 Evidence 引用都存在；
5. JSON round-trip 后重新执行相同校验。

Builder 为非 taxonomy 节点使用 architecture + sample ID + local ID 的稳定身份；
无显式 ID 的 Trigger/Precondition 使用规范 JSON 的 SHA-256 短摘要。全局 CWE/CAPEC
按规范化 taxonomy ID 去重。Evidence 被复制为
`sample:<sample-id>:evidence:<local-id>`，所有引用同步映射，源 Sample 不被修改。
源关系没有 Evidence 时保留空列表，不生成伪证据。

## EntityLink 与 CrossGraphCandidate

`EntityLink` 保存 architecture、两端 Node ID/kind、非空精确 match key 交集和
`exact_canonical_key` 方法。ID 由 architecture 与两端 ID 确定性生成。当前模型
只接受 Behavior Register/HardwareResource 和 Knowledge HardwareResource；
CWE/CAPEC 不能作为 endpoint。它不是 BehaviorEdge、KnowledgeEdge 或
AttackChainEdge。

`EntityLinkResult` 独立保存 links、unmatched Behavior IDs 和 unmatched Knowledge
IDs，便于单独评测链接能力。一个 Behavior ID 可以出现在多个 EntityLink 中。

`CrossGraphCandidate` 保存：

- 原始 `GraphPath`、对应 path layer 和精确 `EntityLink`；
- Knowledge Vulnerability/anchor ID 及原方向一跳 Knowledge Edge ID；
- Component、Trigger、Precondition、CWE、CAPEC、Behavior、Interface、Hardware
  Resource、Security Mechanism、Impact 和 Root Cause Node ID；
- Behavior/Knowledge Evidence ID、知识证据计数和缺失知识证据标记；
- 明确的 `unverified_correlation` metadata。

Candidate 要求 GraphPath/EntityLink architecture 一致、路径终点等于 Behavior
anchor、Knowledge anchor 等于链接端点、路径跨至少两个 layer 且包含 hardware。
Candidate ID 由 architecture、GraphPath Node/Edge IDs、EntityLink ID 和
Vulnerability ID 的稳定摘要生成。所有引用列表拒绝重复并支持 JSON round-trip。

## CandidateContext 与 Semantic Assessment

`CandidateContext` 是 CrossGraphCandidate 引用事实的只读解析视图，包含 Behavior
Node/Edge/Evidence、Knowledge Vulnerability/Anchor/Node/Edge/Evidence，以及分类后
的 Trigger、Precondition、Impact、SecurityMechanism、RootCause 和 taxonomy Node。
它不重新定义或补写事实。Behavior Evidence 由独立 resolver 从
`ProgramAnalysisResult.evidence` 创建；Knowledge Evidence 由 Knowledge Repository
解析。任何缺失 ID 都产生稳定错误，不能静默忽略。

`ArchitectureKnowledgeDocument` 的 `scope=architecture` 必须带 architecture，
`scope=global` 必须不带 architecture。`RetrievedKnowledgeChunk.score` 仅表示本地
lexical retrieval relevance，不是漏洞或攻击链置信度；Chunk 保留 document、source、
reference、section 和 scope provenance。

`CandidateSemanticAssessment` 只允许：

```text
requires_verification
insufficient_context
contextually_inconsistent
```

它保存 summary、输入范围内的 Evidence/Chunk citation、未解析 Trigger/Precondition、
缺失信息、矛盾和建议验证步骤。模型没有 verified、exploitable、probability 或最终
confidence 字段。Reasoner 进一步检查 Candidate/Architecture 身份、citation 子集，
并要求 Phase 7 中所有 Trigger/Precondition 保持 unresolved。

`LLMProviderConfig` 只保存 base URL、model、显式 API style、JSON mode、timeout 和
可选 reasoning/output limit；
API Key 不属于模型，不能出现在 repr/model_dump/metadata。

Demo Evidence 固定 `type=static_analysis`、`source=demo_analyzer`、`verified=true`、`metadata.fixture=true`。其中 confidence 1.0 只表示该关系由确定性 fixture 明确给出，不表示真实漏洞或攻击可信度。

## Typed Multi-Agent Models

`MultiAgentContext` 保存一次解析的 CandidateContext、一次确定性 retrieval query 和
同一批 ARM/global chunks。三个 Agent 共用该对象，不各自检索。

`EvidenceAnalysis` 记录已观察 Behavior/Knowledge Evidence ID、Evidence gap、缺失
Evidence 标志和全部 unresolved Trigger/Precondition。`SecurityReasoningAssessment`
包含一个或多个 `SemanticHypothesis`；Hypothesis 仍是待验证解释，不是 Fact、Evidence
或 AttackChain Edge。`CriticReview` 记录 bounded review issue，并显式引用当前
Evidence、Chunk、Condition 和 Hypothesis ID。

`AgentExecutionRecord` 只保存固定 sequence/role、身份、SHA-256 input/prompt/output
digest、状态和安全 error type；不保存时间戳参与 identity，也不保存 Prompt、原始响应
或 reasoning content。`MultiAgentReasoningResult` 保留三份原始结构化输出、完整 Trace、
全部 unresolved 条件和非验证 final semantic status，不包含 score/confidence/probability。

## 当前边界

模型只负责结构和明确的领域不变量，不执行真实漏洞检测或证据真实性判断。
ProgramAnalyzer 生产程序观察，Behavior Graph 返回 GraphPath，Phase 5 Builder 生产
独立漏洞知识，Phase 6 只生成 CrossGraphCandidate，Phase 7 产生单 Reasoner Semantic
Assessment，Phase 8 产生类型化 Multi-AgentReasoningResult；两者都不可表达验证结论。
后续阶段完成条件满足性和 Evidence Verification 后，才可
讨论投影为 `AttackChain(status=candidate)`；当前不得把 Assessment 或 Retrieved
文本解释成 Evidence 或已验证 AttackChain。

Phase 9A-R 新增独立 verification package：`InteractionReferenceBinding`、
`InteractionConditionBinding`、`InteractionVerificationInput`、interaction-scoped
`VerificationRecord` / `ConditionAssessment`、`CrossLayerTriggerFeatureSet`、
`ObjectiveEvidenceInventory`、`CrossLayerLocationFinding` 和 `InteractionVerificationResult`。

Type III 结果严格要求 `verification_status=None`、`verification_score=None`、空 score
components；semantic feature 不等于 verified fact。没有新增 hardware→software BehaviorEdge。

Phase 9A-R1 为 VerificationRecord 增加 supporting Evidence 子集约束，并要求
CrossLayerTriggerFeatureSet 的每个重要输出 feature 至少具有一条 TriggerFeatureProvenance。

Phase 9A-R2 为 InteractionVerificationResult 增加 required fact status map，并强化 feature
type/direction identity；Evidence 合并拒绝同 ID 异内容碰撞。硬件资源 binding 必须通过
EntityLink anchor 的 exact external/resource/Memory Map identity 对应 Interaction reference。

Phase 9A-R3 将 binding cardinality 收紧为每个 semantic `(role, reference ID)` 至多一个
source。不同 reference ID 可继续独立绑定；InteractionVerificationResult 的各
VerificationRecord collection 另外执行 record ID uniqueness 校验，binding collection 同时
校验 subject ID uniqueness。

## Runtime Evidence Contract

Phase 9B0 的 `chipchain.runtime` 是独立领域边界：

- `RuntimeBackendManifest` 保存 backend kind/name/version、architecture、system-emulation
  标志和唯一排序的 capability；metadata 不参与 canonical SHA-256 identity。
- `RuntimeTraceManifest` 保存 run/scenario、backend、artifact SHA-256、machine/CPU/vCPU、
  可选 Memory Map 与 input/environment fingerprint；不以 wall-clock 时间建立身份。
- `RuntimeObservation` 使用全局 `sequence_index` 排序，并为 instruction、MMIO、interrupt/
  exception discontinuity 和 DMA 执行事件特定校验。`address_space_id` 保留可选地址空间。
- `RuntimeTrace` 使用 `chipchain_runtime_trace` version 1 envelope，重新校验 identity、
  architecture、sequence、vCPU 和 backend capability，并确定性排序 observations。
- `RuntimeIntervention` 表示受控 action；它与 Observation 使用不同 enum、模型和 ID 空间。

Observation identity 包含 trace、sequence、architecture、event、vCPU 和全部事件语义字段；
host timestamp 与 metadata 明确排除。物理地址不能被默认视为跨 address space 全局唯一；
未来 resolver 在多地址空间场景必须同时使用 `address_space_id`。

`RuntimeEvidenceNormalizer` 产生现有 `Evidence(type=dynamic_analysis)`。Evidence 的
`source` 是 backend manifest ID，`artifact` 是 trace ID，metadata 保存 observation/event/
sequence/vCPU 和事件字段，不写入 Interaction ID、reference ID 或 role。
