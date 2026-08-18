# Exact Entity Linking 与 Candidate Search

## 结果语义

Phase 6 的 `CrossGraphCandidate` 表示：存在一条结构化 Behavior GraphPath，其末端
硬件实体通过精确 canonical identity anchor 与某个 Vulnerability 的 Knowledge
HardwareResource 相连。

它不表示：

- 漏洞已在目标程序中验证；
- Trigger 或 Precondition 已被路径满足；
- 漏洞可利用或权限提升成立；
- Candidate 已经是线性或已验证 AttackChain。

## 三类独立对象

```text
Behavior Graph                  Vulnerability Knowledge Graph
     │                                      │
     └──── exact canonical EntityLink ──────┘
                         │
                         ▼
              CrossGraphCandidate
```

Behavior/Knowledge Repository 始终独立。EntityLink 和 Candidate 不写回 Node、不新增
跨图 Edge，也不创建 MergedNetworkXGraph。

`EntityLink != AttackChainEdge`。它只证明两个硬件实体共享结构化 identity key。

## Phase 6A：Exact Hardware Linking

第一版只考虑：

```text
Behavior NodeKind.REGISTER / HARDWARE_RESOURCE
                        ↓ exact key intersection
Knowledge KnowledgeNodeKind.HARDWARE_RESOURCE
```

算法先检查 `behavior.architecture == knowledge.architecture == search architecture`，
随后调用 Phase 5 的同一 `hardware_resource_match_keys()` helper。只有
`behavior_keys ∩ knowledge.match_keys` 非空才生成 EntityLink。

没有 name/label equality、substring、Levenshtein、embedding、semantic 或 LLM
匹配。CWE/CAPEC 是全局 taxonomy，不是 EntityLink endpoint。

One-to-many 是正常结果。同一 Behavior Register 被两个漏洞样本引用时，生成两个
EntityLink，而不是返回 ambiguous/zero match。

## Phase 6B：Candidate Search

搜索顺序：

1. 运行独立 Exact Hardware Linker。
2. 取得 linkable Behavior Hardware Anchor ID。
3. 分别执行 `start → target anchor` 的有界 GraphPath 查询。
4. 遍历时过滤 architecture、allowed layers 和 allowed relations。
5. 要求路径跨至少两个 layer，并包含 `Layer.HARDWARE`。
6. 查找原方向 `Vulnerability → TARGETS_RESOURCE → linked resource`。
7. 收集 Vulnerability 的现有一跳知识上下文。
8. 聚合 Behavior Edge 和 Knowledge Node/Edge 的 Evidence ID。
9. 生成稳定 CrossGraphCandidate，确定性排序后应用 `top_n`。

搜索不会先枚举所有无目标 simple path。`max_hops` 始终表示 Edge 数量。

## Behavior 约束

允许 layer：

```text
firmware, driver, interface, hardware
```

允许 relation：

```text
CALLS, ISSUES, INVOKES, DATA_FLOWS_TO,
MMIO_READ, MMIO_WRITE, ACCESSES
```

`TRIGGERS`、`EXPLOITS` 和 `LEADS_TO` 不作为真实程序路径关系。新增的
`allowed_relations` 在 `GraphRepository.find_paths` 遍历过程中生效，省略时保持
Phase 2 原行为。

## Knowledge 方向与上下文

KG 保存的是语义方向：

```text
Vulnerability ── TARGETS_RESOURCE ──> HardwareResource
```

Searcher 从 HardwareResource 查询 incoming Edge，但不会把它改写成
`HardwareResource → Vulnerability`。Candidate 保存原 Edge ID 和 relation。
TARGETS_RESOURCE 的 source 不是 Vulnerability 时，以非法知识上下文拒绝。

直接上下文包括已有的 CWE、CAPEC、Component、Trigger、Precondition、Behavior、
Interface、HardwareResource、SecurityMechanism、Impact 和 RootCause；缺失项保持
空列表，不自动补全。Synthetic `FIXTURE-CAPEC-MMIO-ACCESS` 仍只是 fixture ID，
不是正式 CAPEC taxonomy 声明。

## Evidence 与排序

Behavior Evidence ID 来自 GraphPath 的每一条 BehaviorEdge。Knowledge Evidence ID
来自 Vulnerability、上下文 Node 和原始一跳 KnowledgeEdge。Candidate 只保存 ID，
完整 Evidence 继续由 ProgramAnalysisResult 或 Knowledge Repository 管理。

Knowledge Edge 没有 Evidence 不会删除 Candidate；`missing_knowledge_evidence` 会
如实记录。Phase 6 不计算概率或可信度。

排序键依次为 hop count、Behavior Node IDs、Behavior Edge IDs、EntityLink ID、
Vulnerability ID 和 Candidate ID。ID 全部由输入的稳定 SHA-256 摘要产生，不使用
随机 UUID。

## 当前边界

Phase 7 可以把 Candidate 的引用解析为只读 `CandidateContext`，并用架构约束 RAG
和 LLMProvider 生成 `CandidateSemanticAssessment`；这不会改变 Candidate 的上述
有限语义。详细契约见 `RAG_REASONING.md`。

尚未实现 Component/Interface linking、Trigger/Precondition 满足性判断、Evidence
Verification、Scoring、AttackChain 投影、Multi-Agent、Neo4j、API 或 GUI。
