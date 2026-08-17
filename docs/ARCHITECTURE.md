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
                  LLM 协作推理（可选）
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

## 分层与职责

### Domain Models

Pydantic 模型定义漏洞、行为、接口、硬件资源、证据、根因和攻击链。它们是模块间数据契约，不包含图搜索或外部服务逻辑。

### Ingestion and Normalization

把上游异构结果转换成领域模型，保留来源、样本类型和验证状态。无法确认的事实应明确为未知，不能由模型补写成真实事实。

### Program Analysis

`ProgramAnalyzer` 抽象程序分析能力。MVP 先使用确定性的 `DemoAnalyzer` 打通流程，后续 `AngrAnalyzer`、`GhidraAnalyzer`、`QEMUAnalyzer` 作为独立适配器加入。

### Graph Storage

`GraphRepository` 统一节点、边、方向邻接和路径查询，不向调用者暴露 NetworkX 类型。MVP 的 `NetworkXGraphRepository` 使用 `MultiDiGraph`，以全局唯一的 `BehaviorEdge.id` 作为 edge key，因此相同 source/target 之间的 CALLS、DATA_FLOWS_TO 等关系可以共存。

搜索在遍历过程中同时检查 Node 和 Edge architecture；可选 `allowed_layers` 要求路径中所有 Node 都属于允许集合。只返回有向 simple `GraphPath`，其中 `max_hops` 和 `hop_count` 都表示 Edge 数量。结果按 hop count、node IDs、edge IDs 确定性排序。`GraphPath` 不是 `AttackChain`，不会产生漏洞或可利用性结论。

JSON 快照使用 `chipchain_graph` / format version 1 信封，保存排序后的 Phase 1 Node/Edge 数据和 metadata。加载时重新执行 Pydantic、端点、唯一 ID 和架构一致性验证，不信任由本项目自身生成的 JSON。

### Candidate Search

融合漏洞知识图与行为图，在最大深度、目标架构、允许的层级转换和最低证据要求下生成 Top-N 候选路径。搜索应是可复现的确定性步骤。

### Knowledge Retrieval and LLM

`KnowledgeRetriever` 必须按目标架构过滤知识。`LLMProvider` 仅接收候选路径、检索知识和程序证据，并输出可校验的结构化候选解释。测试使用 Mock 实现。

### Verification and Scoring

验证器逐边检查图关系、静态证据、动态证据和架构规则。评分权重来自配置文件；缺失证据降低置信度并出现在解释中，LLM 置信度不能覆盖证据冲突。

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

## GraphRepository API 语义

- 重复 Node/Edge ID、悬空 Edge 和跨架构 Edge 立即失败，不静默覆盖。
- `successors` / `predecessors` 返回按 ID 排序的唯一相邻节点；并行 Edge 通过 `list_edges` / `get_edge` 保留。
- `find_paths` 在指定 target 时返回起点到目标的全部受限简单路径；未指定 target 时返回 1 到 `max_hops` 内的可达非空路径。
- target 与 start 相同时允许一个 0-hop GraphPath。
- `max_results` 在完整确定性排序后截断。该实现优先保证科研复现性，不面向超大稠密图的无界枚举。
- `save` 使用稳定 JSON；`load` 返回新 Repository，避免失败加载污染已有实例。

## 当前实现边界

Phase 0～2 已实现 Python 包、CLI、严格领域模型、GraphRepository、NetworkX MultiDiGraph 后端、ARM Graph fixture、确定性简单路径、JSON 图快照和 Schema 导出。程序分析、候选攻击链推理、证据验证算法、LLM/RAG 和 API 仍是受阶段退出条件约束的设计，不表示已经实现。
