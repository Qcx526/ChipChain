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

`GraphRepository` 统一节点、边和路径查询。MVP 默认实现基于 NetworkX + JSON，Neo4j 只作为可选生产适配器，避免首次运行依赖外部服务。

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

## 当前实现边界

Phase 0 和 Phase 1 已实现 Python 包、CLI、严格领域模型、ARM fixture 和 JSON Schema 导出。GraphRepository、候选搜索、程序分析、验证算法、LLM/RAG 和 API 仍是受阶段退出条件约束的设计，不表示已经实现。
