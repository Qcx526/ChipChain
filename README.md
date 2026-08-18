# ChipChain

ChipChain 是一个面向防御性科研的、证据驱动的芯片跨层漏洞攻击链检测项目。当前只建设同一 ARM 架构内的 MVP。

## 当前能力

- 可安装的 Python 包骨架
- `chipchain --help` CLI 入口
- 基于 Pydantic 的严格领域模型与稳定字符串枚举
- 漏洞样本和线性攻击链的 JSON 校验及 round-trip
- ARM toy fixture 和 JSON Schema 导出脚本
- 存储无关的 `GraphRepository` 和 NetworkX `MultiDiGraph` 后端
- 架构/层过滤、确定性有向简单路径和稳定 JSON 图快照
- 存储无关的 `ProgramAnalyzer`、确定性 `DemoAnalyzer` 和原子预检 Ingestion
- 从 ARM Program Spec 到 GraphPath 的可运行 fixture Pipeline
- 可选 `AngrAnalyzer`：真实 ARM ELF 装载、CFGFast 函数/CALLS 恢复和 call-site Static Evidence
- 可审计、可重复生成且带 SHA-256/Ground Truth 的 synthetic ARM A32 ELF
- ARM ELF 到 `ProgramAnalysisResult`、Ingestion 和 GraphPath 的端到端示例
- 严格 Program Layer 与显式、架构绑定的 Memory Map 分析配置
- 基于真实 ARM/VEX 常量地址解析的 MMIO_READ/MMIO_WRITE 与 Hardware Node
- Driver Function → Hardware Register 的真实机器码跨层 GraphPath
- 与 Behavior Graph 分离的 Vulnerability Knowledge Graph 领域模型和存储接口
- `VulnerabilitySample` 到知识节点、语义关系和 Evidence 目录的确定性转换
- ARM 硬件地址、Memory Map region、Component 和 Interface canonical match keys
- `chipchain_knowledge_graph` v1 稳定 JSON 快照与自有 synthetic ARM KG fixture
- Exact Hardware EntityLink、one-to-many 链接结果和未匹配诊断
- 受 architecture、layer、relation、hop 约束的 CrossGraphCandidate Search
- Phase 4B ARM ELF + Phase 5 Knowledge Fixture 的端到端未验证候选 Demo
- CandidateContext、完整 Evidence Resolution 和只读事实组装
- architecture-first ARM/global Local Lexical RAG 与 RISC-V leakage 防护
- 确定性 Prompt、LLMProvider 抽象、Mock Provider 和结构化 Assessment 后校验
- 可选 OpenAI-compatible Responses/Chat Completions 客户端和人工 smoke script
- 不依赖外部服务的领域模型、分析、搜索与 Mock reasoning 测试

当前尚未实现通用跨块/跨函数地址分析、Candidate 到 AttackChain 的语义投影、
Trigger/Precondition 满足性验证、Evidence Verification、最终评分、Multi-Agent
或 API；这些能力会按
[PLANS.md](PLANS.md) 的阶段退出条件逐步加入。

## 环境要求

- Python 3.11 或更高版本
- Git

## 开发安装

PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\chipchain --help
.\.venv\Scripts\python -m pytest
```

Phase 4 的真实 ARM 静态分析为可选能力，不会被普通 `dev` 安装引入：

```powershell
.\.venv\Scripts\python -m pip install -e ".[dev,angr]"
.\.venv\Scripts\python examples\arm_angr_analysis_demo.py
```

Phase 7 的真实 OpenAI-compatible 客户端同样是可选能力；默认测试只使用 Mock：

```powershell
.\.venv\Scripts\python -m pip install -e ".[llm]"
.\.venv\Scripts\python scripts\check_llm_provider.py
```

配置字段见 `.env.example`，真实 API Key 不得写入仓库。

也可以不安装入口脚本，通过源码运行：

```powershell
$env:PYTHONPATH = "src"
python -m chipchain --help
```

## Domain Model Example

以下示例读取测试用 ARM 候选链，并完成 Pydantic 校验和 JSON 序列化：

```python
from pathlib import Path

from chipchain.models import AttackChain

fixture_path = Path("tests/fixtures/valid_arm_chain.json")
chain = AttackChain.model_validate_json(fixture_path.read_text(encoding="utf-8"))

print(chain.architecture.value)  # arm
print(chain.model_dump_json(indent=2))
```

该 fixture 只用于验证数据契约，不代表真实漏洞。另一个漏洞样本位于 `tests/fixtures/valid_arm_vulnerability.json`。

导出核心 JSON Schema：

```powershell
.\.venv\Scripts\python scripts\export_schema.py
```

默认输出到被 Git 忽略的 `artifacts/schema/`。Schema 可以从模型确定性重新生成，因此不提交生成文件，避免代码与生成副本漂移。

## Graph Repository Example

以下示例构建明确标记为 fixture 的 ARM Behavior Graph，并查询固件函数到 MMIO 寄存器的结构路径：

```python
from chipchain.graph import build_arm_demo_graph
from chipchain.models import Architecture, Layer

repository = build_arm_demo_graph()
paths = repository.find_paths(
    "fixture_parse_command",
    target_id="fixture_debug_ctrl",
    architecture=Architecture.ARM,
    max_hops=3,
    allowed_layers={
        Layer.FIRMWARE,
        Layer.INTERFACE,
        Layer.DRIVER,
        Layer.HARDWARE,
    },
)

print(paths[0].node_ids)
print(paths[0].edge_ids)
print(paths[0].hop_count)
```

`GraphPath` 只表示图中存在的路径，不是 `AttackChain`，也不表达漏洞成立或可利用。

运行完整的创建、查询、保存和重新加载示例：

```powershell
.\.venv\Scripts\python examples\arm_graph_demo.py
```

默认图快照保存到 Git 忽略的 `artifacts/arm_graph_demo.json`。

## Program Analysis Example

Phase 3 的 DemoAnalyzer 读取语义化 fixture spec，而不是直接返回硬编码 BehaviorNode/Edge：

```python
from chipchain.analysis import DemoAnalyzer, ProgramArtifact

artifact = ProgramArtifact(
    id="fixture-arm-program",
    architecture="arm",
    artifact_type="fixture",
    path="tests/fixtures/program_analysis/arm_demo_program.json",
    fixture_identifier="fixture-arm-demo-program-spec",
)
result = DemoAnalyzer().analyze(artifact)

print(len(result.nodes), len(result.edges), len(result.evidence))
```

运行从 Program Spec、Analyzer、Ingestion 到 GraphPath 的完整示例：

```powershell
.\.venv\Scripts\python examples\arm_program_analysis_demo.py
```

DemoAnalyzer 的 `confidence=1.0` 只表示 fixture 中确定存在该观察关系，不代表真实攻击可信度。AngrAnalyzer 同样只返回静态程序观察，不会从函数、CALLS 或 MMIO 等行为自动推断漏洞、影响或 AttackChain。

真实 ARM ELF 示例：

```powershell
.\.venv\Scripts\python examples\arm_angr_analysis_demo.py
```

该示例使用仓库自有的 synthetic ARM A32 ELF，恢复 Function、CALLS、call-site
Evidence，并经现有 Ingestion 查询三跳调用 GraphPath。生成方法、哈希和 Ground
Truth 见 [angr 接入说明](docs/ANGR_INTEGRATION_PLAN.md)。

Phase 4B 的真实 ARM MMIO 跨层示例：

```powershell
.\.venv\Scripts\python examples\arm_angr_mmio_demo.py
```

该示例从真实 `movw/movt` 和 `LDR/STR` 的 VEX IR 解析 effective address，只有
命中显式 ARM Memory Map 的 `0x40000000` 才生成 MMIO Edge；普通 RAM 和
unresolved 地址只进入诊断。MMIO Evidence 的 confidence 表示静态关系观察的
确定程度，不是漏洞可信度。

## Vulnerability Knowledge Graph Example

Phase 5 示例读取仓库自有、明确标记为 fixture/synthetic 的 ARM
`VulnerabilitySample`，构建独立 Knowledge Graph 并打印硬件 match keys：

```powershell
.\.venv\Scripts\python examples\arm_vulnerability_kg_demo.py
```

该图保存漏洞样本的结构化描述和来源证据，不与 Behavior Graph 建立 Edge，
不执行 Candidate Search，也不表示漏洞或攻击链已确认。实体链接键约定见
[实体链接契约](docs/ENTITY_LINKING.md)。

## Exact Candidate Correlation Example

Phase 6 示例复用真实 ARM MMIO ELF 和 Phase 5 synthetic knowledge fixture：

```powershell
.\.venv\Scripts\python examples\arm_candidate_search_demo.py
```

它先独立构建 Behavior/Knowledge Repository，通过硬件 canonical key 精确链接，
再查找可达跨层 GraphPath 和 Vulnerability 的一跳知识上下文。输出是
`unverified correlation`，不是已验证漏洞或 AttackChain。搜索设计见
[Candidate Search](docs/CANDIDATE_SEARCH.md)。

## Architecture RAG + Mock Reasoning Example

Phase 7 继续复用同一 ARM ELF、Knowledge Fixture 和 CrossGraphCandidate：

```powershell
.\.venv\Scripts\python examples\arm_rag_reasoning_demo.py
```

Context Assembler 会解析完整 Node/Edge/Evidence，Local Retriever 在评分前排除
非 ARM 文档，Mock Provider 输出 `requires_verification` Assessment。Retrieved
内容只作为 reference data，LLM interpretation 不等于 Evidence 或 Verification。
设计见 [RAG Reasoning](docs/RAG_REASONING.md)。

## 文档导航

- [项目范围](docs/PROJECT_SCOPE.md)
- [系统架构](docs/ARCHITECTURE.md)
- [数据模型](docs/DATA_MODEL.md)
- [实体链接契约](docs/ENTITY_LINKING.md)
- [Candidate Search](docs/CANDIDATE_SEARCH.md)
- [RAG Reasoning](docs/RAG_REASONING.md)
- [评测设计](docs/EVALUATION.md)
- [angr 接入说明](docs/ANGR_INTEGRATION_PLAN.md)
- [阶段计划](PLANS.md)

## 数据真实性

演示和测试数据必须标记为 `demo`、`synthetic` 或 `fixture`。没有可审计来源的数据不得作为真实 CVE 或正式 Benchmark 发布。
