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
- 不依赖外部服务的领域模型、图仓库与程序分析测试

当前尚未实现真实二进制分析、候选攻击链推理、LLM、RAG 或 API；这些能力会按 [PLANS.md](PLANS.md) 的阶段退出条件逐步加入。

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

DemoAnalyzer 的 `confidence=1.0` 只表示 fixture 中确定存在该观察关系，不代表真实攻击可信度。当前没有实现 angr，也不会从 MMIO 等程序行为自动推断漏洞、影响或 AttackChain。

## 文档导航

- [项目范围](docs/PROJECT_SCOPE.md)
- [系统架构](docs/ARCHITECTURE.md)
- [数据模型](docs/DATA_MODEL.md)
- [评测设计](docs/EVALUATION.md)
- [阶段计划](PLANS.md)

## 数据真实性

演示和测试数据必须标记为 `demo`、`synthetic` 或 `fixture`。没有可审计来源的数据不得作为真实 CVE 或正式 Benchmark 发布。
