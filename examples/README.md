# Examples

此目录保存可复现的 ARM toy/demo 用例。所有用例必须明确标记数据类型和来源。

- `arm_graph_demo.py`：创建 ARM fixture MultiDiGraph，查询 firmware 到 hardware 的 GraphPath，保存 JSON 后重新加载并复查路径。
- `arm_program_analysis_demo.py`：读取审计友好的 Program Spec，经 DemoAnalyzer 和原子 Ingestion 生成 Behavior Graph，再查询 firmware 到 MMIO register 的 GraphPath。
