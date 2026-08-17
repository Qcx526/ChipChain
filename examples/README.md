# Examples

此目录保存可复现的 ARM toy/demo 用例。所有用例必须明确标记数据类型和来源。

- `arm_graph_demo.py`：创建 ARM fixture MultiDiGraph，查询 firmware 到 hardware 的 GraphPath，保存 JSON 后重新加载并复查路径。
- `arm_program_analysis_demo.py`：读取审计友好的 Program Spec，经 DemoAnalyzer 和原子 Ingestion 生成 Behavior Graph，再查询 firmware 到 MMIO register 的 GraphPath。
- `arm_angr_analysis_demo.py`：使用可选 angr 后端分析自有 synthetic ARM ELF，经现有 Ingestion 写入图，再查询真实机器码恢复出的三跳函数调用 GraphPath。运行前安装 `pip install -e ".[dev,angr]"`；示例只报告程序事实，不作漏洞结论。
