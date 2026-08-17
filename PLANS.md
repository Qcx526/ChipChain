# ChipChain 阶段计划

## 当前状态

Phase 0～Phase 4 已完成。Phase 4 在 Candidate Search 之前补齐真实 ARM ELF
静态分析能力；每个后续阶段仍须在测试、复核和文档更新后才能关闭。

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

## 后续路线（尚未实施）

### Phase 5：Vulnerability Knowledge Graph MVP

规范化防御性漏洞、弱点、硬件资源、架构约束和来源证据，建立与行为图分离但
可受控关联的知识图谱。先使用可审计 fixture/公开数据子集，不下载或伪造 CVE。

### Phase 6：Candidate Chain Search

在 ARM、层级、关系、深度和证据约束下，以确定性搜索融合知识图与程序行为图，
只生成候选路径，不宣称已验证攻击链。

### Phase 7：Architecture RAG + LLM Provider

实现架构强过滤的知识检索、`LLMProvider` 抽象和 Mock Provider。LLM 只解释或
补充候选，不覆盖结构化证据。

### Phase 8：Multi-Agent

在稳定单体 Pipeline 上拆分候选生成、知识检索和验证职责；不得通过 Agent
边界绕过领域模型和证据校验。

### Phase 9：Evidence Verification / Scoring / Root Cause

逐边验证静态、动态与架构证据；从配置加载评分权重并计算覆盖率、置信度和根因，
LLM 语义置信度不得占主导。

### Phase 10：Evaluation

固定 ARM Ground Truth、指标、错误分类、消融实验和可复现报告。

### Phase 11：API / Visualization

核心算法稳定后再提供 FastAPI 与可解释可视化，不把 API 层变成算法或存储层。

### Phase 12：Additional Architectures

仅在 ARM 闭环稳定并完成评测后，讨论并验证第二种架构；不进行跨架构拼接。

任何阶段都不得为了展示功能而跳过其退出条件。
