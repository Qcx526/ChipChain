# ChipChain 阶段计划

## 当前状态

Phase 0 和 Phase 1 已完成。当前尚未开始 Phase 2；每个后续阶段仍须在测试、复核和文档更新后才能关闭。

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

## 后续路线（尚未实施）

1. Phase 2：`GraphRepository` 与 NetworkX ARM Demo Graph
2. Phase 3：`ProgramAnalyzer` 与 `DemoAnalyzer`，之后再评估 angr
3. Phase 4：受架构、层级和证据约束的候选链搜索
4. Phase 5：`LLMProvider`、Mock Provider 和本地知识检索
5. Phase 6：在稳定 Pipeline 上拆分多 Agent 职责
6. Phase 7：逐边证据验证与覆盖率计算
7. Phase 8：评测指标、错误分类和报告
8. Phase 9：核心算法稳定后提供 FastAPI
9. Phase 10：ARM 闭环完成后再讨论 RISC-V

任何阶段都不得为了展示功能而跳过其退出条件。
