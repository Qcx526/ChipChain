# 评测设计

## 目标

评测必须区分“候选检索到了正确链”“链的结构正确”“根因定位正确”和“验证器正确接受/拒绝证据”。不以少量 Prompt 调优结果代替可重复实验。

## 数据划分与 Ground Truth

- 初期使用 10–20 条高质量 ARM 样本验证 Schema 和算法。
- `real` 样本保存 CVE、论文或厂商公告等来源；`synthetic` / `demo` / `fixture` 单独统计。
- Ground Truth 使用与预测相同的结构化节点、边、架构、根因和影响模型。
- 训练/开发/测试划分按漏洞族或组件去重，避免同一链的轻微变体泄漏。
- 记录数据集版本、配置、代码版本和随机种子，保证实验可复现。

## 排序命中指标

对每个查询按评分返回候选链：

- **Hit@1**：第一条候选中存在匹配 Ground Truth 的查询比例。
- **Hit@3**：前三条中存在匹配项的查询比例。
- **Hit@5**：前五条中存在匹配项的查询比例。

“匹配”必须预先定义。建议主结果使用完整边序列匹配，另报告允许别名归一化的匹配，不能只凭自然语言相似度判断。

最终 Cross-Layer Hit Rate 除总体值外必须分别报告 Type I Hit@K、Type II Hit@K 和
Type III Hit@K，并给出每类样本数与置信区间。总体 ≥80% 不能掩盖任一类别完全失效。

## 集合指标

对预测为有关联的样本对或攻击链计算：

```text
Precision = TP / (TP + FP)
Recall    = TP / (TP + FN)
F1        = 2 * Precision * Recall / (Precision + Recall)
```

当分母为零时采用显式、固定的处理规则，并在报告中说明。

## 结构指标

### Node Recall

对归一化后的节点 ID 或 `(kind, canonical_name)` 集合，计算 Ground Truth 节点中被预测覆盖的比例。可同时报告 Node Precision/F1，防止靠加入大量节点提高召回。

### Edge Recall

以 `(source, relation, target)` 三元组比较边。计算 Ground Truth 边中被预测覆盖的比例，并同时报告 Edge Precision/F1。

### Root Cause Accuracy

主要采用严格位置匹配的 top-1 accuracy；地址可按预先定义的函数范围或指令容差另报 relaxed accuracy。函数、寄存器和硬件资源分别统计，避免一个粗粒度正确结果掩盖精确定位失败。

Ground Truth 不再使用单一 `root_cause_line`，而是按适用样本分别记录：

- `software_root_cause_line`；
- `trigger_site_line`；
- `affected_firmware_line`；
- `hardware_root_cause_module`；
- `hardware_root_cause_rtl_line`。

不同样本不要求五类标签全部存在。没有源码/RTL line Ground Truth 时，不得把 byte
distance 或 instruction count 冒充 source-line error；“<5 lines”必须按对应角色和
同一 line namespace 计算。

## 证据与验证指标

- **Evidence Coverage**：链中具有至少一条可接受非 LLM 证据的必需边比例。
- **Evidence Precision**：预测支持证据中经 Ground Truth/人工确认有效的比例。
- **Verifier TPR/FPR/FNR**：在包含正负边的验证集上评估验证器。
- **Architecture Consistency Rate**：未出现跨架构专有节点或非法权限转换的预测比例。

## 80% 目标的报告方式

“关联漏洞命中率 ≥80%”在基准冻结前暂定义为测试集 Hit@K 指标目标，并同时报告 Precision、Recall、F1、节点/边指标与置信区间。正式论文前需要明确 K、匹配规则、样本构成和统计不确定性，避免只选择最有利口径。

## 错误分类

每个未命中或错误接受结果至少归入一个主因：

- `KG_MISSING`
- `BEHAVIOR_EDGE_MISSING`
- `CANDIDATE_SEARCH_FAILURE`
- `ARCHITECTURE_FILTER_FAILURE`
- `LLM_MISCLASSIFICATION`
- `VERIFIER_FALSE_NEGATIVE`
- `VERIFIER_FALSE_POSITIVE`
- `ROOT_CAUSE_LOCALIZATION_ERROR`
- `GROUND_TRUTH_AMBIGUITY`

报告应给出数量、占比和代表案例，支持后续模块级改进。

## 消融实验预留

评分权重必须配置化，以便分别移除知识图证据、静态证据、动态证据、架构规则和 LLM 语义分量。消融使用相同数据划分和搜索预算，报告指标差异而不是只报告最终分数。

## 当前评测契约状态

已建立总体与 Type I/II/III 分类型 Hit@K、结构指标、角色化位置 Ground Truth 和未来
verification 指标约束。Phase 8R 的三份 semantic fixture 只验证数据契约，不是正式
Ground Truth Benchmark；正式命中率、定位误差和统计实验留到 Phase 10。
