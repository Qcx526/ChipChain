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

Verification metrics 与 Candidate Search Hit@K 必须分开报告，并分别统计 Type I、II、III。
Type III 在 verifier 未实现期间报告 capability coverage，不能用 0 分冒充 evidence support。
定位必须分别评测 initiating root cause、cross-layer trigger point 与 affected execution
point；MMIO trigger instruction 不得计作 root-cause line。

## 80% 目标的报告方式

Phase 10A Step 1 将 strict project metric 的候选单位固定为完整 `ReasoningSession` 的唯一
`merged_hypothesis`。四个 role hypotheses 不是四个独立候选。未来指标定义为：

```text
VerificationHitRate
= N(finalized candidates objectively confirmed feasible)
  / N(all finalized candidates produced in predeclared primary scope)
```

Phase 10A Step 2 已实现 Ground-Truth-free 的单候选 objective oracle，但尚未实现 manifest runner 或
计算指标。不能只保留验证成功或具备方便 runtime evidence 的候选。可另报预先冻结 eligibility 的 secondary
verifier-conditioned rate，但它不能替代 strict metric。还必须报告 `GroundTruthChainRecall`，防止通过
只输出少量保守候选虚增 hit rate。Hit@K、Precision/Recall/F1、节点/边指标仍是不同问题的辅助指标，
不得与上述 verification hit rate 混为一谈。

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

Phase 10A Step 1 已建立 finalized candidate、typed Ground Truth、source provenance、predeclared
scope 与 versioned manifest contract。Step 2 已建立不读取 Ground Truth 的单候选 objective oracle：
只有完整绑定的 Type II + Phase 9C `TRIGGERABLE` 可得到 `CONFIRMED_FEASIBLE`；Type I 为
`UNRESOLVED`，Type III 为 `UNSUPPORTED`。Initial owned synthetic cases 不是真实 CVE 或正式 public
Benchmark。Metric runner、Ground Truth recall、消融与真实模型比较仍未实现；没有计算“关联漏洞命中率
>=80%”。
