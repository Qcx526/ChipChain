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
`merged_hypothesis`。四个 role hypotheses 不是四个独立候选。Phase 10B 的 exact-cohort 指标为：

```text
VerificationHitRate
= N(PRIMARY_TARGET finalized candidates with ALIGNED + CONFIRMED_FEASIBLE + exact GT match)
  / N(all finalized candidates produced in predeclared primary scope)
```

Phase 10A Step 2 已实现 Ground-Truth-free 的单候选 objective oracle。Step 3 另行要求模型通过
`ModelAuthoredChainClaim` 显式提出 interaction type 与 participant references，并使用不读取 Ground
Truth 的 `ModelClaimBinder` 比较 candidate-side typed interaction。Context interaction 不是模型
authorship，model claim 不是 verified truth。Required references 必须 exact；optional references 为空
表示未声明，非空时按 candidate-side 集合的子集关系判断兼容。Strict provider transport 用 required
nullable `chain_claim` 表示缺失 claim；`null` 不构成 authorship，且 Coordinator 会复核实际 source
Agent 必须为 ATTACK_CHAIN。`CONFIRMED_FEASIBLE` 与 `ALIGNED` 单独或组合仍不充分；Phase 10B 还要求
exact interaction ID、可选 attack-pattern 与 declared hardware signature Ground Truth match。不能只保留
验证成功或具备方便 runtime evidence 的候选。可另报预先冻结 eligibility 的 secondary
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

## Phase 10C 消融合同

当前已实现的消融不是评分权重重调，而是四个预声明条件：现有 full-context model、隐藏 typed
chain-answer prompt context 的 masked model、无 model claim 的 no-model baseline，以及仅移除
claim-alignment gate 的 Context/objective upper bound。FULL 是有意的 control，不代表模型独立发现；
MASKED 只改变 model-visible view，完整 Context 仍留在 candidate-side evaluation，parser 不修复模型
错误。Upper bound 仍要求 `CONFIRMED_FEASIBLE` 与 exact Ground Truth，negative 永不命中，并明确不是
`VerificationHitRate` 或模型指标。

所有条件绑定同一 manifest/version，普通条件原样消费 Phase 10B report；失败不可省略，coverage 必须
显式比较，delta 保存 exact rational components。Prompt audit 只进行构造后的 exact-reference 检查，
不进入 reasoning 或 metric。只能报告 observed ablation difference，不能声称 causal model effect。

## 当前评测契约状态

Phase 10A Step 1 已建立 finalized candidate、typed Ground Truth、source provenance、predeclared
scope 与 versioned manifest contract。Step 2 已建立不读取 Ground Truth 的单候选 objective oracle：
只有完整绑定的 Type II + Phase 9C `TRIGGERABLE` 可得到 `CONFIRMED_FEASIBLE`；Type I 为
`UNRESOLVED`，Type III 为 `UNSUPPORTED`。Step 3 已建立显式 model-authored claim 与独立 binding
assessment；缺失/不完整/错误 claim 分别保持可测量，不由 Context 或 Ground Truth 修复。Initial owned
synthetic cases 不是真实 CVE 或正式 public Benchmark。Phase 10B 已实现 all-case accounting、post-hoc
Ground Truth comparison、`VerificationHitRate`、`GroundTruthChainRecall`、negative-control FPR 与 primary
coverage。Phase 10C 已实现离线 ablation/prompt-firewall contracts；Owned fixture 的 `1/2` 仍只验证
合同。Phase 10D Step 1 已冻结 secret-free provider descriptor、同模型四条件 matrix、hash-only
invocation/failure provenance 与顶层 experiment artifact；所有验收仍为 `OFFLINE_CONTRACT`。真实模型
执行与正式 benchmark expansion 未实现，没有得出“关联漏洞命中率 >=80%”结论。

## Phase 10D Step 1 实验来源合同

未来 FULL/MASKED real-model comparison 必须在输出前冻结同一 manifest、Phase 10C plan 和唯一 provider
descriptor。Descriptor 不保存 API key、base URL、endpoint、timeout 或 retry。每个 model-backed
condition/case 都有固定 Code、Hardware、Vulnerability、AttackChain 四个 repetition-0 invocation slot；
失败角色占用自己的 `FAILED` slot，后续未调用角色以 `NOT_ATTEMPTED` 和 typed blocking role 记账，不能
伪造额外 provider failure。NO_MODEL 与 upper bound 在同一 matrix 中显式记账但不能包含 provider
invocation。

Canonical invocation 逐角色只保留 exact prompt/raw-response SHA-256，不保留内容。MASKED audit 对每个
attempted role 的 prompt SHA 精确绑定；完整 case×role accounting、同 descriptor 和同 benchmark 分别
进入独立 experiment-quality flags，不改变 frozen Phase 10B metrics 或 Phase 10C comparison。Claim
`MISSING`/`MISMATCHED` 等是语义结果，不是连接或 transport 失败。Step 1 没有运行真实模型，也没有阈值结论。
