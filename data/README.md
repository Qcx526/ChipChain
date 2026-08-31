# Data

数据目录只保存允许进入版本控制的小型清单与 fixture。真实样本必须包含来源；合成数据必须明确标记 `synthetic`。

大型二进制、外部 Benchmark 和生成产物不得直接提交，应通过后续数据准备脚本获取并校验。

`public_cve/source/arm_cross_layer_seed_v1.source.json` 是公开 CVE corpus 的唯一人工维护来源。
它不保存任何 derived ID；编辑者只修改 `source/*.json` 中的研究事实。运行：

```bash
python scripts/build_public_cve_corpus.py --check
python scripts/build_public_cve_corpus.py --write
```

会完全离线地派生 `VulnerabilityKnowledgeEntry`、`knowledge_entry_id`、research sample ID 和 corpus ID。
`public_cve/arm_cross_layer_seed_v1.json` 是确定性生成且继续提交的 immutable snapshot；测试和实验依赖
其稳定 ID，reviewer 也可逐字节复核它是否能从单一 source 重建。不得直接手改 snapshot 中的 derived
knowledge entry、sample ID 或 corpus ID。

Corpus 只保存七条经释义的公开来源记录、对应的非 verdict `VulnerabilityKnowledgeEntry`，以及未来
benchmark admission 的 staging 状态。它不是 owned/synthetic fixture，不属于当前 `PRIMARY_TARGET`，
也不包含下载网页、原始 HTML、利用载荷或客观 triggerability 输出。构建过程不联网或抓取 NVD。

`total_cve_records` 与按 curator-declared `underlying_issue_key` 计算的独立问题数必须分别报告；
`related_cve_ids` 不会自动创建额外 corpus record 或独立硬件漏洞计数。

`public_cve/evaluation/arm_secondary_v1.json` 是独立的人工 evaluation-selection 文件，只允许保存 CVE
选择与 `software_source_layer`；不得复制 public source 中的技术事实。运行：

```bash
python scripts/build_public_secondary_cohort.py --check
python scripts/build_public_secondary_cohort.py --write
```

会从 authoritative source、generated corpus 与 selection 完全离线生成
`evaluation/public_documented_arm_secondary_v1.json`。该 artifact 包含五条 `PUBLIC_DOCUMENTED` /
`SECONDARY_ONLY` case、documented interaction、reference-only reasoning context、FULL/MASKED prompt
SHA-256 与 MASKED visibility audit，不包含 raw prompt、provider response、model output、runtime Evidence、
triggerability 或 benchmark result。当前 readiness 为 `REFERENCE_CONTENT_INSUFFICIENT`，因为实际 prompt
没有承载 public references 或描述性漏洞文本；这不会改变 PRIMARY metrics，也不构成 public-CVE hit rate。

Step 8B-1B 不重写上述 frozen artifact。运行：

```bash
python scripts/build_public_knowledge_readiness.py --check
python scripts/build_public_knowledge_readiness.py --write
```

会从 frozen Step 8B-1A cohort 与 generated corpus 中已绑定的 `VulnerabilityKnowledgeEntry`，离线生成
`evaluation/public_documented_arm_secondary_knowledge_projection_v1.json`。新 artifact 只保存 projection
ID、case/context/interaction/knowledge bindings、FULL/MASKED Prompt SHA-256、MASKED visibility audit、
structured-label leakage audit 与 visibility booleans，不保存 raw Prompt、knowledge metadata、Provider
response 或模型输出。FULL/MASKED 获得相同的 title/summary/components/references public reference content；
当前 readiness 为 `READY_FOR_PUBLIC_PROVIDER`，但这不表示 Provider 已执行、漏洞已验证或指标已产生。

`evaluation/runs/phase10d_step8b1d_public_deepseek_20260831_one_shot.json` 是经独立审批后冻结的
Step 8B-1D 五案 public-provider hash-only archive。它不保存 raw prompt、raw response、secret 或 endpoint，
且 `SECONDARY_ONLY` 结果不进入 PRIMARY metrics。

运行：

```bash
python scripts/build_masked_semantic_recovery_diagnostic.py --check
```

会完全离线地从上述 frozen archive 与运行前已存在的 authoritative source 重建
`evaluation/public_documented_arm_secondary_masked_semantic_recovery_v1.json`。该 Step 8B-1E artifact 只使用
MASKED session 中唯一携带 model-authored claim 的 ATTACK_CHAIN hypothesis description；当前五案没有匹配
该 hypothesis ID 的 ATTACK_CHAIN `ReasoningResult`，因此显式保存 null result provenance 和
description-only text source，不使用 merged/final/其他角色/FULL 文本。

Artifact 分别保留 exact binder status、interaction-type exact comparison、participant-grounding diagnostic、
trigger/precondition/hardware-effect content coverage、扣除 Provider-visible public summary 后的 held-out
coverage，以及原 objective feasibility。Coverage 是 token-set exact numerator/denominator 与 SHA-256，
不是 semantic correctness、verification、模型准确率或攻击链检测率；没有阈值、综合成功分数或 PASS/FAIL。
当前输出固定为 `RETROSPECTIVE_DIAGNOSTIC` / `prospective_metric_eligible=false`，因为诊断合同在第一次
one-shot 输出被观察后才定义。构建器不调用 Provider、网络、QEMU，也不重写任何 frozen public input。

`public_cve/objective/cve_2023_34320_erratum_1508412.source.json` 是 Step 8B-2B0 的窄范围人工审阅
curation input，只保存 Arm SDEN-1152370 v11.0 对 erratum 1508412 的 concise normalized semantics，
不保存 PDF、长摘录、machine-code sequence、workaround 可执行序列、Ground Truth、模型输出或 metric。
运行：

```bash
python scripts/build_cve_2023_34320_documented_erratum.py --check
python scripts/build_cve_2023_34320_documented_erratum.py --write
```

会从该 source 与 byte-exact frozen public CVE source 完全离线生成
`evaluation/cve_2023_34320_documented_erratum_1508412_v1.json`。生成物绑定 source-file SHA-256、exact
CVE source-record canonical SHA-256 与 public corpus ID；Case A/B 的有向 program order、memory-type
限制、CPU revision disposition、documented mitigations 与所有 precision flags 均进入 deterministic ID。

该生成物只回答 authoritative Arm documentation 声明了什么：
`DocumentedHardwareErratumContract != HardwareTriggerSignature`，documentation 也不等于 hardware
experimental proof。`CLOSE_PROXIMITY` 是 qualitative-only 且 `quantitative_bound=null`；semantic pattern
reference 不等于 objective observation、triggerability、feasibility、verification 或 PRIMARY admission。
CVE-2023-34320 仍属于 `NEXT_OBJECTIVE_CANDIDATE` / `SECONDARY_ONLY`。

Step 8B-2B1 不增加第二份人工 source。运行：

```bash
python scripts/build_cve_2023_34320_a_profile_semantic_trigger_pattern.py --check
python scripts/build_cve_2023_34320_a_profile_semantic_trigger_pattern.py --write
```

只读取 byte-exact `evaluation/cve_2023_34320_documented_erratum_1508412_v1.json`，并离线生成
`evaluation/cve_2023_34320_a_profile_semantic_trigger_pattern_v1.json`。Builder 对冻结 2B0 artifact 的
SHA-256、documented-erratum ID 与 contract version 全部 fail closed，不读取 2B0 curation source、Provider、
QEMU、Ground Truth 或网络。

生成物是 `AProfileSemanticTriggerPattern` predicate，不是 static occurrence、runtime observation、
`HardwareTriggerSignature`、proof 或 triggerability。Load 的 memory constraints 只表示 future analyzer 必须
建立 effective architectural memory type，并不表示当前已观测 Device/Normal-NC；qualitative
`CLOSE_PROXIMITY` 仍没有数值界限。后续 2B2/2B3 objective facts 与 stateful evaluation 尚未实现，当前
public CVE scope 和 PRIMARY metrics 均不改变。
