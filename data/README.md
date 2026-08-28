# Data

数据目录只保存允许进入版本控制的小型清单与 fixture。真实样本必须包含来源；合成数据必须明确标记 `synthetic`。

大型二进制、外部 Benchmark 和生成产物不得直接提交，应通过后续数据准备脚本获取并校验。

`public_cve/arm_cross_layer_seed_v1.json` 是 Phase 10D Step 8A 的公开 CVE 研究 intake。
它只保存七条经释义的公开来源记录、对应的非 verdict `VulnerabilityKnowledgeEntry`，以及未来
benchmark admission 的 staging 状态。该数据不是 owned/synthetic fixture，不属于当前
`PRIMARY_TARGET`，也不包含下载网页、原始 HTML、利用载荷或客观 triggerability 输出。

`total_cve_records` 与按 curator-declared `underlying_issue_key` 计算的独立问题数必须分别报告；
`related_cve_ids` 不会自动创建额外 corpus record 或独立硬件漏洞计数。
