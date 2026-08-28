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
