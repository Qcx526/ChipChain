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
`CLOSE_PROXIMITY` 仍没有数值界限。当前 public CVE scope 和 PRIMARY metrics 均不改变。

Step 8B-2B2-A 继续只读取上述 byte-exact 2B1 artifact。运行：

```bash
python scripts/build_cve_2023_34320_a_profile_static_semantic_extraction_plan.py --check
python scripts/build_cve_2023_34320_a_profile_static_semantic_extraction_plan.py --write
```

会确定性生成
`evaluation/cve_2023_34320_a_profile_static_semantic_extraction_plan_v1.json`。该计划为 2B1 中每个 exact
alternative 保存 canonical predicate reference、case/position、decoded-semantics recognition rule，以及全部
未解决的 runtime execution、适用的 privilege/effective-memory-type、qualitative proximity 和 hardware timing
义务。生成物不含 artifact-specific instruction occurrence、ELF 路径、runtime observation 或结果 verdict。

由 2B2-B 生成的 `AProfileStaticSemanticInstructionFact` 只表示 immutable artifact 中存在一个 decoded A64 instruction；
`AProfileStaticPredicateCandidate` 只表示该事实可作为一个 pattern predicate 的候选。静态存在不等于运行时
执行，decoded load 不等于 Device/Normal-NC 已解析，candidate 不等于 predicate satisfied，也不等于
triggerability。2B2-C1 只增加纯 function-local static CFG order candidate 合同；2B2-C2 已在独立 generic
real-angr adapter 中材料化 CFG 并复用该合同，后续 stateful evaluation 仍未实现。

Step 8B-2B2-B 的 owned synthetic AArch64 fixture 位于
`../tests/fixtures/phase10d/a_profile_static_semantic_a64/`。它包含四个互不调用的隔离函数，分别用于
ordinary LDR、STXR、MRS PAR_EL1 和 near-miss regression；非执行 `.data` 保存用零值分隔的 exact byte
copies，以证明 executable filtering。该 fixture 明确不是 CVE trigger/reproducer、affected hardware
reproduction、Ground Truth、triggerability demonstration 或 PRIMARY case。

`AngrAProfileStaticSemanticExtractor` 只使用 frozen 2B2-A plan、immutable ELF bytes、main-object executable
CFG blocks 与 Capstone decoded instruction ID/operands。它产生 `AProfileStaticSemanticInstructionFact` 和
`AProfileStaticPredicateCandidate`，不向 `data/evaluation/` 写入 artifact-specific extraction result。静态
instruction existence 不等于 runtime execution；load fact 不解析 Device/Normal-NC；PAR_EL1 fact 不证明
runtime privilege；多个 candidates 不构成 Case/program-order/proximity 结论。

Step 8B-2B2-C1 不新增数据 artifact 或 ELF。其 normalized CFG snapshots 与 positive graph tests 全部由
in-memory owned/synthetic DomainModels 构造。保存的 deterministic BFS path 仅是 reachability audit provenance，
不是 runtime path、symbolic-feasibility 证明或 proximity evidence；same function、same block 和 direct edge
均不能解析 qualitative `CLOSE_PROXIMITY`。现有 2B2-B ELF 和 expectations 保持 byte-for-byte 不变。

Step 8B-2B2-C2 同样不新增或修改数据 artifact/ELF。`AngrAProfileStaticCaseMaterializer` 直接重用上述 frozen
owned ELF 与 extraction plan，经冻结 2B2-B extractor 得到 exact semantic snapshot，再从同一 artifact SHA
材料化 predicate-referenced exact function 的 main-object executable CFG，最后调用冻结 C1 pure assembler。
当前 real-angr 输出固定为 3 instruction facts、6 predicate candidates、3 function CFG snapshots 与 0 static
case-order candidates；零候选是中性结构结果。C2 是可复用于兼容 AArch64 ELF/kernel/firmware build 的 binary
adapter，不包含 processor/CVE/Case/event-specific 规则；ELF loading 是未来 raw/firmware loader 可替换的边界。
它不产生 runtime、effective-memory-type、proximity、symbolic-feasibility、triggerability、verification 或 PRIMARY
结论。

Step 8B-2D1 不新增或修改任何 data artifact、ELF、plan 或 fixture。它只在内存中 detached-validate frozen C2
`AProfileStaticCaseAssemblyResult`，并纯确定性生成 objective `program_graph` 与独立的 pattern-binding
projection。program graph 不包含 vulnerability/AttackChain node，pattern candidate 不成为 graph edge，CFG
successor/path 不表示 causality。architecture-neutral shared projection 不含 A-profile source model；exact source
snapshot 与 artifact SHA provenance 只保存在 A-profile materialization envelope 中；不写入
`data/evaluation/`，也不创建 CrossLayerInteraction、ReasoningContext、Evidence、VerificationRecord、
Triggerability 或 PRIMARY 结果。当前 coverage 仍受 frozen narrow A-profile v1 decoder 限制。

Step 8B-2D2-A 同样不新增或修改任何 data artifact、ELF、plan、fixture 或 evaluation output。它只定义
plan-independent `StaticSemanticInstructionFact` / `StaticSemanticInventory` 领域合同和纯 synthetic model tests；
不读取现有 extraction plan，也不运行 angr、QEMU、Provider 或 pattern matcher。inventory 的 opaque
`decoder_profile_id` 仅是未来 decoder provenance boundary，当前冻结 A77/C2 数据路径及其 IDs/bytes 均不变。
该 generic IR 可服务未来 ARM、RISC-V 等 architecture adapter，但不声称完整 AArch64/ISA coverage，也不产生
predicate/case/candidate、pattern obligations、runtime、Evidence、verification、triggerability 或 benchmark 数据。
