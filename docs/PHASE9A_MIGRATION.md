# Phase 9A-R Migration Assessment

## 审计范围

Phase 8R 通过只读 `git show phase-9a-old-semantics:<path>` 审计旧 Phase 9A 的
models、pipeline、scoring、root_cause、architecture、behavior、entity_link、knowledge、
conditions、evidence 和 trigger_features。没有 checkout、merge、rebase 或 cherry-pick；
当前分支没有 verification package。

## A. 可直接迁移的基础契约

| 旧模块 | 可迁移内容 | 理由 |
| --- | --- | --- |
| `verification/enums.py` | VerificationStatus、ConditionStatus、VerificationSubjectKind | 三态与 subject 概念不依赖传播方向 |
| `verification/models.py` | VerificationRecord、ProgramAddress、HardwareAddress | 稳定记录和地址 namespace 是通用 primitive |
| `verification/evidence.py` | detached EvidenceCatalog / inventory 思路 | 不绑定 Candidate path 方向 |
| `verification/behavior.py` | CALLS/MMIO Evidence contract helpers | 可继续验证已有 software→hardware observation |
| `verification/entity_link.py` | exact canonical key recheck | 适用于 legacy exact-anchor primitive |
| score config loader/schema base | 外置配置、sum=1、uncalibrated metadata | 配置机制可复用，但 component 需要重设计 |

“可直接迁移”仍要求重新落到 Phase 8R 基线并运行测试，不代表整文件无审查复制。

## B. 需要按新语义适配

| 旧模块 | 实际绑定点 | Phase 9A-R 适配方向 |
| --- | --- | --- |
| `architecture.py` | 要求 path 包含 hardware、终点为 linked anchor、MMIO software→hardware | 按 InteractionType/Direction 分规则集；Type III 使用真实反向机制 Evidence |
| `trigger_features.py` | 输入是 Candidate behavior path，特征围绕 MMIO/Trigger | 区分 initiating/trigger/affected roles，并支持 fault state |
| `CandidateVerificationResult` | 顶层身份只有 `candidate_id` | 引入 interaction identity/类型/方向，同时保留 legacy candidate adapter |
| `RootCauseLocalizationResult` | function/MMIO sink 与单一 root-cause 语义 | 输出 role-aware locations，避免把 trigger site 当 initiating root cause |
| `scoring.py` | 固定 behavior/entity-link/knowledge/conditions/architecture 五项 | 按类型定义 required evidence component，不能让 Type III 因无 EntityLink 被扣分 |
| `pipeline.py` | 直接展开 CrossGraphCandidate，假设 knowledge vulnerability 和硬件终点 | 设计 direction-aware verification input/adapter；legacy Candidate 只走 Type I/II 底层路径 |
| `knowledge.py` | 所有一跳关系假设 source 是 Vulnerability | Type II/III 不能以该假设代表 initiating side |
| `conditions.py` | trigger/precondition 来自 legacy KG context | 明确条件属于 interaction 哪一侧及哪个 location role |

## C. 不能直接复用的假设

- `behavior_path[-1] == linked hardware anchor` 被当作所有跨层交互结构；
- 只允许 software/driver MMIO → hardware 的 architecture transition；
- `knowledge_vulnerability_id` 被隐含理解为 software initiating vulnerability；
- 第一个 verified MMIO sink 被当作统一 root-cause candidate；
- function、MMIO instruction、hardware fault 与 affected firmware point 共用单一根因语义；
- 反转 legacy GraphPath 或伪造 `HardwareResource → Function` Edge 来支持 Type III；
- 对 Type II 人工补一个 firmware vulnerability；
- 用同一 score denominator 比较三种 evidence topology。

## 推荐迁移顺序

1. 迁移通用 enum/address/record/catalog primitives；
2. 定义 InteractionVerificationInput 和 legacy Candidate adapter；
3. 建立 Type I/II/III 各自 required facts 与 architecture rules；
4. 将 location result 改为 role-aware collection；
5. 迁移已有 CALLS/MMIO/entity-link verifier 作为 software→hardware 子能力；
6. 只有获得真实机制 Evidence 后才实现 Type III verifier/search；
7. 最后重建 type-aware score config 和端到端 tests。

旧 Phase 9A 完整保留在 `phase-9a-old-semantics`；Phase 9A-R 应迁移而非从零重写，
也不应直接 cherry-pick 顶层 pipeline。
