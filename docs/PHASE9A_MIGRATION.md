# Phase 9A-R Migration Result

旧版 Phase 9A 保存在 `phase-9a-old-semantics` / `ebc647e`。本轮只读审计，没有
checkout、merge、rebase 或 cherry-pick。迁移以 Phase 8R `CrossLayerInteraction` 为顶层
identity，而不是恢复旧 Candidate pipeline。

## 直接迁移并强化

- VerificationStatus、ConditionStatus、ProgramAddress、HardwareAddress；
- interaction-scoped deterministic VerificationRecord；
- detached EvidenceCatalog / objective inventory；
- CALLS 与 MMIO_READ/MMIO_WRITE 的逐字段 Static Evidence contract；
- Exact EntityLink canonical-key 重新计算；
- JSON score config loader、权重和为 1、uncalibrated profile。

## 适配或重写

- CandidateVerificationResult 被 InteractionVerificationResult 替代；
- 新增 Reference/Condition Binding 与 InteractionVerificationInput，禁止自动分类；
- LegacyCandidateVerificationAdapter 只读解析 software→hardware facts，Type III 拒绝；
- Knowledge verifier 只验证 relation/provenance；漏洞角色由 explicit binding 决定；
- Architecture rules 按 type/direction 重构；features 改为 interaction-aware；
- Scoring 使用 Type I/II 独立 denominator，空记录为 0.0，Type III disabled；
- 旧 RootCauseLocalizer 被 role-aware localizer 替换，MMIO 只能是 trigger point。

## 放弃的旧假设

不再假设所有 interaction 结束于 hardware anchor，不把 legacy KG vulnerability 自动当成
initiating firmware vulnerability，不用 Candidate 有无漏洞分类 Type I/II，不把第一个
MMIO sink 当统一 root cause，不让空证据得满分，也不反转 GraphPath 支持 Type III。

Type I/II 当前为 partially_supported；完整结果仍依赖 vulnerability/condition evidence。
Type III 为 not_implemented，只提取 semantic features，不输出 verification status/score。

## Phase 9A-R1 Hardening

后续审查进一步移除五类宽松边界：Evidence binding 增加 deterministic subject linkage；
Behavior/Knowledge Node existence 降为 UNKNOWN；partial status 必须有 substantive security
fact；partial capability 禁止 VERIFIED；features 限于 explicit scope 并要求完整 provenance；
localization 与 inventory 只消费真正 supporting Evidence。

## Phase 9A-R2 Final Integrity Hardening

Transition truth 不再扫描所有 legacy facts，只消费 bound MMIO 与 bound、resource-matched
EntityLink。CALLS 保留诊断作用但不构成 transition。Evidence merge 对同 ID 异内容立即失败；
direct Evidence 不可独立验证漏洞参与者；结果模型进一步绑定 feature type/direction。
