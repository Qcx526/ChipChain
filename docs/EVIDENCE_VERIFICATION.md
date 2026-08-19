# Objective Evidence Verification

Phase 9A-R 只消费结构化 domain objects 与 EvidenceCatalog。LLM output、Agent analysis、
retrieved text 和 consensus 都不是 Evidence。

Phase 9A-R1 要求 `source_kind=evidence` 的 binding 同时匹配 Evidence metadata 中的
`interaction_reference_id` 与 `reference_role`。缺字段为 UNKNOWN，显式不匹配为
REJECTED；不允许任意 verified Evidence 支持任意 interaction participant。

- VERIFIED：verified、非 LLM、类型正确且逐字段一致；
- REJECTED：端点、架构、relation 或 observation 有明确冲突；
- UNKNOWN：Evidence 缺失、不可解析、verified=false、仅 LLM 或字段不足。

CALLS 检查 function endpoints、call_xref、caller/callee address 与 resolved。MMIO 检查
relation/observation、instruction、resolved target、Memory Map ID/region 和 hardware range。
EntityLink 重新计算 canonical key intersection。KG node 存在只代表 reference resolution，
不等于漏洞已验证。

Inventory 只收集 required interaction bindings 引用的 evidence，避免无关 legacy context
污染 score。计数是 resolution/support 统计，不是概率。

`VerificationRecord.evidence_ids` 表示 inspected/resolved Evidence；
`supporting_evidence_ids` 只包含真正通过 verifier contract 的 Evidence，且必须是前者子集。
UNKNOWN/REJECTED record 的 supporting list 必须为空。Inventory 的正向计数以 supporting
Evidence 为准。
