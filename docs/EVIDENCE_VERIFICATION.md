# Non-LLM Evidence Verification

## 信任边界

Phase 9A 只接受原始 `Evidence`、结构化程序事实、Knowledge Graph 和 ARM rule：

```text
LLM Output != Evidence
Agent Consensus != Verification
Semantic Status != Verification Status
Missing Evidence != Contradiction
Unknown != Rejected
```

Multi-Agent 结果只能贡献 `advisory_verification_steps`，不能改变 record、condition、
score、root-cause status 或 Candidate status。

## 三态与只读性

`VERIFIED` 要求足够的已验证非 LLM 结构化证据；`REJECTED` 要求明确结构冲突；证据
缺失、未验证或仅 `LLM_SEMANTIC` 均为 `UNKNOWN`。Verifier 产生新模型，不修改
Evidence、BehaviorEdge、KnowledgeEdge、EntityLink 或 CrossGraphCandidate。

## 已实现规则

- CALLS：Function endpoints、`call_xref`、caller/callee address、resolved 和 Static Evidence；
- MMIO_READ/WRITE：relation/observation、instruction address、target address、Memory Map
  ID/region、resolved 和 Static Evidence；
- EntityLink：重新调用 `hardware_resource_match_keys()` 并检查交集；
- Knowledge：方向、relation、endpoint kind、architecture 和 attached Evidence source；
- ARM rules：Candidate/Path/Link/KG architecture、跨层、Hardware endpoint、anchor 和
  software→hardware MMIO transition；
- Conditions：只接受 exact `condition_node_id` + `condition_assertion` Evidence。

其他没有正式 Evidence contract 的 Behavior relation 保持 UNKNOWN。Phase 9A 不执行
QEMU，也不观察 privilege/security/configuration runtime state。

## Inventory 与 Score

Evidence Inventory 从 required Edge 引用和缺证据 Edge slot 重新计算，不使用 Agent 的
`analysis_status`。等权配置位于 `configs/verification_scoring_mvp.json`，五项是 Behavior、
EntityLink、Knowledge、Conditions 和 Architecture；unknown/rejected 不计正分。
`verification_score` 是验证支持度，不是 attack/exploit/vulnerability probability。

## 当前 Fixture Ground Truth

真实 ARM ELF fixture 的 CALLS/MMIO、EntityLink 和 ARM Rules 可验证；Phase 5
`TARGETS_RESOURCE` 没有 Evidence，Trigger/Precondition 没有执行事实。因此顶层状态是
`partially_verified`，不能为了演示改为 `verified`。

