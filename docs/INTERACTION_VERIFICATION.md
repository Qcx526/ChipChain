# Interaction Verification

正式入口是 `CrossLayerInteraction + InteractionVerificationInput`。Input 的 ID、architecture、
type 与 direction 必须完全匹配；Repository 和 Python object 不进入 Pydantic input。

`InteractionReferenceBinding` 将 interaction 中已有 semantic ID 显式映射到 Behavior、
Knowledge、EntityLink 或 Evidence source。role/source kind 是封闭枚举，越权 reference
立即失败。Legacy Candidate 只有显式 ID 才启用，不决定 Type I/II，且禁止用于 Type III。

Legacy Candidate 只是 evidence source。Cross-layer transition 只在显式绑定的 verified
MMIO trigger 与显式绑定、语义资源精确匹配的 verified EntityLink 同时存在时 VERIFIED。
未绑定 CALLS/MMIO/EntityLink 仅保留诊断记录，不进入 required truth、inventory 或 score；
CALLS 即使 VERIFIED 也不能代替 MMIO transition。

BehaviorNode/KnowledgeNode existence 只表示 source reference resolved，默认 UNKNOWN；只有
relation-specific verified BehaviorEdge 或其他明确 Evidence contract 才能提供正向支持。

- Type I：需要 initiating software vulnerability、trigger、transition、target hardware
  vulnerability、ARM rules 和 required conditions；当前部分支持。
- Type II：无需 initiating vulnerability；其余同类 required facts 当前部分支持。
- Type III：requirements 被描述，但 reverse propagation verifier 未实现，status/score=None。

Score 来自 type-aware JSON profile。空 required component 为 0.0，LLM weight 为 0.0；它
不是 attack/exploit/vulnerability probability。Owned Type II demo 缺独立硬件漏洞证据，
因此保守输出 partially_verified。

Architecture rules 和 Conditions 不是 substantive security facts，不能单独触发
PARTIALLY_VERIFIED。当前 Type I/II capability 为 PARTIALLY_SUPPORTED，因此 status 上限
也是 PARTIALLY_VERIFIED；只有未来 capability=SUPPORTED 才允许 VERIFIED。

Trigger features 只从 Interaction、explicit bindings/conditions、其 source facts 与必要的
bound legacy structural facts 提取。未绑定 legacy CWE/CAPEC/Trigger/Precondition 不进入
interaction feature set，每个输出 feature 必须具有 structured provenance。

`InteractionVerificationResult.required_fact_statuses` 显式保存 transition 等 required fact
状态；result 同时校验 TriggerFeatureSet 的 interaction ID、architecture、type 与 direction。
