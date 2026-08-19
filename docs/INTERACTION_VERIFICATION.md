# Interaction Verification

正式入口是 `CrossLayerInteraction + InteractionVerificationInput`。Input 的 ID、architecture、
type 与 direction 必须完全匹配；Repository 和 Python object 不进入 Pydantic input。

`InteractionReferenceBinding` 将 interaction 中已有 semantic ID 显式映射到 Behavior、
Knowledge、EntityLink 或 Evidence source。role/source kind 是封闭枚举，越权 reference
立即失败。Legacy Candidate 只有显式 ID 才启用，不决定 Type I/II，且禁止用于 Type III。

- Type I：需要 initiating software vulnerability、trigger、transition、target hardware
  vulnerability、ARM rules 和 required conditions；当前部分支持。
- Type II：无需 initiating vulnerability；其余同类 required facts 当前部分支持。
- Type III：requirements 被描述，但 reverse propagation verifier 未实现，status/score=None。

Score 来自 type-aware JSON profile。空 required component 为 0.0，LLM weight 为 0.0；它
不是 attack/exploit/vulnerability probability。Owned Type II demo 缺独立硬件漏洞证据，
因此保守输出 partially_verified。
