# Typed Multi-Agent Collaborative Reasoning

## Research Boundary

Phase 8 在 Phase 7 的只读 `CandidateContext`、architecture-first RAG 和结构化
Provider 之上增加协同语义分析，但不增加安全事实：

```text
Evidence Analyst        != Evidence Verification
Security Reasoner       != AttackChain Confirmation
Critic Review           != Security Verification
Multi-Agent Consensus   != Ground Truth
Agent Output            != Evidence
```

三个 Agent 全部只能生成类型化分析。即使三个输出一致，也不能确认漏洞、可利用性、
权限提升或 AttackChain。Phase 9 才能引入 Evidence Verification 和正式评分。

## Fixed Architecture

```text
CrossGraphCandidate
  → CandidateContextAssembler
  → CandidateRetrievalQueryBuilder
  → ARM/global KnowledgeRetriever (exactly once)
  → MultiAgentContext
       ├─ 1 EvidenceAnalystAgent
       ├─ 2 SecurityReasoningAgent
       └─ 3 CriticAgent
  → deterministic MultiAgentCoordinator
  → MultiAgentReasoningResult
```

执行顺序写死为 Evidence Analyst → Security Reasoner → Critic。没有动态 Agent 选择、
并发调用、递归、对话循环、自我反思循环、Agent 级自动 retry 或多数投票。

## Shared Context and Retrieval

Coordinator 只组装一次 `CandidateContext` 并只执行一次 RAG。`MultiAgentContext`
包含 Candidate ID、ARM architecture、完整 CandidateContext、确定性 retrieval query
和同一批 retrieved chunks。三个 Agent 不重新查询 Repository 或检索文档，因此相同
输入看到相同事实和参考知识。

Architecture-scoped Chunk 必须为 ARM，global Chunk 必须显式为 global。RISC-V
distractor 在评分前排除，因此不会进入任何 Agent Prompt。

## Role Contracts

### Evidence Analyst

`EvidenceAnalysis` 只清点 Behavior/Knowledge Evidence、Evidence gap 和待收集证据。
所有 Trigger/Precondition 必须继续出现在 unresolved 列表。状态仅允许
`context_ready`、`evidence_incomplete`、`context_inconsistent`。

### Security Reasoner

`SecurityReasoningAssessment` 消费共享 Context 和已校验的 EvidenceAnalysis。Prompt
明确声明 prior agent output is analysis, not evidence。`SemanticHypothesis` 是待验证
语义假设，只能引用 Context Evidence、Retrieved Chunk 和当前条件节点。

### Critic

`CriticReview` 只寻找 unsupported claim、citation problem、architecture leakage、
unresolved condition、contradiction、overclaiming 和 missing verification requirement。
它不能原地修改前序输出，也不能补充漏洞事实。状态仅允许 `review_complete`、
`revision_required`、`context_conflict`。

## Citation and Condition Boundary

- Evidence Analyst 只能引用 CandidateContext 中的 Evidence。
- Security Reasoner 只能引用 CandidateContext Evidence 和共享 Retrieved Chunk。
- Critic 只能引用上述 ID 和前序 `SemanticHypothesis.id`。
- 三个输出的 Candidate ID 和 architecture 必须与共享 Context 一致。
- 三个输出都必须完整保留当前 Trigger/Precondition 为 unresolved。
- 任意未知引用、条件丢失或 RISC-V 文本泄漏都会终止 Coordinator。

## Verification Boundary

统一 `reasoning.validation.validate_verification_boundary()` 扫描 Phase 7 与 Phase 8
全部结构化输出字符串，包括嵌套 Hypothesis、Metadata 和 Critic 字段。至少拒绝：

```text
verified attack chain
vulnerability confirmed
exploit confirmed
privilege escalation confirmed
```

Agent Prompt 禁止请求 chain-of-thought；Execution Trace 不保存 reasoning content、
Prompt 原文、HTTP Response、API Key、Authorization 或 endpoint。

Phase 8R 不改变 Agent 数量、顺序或 Prompt。现有三个 Agent 只解释已有
software→hardware CrossGraphCandidate，不承担 InteractionType 分类，也不生成
hardware→software propagation facts。

## Phase 9B2B Dynamic Context Boundary

Phase 9B2B 的新四角色 workflow 与 Phase 8 Coordinator 保持分离。Step 7 仅扩展
`ReasoningContext` 输入，允许绑定同架构 `CrossLayerInteraction`、detached
`RuntimeObservation` snapshots 和 `KnowledgeRetrievalResult`。Snapshot 排除 metadata 与
host timestamp；Context identity 只纳入既有确定性 object ID。

Runtime observation 可以改变未验证 Hypothesis 的输入描述，但 Observation 不等于
Evidence，不会自动进入 `ReasoningResult.supporting_evidence_ids`。缺失 runtime
observation 只会生成 `EvidenceRequest`。Knowledge retrieval 同样只提供参考上下文。

```text
CrossLayerInteraction + RuntimeObservation + KnowledgeRetrievalResult
                              |
                              v
                      ReasoningContext
                              |
                              v
             Hypothesis / EvidenceRequest / ReasoningResult
```

该路径不创建 Evidence、VerificationRecord、vulnerability judgement 或 AttackChain，
也不修改 RuntimeEvidence contract、Phase 9A-R pipeline/status/score。Agent agreement 与
reasoning confidence 仍不属于 verification truth。

## Deterministic Coordinator and Final Status

Coordinator 不是第四个 LLM。它只负责固定调度、post-validation、failure handling、
digest trace 和透明状态规则：

1. 任一 context conflict / contextually inconsistent → `contextually_inconsistent`；
2. Evidence incomplete 或 Security insufficient context → `insufficient_context`；
3. 其他情况 → `requires_verification`。

没有 score、confidence、probability 或 consensus vote。

## Failure Boundary and Audit Trace

任何 JSON/Pydantic 失败、错误身份、未知引用、架构泄漏、条件丢失或 forbidden claim
都会生成 failed `AgentExecutionRecord` 并立即抛出 `AgentExecutionError`。后续 Agent
不执行，也不会切换 Provider、补数据或静默 fallback 到 Mock。

Trace 固定保存 sequence、role、Candidate ID、architecture、input/prompt/output SHA-256、
execution status 和安全 error type。Digest 不依赖 wall clock。

## Providers and Manual Validation

Phase 7 `LLMProvider.generate()` 保持兼容。新增 `StructuredOutputProvider` 允许三种
Phase 8 Schema 复用同一 OpenAI-compatible Chat/Responses transport，继续执行严格
JSON→Pydantic 校验，且不复制三套 HTTP Client。

默认测试和 Demo 使用 `MockStructuredOutputProvider`，完全离线：

```powershell
.\.venv\Scripts\python examples\arm_multi_agent_demo.py
```

真实 Qwen 只通过人工脚本串行调用三次：

```powershell
.\.venv\Scripts\python scripts\check_real_multi_agent.py
```

脚本显式 `load_dotenv(..., override=False)`，不打印 secret、endpoint、Prompt 或响应原文。
