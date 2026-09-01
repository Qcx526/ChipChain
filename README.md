# ChipChain

ChipChain 是一个面向防御性科研的、证据驱动的芯片跨层漏洞攻击链检测项目。当前只建设同一 ARM 架构内的 MVP。

## 当前能力

- 可安装的 Python 包骨架
- `chipchain --help` CLI 入口
- 基于 Pydantic 的严格领域模型与稳定字符串枚举
- 漏洞样本和线性攻击链的 JSON 校验及 round-trip
- ARM toy fixture 和 JSON Schema 导出脚本
- 存储无关的 `GraphRepository` 和 NetworkX `MultiDiGraph` 后端
- 架构/层过滤、确定性有向简单路径和稳定 JSON 图快照
- 存储无关的 `ProgramAnalyzer`、确定性 `DemoAnalyzer` 和原子预检 Ingestion
- 从 ARM Program Spec 到 GraphPath 的可运行 fixture Pipeline
- 可选 `AngrAnalyzer`：真实 ARM ELF 装载、CFGFast 函数/CALLS 恢复和 call-site Static Evidence
- 可审计、可重复生成且带 SHA-256/Ground Truth 的 synthetic ARM A32 ELF
- ARM ELF 到 `ProgramAnalysisResult`、Ingestion 和 GraphPath 的端到端示例
- 严格 Program Layer 与显式、架构绑定的 Memory Map 分析配置
- 基于真实 ARM/VEX 常量地址解析的 MMIO_READ/MMIO_WRITE 与 Hardware Node
- Driver Function → Hardware Register 的真实机器码跨层 GraphPath
- 与 Behavior Graph 分离的 Vulnerability Knowledge Graph 领域模型和存储接口
- `VulnerabilitySample` 到知识节点、语义关系和 Evidence 目录的确定性转换
- ARM 硬件地址、Memory Map region、Component 和 Interface canonical match keys
- `chipchain_knowledge_graph` v1 稳定 JSON 快照与自有 synthetic ARM KG fixture
- Exact Hardware EntityLink、one-to-many 链接结果和未匹配诊断
- 受 architecture、layer、relation、hop 约束的 CrossGraphCandidate Search
- Phase 4B ARM ELF + Phase 5 Knowledge Fixture 的端到端未验证候选 Demo
- CandidateContext、完整 Evidence Resolution 和只读事实组装
- architecture-first ARM/global Local Lexical RAG 与 RISC-V leakage 防护
- 固定 Evidence Analyst → Security Reasoner → Critic 的类型化 Multi-Agent 推理
- 确定性 Prompt、LLMProvider 抽象、Mock Provider 和结构化 Assessment 后校验
- 可选 OpenAI-compatible Responses/Chat Completions 客户端和人工 smoke script
- 导师三类 CrossLayerInteraction、双向 Direction 与三种 Location Role 严格契约
- software→hardware exact-anchor / hardware→software not-implemented 搜索能力边界
- Phase 9A-R 显式 Interaction binding、CALLS/MMIO/Exact EntityLink 客观验证
- Phase 9A-R1 subject-linked Evidence、substantive status 和 supporting-evidence hardening
- Phase 9A-R2 binding-aware transition、Evidence collision 与 vulnerability boundary
- Phase 9A-R3 semantic binding cardinality 与 VerificationRecord uniqueness hardening
- Phase 9B0 backend-neutral Runtime Trace/Observation/Intervention 与 Dynamic Evidence contract
- Phase 9B0-R1 detached Runtime snapshot revalidation 与 mutation-bypass 防护
- Phase 9B1 R2 raw v2 physical observer、同进程 QMP FlatView capture 与 topology classifier
- path-neutral memory map ID、exact topology SHA、分类差异 metadata 与 owned STRB ELF
- Phase 9B2A 显式 DynamicTriggerFact/Observation Binding、detached Dynamic Verification
- Static/Dynamic 八态 aggregation、multi-record conflict 与分离 Evidence provenance
- Phase 9B2B 非验证多 Agent reasoning contracts 与 Step 7 dynamic context binding
- Phase 9B2C Step 1～3 strict-schema Provider bridge、固定四角色 workflow 与 release acceptance hardening
- Phase 9C Step 1 ARM A32 exact HardwareTriggerSignature 与硬件侧 proof provenance contract
- Phase 9C Step 2 executable decoded A32 exact-sequence 与 function-local CFG static matching
- Phase 9C Step 3A 独立 QEMU instruction-byte trace 与 exact contiguous runtime T confirmation
- Phase 9C Step 4 deterministic triggerability aggregation 与 declared-precondition fail-closed policy
- Phase 10A Step 1 finalized candidate、typed Ground Truth、predeclared scope 与 versioned manifest contracts
- Phase 10A Step 2 Ground-Truth-free candidate-side objective chain feasibility oracle
- Phase 10A Step 3 explicit model-authored chain claim 与 candidate-context binding assessment
- Phase 10B deterministic all-case benchmark runner、exact Ground Truth comparison 与 exact-cohort metrics
- Phase 10C 四条件 ablation protocol、prompt visibility firewall 与 deterministic comparison contracts
- Phase 10D Step 1 secret-free real-model experiment provenance、execution matrix 与 artifact contracts
- Phase 10D Step 2 explicit opt-in execution harness、pre-transport MASKED audit 与 canonical execution archive
- Phase 10D Step 6 GT-firewalled objective triggerability materialization、persistent source provenance 与
  REAL_PROVIDER completeness gate
- Phase 10D Step 7 collision-safe MASKED projection、single-policy prompt audit 与 projection-protocol provenance
- Phase 10D Step 8A public CVE research intake、A/M profile admission staging 与 issue-level dedup reporting
- Phase 10D Step 8B-0 single-source public CVE builder、derived IDs 与 byte-stable committed snapshot
- Phase 10D Step 8B-1A 五条 public-documented SECONDARY cohort、FULL/MASKED hash audit 与
  model-visible content readiness gate
- Phase 10D Step 8B-1B versioned neutral public-knowledge projection、legacy Prompt compatibility 与
  structured-label leakage audit
- Phase 10D Step 8B-1C 独立 public execution binding、40-key pre-transport provenance gate 与
  显式 opt-in execution wrapper
- Phase 10D Step 8B-1D 冻结五案 public-provider one-shot hash-only archive
- Phase 10D Step 8B-1E retrospective MASKED ATTACK_CHAIN hypothesis-description content diagnostic
- Phase 10D Step 8B-2B0 Cortex-A77 erratum 1508412 authoritative documented-semantics contract
- Phase 10D Step 8B-2B1 versioned ARM A-profile semantic trigger-pattern predicate language
- Phase 10D Step 8B-2B2-A deterministic A-profile static semantic extraction plan、A64 decoded-instruction fact
  与 unresolved-obligation predicate-candidate contracts（不含真实 extractor）
- Phase 10D Step 8B-2B2-B real angr AArch64 decoded-event extractor、owned synthetic ELF 与
  closed instruction-ID/structured-operand recognition profile
- Phase 10D Step 8B-2B2-C1 pure function-local CFG static-order candidate contracts 与
  deterministic reachability-audit witness（不含 real-angr case assembler）
- Phase 10D Step 8B-2B2-C2 generic AArch64 binary CFG materialization、exact semantic/CFG artifact binding 与
  pattern-driven static case assembly
- 类型化 evidence support score 与 role-aware cross-layer trigger-point 定位
- owned synthetic ARM Type II Verification Demo（部分验证，不生成已验证攻击链）
- 不依赖外部服务的领域模型、分析、搜索与 Mock reasoning 测试

当前尚未实现通用跨块/跨函数地址分析、Candidate 到 AttackChain 的语义投影、
Type III hardware→software propagation verification 或 API。Phase 9B1 已在 Ubuntu 22.04、
QEMU 11.0.3、ARM32 `virt` / `cortex-a15` / 单 vCPU 环境通过 real acceptance，并由
`phase-9b1-stable` 封存。Ubuntu 是 canonical development/runtime validation 环境；Windows
只用于 secondary portability regression。Phase 9A-R 的 score 是未校准客观证据支持度，
不是攻击、利用或漏洞概率。

Phase 9A-R 通过显式 adapter 使用 software→hardware legacy Candidate 支持 Type I/II；
Type III 的 semantic feature 可提取，但 verifier 与反向 Evidence 明确未实现。

## 环境要求

- Python 3.11 或更高版本
- Git

## 开发安装

PowerShell：

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\chipchain --help
.\.venv\Scripts\python -m pytest
```

Phase 4 的真实 ARM 静态分析为可选能力，不会被普通 `dev` 安装引入：

```powershell
.\.venv\Scripts\python -m pip install -e ".[dev,angr]"
.\.venv\Scripts\python examples\arm_angr_analysis_demo.py
```

Phase 7 的真实 OpenAI-compatible 客户端同样是可选能力；默认测试只使用 Mock：

```powershell
.\.venv\Scripts\python -m pip install -e ".[llm]"
.\.venv\Scripts\python scripts\check_llm_provider.py
.\.venv\Scripts\python scripts\check_real_reasoning.py
.\.venv\Scripts\python scripts\check_real_multi_agent.py
```

Phase 9B2C Step 1 可显式执行一个 CODE role 的真实 Provider smoke；它要求目标
provider/model 支持 OpenAI-compatible strict JSON Schema structured output，且不会启动四
Agent workflow：

```bash
.venv/bin/python scripts/check_real_phase9b2c_reasoning.py
```

Phase 9B2C release acceptance 必须按以下顺序执行；任一命令失败即停止，不重试：

```bash
.venv/bin/python scripts/check_llm_provider.py
.venv/bin/python scripts/check_real_phase9b2c_reasoning.py
.venv/bin/python scripts/check_real_phase9b2c_multi_agent.py
```

四角色脚本直接观测实际 Provider 调用，并断言调用恰好四次、顺序为 Code → Hardware →
Vulnerability → AttackChain 且全部使用同一 detached Context。脚本只打印 provider/model 的
非敏感摘要、role、Context/输出 ID，不打印 endpoint、prompt 或 raw response。输出仍须经过
constrained parser，且只表示 reasoning，不表示 verification 或漏洞确认。

配置字段见 `.env.example`，真实 API Key 不得写入仓库。只有这些人工脚本显式
加载根目录 `.env`；核心 Provider 和默认 pytest 不读取该文件。

Qwen 3.8 Max 的 reasoning effort 和 completion limit 也必须由用户显式配置；
Phase 7R 结构化 smoke test 使用 `none` / `2048`，Provider 不会自动改变这些值。

Phase 9B1 R2 的真实 smoke test 是显式可选能力，不会自动下载 QEMU、编译器或 headers。
它在同一进程中先通过 QMP 捕获 `info mtree -f`，再继续 owned guest；PL011 trace 仅作独立 oracle：

```bash
export CHIPCHAIN_QEMU_SYSTEM_ARM="$HOME/chipchain-tools/qemu-11.0.3/build/qemu-system-arm"
export QEMU_PLUGIN_INCLUDE="$HOME/chipchain-tools/qemu-11.0.3/include/plugins"
.venv/bin/python tools/qemu_plugins/build.py
export CHIPCHAIN_QEMU_PLUGIN="$HOME/ChipChain/tools/qemu_plugins/chipchain_runtime_observer.so"
.venv/bin/python scripts/qemu_phase9b1_smoke.py
```

参考验证环境为 QEMU 11.0.3，但代码按实际 executable version 和 plugin API probe 记录
能力，不用版本字符串硬编码放行。仅可对仓库自有 fixture 启用 semihosting。

也可以不安装入口脚本，通过源码运行：

```powershell
$env:PYTHONPATH = "src"
python -m chipchain --help
```

## Domain Model Example

以下示例读取测试用 ARM 候选链，并完成 Pydantic 校验和 JSON 序列化：

```python
from pathlib import Path

from chipchain.models import AttackChain

fixture_path = Path("tests/fixtures/valid_arm_chain.json")
chain = AttackChain.model_validate_json(fixture_path.read_text(encoding="utf-8"))

print(chain.architecture.value)  # arm
print(chain.model_dump_json(indent=2))
```

该 fixture 只用于验证数据契约，不代表真实漏洞。另一个漏洞样本位于 `tests/fixtures/valid_arm_vulnerability.json`。

导出核心 JSON Schema：

```powershell
.\.venv\Scripts\python scripts\export_schema.py
```

默认输出到被 Git 忽略的 `artifacts/schema/`。Schema 可以从模型确定性重新生成，因此不提交生成文件，避免代码与生成副本漂移。

## Graph Repository Example

以下示例构建明确标记为 fixture 的 ARM Behavior Graph，并查询固件函数到 MMIO 寄存器的结构路径：

```python
from chipchain.graph import build_arm_demo_graph
from chipchain.models import Architecture, Layer

repository = build_arm_demo_graph()
paths = repository.find_paths(
    "fixture_parse_command",
    target_id="fixture_debug_ctrl",
    architecture=Architecture.ARM,
    max_hops=3,
    allowed_layers={
        Layer.FIRMWARE,
        Layer.INTERFACE,
        Layer.DRIVER,
        Layer.HARDWARE,
    },
)

print(paths[0].node_ids)
print(paths[0].edge_ids)
print(paths[0].hop_count)
```

`GraphPath` 只表示图中存在的路径，不是 `AttackChain`，也不表达漏洞成立或可利用。

运行完整的创建、查询、保存和重新加载示例：

```powershell
.\.venv\Scripts\python examples\arm_graph_demo.py
```

默认图快照保存到 Git 忽略的 `artifacts/arm_graph_demo.json`。

## Program Analysis Example

Phase 3 的 DemoAnalyzer 读取语义化 fixture spec，而不是直接返回硬编码 BehaviorNode/Edge：

```python
from chipchain.analysis import DemoAnalyzer, ProgramArtifact

artifact = ProgramArtifact(
    id="fixture-arm-program",
    architecture="arm",
    artifact_type="fixture",
    path="tests/fixtures/program_analysis/arm_demo_program.json",
    fixture_identifier="fixture-arm-demo-program-spec",
)
result = DemoAnalyzer().analyze(artifact)

print(len(result.nodes), len(result.edges), len(result.evidence))
```

运行从 Program Spec、Analyzer、Ingestion 到 GraphPath 的完整示例：

```powershell
.\.venv\Scripts\python examples\arm_program_analysis_demo.py
```

DemoAnalyzer 的 `confidence=1.0` 只表示 fixture 中确定存在该观察关系，不代表真实攻击可信度。AngrAnalyzer 同样只返回静态程序观察，不会从函数、CALLS 或 MMIO 等行为自动推断漏洞、影响或 AttackChain。

真实 ARM ELF 示例：

```powershell
.\.venv\Scripts\python examples\arm_angr_analysis_demo.py
```

该示例使用仓库自有的 synthetic ARM A32 ELF，恢复 Function、CALLS、call-site
Evidence，并经现有 Ingestion 查询三跳调用 GraphPath。生成方法、哈希和 Ground
Truth 见 [angr 接入说明](docs/ANGR_INTEGRATION_PLAN.md)。

Phase 4B 的真实 ARM MMIO 跨层示例：

```powershell
.\.venv\Scripts\python examples\arm_angr_mmio_demo.py
```

该示例从真实 `movw/movt` 和 `LDR/STR` 的 VEX IR 解析 effective address，只有
命中显式 ARM Memory Map 的 `0x40000000` 才生成 MMIO Edge；普通 RAM 和
unresolved 地址只进入诊断。MMIO Evidence 的 confidence 表示静态关系观察的
确定程度，不是漏洞可信度。

## Vulnerability Knowledge Graph Example

Phase 5 示例读取仓库自有、明确标记为 fixture/synthetic 的 ARM
`VulnerabilitySample`，构建独立 Knowledge Graph 并打印硬件 match keys：

```powershell
.\.venv\Scripts\python examples\arm_vulnerability_kg_demo.py
```

该图保存漏洞样本的结构化描述和来源证据，不与 Behavior Graph 建立 Edge，
不执行 Candidate Search，也不表示漏洞或攻击链已确认。实体链接键约定见
[实体链接契约](docs/ENTITY_LINKING.md)。

## Exact Candidate Correlation Example

Phase 6 示例复用真实 ARM MMIO ELF 和 Phase 5 synthetic knowledge fixture：

```powershell
.\.venv\Scripts\python examples\arm_candidate_search_demo.py
```

它先独立构建 Behavior/Knowledge Repository，通过硬件 canonical key 精确链接，
再查找可达跨层 GraphPath 和 Vulnerability 的一跳知识上下文。输出是
`unverified correlation`，不是已验证漏洞或 AttackChain。搜索设计见
[Candidate Search](docs/CANDIDATE_SEARCH.md)。

## Architecture RAG + Mock Reasoning Example

Phase 7 继续复用同一 ARM ELF、Knowledge Fixture 和 CrossGraphCandidate：

```powershell
.\.venv\Scripts\python examples\arm_rag_reasoning_demo.py
```

Context Assembler 会解析完整 Node/Edge/Evidence，Local Retriever 在评分前排除
非 ARM 文档，Mock Provider 输出 `requires_verification` Assessment。Retrieved
内容只作为 reference data，LLM interpretation 不等于 Evidence 或 Verification。
设计见 [RAG Reasoning](docs/RAG_REASONING.md)。

## Typed Multi-Agent Reasoning Example

Phase 8 只执行固定的 Evidence Analyst → Security Reasoner → Critic，并共享一次
CandidateContext 和一次 ARM/global RAG。默认 Demo 完全离线：

```powershell
.\.venv\Scripts\python examples\arm_multi_agent_demo.py
```

Coordinator 是确定性 Python 编排器；三 Agent 共识不等于 Evidence Verification。
设计见 [Multi-Agent Reasoning](docs/MULTI_AGENT_REASONING.md)。

## Interaction Verification Example

Phase 9A-R 使用 owned synthetic ARM ELF、显式 Type II interaction/bindings 和非 LLM
verifier。该示例完全离线，不调用真实 Provider：

```powershell
.\.venv\Scripts\python examples\arm_interaction_verification_demo.py
```

输出的 MMIO 位置是 `cross_layer_trigger_point`，不是 initiating root cause；结果也不会
投影为 verified AttackChain。

## Dynamic Interaction Verification

Phase 9B2A 在 Phase 9B1 Runtime Evidence 与 Phase 9A-R 静态 trigger record 之间增加显式、
只读的 Dynamic Trigger Observation Verification：

```text
Phase 9B1 Runtime Evidence
            |
            v
     DynamicTriggerFact
            |
            v
   Dynamic Verification
            |
            v
Static/Dynamic Aggregation
```

Dynamic verifier 会 detached revalidate RuntimeTrace、按 ID 解析 Observation，并使用未修改的
`RuntimeEvidenceNormalizer` 重新生成 Evidence 后做精确比较。成功产生的
`VerificationRecord(status=VERIFIED, subject_kind=DYNAMIC_TRIGGER_OBSERVATION)` 只表示
runtime observation matches explicit trigger fact；它不表示 vulnerability 或 Interaction 已验证，
不修改 Phase 9A-R status/scoring，也不创建 BehaviorEdge、AttackChain 或 causality。

完整合同与八态 conflict policy 见
[Dynamic Interaction Verification](docs/DYNAMIC_INTERACTION_VERIFICATION.md)。

## Dynamic Evidence Reasoning Context

Phase 9B2B Step 7 将已有 `CrossLayerInteraction`、detached `RuntimeObservation`
和 `KnowledgeRetrievalResult` 作为可选、同架构的 `ReasoningContext` 输入。这些
对象只能影响未验证 hypothesis 和 evidence request；runtime observation ID 不会
自动进入 `supporting_evidence_ids`。缺失 runtime context 时，Agent 只产生
`EvidenceRequest`，不创建 Evidence 或 verification truth。

Agent 输出仍限于 `Hypothesis`、`EvidenceRequest` 和 `ReasoningResult`。该绑定
不修改 RuntimeEvidence、Phase 9A-R verification/scoring，也不产生 VerificationRecord、
vulnerability judgement 或 AttackChain。

## Real Reasoning Provider Bridge

Phase 9B2C Step 1 通过 `OpenAICompatibleReasoningProvider` 复用已有 Phase 7/8
`OpenAICompatibleLLMProvider` transport。固定数据流为：

```text
RoleBasedReasoningPromptBuilder
    -> StructuredPromptRequest
    -> OpenAICompatibleReasoningProvider
    -> raw JSON text
    -> ConstrainedReasoningOutputParser
    -> Hypothesis / EvidenceRequest / ReasoningResult
```

Phase 9B2C 曾冻结 reduced semantic v2；Phase 10A Step 3 将当前 provider contract 显式升级为
`phase10a_model_authored_chain_claim_v3`。不兼容的 v1/v2 不会在当前 DTO 下被接受，也没有 legacy
parser。该 bridge 从
constrained parser 使用的同一 Pydantic transport DTO 生成 strict JSON Schema，并通过确定性递归
规范化令每个 object 的 `required` 覆盖全部 properties、保持 `additionalProperties=false`。
Strict transport 必须携带 nullable `hypothesis.chain_claim`：CODE/HARDWARE/VULNERABILITY 固定为
`null`，ATTACK_CHAIN 可为 `null` 或一个完整结构对象。`null` 仅表示没有 model-authored claim，
不会创建 claim identity；普通 constrained parser 仍兼容手工输入省略该字段。
Provider schema 是第一道结构约束；`ConstrainedReasoningOutputParser` 仍是必须执行的第二道
语义/引用约束。Bridge 不在 schema 被拒绝时降级到 JSON Object，不解析安全语义、不绕过
Parser，也不在失败时 fallback 到 Mock。Legacy Phase 7/8 JSON mode 行为保持不变。Step 1
支持显式单角色 `ReasoningEngine` smoke。

Step 2 增加 `ProviderBackedReasoningAgent` 与显式 provider-backed workflow，固定按 Code →
Hardware → Vulnerability → AttackChain 执行。每个角色共享同一 detached Context 并至多调用
Provider 一次；不会把前序 Agent 的自由文本传给后序角色。Provider DTO 只允许 LLM 创作
description/confidence、request `required_fact`、reasoning steps 和 Context 白名单内的 supporting
Evidence ID 选择。Component、attack-pattern identity、Evidence category/priority 和 dynamic
trigger 由 ChipChain 从 typed Context/role contract 构造；这是 authority minimization，不是
输出修补。AttackChain 仍为 hypothesis-only，任一失败立即停止且没有 retry 或 fallback。

Step 3 使用透明 Provider wrapper 只记录每次实际调用的 role 与 Context ID，用于 release
acceptance 断言；它不保存 prompt、raw response、secret、endpoint 或 header，也不修改请求、
响应、解析和错误传播。观测到的 Agent 一致或完整执行不会升级 confidence，更不会产生
Evidence、VerificationRecord、vulnerability verdict 或 AttackChain。

## Hardware Trigger Signature

Phase 9C Step 1 用独立 `HardwareTriggerSignature` 保存已有硬件侧 proof 支持的
`exact ARM A32 instruction sequence + declared machine-state preconditions -> known hardware
failure` 合同。它不证明任何 firmware 可执行该序列或满足前置条件，也不是 Evidence、
VerificationRecord、AttackChain 或评分输入。

Step 2 的 `FirmwareTriggerMatcher` 只在授权 ARM ELF 的 decoded executable A32 instructions 上
匹配 exact sequence，并要求 occurrence 位于同一 recovered function、从函数入口结构可达的 CFG
path。真实 artifact bytes 以 SHA-256 绑定；不执行 raw ELF byte scan，因此非执行 `.data` 中的
相同字节不会匹配。`StaticFirmwareTriggerMatch` 仍不表示实际 runtime execution、具体输入路径
可行、任何 precondition 已满足、硬件失败重现或 triggerability/AttackChain 已验证。

Step 3A 使用与 Phase 9B1 分离的 `chipchain_trigger_sequence_observer`。它在 QEMU translation
callback 内通过 `qemu_plugin_insn_vaddr()`、`qemu_plugin_insn_size()` 与
`qemu_plugin_insn_data()` 复制 PC/size/bytes，并只在 instruction execution callback 中写入 raw
v1 event。Runner 对 ELF 做运行前后 SHA-256 检查；领域 matcher 再要求 runtime artifact ID/hash 与
Step 2 result 相同，并按连续事件精确比较 `(PC, logical A32 word)`。PC-only 和 word-only 都不会匹配。

```text
static exact T occurrence != concrete runtime T execution
concrete runtime T execution != declared T + P confirmation
declared T + P contract != hardware failure reproduced in QEMU
```

Step 3A 不读取 register/CPSR 或 guest memory，不判断 privilege/register/memory preconditions，
也不创建 Evidence、VerificationRecord、BehaviorEdge、AttackChain、score 或 vulnerability/
triggerability verdict。Generic runner 只记录本层实际拥有的 observation scope，不会根据
artifact ID、path、run ID 或 scenario ID 发明 fixture/synthetic/owned/benchmark provenance；owned
fixture 的 provenance 仍由其 fixture、Ground Truth、Signature 与 ProgramArtifact 显式提供。
`declared_arm_a32` 只是当前 runner/fixture execution scope，不表示动态观察了 CPSR.T。Plugin
instrumentation 可能增加执行开销，Step 3A 不作 timing non-interference 声明。Step 3B 与 Step 4
的关系是：Step 3B 仍未实现，而 Step 4 对非空 declared P 保守返回
`INSUFFICIENT_PRECONDITION_EVIDENCE`。

Step 4 的 `TriggerabilityAggregator` detached-revalidate Signature、static result 与 runtime result，
并交叉检查 signature/static exact words、artifact identity/hash、static semantic hash/完整 match ID
集合，以及每个 runtime occurrence 对应 static match 的 exact PC+word sequence。四个正常状态为：

- `TRIGGERABLE`：static T 与 runtime T 均存在，且 Signature 无 declared P；
- `INSUFFICIENT_PRECONDITION_EVIDENCE`：static/runtime T 存在，但 typed Signature 声明了 P；
- `NOT_OBSERVED_IN_RUNTIME`：static T 存在，但当前 concrete trace 未执行；
- `NO_STATIC_TRIGGER_MATCH`：当前 artifact/signature 没有 static exact T。

`TRIGGERABLE` 只表示“firmware 在无 additional declared P 的 prevalidated hardware-trigger contract
下实际执行了 exact T”。它不表示 QEMU 重现 hardware failure，不验证 vulnerability、Interaction
或 AttackChain，也不创建 Evidence、VerificationRecord 或 score。它不是完整 candidate-chain
feasibility outcome，不能直接等同于未来的 `CONFIRMED_FEASIBLE`。
设计边界见 [Hardware Trigger Signatures](docs/HARDWARE_TRIGGER_SIGNATURES.md)。

## Phase 10A Evaluation Contracts

Phase 10A Step 1 将 project candidate 边界固定为：一次完整 `ReasoningSession` 只产生一个
`FinalizedCandidateRecord`，唯一命题是 `session.merged_hypothesis`。Code、Hardware、Vulnerability
和 AttackChain role hypotheses 是同一次协同推理的内部产物，不分别进入未来 denominator。

候选构建器只接收 `benchmark_case_id` 与 detached `ReasoningSession`，不接收或读取 Ground Truth。
它保留 typed Context 中已有的 interaction ID/type/direction；Context 缺少 interaction 时字段保持
空，不从答案键或自由文本补全。Model confidence 可用于以后分析，但不影响 candidate identity，
也不能决定 feasibility。

Benchmark 侧独立定义 ARM-only artifact reference、`GroundTruthChain`、positive/negative case、
source provenance、predeclared evaluation scope 和 versioned manifest。Artifact 只保存稳定相对引用和
canonical SHA-256，不保存 host absolute path。Initial manifest 只有一个明确标注 owned/synthetic/
fixture 的 Type II positive contract case 与一个 negative control；它们不是真实 CVE 或公共 Benchmark。

Phase 10B 实现的 strict project metric contract 定义为：

```text
VerificationHitRate
= N(PRIMARY_TARGET 中 ALIGNED + CONFIRMED_FEASIBLE + exact Ground Truth match 的 finalized candidates)
  / N(predeclared primary scope 中产生的全部 finalized candidates)
```

结构较弱或缺少 typed binding 的候选不得从 denominator 静默消失。未来可单独报告预先冻结 eligibility
的 verifier-conditioned secondary rate，并必须配套 `GroundTruthChainRecall`。

Phase 10A Step 2 新增单条候选的 `ChainFeasibilityOracle`，输入只允许 finalized candidate、
path-neutral artifact、candidate-side typed interaction、Phase 9C triggerability 与显式 bounded
infrastructure failure。Ground Truth、BenchmarkCase、Manifest 和 EvaluationScope 不进入 oracle。
Candidate 的 interaction ID/type/direction 来自 `ReasoningContext` typed binding，并不自动说明 LLM
独立创作或正确预测了这些字段。

当前矩阵为：

- Type II + 完整 exact binding + `TRIGGERABLE` → `CONFIRMED_FEASIBLE`；
- Type I → `UNRESOLVED`，直到有 objective software-vulnerability→exact-T enabling link；
- Type III → `UNSUPPORTED`，因为 HW→SW objective propagation 未实现；
- `NO_STATIC_TRIGGER_MATCH` → `NOT_SUPPORTED`；
- `NOT_OBSERVED_IN_RUNTIME` 或 declared P 未确认 → `UNRESOLVED`；
- 只有显式 `ObjectiveEvaluationFailure` 可产生 `INFRA_FAILURE`。

该 assessment 不是 domain AttackChain，也不创建 VerificationRecord 或 score。Phase 10A Step 2
没有运行 benchmark manifest、比较 Ground Truth 或计算“关联漏洞命中率 >=80%”。

Phase 10A Step 3 新增独立 `ModelAuthoredChainClaim` proposal。它只保存 ATTACK_CHAIN role 明确
选择的 interaction type 与 participant/reference lists；architecture、author role 与 deterministic ID
由 ChipChain 绑定。它不是 `CrossLayerInteraction`、AttackChain、Evidence、VerificationRecord 或
feasibility verdict。缺失 claim 保持 `MISSING`，不完整或错误 claim 保持 `INCOMPLETE` / `MISMATCHED`，
不会从 Context 或 Ground Truth 静默补全。

`ModelClaimBinder` 只比较显式 model claim 与 candidate-side typed interaction，输出独立的
`ALIGNED`、`INCOMPLETE`、`MISMATCHED`、`UNBOUND` 或 `MISSING`。因此 Context interaction != model
authorship，model claim != verified truth。Required participant categories 必须 exact；optional category
为空表示未显式声明，非空时只需是 candidate-side 对应集合的子集。Coordinator 还会依据实际返回
hypothesis 的 Agent role 独立拒绝非 ATTACK_CHAIN claim，不能只信任 claim 自带的 author role。
`CONFIRMED_FEASIBLE` 单独不足以说明模型正确提出了该链。
Phase 10B 还要求同一候选 exact match case Ground Truth；`ALIGNED` 或 `CONFIRMED_FEASIBLE` 单独均不
足够。
详见 [Evaluation Contracts](docs/EVALUATION_CONTRACTS.md)。

## Phase 10B Deterministic Benchmark Evaluation

Phase 10B 只消费已经 finalized 的 manifest、candidate、claim-binding、feasibility 与必要的
triggerability，不调用 LLM、Agent workflow、Binder、Oracle、angr 或 QEMU。每个 manifest case 必须
恰好具有一个 `BenchmarkCaseRunRecord`；pre-finalization failure 不伪造 candidate，而是降低
`PrimaryCaseCoverage` 并令 `primary_scope_complete=false`。

评测层次固定为：

```text
ReasoningSession -> FinalizedCandidateRecord
ModelAuthoredChainClaim -> ModelClaimBindingAssessment
candidate-side objective facts -> ChainFeasibilityAssessment
frozen Ground Truth comparison -> BenchmarkCandidateAssessment
manifest aggregation -> BenchmarkEvaluationReport
```

Companion metrics 为 `GroundTruthChainRecall`、`NegativeControlFalsePositiveRate` 和
`PrimaryCaseCoverage`。Negative control 永不成为 strict hit；若其 candidate 为 ALIGNED +
CONFIRMED_FEASIBLE，则作为 benchmark false positive。Owned synthetic fixture 的 `1/2` hit rate 仅是
合同验收结果，不是项目性能结果，也没有产生“>=80%”阈值结论。

## Phase 10C Ablation and Prompt Visibility

Phase 10C 预声明四个不可矛盾配置的条件：`FULL_CONTEXT_MODEL` 保留现有 provider prompt；
`MASKED_CHAIN_CONTEXT_MODEL` 仅从 model-visible prompt 移除 typed interaction、attack-pattern 与
dynamic-trigger chain-answer context；`NO_MODEL_BASELINE` 保持无 model-authored claim；
`CONTEXT_OBJECTIVE_UPPER_BOUND` 只在后验 comparison 中移除 claim-alignment gate。

MASKED 使用只由可见字段生成的 `reasoning-prompt-view:<sha256>`，不会在 prompt 中序列化完整
`ReasoningContext.id`。完整 Context 不被替换或修改，仍由 `ReasoningSession`、candidate builder、
`ModelClaimBinder` 和 `ChainFeasibilityOracle` 使用；parser 也继续对完整 trusted Context 校验 provider
输出，但绝不把隐藏 participant 复制进错误或缺失的 model claim。Exact-reference prompt audit 只报告
实验质量 `PASS`/`LEAK_DETECTED`，不参与 verification hit rate。

三个普通条件原样使用 Phase 10B `BenchmarkEvaluationReport`。upper bound 仍要求 PRIMARY_TARGET
finalized candidate、`CONFIRMED_FEASIBLE` 与 exact Ground Truth match，negative control 永不命中；它
不是模型指标，也不叫 `VerificationHitRate`。Comparison 强制同一 manifest/version/runner contract、
四条件完整记账、显式失败与可比较的完整 coverage，并以整数分子/分母保存 delta。这里的差异只是
observed ablation difference，不是因果模型效应。本阶段没有真实模型实验，也没有 >=80% 结论。

## Phase 10D Step 1 Experiment Provenance

Phase 10D Step 1 只冻结未来真实模型运行所需的可审计合同。`RealModelProviderDescriptor` 保存 model、
API style、strict schema、reasoning effort、token limit 与 schema name，但结构上不允许 API key、base
URL、endpoint、timeout、retry 或 host path。FULL 与 MASKED 在一个 plan 中只能共享同一 descriptor；
NO_MODEL 与 upper bound 保留在同一四条件 matrix，但不产生 provider invocation。

每个 model condition/frozen case 都固定展开 Code → Hardware → Vulnerability → AttackChain 四个
repetition-0 role slot；role 进入 deterministic invocation identity。Canonical record 为每个实际角色调用
分别保存 exact final prompt 与 raw response 的 lowercase SHA-256。串行失败只允许若干 `COMPLETED`、一个
实际 `FAILED`、随后全部 `NOT_ATTEMPTED`；未调用 slot 只保存 typed blocking role，不伪造 failure 或 hash。
MASKED audit 必须逐 attempted role 与 invocation prompt SHA 精确对应。合同不保存 raw prompt、raw response、
traceback、stderr 或 secret。MISSING/MISMATCHED 等 claim assessment 是成功解析后的语义输出，不是
transport failure。顶层 artifact 显式报告 provider/benchmark comparability、MASKED audit validity 与
execution completeness。

本阶段所有 fixture 均标记 `OFFLINE_CONTRACT`，不等于真实模型实验。

## Phase 10D Step 2 Opt-In Execution Harness

Step 2 以 `RealExperimentCaseInput` / `RealExperimentInputSet` 冻结每个 plan case 的同一份完整
candidate-side `ReasoningContext` 和可选 triggerability。FULL 与 MASKED 对同一 detached Context 执行
冻结的 `ProviderBackedAgentWorkflow`，共享 provider object/configuration；唯一差异是
`ReasoningPromptVisibility`。实验 recorder 委托现有 prompt builder、provider 和 constrained parser，
只把 exact prompt/response SHA-256 送入 Step 1 provenance，不复制推理语义。

MASKED 在最终 prompt 构造后、provider transport 前执行 hidden-reference audit；检测到泄漏立即 fail
closed，不发送 prompt，也不产生 response hash。一个 case 失败只形成该 case 的合法 fail-stop role
记录，后续 case 仍执行。NO_MODEL 使用 deterministic `AgentWorkflow` 且 provider 调用数为零；UPPER
复用 exact NO_MODEL case-run cohort。`RealModelExecutionArchive` exact-bind input set、parsed
`ReasoningSession`、FULL/MASKED/NO_MODEL case runs、Phase 10C comparison 与 Step 1 artifact。

显式入口为 `chipchain experiment real-model ... --execute-real-provider`。缺少该标志时不会创建
Provider、读取 Provider 环境变量或发起网络请求。Canonical archive 包含 parsed semantic outputs 和
SHA-256，不包含 raw prompt/response、API key、Authorization、base URL、endpoint、时间或 host path。
默认测试完全离线；当前没有执行真实模型实验，也没有项目 >=80% 结论。

## Phase 10D Step 6 Objective Input Materialization

Step 6 使用独立 candidate-side source contract 将实际 owned ARM ELF、HardwareTriggerSignature 与
冻结 QEMU raw JSONL 依次送入现有 Angr static matcher、公开纯 raw-trace normalizer、runtime matcher
和 production aggregator。source 只保存 repo-relative logical references、expected content hashes、
run/scenario 与 interaction/target binding；不包含 benchmark label、Ground Truth、expected status 或
任何 expected derived output ID。

派生的 `ObjectiveTriggerabilityMaterializationRecord` 保存 source snapshot、Context ID、parsed/runtime
trace IDs、static/runtime semantic hashes 与 aggregation ID，并随 `RealExperimentCaseInput` 进入 archive。
旧 input/archive 缺该字段时仍保持原 ID 和反序列化能力；新的 `REAL_PROVIDER` input 若携带
triggerability，则 create、CLI 和 executor preflight 都要求完整 materialization provenance。整个
materialization 过程不启动 QEMU、不调用 Provider、不触网，也不改变 Phase 9C/10A/10B/10C 语义。

## Phase 10D Step 7 Collision-Safe MASKED Projection

Step 7 将 MASKED hidden-reference derivation 集中到 reasoning layer，由同一冻结函数同时驱动
`ReasoningPromptView` 和 transport 前 `PromptVisibilityAuditor`。投影会从 remaining visible ID fields
删除任何包含 hidden reference 的值；`subject_id` 碰撞或全部 affected component 被删除时在 Provider
调用前 fail closed。包含 hidden reference 的 runtime observation 或 knowledge retrieval result 整项省略，
不使用 placeholder、hash alias 或不完整 typed object。

`provider_authority.supporting_evidence_ids_allowed_values` 只来自 MASKED projected evidence IDs。完整
trusted `ReasoningContext` 不被修改，parser/system-owned binding 仍使用它；FULL prompt 以及没有 collision
的历史 MASKED prompt 保持 byte-for-byte identity。新建 experiment plan 绑定冻结 projection contract，
旧 Step 1～6 plan/archive 缺字段时仍可读取，但不能作为新的 `REAL_PROVIDER` execution 重放。
读取历史 REAL_PROVIDER archive 时，validator 会依据归档 plan 的 optional contract 精确选择 legacy 或
current reconstruction，再与唯一 archived prompt SHA 比较；不会跳过历史 MASKED hash，也不会同时接受
legacy/current 两种结果。

## Phase 10D Step 8A Public CVE Corpus Intake

`data/public_cve/arm_cross_layer_seed_v1.json` 保存首批七条公开 ARM CVE 研究记录，并为每条记录
绑定一个现有 `VulnerabilityKnowledgeEntry(CVE)`。该 corpus 只进行分类与未来 benchmark admission
staging：它不创建 Evidence、VerificationRecord、Ground Truth、triggerability 或漏洞判定，也没有把
任何记录加入当前 `PRIMARY_TARGET`。

Corpus 显式区分 A-profile/M-profile、CVE record 与 `underlying_issue_key`，并把 related CVE 保持为
关系引用。`NEXT_OBJECTIVE_CANDIDATE` 只表示后续客观输入研究优先级；在独立 admission 评审完成前，
不得写入 owned-synthetic Phase 10A/10D fixture。

Phase 10D Step 8B-0 将 `data/public_cve/source/*.json` 固定为唯一人工维护来源。source loader 经纯
deterministic builder 派生一个 `VulnerabilityKnowledgeEntry` 和对应 `PublicCveResearchSample`，再生成
继续提交的 `PublicCveCorpus` snapshot：

```text
data/public_cve/source/
        ↓
source loader → deterministic builder
        ↓
VulnerabilityKnowledgeEntry + PublicCveResearchSample
        ↓
PublicCveCorpus generated snapshot
```

维护者不手算或手改 `knowledge_entry_id`、sample ID、knowledge entries 或 corpus ID。运行
`python scripts/build_public_cve_corpus.py --check` 可离线核对 committed snapshot；`--write` 只执行
确定性本地重建，不访问 NVD 或任何外部服务。

## Phase 10D Step 8B-1A Public SECONDARY Cohort

Step 8B-1A 从上述 source 与 generated corpus 派生首批五条 A-profile public-documented case。人工维护的
`data/public_cve/evaluation/arm_secondary_v1.json` 只记录 CVE 选择及 ChipChain 软件 source-layer 抽象；
title、summary、trigger/precondition/effect、components、references 与 classification 不在 selection 中
重复维护。每个 `EvaluationBenchmarkCase` 均为 `PUBLIC_DOCUMENTED` / `SECONDARY_ONLY`，其
`POSITIVE_FEASIBLE` label 只表示公开文档描述了 vulnerability scenario，不表示 ChipChain 已确认
triggerability、feasibility 或 vulnerability。

Materializer 为每条 CVE 生成 source-record canonical SHA-256、path-neutral artifact reference、最小
documented Type I/II interaction、唯一 knowledge-entry binding 与没有 runtime/Evidence/triggerability 的
`ReasoningContext`，并对四角色的 FULL/MASKED prompt 分别保存 exact SHA-256。20 个 MASKED audit 均为
`PASS`。当前实际 prompt payload 可见 CVE ID、components 与 knowledge-entry ID，但 knowledge contract
仅提供 reference，未把 public source references 或描述性漏洞内容序列化给模型。因此 committed readiness
结果是 `REFERENCE_CONTENT_INSUFFICIENT`；本步骤不修改 prompt、masking 或检索合同，也没有调用真实
Provider。SECONDARY cohort 完全排除在 PRIMARY hit rate、recall、false-positive rate 与 coverage 之外，
目前没有 public-CVE hit-rate 声明。

## Phase 10D Step 8B-1B Public Knowledge Projection

Step 8B-1B 保持 `ReasoningContext` 为纯 structural/reference binding，并新增独立的
`phase10d_public_knowledge_content_projection_v1` attachment。Projection 只能从 Context 精确绑定且已通过
deterministic ID revalidation 的 `VulnerabilityKnowledgeEntry(CVE)` 构造，只向模型暴露 entry ID/kind、
external ID、architecture、title、summary、affected components 与 public references；knowledge metadata、
curator classification/admission/trigger/precondition/effect 字段、Ground Truth、objective status 与 metrics
均不进入 attachment。

`RoleBasedReasoningPromptBuilder.build_with_knowledge_projection()` 是显式新路径，原 `build()` 与历史
projection-contract 路径字节不变。FULL 与 MASKED 接收同一份 public reference content，MASKED 仍按冻结
Step 7 policy 隐藏 chain-answer context。最终 serialized Prompt 同时经过 exact hidden-reference audit 和
versioned structured-label leakage audit；新的 hash-only readiness artifact 为
`READY_FOR_PUBLIC_PROVIDER`。这只说明离线 Prompt 输入合同已就绪：public reference content 不是 Evidence、
Ground Truth、漏洞 verdict、因果证明或 model-authored content，且尚未调用任何真实 Provider、未产生模型
性能结果。

## Phase 10D Step 8B-1C Public Knowledge Execution Wiring

Step 8B-1C 不修改历史 `RealModelExperimentPlan`、`RealExperimentInputSet` 或
`RealModelExecutionArchive` 字段，而以独立
`phase10d_public_knowledge_execution_binding_v1` 连接冻结的五条 SECONDARY cohort、Step 8B-1B
readiness、每案精确 `KnowledgeContentProjection` 和普通 candidate-side inputs。Binding 内恰好保存
5 × 2 visibility × 4 role 的 40 个 expected prompt SHA-256；projection 必须从本地 corpus 的精确 entry
重建并与冻结 readiness projection ID 一致。

`RealModelExperimentExecutor.execute_with_public_knowledge()` 仍经过官方
`RoleBasedReasoningPromptBuilder.build_with_knowledge_projection()`。本地 preflight 会先重建全部 40 个
prompt，并在任何 transport 前检查冻结 hash、MASKED hidden-reference audit 与既有 structured leakage
audit；任何缺失、额外、crosswire 或 prompt drift 都 fail closed，且没有 legacy prompt fallback。
输出使用独立 `phase10d_public_knowledge_execution_archive_v1` wrapper 绑定 public provenance 与历史
hash-only execution archive，不保存 assembled prompt、raw provider response、secret 或 endpoint。

本步骤只完成 wiring、deterministic fake-provider integration 和 offline preflight；没有调用真实 Provider，
也没有产生真实模型性能结果。五条 case 继续是 `PUBLIC_DOCUMENTED` / `SECONDARY_ONLY`，所有 PRIMARY
metric denominator 仍为 0。

## Phase 10D Step 8B-1D Frozen Public One-Shot

Step 8B-1D 在独立审批下完成一次五案 public-provider one-shot，并把 hash-only execution archive 冻结在
`phase-10d-step8b1d-stable`。归档仍不保存 raw prompt、raw provider response、secret 或 endpoint；五案
继续是 `SECONDARY_ONLY`，不能进入 PRIMARY denominator，也不能据此宣称验证命中率、模型准确率或
`>=80%` 结论。该执行不会把 reasoning、claim 或 agent agreement 提升为 Evidence、VerificationRecord、
AttackChain 或 vulnerability verdict。

## Phase 10D Step 8B-1E Masked Semantic Recovery Diagnostic

Step 8B-1E 新增版本化、确定性、完全离线的
`phase10d_masked_semantic_recovery_diagnostic_v1`，把三个独立问题明确分开：

1. Axis A：既有 `ModelClaimBinder` 的 exact candidate-reference alignment；
2. Axis B：新的 MASKED cross-layer type 与 lexical content recovery diagnostic；
3. Axis C：既有 `ChainFeasibilityOracle` 的 objective feasibility。

Axis B 不修改或放宽 Axis A/C。当前冻结 workflow 中 ATTACK_CHAIN 是 hypothesis-only role，因此五案的
诊断文本都严格来自唯一携带 `ModelAuthoredChainClaim` 的 ATTACK_CHAIN hypothesis description；归档中
没有同 hypothesis ID 的 `ReasoningResult`，故 artifact 明确保存 `reasoning_result_id=null`、
`reasoning_steps_available=false` 与 `ATTACK_CHAIN_HYPOTHESIS_DESCRIPTION_ONLY`。实现不会回退到 merged
hypothesis、final result、其他角色文本、FULL condition 或重建 raw provider response。

交互类型只与 frozen typed interaction 做 exact comparison；participant diagnostic 只解释既有 binder
结果，不修复 hidden opaque participant ID。`phase10d_semantic_tokenization_v1` 对 evaluator-side、运行前
已存在且未投影给 Provider 的 trigger/precondition/hardware-effect 字段计算精确 token-set content coverage，
并另行扣除 Provider-visible public summary tokens 得到 held-out coverage。所有 coverage 都保存 exact
numerator/denominator、defined flag 与 token-set SHA-256，不设置阈值、加权分数、PASS/FAIL 或 semantic
success。

当前 artifact 是 `RETROSPECTIVE_DIAGNOSTIC` 且 `prospective_metric_eligible=false`：合同是在第一次
one-shot 输出已被观察后定义的。它只可称为“ATTACK_CHAIN hypothesis-description content coverage”，不是
完整 ATTACK_CHAIN reasoning coverage、semantic correctness、模型准确率、漏洞验证或 attack-chain detection
rate。运行以下命令可在无 Provider、网络或 QEMU 的环境中逐字节复现：

```bash
python scripts/build_masked_semantic_recovery_diagnostic.py --check
```

## Phase 10D Step 8B-2B0 Documented Erratum Contract

Step 8B-2B0 以独立的 `DocumentedHardwareErratumContract` 冻结 Arm SDEN-1152370 v11.0 对
Cortex-A77 erratum 1508412 的规范性文档语义。人工审阅的 concise curation source 与冻结的
CVE-2023-34320 public-source file/record/corpus identity 共同输入完全离线 builder；它不下载或提交 Arm
PDF，也不保存长摘录、机器码或 workaround 可执行序列：

```text
frozen public CVE source + authoritative erratum curation
                         ↓
              deterministic offline builder
                         ↓
       DocumentedHardwareErratumContract
```

该合同精确保留 r0p0/r1p0 affected、r1p1 fixed、Case A/Case B 的 program order、Device 与
Normal Non-cacheable 的不同适用范围、`CLOSE_PROXIMITY` 以及 `CORE_DEADLOCK/POSSIBLE`。Program order
由来源明确，但 proximity 只有 `QUALITATIVE_ONLY`，没有 instruction/cycle/distance 数值界限；额外 timing
conditions 仍是 `UNSPECIFIED_BY_PUBLIC_SOURCE`。`PAR_EL1` alternative 明确限 privileged AArch64，其他
load/store-exclusive 路径仍保持 ARM A-profile applicability，不把整个 Cortex-A77 erratum 错写为 A64-only。

`DocumentedHardwareErratumContract != HardwareTriggerSignature`；authoritative documentation 也不等于
`HardwareTriggerProof` 或 hardware experimental proof。`SEMANTIC_PATTERN_REFERENCE_ONLY` 不是 objective
observation、Evidence、VerificationRecord、`TriggerabilityAggregationResult`、feasibility 或漏洞 verdict。
CVE-2023-34320 继续是 `NEXT_OBJECTIVE_CANDIDATE`，其 evaluation cohort 继续是 `SECONDARY_ONLY`，没有
PRIMARY admission 变化。可用下列命令离线核对唯一生成物：

```bash
python scripts/build_cve_2023_34320_documented_erratum.py --check
```

## Phase 10D Step 8B-2B1 A-profile Semantic Trigger Pattern

Step 8B-2B1 只从冻结的 2B0 generated artifact 翻译出
`phase10d_a_profile_semantic_trigger_pattern_v1`；production builder 不再读取 Arm 文档或人工 curation
source。该通用合同描述未来 objective analyzer 需要寻找的 event predicates、ordered positions、OR
alternatives 与 source obligations：

```text
DocumentedHardwareErratumContract
        ↓ semantic translation only
AProfileSemanticTriggerPattern
        ↓ future extraction (not implemented in 2B1)
Static / Runtime objective facts
        ↓ future stateful evaluation
Triggerability
```

`AProfileSemanticTriggerPattern` 不是 observation、occurrence、`HardwareTriggerSignature`、
`HardwareTriggerProof` 或 `TriggerabilityAggregationResult`。2B1 没有 PC、instruction address、machine-code
word、effective address、trace position 或任何 matched/executed/satisfied outcome。它仅保留 Case A/B 的
有向 program order：alternatives 是 OR，positions 不能交换。

`MEMORY_LOAD` 的 Device/Normal Non-cacheable 条件明确指
`EFFECTIVE_ARCHITECTURAL_MEMORY_TYPE`，并携带
`OBJECTIVE_EFFECTIVE_MEMORY_TYPE_REQUIRED` obligation。未来静态/运行时分析不能仅凭 load opcode、MMIO
分类、section 名或地址范围声称 effective memory type 已成立。`CLOSE_PROXIMITY` 仍为
`QUALITATIVE_ONLY` / `quantitative_bound=null`，并明确是
`SOURCE_INSUFFICIENT_FOR_EXACT_SOFTWARE_ONLY_SATISFACTION`；不得发明 instruction/cycle/window threshold。

未来 2B2 可产生带 PC/instruction provenance 的静态 candidate occurrences，但不能仅由 opcode 解析 memory
type；未来 2B3 可产生 event execution、program order、effective address/context 与解析后的 effective
memory type facts，但即使 trace 完整，也不能在 v1 下把 qualitative proximity 标记为 satisfied。当前 CVE
继续是 `NEXT_OBJECTIVE_CANDIDATE` / `SECONDARY_ONLY`，没有 PRIMARY admission 变化。离线复核命令：

```bash
python scripts/build_cve_2023_34320_a_profile_semantic_trigger_pattern.py --check
```

## Phase 10D Step 8B-2B2-A Static Semantic Extraction Contract

Step 8B-2B2-A 只把冻结 2B1 pattern 翻译为 artifact-neutral、确定性的
`AProfileStaticSemanticExtractionPlan`，并冻结未来 extractor 可输出的静态事实、谓词候选与结果合同：

```text
DocumentedHardwareErratumContract
        ↓
AProfileSemanticTriggerPattern
        ↓
AProfileStaticSemanticExtractionPlan
        ↓ 2B2-B real static decoded-event extraction
AProfileStaticSemanticInstructionFact
        ↓ exact predicate binding
AProfileStaticPredicateCandidate
        ↓ 2B2-C2 real-angr function CFG materialization
AProfileStaticFunctionCfgSnapshot[]
        ↓ 2B2-C1 pure function-local CFG order semantics
AProfileStaticCaseOrderCandidate
        ↓ future runtime/stateful evidence
Triggerability
```

计划的唯一 production 输入是 2B1 artifact 的同一 immutable byte snapshot，并同时校验其 SHA-256、semantic
ID 与 contract。每个 source alternative 都由 pattern ID、case ID、position index 和 canonical predicate
content 生成独立 deterministic reference；reference 不依赖 alternative 的展示索引。

新 static namespace 的 v1 只支持 AArch64 decoded semantics，使用 16 位十六进制 code address 和 8 位
十六进制 logical instruction word；它没有给旧 A32 `ArmExecutionMode` 增加 A64，也没有改变 Phase 9C
signature/matcher/triggerability 合同。`AProfileStaticSemanticInstructionFact` 仅表示该指令存在于被分析的
immutable artifact，`AProfileStaticPredicateCandidate` 仅表示 decoded semantics 可作为某个 pattern predicate
的候选。两者都不表示指令已执行、predicate 已满足或 Case A/B 已成立。

尤其是 decoded `MEMORY_LOAD` 不等于 Device/Normal-NC 已建立：事实只能记录
`REQUIRES_OBJECTIVE_TRANSLATION_CONTEXT`，物理 MMIO、section、地址范围或 opcode 都不能替代 effective
architectural memory type。静态识别 `SYSTEM_REGISTER_READ(PAR_EL1)` 也不证明 runtime EL/privilege。所有
候选继续携带 runtime execution、适用的 runtime context/effective memory type、qualitative proximity 和
additional hardware timing obligations。

本步骤（2B2-A）不打开 ELF、不执行 angr、不组装 Case、不判断 CFG/program order、不发明 proximity 数值界限，也不
创建 runtime observation、Evidence、VerificationRecord、`TriggerabilityAggregationResult`、feasibility 或
PRIMARY 结论。2B2-B 已在独立边界下实现 AArch64 decoded-event extractor；2B2-C1/C2 已分别冻结纯
case/path/order 合同与 generic real-angr CFG materializer，但不改变本计划合同。确定性计划可完全离线复核：

```bash
python scripts/build_cve_2023_34320_a_profile_static_semantic_extraction_plan.py --check
```

## Phase 10D Step 8B-2B2-B AArch64 Static Semantic Event Extractor

Step 8B-2B2-B 首次使用真实 angr `CFGFast(normalize=True)`，但只分析 owned synthetic AArch64 ELF 的
main-object executable functions/blocks。`AngrAProfileStaticSemanticExtractor` 在分析前后分别读取并校验
artifact SHA-256，实际加载的 ELF 必须是 AArch64/64-bit；外部对象、SimProcedure、PLT 与非执行数据不产生
static semantic fact。

v1 recognition profile 明确标记为 `STATIC_RECOGNITION_PROFILE_PARTIAL`，采用 Capstone exact instruction
ID 与 structured operand shape 的组合：`LDR(REG,MEM)`；`STXR/STXRB/STXRH/STLXR/STLXRB/STLXRH`
的 `(REG,REG,MEM)`；以及 `MRS(REG,SYSREG)` 且 system-register identity 必须精确为 `PAR_EL1`。它不使用
mnemonic prefix、raw ELF scan、source/disassembly text grep。`LDUR` 等未列出的 load family 不产生事实。

```text
2B2-A frozen extraction plan
        +
owned immutable AArch64 ELF
        ↓ real angr/Capstone static decoding
AProfileStaticSemanticInstructionFact
        ↓ official candidate.create, plan-driven only
AProfileStaticPredicateCandidate
        ↓ 2B2-C2 generic real-angr CFG materialization
AProfileStaticFunctionCfgSnapshot[]
        ↓ frozen 2B2-C1 pure typed graph semantics
AProfileStaticCaseOrderCandidate
```

静态 instruction existence 不等于 runtime execution；decoded `MEMORY_LOAD` 不等于 Device/Normal-NC 已建立；
`MRS PAR_EL1` 的存在不等于 runtime privileged execution；predicate candidate 不等于 predicate satisfied。
即使结果中存在多个 individual candidates，也不表示 Case A/B、program order 或 `CLOSE_PROXIMITY` 已成立。
本步骤不创建 runtime observation、Evidence、VerificationRecord、`TriggerabilityAggregationResult`、feasibility
或 PRIMARY 结论。2B2-C1 冻结纯 function-local static CFG order candidate 合同；2B2-C2 只把同一 immutable
binary 的 normalized CFG 输入该合同，不改变 2B2-B facts 或 C1 判断语义。

## Phase 10D Step 8B-2B2-C1 Static Case / Function-Local CFG Order Candidate

Step 8B-2B2-C1 新增 backend-independent 的 normalized function CFG snapshot、strict directed edge、
standalone `AProfileStaticCaseOrderCandidate` 与 assembly result。纯 evaluator 只在同一 artifact、同一 exact
extraction result/plan/case、同一非空 function address 内配对 position 1/2 candidates。同 basic block 仅接受
instruction address 前向顺序；不同 block 仅接受 directed reachability，并保存 sorted-successor BFS 的确定性
path，固定用途为 `REACHABILITY_AUDIT_ONLY`。

该 path 只证明结构可达：static CFG reachability 不等于 runtime execution，也不等于 symbolic path feasibility。
same function、same block 或 direct CFG edge 均不等于 `CLOSE_PROXIMITY`。全部 runtime、effective-memory-type、
privilege/context、qualitative proximity 与 additional timing obligations 原样保留；case-order candidate 不等于
triggerability。2B2-C1 不导入 angr；2B2-C2 的独立 backend adapter 已实现，但不改变此纯合同。

## Phase 10D Step 8B-2B2-C2 Generic AArch64 Binary CFG Materialization

`AngrAProfileStaticCaseMaterializer.materialize(artifact, extraction_plan)` 提供 binary-first、pattern-driven 的
通用 AArch64 静态分析入口：它先调用冻结的 `AngrAProfileStaticSemanticExtractor`，再把同一 ELF 的
main-object、executable、function-local CFG 规范化为 C1 snapshots，最后只调用冻结的
`assemble_static_case_order_candidates()`。C2 不识别 CVE、处理器/erratum、Case A/B、semantic event kind
或 system register；漏洞语义只来自外部 plan/pattern。

```text
ProgramArtifact + AProfileStaticSemanticExtractionPlan
        ↓ frozen 2B2-B extractor
exact AProfileStaticSemanticExtractionResult
        ↓ same artifact SHA + real angr CFGFast(normalize=True)
relevant AProfileStaticFunctionCfgSnapshot[]
        ↓ frozen 2B2-C1 pure assembler
AProfileStaticCaseAssemblyResult
```

C2 只为 predicate-referenced、non-null exact function address 各生成一个 snapshot；函数必须精确存在于
main object、非 SimProcedure/PLT，并包含所有相关 fact blocks。节点和边只保留 exact function-local executable
block set，按数值排序并去重；外部/被调用函数 endpoint 被过滤。artifact 在 C2 CFG pass 前后独立校验 SHA，
确保 semantic facts 与 normalized CFG 绑定同一 bytes。当前 frozen owned A64 fixture 得到 3 个 facts、6 个
predicate candidates、3 个 CFG snapshots 和 0 个 case candidates；零候选是中性结构结果，不表示安全。

该 backend 可不改源码地重跑其他兼容 AArch64 ELF、处理器上的 ELF 或不同 Linux kernel/firmware build。
处理器特定 vulnerability pattern 仍必须由外部知识/plan 提供；这不表示每个处理器共享同一 pattern。当前 ELF
loader 是 adapter boundary，未来 raw/firmware loader 应继续输出相同 semantic/CFG IR，而无需重设计
`AProfileStaticSemanticInstructionFact`、`AProfileStaticPredicateCandidate`、
`AProfileStaticFunctionCfgSnapshot` 或 `AProfileStaticCaseOrderCandidate`。

C2 不做 symbolic execution、runtime program-order、effective memory-type 或 proximity 求值，不创建 runtime
observation、Evidence、VerificationRecord、`TriggerabilityAggregationResult`、feasibility、vulnerability 或
PRIMARY 结论。static CFG reachability 仍只作 `REACHABILITY_AUDIT_ONLY`，不证明运行路径可行或实际执行。

## Phase 10D Step 8B-2D1 Typed Static Behavior Analysis Projection

Step 8B-2D1 在独立 `chipchain.analysis` 层中，通过 A-profile adapter 把 frozen C2
`AProfileStaticCaseAssemblyResult` 纯确定性投影为 architecture-neutral
`StaticBehaviorAnalysisProjection`。shared representation 明确分成两个 sibling：

```text
AProfileStaticCaseAssemblyResult
        ↓ A-profile detached materialization adapter
AProfileStaticBehaviorProjectionMaterialization
        ├── exact C2 source snapshot
        └── StaticBehaviorAnalysisProjection
                ├── program_graph: objective binary facts + structural CFG relations
                └── pattern_bindings: deterministic predicate/case-order candidates
```

`program_graph` 只允许 FUNCTION、BASIC_BLOCK、SEMANTIC_INSTRUCTION_FACT 节点，以及
FUNCTION_CONTAINS_BASIC_BLOCK、BASIC_BLOCK_CONTAINS_SEMANTIC_FACT、CFG_SUCCESSOR 关系。所有关系固定
`causal=false`、`runtime_execution=false`、`symbolic_feasibility=false`。artifact ID/SHA、source analysis
ID/contract、fact、CFG block/edge 与 candidate references 全部进入 generic deterministic identity。共享模型
不导入 `hardware_trigger` 或 A-profile 类型；exact C2 snapshot 只由 adapter materialization envelope 保存，并
从该 snapshot 重建预期 generic projection 以拒绝 provenance retarget。

pattern candidate 不进入 program graph，也不是 program edge；它只在 sibling projection 中保留 exact
predicate/case/position/fact-node references、CFG audit witness 和全部 unresolved objective obligations。
因此 pattern binding 不等于 objective binary fact，candidate 不等于 trigger satisfied，program graph path
也不等于 causal attack chain。

2D1 没有修改 legacy `BehaviorType`/`NodeKind`/`RelationType` 或旧 Behavior Graph；program graph 也不是
knowledge graph。它不创建 vulnerability/AttackChain node、CrossLayerInteraction、Evidence、
VerificationRecord、Triggerability 或 ReasoningContext binding。共享投影模型和 JSON Schema 均保持
architecture-neutral；未来 architecture adapter 可产生同一 shared representation，无需修改 graph contracts，
但当前 adapter 的语义覆盖仍严格受 frozen narrow A-profile v1 decoder 限制；2D1 不是完整 AArch64
semantic graph，也没有实现未来 2D2 generic semantic decoder。

## 文档导航

- [项目范围](docs/PROJECT_SCOPE.md)
- [系统架构](docs/ARCHITECTURE.md)
- [数据模型](docs/DATA_MODEL.md)
- [实体链接契约](docs/ENTITY_LINKING.md)
- [Candidate Search](docs/CANDIDATE_SEARCH.md)
- [RAG Reasoning](docs/RAG_REASONING.md)
- [Multi-Agent Reasoning](docs/MULTI_AGENT_REASONING.md)
- [Cross-Layer Semantics](docs/CROSS_LAYER_SEMANTICS.md)
- [Phase 9A Migration](docs/PHASE9A_MIGRATION.md)
- [Interaction Verification](docs/INTERACTION_VERIFICATION.md)
- [Evidence Verification](docs/EVIDENCE_VERIFICATION.md)
- [Dynamic Interaction Verification](docs/DYNAMIC_INTERACTION_VERIFICATION.md)
- [Hardware Trigger Signatures](docs/HARDWARE_TRIGGER_SIGNATURES.md)
- [QEMU Passive Observer](docs/QEMU_PASSIVE_OBSERVER.md)
- [QEMU MMIO Classification](docs/QEMU_MMIO_CLASSIFICATION.md)
- [Role-Aware Localization](docs/ROOT_CAUSE_LOCALIZATION.md)
- [评测设计](docs/EVALUATION.md)
- [Phase 10A Evaluation Contracts](docs/EVALUATION_CONTRACTS.md)
- [angr 接入说明](docs/ANGR_INTEGRATION_PLAN.md)
- [阶段计划](PLANS.md)

## 数据真实性

演示和测试数据必须标记为 `demo`、`synthetic` 或 `fixture`。没有可审计来源的数据不得作为真实 CVE 或正式 Benchmark 发布。
