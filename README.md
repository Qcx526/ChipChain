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

当前 reduced semantic provider contract 标识为
`phase9b2c_reasoning_semantic_output_v2`；不兼容的旧
`phase9b2b_reasoning_output_v1` 不会在新 DTO 下被接受，也没有 legacy parser。该 bridge 从
constrained parser 使用的同一 Pydantic transport DTO 生成 strict JSON Schema。
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
仍未实现。
设计边界见 [Hardware Trigger Signatures](docs/HARDWARE_TRIGGER_SIGNATURES.md)。

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
- [angr 接入说明](docs/ANGR_INTEGRATION_PLAN.md)
- [阶段计划](PLANS.md)

## 数据真实性

演示和测试数据必须标记为 `demo`、`synthetic` 或 `fixture`。没有可审计来源的数据不得作为真实 CVE 或正式 Benchmark 发布。
