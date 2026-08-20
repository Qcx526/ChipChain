# ChipChain 开发约束

本文件记录仓库内所有后续开发必须遵守的长期原则。若具体任务与本文件冲突，先向项目负责人说明冲突，不得静默扩大研究范围。

## 研究边界

- ChipChain 面向防御性科研，用于检测、分析、验证和解释跨层芯片漏洞攻击链。
- “跨层”指同一芯片架构内由真实软硬件接口传播的双向安全关联，不等于跨架构拼接。
- 正式 Cross-Layer Semantics 只有三类：软件侧漏洞触发硬件漏洞、正常软件行为在特定
  条件下触发硬件漏洞、硬件漏洞或异常状态反向影响软件执行。后续实现不得默认所有
  跨层链都始于软件漏洞。
- Type II 不得为建模方便伪造 firmware vulnerability；Type III 不得反转现有
  software→hardware GraphPath 来冒充 hardware→software Evidence。
- 当前只实现 ARM MVP；ARM 闭环稳定并完成评测后，才讨论第二种架构。
- 不生成面向真实未授权目标的武器化利用代码。测试仅使用自有代码、toy、synthetic、fixture、公开基准或明确授权环境。
- 示例或合成数据必须明确标记 `demo`、`synthetic` 或 `fixture`，不得伪装成真实 CVE 或正式 Benchmark。

## 工程原则

- 优先级：正确性 > 可验证性 > 可解释性 > 可维护性 > 功能数量 > 表面复杂度。
- 采用 `src` 布局，Python 版本下限为 3.11，公共接口必须有类型标注和必要的 docstring。
- 每个阶段遵循 Plan → Implement → Test → Review → Fix → Document。
- 每个新增能力应有相称的单元测试；测试默认不得依赖 API Key、外部数据库或网络。
- 保持模块职责单一，避免巨大文件、重复代码、隐藏的全局状态和硬编码实验权重。
- API Key 只能从环境变量读取；`.env` 不得提交，新增变量同步写入 `.env.example`。
- 不破坏用户已有改动；修改前先检查仓库和相关文档。

## 架构约束

- 核心系统不得绑定单一程序分析器、图数据库、LLM Provider 或知识检索实现。
- MVP 的图存储使用 NetworkX + JSON；Neo4j 只能作为后续可选实现。
- 测试中的 LLM 必须使用 Mock Provider；真实 Provider 只能是可选集成。
- 架构知识必须隔离或强过滤，攻击链中的架构相关节点必须与目标架构一致。
- LLM 只能生成候选链，未经静态/动态证据和架构规则验证，不得称为已确认攻击链。
- 评分权重放入配置文件，LLM 语义置信度不得占主导。

## 当前阶段限制

- Phase 0～8R、Phase 9A-R1/R2/R3、Phase 9B0 与 Phase 9B0-R1 Runtime Snapshot
  Integrity Hardening 已完成。Phase 9B1 passive observer 的离线实现已完成，但真实 QEMU、
  plugin 编译/加载和 owned firmware 执行尚未在参考环境验证，阶段状态仍为 real blocked。
  Verification 顶层 identity 是
  `CrossLayerInteraction`，legacy Candidate 只能作为显式 software→hardware evidence source。
- Type I/II 当前只有部分客观验证能力；Type III 客观 hardware→software propagation
  verification 为 `not_implemented`，不得反转旧 GraphPath 或伪造反向 BehaviorEdge。
- Evidence binding 必须具有结构化 subject linkage；Node existence 只能解析 reference；
  architecture/condition 不能单独产生 partial verification；定位只能使用 supporting Evidence。
- Legacy Candidate facts 只有通过显式 Interaction binding 才能支持 required truth；Evidence
  ID collision 必须拒绝；direct Evidence 不能独立验证 vulnerability participant。
- 同一 `(reference_role, interaction_reference_id)` 在 MVP 中至多绑定一个 source；
  VerificationResult 的各 VerificationRecord 集合不得包含重复 ID。
- RuntimeObservation 与 RuntimeIntervention 必须分离；事件顺序不等于因果，Dynamic
  Evidence verified 只表示 observation contract/integrity 已验证，不表示漏洞或 Interaction。
- 从 mutable RuntimeTrace 生成 verified Dynamic Evidence 前，必须经过 detached serialized
  snapshot revalidation；不得信任先前校验过但可能被原地修改的 Pydantic object。
- Runtime Trace 独立于 Behavior Graph；不得伪造 reverse BehaviorEdge，也不得绕过显式
  Interaction binding。9B1 仅允许 ARM32 `virt`/`cortex-a15`/单 vCPU 的 passive QEMU
  instruction 与 IO-classified MMIO observation；不得把它接入 Interaction verifier。
- 未经明确安排，不实现 QEMU mutation/fault/interrupt/DMA injection、Verified AttackChain
  projection、Additional Architectures、FastAPI/GUI 或 Exploit Generation。

## 提交前检查

- 运行完整测试并如实记录命令与结果。
- 验证 `chipchain --help` 和 `python -m chipchain --help`。
- 检查新增数据的来源、类型和架构字段。
- 更新受影响的 README、设计文档和阶段计划。
